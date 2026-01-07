//! VM execution using libkrun
//!
//! This module handles starting VMs using the libkrun-efi library.
//! libkrun-efi uses EFI firmware for boot, so we boot from disk images
//! that have GRUB2 bootloader installed in the EFI System Partition.

use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::os::unix::io::FromRawFd;
use std::path::Path;
use tracing::{debug, info};

use super::krun_ffi::{KrunContext, KRUN_LOG_LEVEL_DEBUG, KRUN_LOG_LEVEL_OFF};
use super::network::{cleanup_orphaned_gvproxy, GvProxy};

/// Vsock port for shell access
pub const VSOCK_SHELL_PORT: u32 = 5000;

/// Configuration for running a VM
pub struct VmConfig {
    pub vcpus: u8,
    pub ram_mib: u32,
    pub disk_path: String,
    /// Quiet mode - suppress logging for cleaner output
    pub quiet: bool,
    /// Host home directory to share with the VM
    pub host_home: Option<String>,
    /// Path to Unix socket for vsock shell access
    pub vsock_path: Option<String>,
    /// Path to gvproxy socket for network access
    pub gvproxy_socket: Option<String>,
    /// Path to bin directory for helper binaries (gvproxy)
    pub bin_dir: Option<String>,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            vcpus: 2,
            ram_mib: 2048,
            disk_path: String::new(),
            quiet: false,
            host_home: None,
            vsock_path: None,
            gvproxy_socket: None,
            bin_dir: None,
        }
    }
}

/// Run a VM with the given configuration
///
/// This function does not return on success - it enters the VM.
/// On error, it returns the error.
pub fn run_vm(config: VmConfig) -> Result<()> {
    // In quiet mode, fork and filter output
    if config.quiet {
        return run_vm_quiet(config);
    }

    run_vm_inner(config)
}

/// Run VM with output filtering for quiet mode
fn run_vm_quiet(config: VmConfig) -> Result<()> {
    // Create a pipe for stderr
    let mut stderr_pipe = [0i32; 2];
    if unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) } != 0 {
        return Err(anyhow::anyhow!("Failed to create pipe"));
    }
    let (stderr_read, stderr_write) = (stderr_pipe[0], stderr_pipe[1]);

    match unsafe { libc::fork() } {
        -1 => Err(anyhow::anyhow!("Failed to fork")),
        0 => {
            // Child process - runs the VM
            unsafe {
                libc::close(stderr_read);
                // Redirect stderr to the pipe
                libc::dup2(stderr_write, libc::STDERR_FILENO);
                libc::close(stderr_write);
            }

            // Run VM in a closure to ensure all destructors run before exit
            let exit_code = {
                match run_vm_inner(config) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("VM error: {}", e);
                        1
                    }
                }
            };

            // All destructors have run, now exit
            std::process::exit(exit_code);
        }
        child_pid => {
            // Parent process - filters output
            unsafe {
                libc::close(stderr_write);
            }

            // Read from pipe and filter
            let stderr_file = unsafe { std::fs::File::from_raw_fd(stderr_read) };
            let reader = BufReader::new(stderr_file);

            for line in reader.lines() {
                let Ok(line) = line else { continue };

                // Always show error messages from our own code
                if line.starts_with("Error:") || line.starts_with("VM error:") {
                    eprintln!("{}", line);
                    continue;
                }

                // Filter and transform libkrun log lines
                // Format: [timestamp ERROR init_or_kernel] message
                if line.contains("ERROR init_or_kernel]") {
                    // Extract the message after the ]
                    if let Some(pos) = line.find("] ") {
                        let message = &line[pos + 2..];
                        // Skip kernel messages (start with [ followed by timestamp)
                        if message.starts_with('[') && message.contains(']') {
                            // This is a kernel message like "[    0.198231] sysrq: Power Off"
                            continue;
                        }
                        // Print the actual command output
                        println!("{}", message);
                    }
                }
            }

            // Wait for child and get exit status
            let mut status: i32 = 0;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };

            // Clean up gvproxy process (child may have exited without running Drop)
            if let Some(ref gvproxy_socket) = config.gvproxy_socket {
                let pid_file = Path::new(gvproxy_socket).with_extension("pid");
                cleanup_orphaned_gvproxy(&pid_file);
            }

            if libc::WIFEXITED(status) {
                let exit_code = libc::WEXITSTATUS(status);
                if exit_code != 0 {
                    std::process::exit(exit_code);
                }
            }

            Ok(())
        }
    }
}

fn run_vm_inner(config: VmConfig) -> Result<()> {
    info!(
        "Starting VM with {} vCPUs and {} MiB RAM",
        config.vcpus, config.ram_mib
    );
    debug!("Disk: {}", config.disk_path);

    // Verify disk exists
    if !Path::new(&config.disk_path).exists() {
        return Err(anyhow::anyhow!(
            "Disk image not found: {}",
            config.disk_path
        ));
    }

    // Set up terminal for raw mode
    let _terminal_guard = setup_terminal()?;

    // Set log level - show boot sequence in verbose mode (quiet=false), suppress in quiet mode
    let log_level = if config.quiet {
        KRUN_LOG_LEVEL_OFF
    } else {
        KRUN_LOG_LEVEL_DEBUG
    };
    KrunContext::set_log_level(log_level)
        .map_err(|e| anyhow::anyhow!("Failed to set log level: {}", e))?;

    // Create context
    let ctx =
        KrunContext::new().map_err(|e| anyhow::anyhow!("Failed to create krun context: {}", e))?;

    // Configure VM resources
    ctx.set_vm_config(config.vcpus, config.ram_mib)
        .map_err(|e| anyhow::anyhow!("Failed to set VM config: {}", e))?;

    // Set the root disk for EFI boot
    // libkrun-efi will use EFI firmware to boot from GRUB2 in the EFI System Partition
    ctx.set_root_disk(&config.disk_path)
        .map_err(|e| anyhow::anyhow!("Failed to set root disk: {}", e))?;

    // Add virtiofs share for home directory if configured
    if let Some(ref home_path) = config.host_home {
        debug!("Sharing host home directory: {}", home_path);
        ctx.add_virtiofs("home", home_path)
            .map_err(|e| anyhow::anyhow!("Failed to add virtiofs share for home: {}", e))?;
    }

    // Set up vsock port for shell access if path provided
    // With listen=true, libkrun creates a Unix socket and listens on it.
    // When guest connects to vsock port, libkrun accepts connections on Unix socket.
    // Host clients connect to Unix socket, libkrun proxies to guest's vsock.
    if let Some(ref vsock_path) = config.vsock_path {
        debug!(
            "Setting up vsock port {} -> {}",
            VSOCK_SHELL_PORT, vsock_path
        );
        // Remove existing socket file if present
        let _ = std::fs::remove_file(vsock_path);

        // Tell libkrun about the vsock port mapping
        // listen=true means libkrun creates and manages the Unix socket
        ctx.add_vsock_port2(VSOCK_SHELL_PORT, vsock_path, true)
            .map_err(|e| anyhow::anyhow!("Failed to add vsock port: {}", e))?;
        debug!("Configured vsock port mapping with libkrun-managed socket");
    }

    // Set up networking via gvproxy if socket path and bin_dir provided
    // We start gvproxy here (inside the forked child in quiet mode) to avoid
    // the parent process killing gvproxy when it drops the handle
    let _gvproxy: Option<GvProxy> = if let (Some(ref gvproxy_socket), Some(ref bin_dir)) =
        (&config.gvproxy_socket, &config.bin_dir)
    {
        debug!("Starting gvproxy for networking");
        let gvproxy = GvProxy::start(Path::new(gvproxy_socket), Path::new(bin_dir))
            .context("Failed to start gvproxy for networking")?;

        debug!(
            "Configuring virtio-net with gvproxy socket: {}",
            gvproxy_socket
        );
        ctx.set_gvproxy_path(gvproxy_socket).map_err(|e| {
            anyhow::anyhow!(
                "Failed to set gvproxy path (error {}): socket={}",
                e,
                gvproxy_socket
            )
        })?;
        debug!("gvproxy path configured");
        Some(gvproxy)
    } else {
        None
    };

    // Boot via GRUB2 from the disk's EFI System Partition
    // No direct kernel boot - libkrun-efi will use EFI firmware to boot GRUB2
    info!("Entering VM (booting via GRUB2)...");

    // Start the VM - this doesn't return on success
    ctx.start_enter()
        .map_err(|e| anyhow::anyhow!("VM exited with error: {}", e))
}

/// RAII guard for terminal settings
struct TerminalGuard {
    original: Option<termios::Termios>,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(ref original) = self.original {
            let _ = termios::tcsetattr(libc::STDIN_FILENO, termios::TCSANOW, original);
        }
    }
}

fn setup_terminal() -> Result<TerminalGuard> {
    use termios::*;

    // Check if stdin is a tty
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Ok(TerminalGuard { original: None });
    }

    // Save original settings
    let original =
        Termios::from_fd(libc::STDIN_FILENO).context("Failed to get terminal settings")?;

    // Set raw mode for input, but keep output processing for proper line endings
    let mut raw = original;
    // Disable canonical mode, echo, signals, and extended input processing
    raw.c_lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
    // Disable input processing except keep some basics
    raw.c_iflag &= !(IXON | BRKINT | INPCK | ISTRIP);
    // Keep ICRNL to translate CR to NL on input
    // Keep OPOST and ONLCR for proper newline handling on output
    raw.c_oflag |= OPOST | ONLCR;
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    tcsetattr(libc::STDIN_FILENO, TCSANOW, &raw).context("Failed to set terminal to raw mode")?;

    Ok(TerminalGuard {
        original: Some(original),
    })
}
