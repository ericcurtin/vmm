//! VM execution using libkrun
//!
//! This module handles starting VMs using the libkrun-efi library.
//! libkrun-efi uses EFI firmware for boot, so we boot from disk images
//! that have a kernel and bootloader installed.

use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::os::unix::io::FromRawFd;
use std::path::Path;
use tracing::{debug, info};

use super::krun_ffi::{KrunContext, KRUN_DISK_FORMAT_RAW, KRUN_LOG_LEVEL_WARN};
use super::kernel::KernelInfo;

/// Configuration for running a VM
pub struct VmConfig {
    pub vcpus: u8,
    pub ram_mib: u32,
    pub disk_path: String,
    pub kernel: KernelInfo,
    /// Command to run (empty for interactive shell)
    pub command: Vec<String>,
    /// Quiet mode - suppress logging for cleaner command output
    pub quiet: bool,
    /// Host home directory to share with the VM
    pub host_home: Option<String>,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            vcpus: 2,
            ram_mib: 2048,
            disk_path: String::new(),
            kernel: KernelInfo {
                kernel_path: std::path::PathBuf::new(),
                initrd_path: std::path::PathBuf::new(),
                cmdline: String::new(),
            },
            command: Vec::new(),
            quiet: false,
            host_home: None,
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

            // Run VM (doesn't return on success)
            run_vm_inner(config)?;
            std::process::exit(0);
        }
        child_pid => {
            // Parent process - filters output
            unsafe { libc::close(stderr_write); }

            // Read from pipe and filter
            let stderr_file = unsafe { std::fs::File::from_raw_fd(stderr_read) };
            let reader = BufReader::new(stderr_file);

            for line in reader.lines() {
                let Ok(line) = line else { continue };

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
    debug!("Kernel: {:?}", config.kernel.kernel_path);

    // Verify disk exists
    if !Path::new(&config.disk_path).exists() {
        return Err(anyhow::anyhow!("Disk image not found: {}", config.disk_path));
    }

    // Set up terminal for raw mode
    let _terminal_guard = setup_terminal()?;

    // Set log level - use WARN normally, but in quiet mode we're already filtered
    KrunContext::set_log_level(KRUN_LOG_LEVEL_WARN)
        .map_err(|e| anyhow::anyhow!("Failed to set log level: {}", e))?;

    // Create context
    let ctx = KrunContext::new()
        .map_err(|e| anyhow::anyhow!("Failed to create krun context: {}", e))?;

    // Configure VM resources
    ctx.set_vm_config(config.vcpus, config.ram_mib)
        .map_err(|e| anyhow::anyhow!("Failed to set VM config: {}", e))?;

    // Add the disk as the boot device (vda)
    // libkrun-efi will use EFI firmware to boot from this disk
    ctx.add_disk2("vda", &config.disk_path, KRUN_DISK_FORMAT_RAW, false)
        .map_err(|e| anyhow::anyhow!("Failed to add disk: {}", e))?;

    // Configure root disk remount - tells the kernel to use /dev/vda as root
    ctx.set_root_disk_remount("/dev/vda", Some("ext4"), Some("rw"))
        .map_err(|e| anyhow::anyhow!("Failed to set root disk remount: {}", e))?;

    // Add virtiofs share for home directory if configured
    if let Some(ref home_path) = config.host_home {
        debug!("Sharing host home directory: {}", home_path);
        ctx.add_virtiofs("home", home_path)
            .map_err(|e| anyhow::anyhow!("Failed to add virtiofs share for home: {}", e))?;
    }

    // Set kernel and initrd for direct boot
    // libkrun-efi can do direct kernel boot as well as EFI boot
    let kernel_path = config
        .kernel
        .kernel_path
        .to_str()
        .context("Invalid kernel path")?;

    let initrd_path = if config.kernel.initrd_path.exists() {
        Some(
            config
                .kernel
                .initrd_path
                .to_str()
                .context("Invalid initrd path")?,
        )
    } else {
        None
    };

    // Detect kernel format from file
    let kernel_format = detect_kernel_format(&config.kernel.kernel_path)?;
    debug!("Detected kernel format: {}", kernel_format);

    ctx.set_kernel(kernel_path, kernel_format, initrd_path, &config.kernel.cmdline)
        .map_err(|e| anyhow::anyhow!("Failed to set kernel: {}", e))?;

    info!("Entering VM...");

    // Start the VM - this doesn't return on success
    ctx.start_enter()
        .map_err(|e| anyhow::anyhow!("VM exited with error: {}", e))
}

/// Detect kernel format from file magic
fn detect_kernel_format(kernel_path: &Path) -> Result<u32> {
    use std::fs::File;
    use std::io::Read;
    use super::krun_ffi::*;

    let mut file = File::open(kernel_path)
        .context("Failed to open kernel file")?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .context("Failed to read kernel magic")?;

    // Check for various kernel formats
    // PE format (ARM64 EFI stub): MZ magic
    if &magic[0..2] == b"MZ" {
        // Could be PE_GZ or uncompressed PE
        // Check for gzip signature after PE header
        return Ok(KRUN_KERNEL_FORMAT_RAW);  // Try RAW first
    }

    // ELF format
    if &magic[0..4] == b"\x7fELF" {
        return Ok(KRUN_KERNEL_FORMAT_ELF);
    }

    // Gzip compressed
    if &magic[0..2] == &[0x1f, 0x8b] {
        return Ok(KRUN_KERNEL_FORMAT_IMAGE_GZ);
    }

    // Bzip2 compressed
    if &magic[0..2] == b"BZ" {
        return Ok(KRUN_KERNEL_FORMAT_IMAGE_BZ2);
    }

    // Zstd compressed
    if &magic[0..4] == &[0x28, 0xb5, 0x2f, 0xfd] {
        return Ok(KRUN_KERNEL_FORMAT_IMAGE_ZSTD);
    }

    // Default to RAW
    Ok(KRUN_KERNEL_FORMAT_RAW)
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

    // Set raw mode
    let mut raw = original.clone();
    raw.c_lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
    raw.c_iflag &= !(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
    raw.c_oflag &= !(OPOST);
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    tcsetattr(libc::STDIN_FILENO, TCSANOW, &raw).context("Failed to set terminal to raw mode")?;

    Ok(TerminalGuard {
        original: Some(original),
    })
}
