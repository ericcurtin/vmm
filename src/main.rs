//! vmm - A Docker-like experience for VMs using libkrun
//!
//! This tool provides a familiar Docker-like interface for creating and managing
//! lightweight virtual machines using libkrun-efi.

mod cli;
mod docker;
mod storage;
mod vm;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use tracing::debug;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use cli::{default_cpus, default_memory_mib, Cli, Commands};
use docker::{extract_image, pull_image, resolve_shortname};
use storage::{VmState, VmStatus, VmStore, VmmPaths};
use vm::{
    create_disk_image, ensure_gvproxy, ensure_kernel, prepare_vm_rootfs, run_vm, HostUserInfo,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Detect if we're running a VM (suppress logging unless --verbose)
    let is_run_command = matches!(&cli.command, Commands::Run { .. });

    // Set up logging - suppress for vmm run for cleaner output (unless verbose)
    let quiet = is_run_command && !cli.verbose;
    if !quiet {
        // Filter out noisy third-party crate logs
        // In verbose mode, show vmm debug + krun/kernel logs for boot sequence
        let filter = if cli.verbose {
            EnvFilter::new("vmm=debug,krun=debug,warn")
        } else {
            EnvFilter::new("vmm=info,warn")
        };

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .without_time()
            .with_writer(std::io::stderr)
            .init();
    }

    // Initialize paths
    let paths = VmmPaths::new()?;
    paths.ensure_dirs()?;

    match cli.command {
        Commands::Run {
            image,
            cpus,
            memory,
            name,
        } => {
            let cpus = cpus.unwrap_or_else(default_cpus);
            let memory = memory.unwrap_or_else(default_memory_mib);
            cmd_run(&paths, &image, cpus, memory, name, quiet).await
        }
        Commands::Ls => cmd_list(&paths).await,
        Commands::Ps => cmd_ps(&paths).await,
        Commands::Stop { vm } => cmd_stop(&paths, &vm).await,
        Commands::Rm { vm, force } => cmd_rm(&paths, &vm, force).await,
        Commands::Start { vm } => cmd_start(&paths, &vm).await,
        Commands::Attach { vm } => cmd_attach(&paths, &vm).await,
        Commands::Inspect { vm } => cmd_inspect(&paths, &vm).await,
        Commands::Pull { image } => cmd_pull(&image).await,
    }
}

async fn cmd_run(
    paths: &VmmPaths,
    image: &str,
    cpus: u8,
    memory: u32,
    name: Option<String>,
    quiet: bool,
) -> Result<()> {
    // Resolve shortnames (e.g., "centos" -> "quay.io/centos/centos")
    let resolved_image = resolve_shortname(image);
    let image = resolved_image.as_str();

    // Check if there's an existing VM for this image that we can reuse
    let mut store = VmStore::load(paths)?;
    store.refresh_status();
    store.save(paths)?; // Save any status updates from refresh

    // Check if there's a VM currently being created for this image
    if let Some(creating_vm) = store.find_creating_by_image(image) {
        eprintln!(
            "VM '{}' is currently being created for image '{}'.",
            creating_vm.name, image
        );
        eprintln!("Please wait for the current creation to complete.");
        return Ok(());
    }

    // Check if there's a running VM for this image - attach to it instead
    if let Some(running_vm) = store.find_running_by_image(image) {
        let vsock_path = paths.vm_vsock(&running_vm.id);
        if vsock_path.exists() {
            // VM is running and has vsock socket - attach to it
            eprintln!(
                "Found running VM '{}' for image '{}', attaching...",
                running_vm.name, image
            );
            let vm_id = running_vm.id.clone();
            drop(store); // Release the store before calling cmd_attach
            return cmd_attach(paths, &vm_id).await;
        } else {
            // VM is running but vsock socket doesn't exist yet
            // This can happen if the guest hasn't started the vsock service
            // or if libkrun hasn't created the socket yet
            eprintln!(
                "VM '{}' is already running for image '{}'.",
                running_vm.name, image
            );
            eprintln!(
                "Use 'vmm attach {}' once the VM's vsock service is ready.",
                running_vm.name
            );
            return Ok(());
        }
    }

    // Check if there's a stopped VM we can restart
    if let Some(existing_vm) = store.find_by_image(image) {
        // Reuse existing VM
        let vm_id = existing_vm.id.clone();
        let _vm_name = existing_vm.name.clone();
        let distro = existing_vm.distro.clone();

        // Get paths
        let disk_path = paths.vm_disk(&vm_id);
        let kernel = ensure_kernel(paths, &distro, Some(image), !quiet).await?;

        // Check disk exists
        if !disk_path.exists() {
            // Disk is gone, can't reuse - fall through to create new
            eprintln!("VM disk missing, creating new VM");
        } else {
            // Update state
            {
                let vm = store.get_mut(&vm_id).unwrap();
                vm.status = VmStatus::Running;
                vm.started_at = Some(Utc::now());
                vm.pid = Some(std::process::id());
            }
            store.save(paths)?;

            // Get host user info for home directory sharing
            let host_user = HostUserInfo::current()?;

            // Ensure gvproxy is available (downloads if needed)
            ensure_gvproxy(&paths.bin_dir()).await?;

            // Run the VM
            let vsock_path = paths.vm_vsock(&vm_id);
            let gvproxy_path = paths.vm_gvproxy(&vm_id);
            let config = vm::runner::VmConfig {
                vcpus: cpus,
                ram_mib: memory,
                disk_path: disk_path.to_string_lossy().to_string(),
                kernel,
                quiet,
                host_home: Some(host_user.home_dir.clone()),
                vsock_path: Some(vsock_path.to_string_lossy().to_string()),
                gvproxy_socket: Some(gvproxy_path.to_string_lossy().to_string()),
                bin_dir: Some(paths.bin_dir().to_string_lossy().to_string()),
            };

            run_vm(config)?;

            // If we get here, VM exited
            let mut store = VmStore::load(paths)?;
            if let Some(vm) = store.get_mut(&vm_id) {
                vm.status = VmStatus::Stopped;
                vm.pid = None;
            }
            store.save(paths)?;

            return Ok(());
        }
    }

    // No existing VM found, create a new one
    let vm_id = Uuid::new_v4().to_string();
    let vm_name = name.unwrap_or_else(|| {
        // Use the base image name (e.g., "ubuntu" from "docker.io/library/ubuntu:latest")
        let base = image.split(':').next().unwrap_or(image);
        base.split('/').last().unwrap_or(base).to_string()
    });

    // Progress output - always shown to user (eprintln goes to stderr)
    eprintln!("Creating VM '{}' from image '{}'", vm_name, image);

    // Save VM state early with "Creating" status to prevent race conditions
    // This ensures a second `vmm run` will see this VM is being created
    let mut vm_state = VmState::new(
        vm_id.clone(),
        vm_name.clone(),
        image.to_string(),
        "unknown".to_string(), // distro will be detected later
    );
    vm_state.vcpus = cpus;
    vm_state.ram_mib = memory;
    vm_state.pid = Some(std::process::id());
    // status is already Creating from VmState::new()

    store.add(vm_state);
    store.save(paths)?;

    // Pull the image
    eprintln!("Pulling image...");
    let image_info = pull_image(image).await.context("Failed to pull image")?;
    debug!("Image ID: {}", image_info.id);

    // Create VM directory
    let vm_dir = paths.vm_dir(&vm_id);
    std::fs::create_dir_all(&vm_dir)?;

    // Extract image to rootfs
    let rootfs = paths.vm_rootfs(&vm_id);
    eprintln!("Extracting image...");
    extract_image(image, &rootfs)
        .await
        .context("Failed to extract image")?;

    // Detect distro
    let distro = vm::setup::detect_distro(&rootfs)?;

    // Prepare rootfs (auto-login, init, etc.)
    eprintln!("Preparing VM rootfs...");
    prepare_vm_rootfs(&rootfs, &distro)
        .await
        .context("Failed to prepare rootfs")?;

    // Ensure kernel is available
    eprintln!("Fetching kernel...");
    let kernel = ensure_kernel(paths, &distro, Some(image), !quiet)
        .await
        .context("Failed to ensure kernel")?;

    // Create disk image from rootfs
    let disk_path = paths.vm_disk(&vm_id);
    eprintln!("Creating disk image...");
    create_disk_image(&rootfs, &disk_path, None)
        .await
        .context("Failed to create disk image")?;

    // Install kernel and initrd on disk
    eprintln!("Installing bootloader...");
    vm::disk::install_bootloader(&disk_path, &kernel.kernel_path, &kernel.initrd_path)
        .await
        .context("Failed to install bootloader")?;

    // Update VM state from Creating to Running, with detected distro
    let mut store = VmStore::load(paths)?;
    if let Some(vm) = store.get_mut(&vm_id) {
        vm.distro = distro.clone();
        vm.status = VmStatus::Running;
        vm.started_at = Some(Utc::now());
    }
    store.save(paths)?;

    eprintln!(
        "Starting VM '{}' with {} vCPUs and {} MiB RAM...",
        vm_name, cpus, memory
    );

    // Get host user info for home directory sharing
    let host_user = HostUserInfo::current()?;

    // Ensure gvproxy is available (downloads if needed)
    ensure_gvproxy(&paths.bin_dir()).await?;

    // Run the VM (this doesn't return on success)
    let vsock_path = paths.vm_vsock(&vm_id);
    let gvproxy_path = paths.vm_gvproxy(&vm_id);
    let config = vm::runner::VmConfig {
        vcpus: cpus,
        ram_mib: memory,
        disk_path: disk_path.to_string_lossy().to_string(),
        kernel,
        quiet,
        host_home: Some(host_user.home_dir.clone()),
        vsock_path: Some(vsock_path.to_string_lossy().to_string()),
        gvproxy_socket: Some(gvproxy_path.to_string_lossy().to_string()),
        bin_dir: Some(paths.bin_dir().to_string_lossy().to_string()),
    };

    run_vm(config)?;

    // If we get here, the VM exited
    let mut store = VmStore::load(paths)?;
    if let Some(vm) = store.get_mut(&vm_id) {
        vm.status = VmStatus::Stopped;
        vm.pid = None;
    }
    store.save(paths)?;

    Ok(())
}

async fn cmd_list(paths: &VmmPaths) -> Result<()> {
    let mut store = VmStore::load(paths)?;
    store.refresh_status();
    store.save(paths)?;

    let vms = store.list();

    if vms.is_empty() {
        println!("No VMs found. Use 'vmm run <image>' to create one.");
        return Ok(());
    }

    // Print header (Docker-style) - use consistent column widths
    println!(
        "{:<12} {:<28} {:<12} {:<12}",
        "NAME", "IMAGE", "MEMORY", "CREATED"
    );

    for vm in vms {
        // Format memory nicely (e.g., 2Gi, 16Gi, 512Mi)
        let memory_str = if vm.ram_mib >= 1024 && vm.ram_mib % 1024 == 0 {
            format!("{}Gi", vm.ram_mib / 1024)
        } else {
            format!("{}Mi", vm.ram_mib)
        };
        let created_ago = format_relative_time(vm.created_at);
        println!(
            "{:<12} {:<28} {:<12} {:<12}",
            truncate(&vm.name, 12),
            truncate(&vm.image, 28),
            memory_str,
            created_ago
        );
    }

    Ok(())
}

async fn cmd_ps(paths: &VmmPaths) -> Result<()> {
    let mut store = VmStore::load(paths)?;
    store.refresh_status();
    store.save(paths)?;

    let vms: Vec<_> = store
        .list()
        .into_iter()
        .filter(|vm| vm.status == VmStatus::Running)
        .collect();

    if vms.is_empty() {
        println!("No running VMs. Use 'vmm run <image>' to start one.");
        return Ok(());
    }

    // Print header (Docker ps style)
    println!(
        "{:<12} {:<28} {:<12} {:<12}",
        "NAME", "IMAGE", "MEMORY", "STATUS"
    );

    for vm in vms {
        // Format memory nicely (e.g., 2Gi, 16Gi, 512Mi)
        let memory_str = if vm.ram_mib >= 1024 && vm.ram_mib % 1024 == 0 {
            format!("{}Gi", vm.ram_mib / 1024)
        } else {
            format!("{}Mi", vm.ram_mib)
        };
        let status_str = if let Some(started_at) = vm.started_at {
            format!(
                "Up {}",
                format_relative_time(started_at).replace(" ago", "")
            )
        } else {
            "Running".to_string()
        };
        println!(
            "{:<12} {:<28} {:<12} {:<12}",
            truncate(&vm.name, 12),
            truncate(&vm.image, 28),
            memory_str,
            status_str
        );
    }

    Ok(())
}

/// Format a DateTime as relative time (e.g., "5 minutes ago", "2 hours ago")
fn format_relative_time(dt: chrono::DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(dt);

    let seconds = duration.num_seconds();
    if seconds < 0 {
        return "just now".to_string();
    }

    let minutes = duration.num_minutes();
    let hours = duration.num_hours();
    let days = duration.num_days();
    let weeks = days / 7;

    if seconds < 60 {
        if seconds == 1 {
            "1 second ago".to_string()
        } else {
            format!("{} seconds ago", seconds)
        }
    } else if minutes < 60 {
        if minutes == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", minutes)
        }
    } else if hours < 24 {
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if days < 7 {
        if days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if weeks < 4 {
        if weeks == 1 {
            "1 week ago".to_string()
        } else {
            format!("{} weeks ago", weeks)
        }
    } else {
        // For older entries, show the date
        dt.format("%Y-%m-%d").to_string()
    }
}

async fn cmd_stop(paths: &VmmPaths, vm_id: &str) -> Result<()> {
    let mut store = VmStore::load(paths)?;
    store.refresh_status();

    let vm = store
        .get_mut(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    if vm.status != VmStatus::Running {
        println!("VM '{}' is not running", vm.name);
        return Ok(());
    }

    if let Some(pid) = vm.pid {
        println!("Stopping VM '{}' (PID: {})...", vm.name, pid);
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        vm.status = VmStatus::Stopped;
        vm.pid = None;
        println!("VM '{}' stopped", vm.name);
    }

    store.save(paths)?;
    Ok(())
}

async fn cmd_rm(paths: &VmmPaths, vm_id: &str, force: bool) -> Result<()> {
    let mut store = VmStore::load(paths)?;
    store.refresh_status();

    let vm = store
        .get(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    if vm.status == VmStatus::Running && !force {
        return Err(anyhow::anyhow!(
            "VM '{}' is running. Stop it first or use --force",
            vm.name
        ));
    }

    let vm_name = vm.name.clone();
    let full_id = vm.id.clone();

    // Stop if running
    if vm.status == VmStatus::Running {
        if let Some(pid) = vm.pid {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
    }

    // Remove from store
    store.remove(vm_id);
    store.save(paths)?;

    // Remove VM directory
    let vm_dir = paths.vm_dir(&full_id);
    if vm_dir.exists() {
        remove_dir_force(&vm_dir).context("Failed to remove VM directory")?;
    }

    println!("Removed VM '{}'", vm_name);
    Ok(())
}

/// Recursively remove a directory, fixing permissions as needed.
/// Container rootfs extractions often have read-only directories that
/// prevent normal removal.
fn remove_dir_force(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Get metadata without following symlinks
    let metadata = match path.symlink_metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    if metadata.is_dir() {
        // Make the directory writable so we can remove its contents
        let mut perms = metadata.permissions();
        perms.set_mode(perms.mode() | 0o700);
        let _ = std::fs::set_permissions(path, perms);

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let entry_metadata = match entry_path.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue, // Skip entries we can't read
            };

            if entry_metadata.is_dir() {
                remove_dir_force(&entry_path)?;
            } else {
                // Make file writable before removing (for regular files)
                if entry_metadata.is_file() {
                    let mut perms = entry_metadata.permissions();
                    perms.set_mode(perms.mode() | 0o600);
                    let _ = std::fs::set_permissions(&entry_path, perms);
                }
                // Remove file or symlink
                std::fs::remove_file(&entry_path)?;
            }
        }
        std::fs::remove_dir(path)?;
    } else {
        // It's a file or symlink
        std::fs::remove_file(path)?;
    }
    Ok(())
}

async fn cmd_start(paths: &VmmPaths, vm_id: &str) -> Result<()> {
    let mut store = VmStore::load(paths)?;

    let vm = store
        .get(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    if vm.status == VmStatus::Running {
        println!("VM '{}' is already running", vm.name);
        return Ok(());
    }

    let vm_id = vm.id.clone();
    let vm_name = vm.name.clone();
    let vm_image = vm.image.clone();
    let distro = vm.distro.clone();
    let vcpus = vm.vcpus;
    let ram_mib = vm.ram_mib;

    // Get paths
    let disk_path = paths.vm_disk(&vm_id);
    let kernel = ensure_kernel(paths, &distro, Some(&vm_image), false).await?;

    // Check disk exists
    if !disk_path.exists() {
        return Err(anyhow::anyhow!(
            "VM disk image not found. The VM may be corrupted."
        ));
    }

    // Update state
    {
        let vm = store.get_mut(&vm_id).unwrap();
        vm.status = VmStatus::Running;
        vm.started_at = Some(Utc::now());
        vm.pid = Some(std::process::id());
    }
    store.save(paths)?;

    println!("Starting VM '{}'...", vm_name);
    println!();

    // Get host user info for home directory sharing
    let host_user = HostUserInfo::current()?;

    // Ensure gvproxy is available (downloads if needed)
    ensure_gvproxy(&paths.bin_dir()).await?;

    let vsock_path = paths.vm_vsock(&vm_id);
    let gvproxy_path = paths.vm_gvproxy(&vm_id);
    let config = vm::runner::VmConfig {
        vcpus,
        ram_mib,
        disk_path: disk_path.to_string_lossy().to_string(),
        kernel,
        quiet: false,
        host_home: Some(host_user.home_dir.clone()),
        vsock_path: Some(vsock_path.to_string_lossy().to_string()),
        gvproxy_socket: Some(gvproxy_path.to_string_lossy().to_string()),
        bin_dir: Some(paths.bin_dir().to_string_lossy().to_string()),
    };

    run_vm(config)?;

    // If we get here, VM exited
    let mut store = VmStore::load(paths)?;
    if let Some(vm) = store.get_mut(&vm_id) {
        vm.status = VmStatus::Stopped;
        vm.pid = None;
    }
    store.save(paths)?;

    Ok(())
}

async fn cmd_attach(paths: &VmmPaths, vm_id: &str) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let store = VmStore::load(paths)?;

    let vm = store
        .get(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    if vm.status != VmStatus::Running {
        return Err(anyhow::anyhow!("VM '{}' is not running", vm.name));
    }

    // Get the vsock socket path for this VM
    let vsock_path = paths.vm_vsock(&vm.id);

    if !vsock_path.exists() {
        return Err(anyhow::anyhow!(
            "VM '{}' does not have a vsock socket. This VM may have been created before vsock support was added.\n\
            Try stopping and restarting the VM, or recreate it.",
            vm.name
        ));
    }

    // Connect to the vsock Unix socket
    let mut stream = UnixStream::connect(&vsock_path).context(format!(
        "Failed to connect to VM '{}' via vsock socket",
        vm.name
    ))?;

    // Set the stream to non-blocking for the read side
    stream.set_nonblocking(true)?;

    // Set up terminal raw mode
    let _terminal_guard = setup_terminal_raw()?;

    println!("Attached to VM '{}'. Press Ctrl+D to detach.\r", vm.name);

    // Create a clone for the write thread
    let mut write_stream = stream.try_clone()?;

    // Spawn a thread to handle stdin -> socket
    let stdin_handle = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut buf = [0u8; 1024];

        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break, // EOF (Ctrl+D)
                Ok(n) => {
                    // Check for Ctrl+D (0x04)
                    if buf[..n].contains(&0x04) {
                        break;
                    }
                    if write_stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = write_stream.flush();
                }
                Err(_) => break,
            }
        }
    });

    // Main thread handles socket -> stdout
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                // Connection closed
                break;
            }
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = stdout.flush();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, sleep briefly and retry
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => break,
        }

        // Check if stdin thread has finished
        if stdin_handle.is_finished() {
            break;
        }
    }

    // Wait for stdin thread to finish
    let _ = stdin_handle.join();

    println!("\r\nDetached from VM '{}'.", vm.name);

    Ok(())
}

/// RAII guard for terminal settings (raw mode for attach)
struct TerminalRawGuard {
    original: Option<termios::Termios>,
}

impl Drop for TerminalRawGuard {
    fn drop(&mut self) {
        if let Some(ref original) = self.original {
            let _ = termios::tcsetattr(libc::STDIN_FILENO, termios::TCSANOW, original);
        }
    }
}

fn setup_terminal_raw() -> Result<TerminalRawGuard> {
    use termios::*;

    // Check if stdin is a tty
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Ok(TerminalRawGuard { original: None });
    }

    // Save original settings
    let original =
        Termios::from_fd(libc::STDIN_FILENO).context("Failed to get terminal settings")?;

    // Set raw mode
    let mut raw = original.clone();
    raw.c_lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
    raw.c_iflag &= !(IXON | BRKINT | INPCK | ISTRIP | ICRNL);
    raw.c_oflag |= OPOST | ONLCR;
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    tcsetattr(libc::STDIN_FILENO, TCSANOW, &raw).context("Failed to set terminal to raw mode")?;

    Ok(TerminalRawGuard {
        original: Some(original),
    })
}

async fn cmd_inspect(paths: &VmmPaths, vm_id: &str) -> Result<()> {
    let store = VmStore::load(paths)?;

    let vm = store
        .get(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    let json = serde_json::to_string_pretty(vm)?;
    println!("{}", json);

    Ok(())
}

async fn cmd_pull(image: &str) -> Result<()> {
    // Resolve shortnames (e.g., "centos" -> "quay.io/centos/centos")
    let resolved_image = resolve_shortname(image);
    println!("Pulling image '{}'...", resolved_image);
    let image_info = pull_image(&resolved_image).await?;
    println!("Successfully pulled {}", resolved_image);
    println!(
        "Image ID: {}",
        &image_info.id[..12.min(image_info.id.len())]
    );
    Ok(())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
