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
use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

use cli::{Cli, Commands};
use docker::{extract_image, pull_image};
use storage::{VmState, VmStatus, VmStore, VmmPaths};
use vm::{create_disk_image, ensure_kernel, prepare_vm_rootfs, run_vm};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let _subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .init();

    // Initialize paths
    let paths = VmmPaths::new()?;
    paths.ensure_dirs()?;

    match cli.command {
        Commands::Run { image, cpus, memory, name } => {
            cmd_run(&paths, &image, cpus, memory, name).await
        }
        Commands::Images | Commands::Ls => {
            cmd_list(&paths).await
        }
        Commands::Stop { vm } => {
            cmd_stop(&paths, &vm).await
        }
        Commands::Rm { vm, force } => {
            cmd_rm(&paths, &vm, force).await
        }
        Commands::Start { vm } => {
            cmd_start(&paths, &vm).await
        }
        Commands::Attach { vm } => {
            cmd_attach(&paths, &vm).await
        }
        Commands::Inspect { vm } => {
            cmd_inspect(&paths, &vm).await
        }
        Commands::Pull { image } => {
            cmd_pull(&image).await
        }
    }
}

async fn cmd_run(
    paths: &VmmPaths,
    image: &str,
    cpus: u8,
    memory: u32,
    name: Option<String>,
) -> Result<()> {
    // Generate VM ID and name
    let vm_id = Uuid::new_v4().to_string();
    let vm_name = name.unwrap_or_else(|| {
        // Generate a name from the image
        let base = image.split(':').next().unwrap_or(image);
        let base = base.split('/').last().unwrap_or(base);
        format!("{}-{}", base, &vm_id[..8])
    });

    info!("Creating VM '{}' from image '{}'", vm_name, image);

    // Pull the image
    info!("Pulling image...");
    let image_info = pull_image(image).await
        .context("Failed to pull image")?;
    debug!("Image ID: {}", image_info.id);

    // Create VM directory
    let vm_dir = paths.vm_dir(&vm_id);
    std::fs::create_dir_all(&vm_dir)?;

    // Extract image to rootfs
    let rootfs = paths.vm_rootfs(&vm_id);
    info!("Extracting image to {:?}...", rootfs);
    extract_image(image, &rootfs).await
        .context("Failed to extract image")?;

    // Detect distro
    let distro = vm::setup::detect_distro(&rootfs)?;
    info!("Detected distribution: {}", distro);

    // Prepare rootfs (auto-login, init, etc.)
    info!("Preparing VM rootfs...");
    prepare_vm_rootfs(&rootfs, &distro).await
        .context("Failed to prepare rootfs")?;

    // Ensure kernel is available
    info!("Ensuring kernel is available...");
    let kernel = ensure_kernel(paths, &distro).await
        .context("Failed to ensure kernel")?;

    // Create disk image from rootfs
    let disk_path = paths.vm_disk(&vm_id);
    info!("Creating disk image...");
    create_disk_image(&rootfs, &disk_path, None).await
        .context("Failed to create disk image")?;

    // Install kernel and initrd on disk
    info!("Installing bootloader...");
    vm::disk::install_bootloader(&disk_path, &kernel.kernel_path, &kernel.initrd_path).await
        .context("Failed to install bootloader")?;

    // Create VM state
    let mut vm_state = VmState::new(
        vm_id.clone(),
        vm_name.clone(),
        image.to_string(),
        distro.clone(),
    );
    vm_state.vcpus = cpus;
    vm_state.ram_mib = memory;
    vm_state.status = VmStatus::Running;
    vm_state.started_at = Some(Utc::now());
    vm_state.pid = Some(std::process::id());

    // Save VM state
    let mut store = VmStore::load(paths)?;
    store.add(vm_state);
    store.save(paths)?;

    info!("Starting VM '{}' with {} vCPUs and {} MiB RAM...", vm_name, cpus, memory);
    println!("\n");

    // Run the VM (this doesn't return on success)
    let config = vm::runner::VmConfig {
        vcpus: cpus,
        ram_mib: memory,
        disk_path: disk_path.to_string_lossy().to_string(),
        kernel,
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

    // Print header
    println!("{:<12} {:<20} {:<15} {:<10} {:<8} {:<8} {}",
        "VM ID", "NAME", "IMAGE", "STATUS", "CPUS", "MEMORY", "CREATED");
    println!("{}", "-".repeat(90));

    for vm in vms {
        let created = vm.created_at.format("%Y-%m-%d %H:%M");
        println!("{:<12} {:<20} {:<15} {:<10} {:<8} {:<8} {}",
            vm.short_id(),
            truncate(&vm.name, 20),
            truncate(&vm.image, 15),
            vm.status,
            vm.vcpus,
            format!("{}Mi", vm.ram_mib),
            created);
    }

    Ok(())
}

async fn cmd_stop(paths: &VmmPaths, vm_id: &str) -> Result<()> {
    let mut store = VmStore::load(paths)?;

    let vm = store.get_mut(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    if vm.status != VmStatus::Running {
        println!("VM '{}' is not running", vm.name);
        return Ok(());
    }

    if let Some(pid) = vm.pid {
        info!("Stopping VM '{}' (PID: {})...", vm.name, pid);
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

    let vm = store.get(vm_id)
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
        std::fs::remove_dir_all(&vm_dir)
            .context("Failed to remove VM directory")?;
    }

    println!("Removed VM '{}'", vm_name);
    Ok(())
}

async fn cmd_start(paths: &VmmPaths, vm_id: &str) -> Result<()> {
    let mut store = VmStore::load(paths)?;

    let vm = store.get(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    if vm.status == VmStatus::Running {
        println!("VM '{}' is already running", vm.name);
        return Ok(());
    }

    let vm_id = vm.id.clone();
    let vm_name = vm.name.clone();
    let distro = vm.distro.clone();
    let vcpus = vm.vcpus;
    let ram_mib = vm.ram_mib;

    // Get paths
    let disk_path = paths.vm_disk(&vm_id);
    let kernel = ensure_kernel(paths, &distro).await?;

    // Check disk exists
    if !disk_path.exists() {
        return Err(anyhow::anyhow!("VM disk image not found. The VM may be corrupted."));
    }

    // Update state
    {
        let vm = store.get_mut(&vm_id).unwrap();
        vm.status = VmStatus::Running;
        vm.started_at = Some(Utc::now());
        vm.pid = Some(std::process::id());
    }
    store.save(paths)?;

    info!("Starting VM '{}'...", vm_name);
    println!("\n");

    let config = vm::runner::VmConfig {
        vcpus,
        ram_mib,
        disk_path: disk_path.to_string_lossy().to_string(),
        kernel,
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
    let store = VmStore::load(paths)?;

    let vm = store.get(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    if vm.status != VmStatus::Running {
        return Err(anyhow::anyhow!("VM '{}' is not running", vm.name));
    }

    // For now, we can't attach to a running VM
    // This would require proper PTY handling
    println!("Attaching to running VMs is not yet supported.");
    println!("Use 'vmm start {}' to start a stopped VM in the foreground.", vm_id);

    Ok(())
}

async fn cmd_inspect(paths: &VmmPaths, vm_id: &str) -> Result<()> {
    let store = VmStore::load(paths)?;

    let vm = store.get(vm_id)
        .context(format!("VM '{}' not found", vm_id))?;

    let json = serde_json::to_string_pretty(vm)?;
    println!("{}", json);

    Ok(())
}

async fn cmd_pull(image: &str) -> Result<()> {
    info!("Pulling image '{}'...", image);
    let image_info = pull_image(image).await?;
    println!("Successfully pulled {}", image);
    println!("Image ID: {}", &image_info.id[..12.min(image_info.id.len())]);
    Ok(())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
