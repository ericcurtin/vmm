//! VM execution using libkrun
//!
//! This module handles starting VMs using the libkrun-efi library.
//! libkrun-efi uses EFI firmware for boot, so we boot from disk images
//! that have a kernel and bootloader installed.

use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, info};

use super::krun_ffi::{KrunContext, KRUN_DISK_FORMAT_RAW, KRUN_LOG_LEVEL_DEBUG, KRUN_LOG_LEVEL_WARN};
use super::kernel::KernelInfo;

/// Configuration for running a VM
pub struct VmConfig {
    pub vcpus: u8,
    pub ram_mib: u32,
    pub disk_path: String,
    pub kernel: KernelInfo,
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
        }
    }
}

/// Run a VM with the given configuration
///
/// This function does not return on success - it enters the VM.
/// On error, it returns the error.
pub fn run_vm(config: VmConfig) -> Result<()> {
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

    // Set log level - use DEBUG for troubleshooting
    KrunContext::set_log_level(KRUN_LOG_LEVEL_DEBUG)
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
