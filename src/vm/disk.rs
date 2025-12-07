//! Disk image creation for VMs
//!
//! This module handles creating bootable disk images from container rootfs directories.

use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::{debug, info};

/// Size of the disk image in bytes (4GB default)
const DEFAULT_DISK_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Create a bootable raw disk image from a rootfs directory
///
/// This creates an ext4 filesystem in a raw disk image and copies the rootfs contents into it.
pub async fn create_disk_image(rootfs: &Path, disk_path: &Path, size_bytes: Option<u64>) -> Result<()> {
    let size = size_bytes.unwrap_or(DEFAULT_DISK_SIZE);

    info!("Creating disk image at {:?} ({} bytes)", disk_path, size);

    // Create a sparse file of the specified size
    create_sparse_file(disk_path, size)?;

    // On macOS, use Docker for all disk operations
    // On Linux, use native tools
    #[cfg(target_os = "macos")]
    {
        create_disk_via_docker(rootfs, disk_path).await
    }

    #[cfg(target_os = "linux")]
    {
        create_disk_native(rootfs, disk_path).await
    }
}

/// Create a sparse file
fn create_sparse_file(path: &Path, size: u64) -> Result<()> {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    let file = File::create(path)
        .context("Failed to create disk file")?;

    // Write a single byte at the end to make it sparse
    file.write_at(&[0], size - 1)
        .context("Failed to set file size")?;

    debug!("Created sparse file: {:?} ({} bytes)", path, size);
    Ok(())
}

/// Create disk image using Docker (for macOS)
#[cfg(target_os = "macos")]
async fn create_disk_via_docker(rootfs: &Path, disk_path: &Path) -> Result<()> {
    use std::fs;

    info!("Formatting and copying rootfs using Docker...");

    let rootfs_abs = fs::canonicalize(rootfs)
        .context("Failed to get absolute path for rootfs")?;
    let disk_abs = fs::canonicalize(disk_path)
        .context("Failed to get absolute path for disk")?;

    // Fix permissions on execute-only files BEFORE running Docker
    // Files like sudo have ---s--x--x (execute-only, no read) which prevents
    // Docker from accessing them through bind mounts on macOS.
    // We add read permission on the macOS side so Docker/tar can read them.
    debug!("Fixing permissions on execute-only files in rootfs...");
    let chmod_output = Command::new("find")
        .arg(&rootfs_abs)
        .args(["-type", "f", "-perm", "+111", "!", "-perm", "+444", "-exec", "chmod", "u+r", "{}", ";"])
        .output()
        .await
        .context("Failed to run find command to fix permissions")?;

    if !chmod_output.status.success() {
        debug!("find/chmod warning (non-fatal): {}", String::from_utf8_lossy(&chmod_output.stderr));
    }

    // Script to format disk and copy rootfs
    let script = r#"
set -e
# Find an available loop device
LOOP=$(losetup -f)
losetup "$LOOP" /disk.raw

# Format with ext4
mkfs.ext4 -F -L rootfs "$LOOP"

# Mount and copy
mount "$LOOP" /mnt

# Copy rootfs using tar (preserves permissions and handles special files)
cd /rootfs && tar cf - . | (cd /mnt && tar xf -)

# Recreate files that might have failed to copy with correct permissions
# These are security-sensitive files in Fedora that have no read perms
if [ ! -f /mnt/etc/gshadow ]; then
    touch /mnt/etc/gshadow
    chmod 000 /mnt/etc/gshadow
fi

# Ensure proper permissions on security files
chown -R root:root /mnt/etc/sudoers.d 2>/dev/null || true
chmod 0755 /mnt/etc/sudoers.d 2>/dev/null || true
chmod 0440 /mnt/etc/sudoers.d/* 2>/dev/null || true

# Fix sudo permissions - needs setuid and execute-only (4111)
if [ -f /mnt/usr/bin/sudo ]; then
    chown root:root /mnt/usr/bin/sudo
    chmod 4111 /mnt/usr/bin/sudo
fi
if [ -f /mnt/usr/bin/sudoedit ]; then
    chown root:root /mnt/usr/bin/sudoedit
    chmod 4111 /mnt/usr/bin/sudoedit
fi

# Sync and unmount
sync
umount /mnt
losetup -d "$LOOP"
"#;

    let output = Command::new("docker")
        .args([
            "run", "--rm", "--privileged",
            "-v", &format!("{}:/rootfs", rootfs_abs.display()),
            "-v", &format!("{}:/disk.raw", disk_abs.display()),
            "ubuntu:24.04",
            "bash", "-c", script,
        ])
        .output()
        .await
        .context("Failed to run Docker container for disk creation")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Docker stderr: {}", stderr);
        return Err(anyhow::anyhow!(
            "Failed to create disk image: {}",
            stderr
        ));
    }

    info!("Disk image created successfully");
    Ok(())
}

/// Create disk image using native tools (for Linux)
#[cfg(target_os = "linux")]
async fn create_disk_native(rootfs: &Path, disk_path: &Path) -> Result<()> {
    info!("Formatting disk with ext4...");

    // Format with ext4
    let output = Command::new("mkfs.ext4")
        .args(["-F", "-L", "rootfs"])
        .arg(disk_path)
        .output()
        .await
        .context("Failed to run mkfs.ext4")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "mkfs.ext4 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Mount and copy
    let mount_dir = tempfile::tempdir()
        .context("Failed to create temp mount directory")?;

    let output = Command::new("sudo")
        .args(["mount", "-o", "loop"])
        .arg(disk_path)
        .arg(mount_dir.path())
        .output()
        .await
        .context("Failed to mount disk image")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to mount disk: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Copy rootfs contents
    let copy_result = Command::new("sudo")
        .args(["cp", "-a"])
        .arg(&format!("{}/.", rootfs.display()))
        .arg(mount_dir.path())
        .output()
        .await;

    // Unmount regardless of copy result
    let _ = Command::new("sudo")
        .args(["umount"])
        .arg(mount_dir.path())
        .output()
        .await;

    let copy_output = copy_result.context("Failed to copy rootfs")?;
    if !copy_output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to copy rootfs: {}",
            String::from_utf8_lossy(&copy_output.stderr)
        ));
    }

    info!("Disk image created successfully");
    Ok(())
}

/// Install bootloader (kernel and initrd) on the disk image
pub async fn install_bootloader(disk_path: &Path, kernel_path: &Path, initrd_path: &Path) -> Result<()> {
    info!("Installing kernel on disk image...");

    #[cfg(target_os = "macos")]
    {
        install_bootloader_via_docker(disk_path, kernel_path, initrd_path).await
    }

    #[cfg(target_os = "linux")]
    {
        install_bootloader_native(disk_path, kernel_path, initrd_path).await
    }
}

/// Install bootloader using Docker (for macOS)
#[cfg(target_os = "macos")]
async fn install_bootloader_via_docker(
    disk_path: &Path,
    kernel_path: &Path,
    initrd_path: &Path,
) -> Result<()> {
    use std::fs;

    let disk_abs = fs::canonicalize(disk_path)
        .context("Failed to get absolute path for disk")?;
    let kernel_abs = fs::canonicalize(kernel_path)
        .context("Failed to get absolute path for kernel")?;
    let initrd_abs = fs::canonicalize(initrd_path)
        .context("Failed to get absolute path for initrd")?;

    // Script to install kernel and bootloader config
    let script = r#"
set -e
LOOP=$(losetup -f)
losetup "$LOOP" /disk.raw
mount "$LOOP" /mnt

# Create boot directory and copy kernel/initrd
mkdir -p /mnt/boot
cp /kernel /mnt/boot/vmlinuz
cp /initrd /mnt/boot/initrd.img

# Create systemd-boot configuration
mkdir -p /mnt/boot/loader/entries
cat > /mnt/boot/loader/loader.conf << 'EOF'
default vmm
timeout 0
EOF

cat > /mnt/boot/loader/entries/vmm.conf << 'EOF'
title VMM Linux
linux /boot/vmlinuz
initrd /boot/initrd.img
options root=/dev/vda rw console=hvc0 quiet
EOF

# Create extlinux configuration (alternative bootloader)
mkdir -p /mnt/boot/extlinux
cat > /mnt/boot/extlinux/extlinux.conf << 'EOF'
DEFAULT vmm
PROMPT 0
TIMEOUT 0

LABEL vmm
    LINUX /boot/vmlinuz
    INITRD /boot/initrd.img
    APPEND root=/dev/vda rw console=hvc0 quiet
EOF

sync
umount /mnt
losetup -d "$LOOP"
"#;

    let output = Command::new("docker")
        .args([
            "run", "--rm", "--privileged",
            "-v", &format!("{}:/disk.raw", disk_abs.display()),
            "-v", &format!("{}:/kernel:ro", kernel_abs.display()),
            "-v", &format!("{}:/initrd:ro", initrd_abs.display()),
            "ubuntu:24.04",
            "bash", "-c", script,
        ])
        .output()
        .await
        .context("Failed to install bootloader")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Docker stderr: {}", stderr);
        return Err(anyhow::anyhow!(
            "Failed to install bootloader: {}",
            stderr
        ));
    }

    info!("Bootloader installed successfully");
    Ok(())
}

/// Install bootloader using native tools (for Linux)
#[cfg(target_os = "linux")]
async fn install_bootloader_native(
    disk_path: &Path,
    kernel_path: &Path,
    initrd_path: &Path,
) -> Result<()> {
    let mount_dir = tempfile::tempdir()
        .context("Failed to create temp mount directory")?;

    // Mount disk
    let output = Command::new("sudo")
        .args(["mount", "-o", "loop"])
        .arg(disk_path)
        .arg(mount_dir.path())
        .output()
        .await
        .context("Failed to mount disk image")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to mount disk: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let result = async {
        // Create boot directory
        let boot_dir = mount_dir.path().join("boot");
        Command::new("sudo")
            .args(["mkdir", "-p"])
            .arg(&boot_dir)
            .status()
            .await?;

        // Copy kernel
        Command::new("sudo")
            .args(["cp"])
            .arg(kernel_path)
            .arg(boot_dir.join("vmlinuz"))
            .status()
            .await?;

        // Copy initrd
        Command::new("sudo")
            .args(["cp"])
            .arg(initrd_path)
            .arg(boot_dir.join("initrd.img"))
            .status()
            .await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Unmount
    let _ = Command::new("sudo")
        .args(["umount"])
        .arg(mount_dir.path())
        .output()
        .await;

    result?;
    info!("Bootloader installed successfully");
    Ok(())
}
