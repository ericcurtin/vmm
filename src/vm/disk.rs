//! Disk image creation for VMs
//!
//! This module handles creating bootable disk images from container rootfs directories.

use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::{debug, info};

#[cfg(target_os = "linux")]
use std::io::Write;

/// Size of the disk image in bytes (4GB default)
const DEFAULT_DISK_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Create a bootable raw disk image from a rootfs directory
///
/// This creates an ext4 filesystem in a raw disk image and copies the rootfs contents into it.
pub async fn create_disk_image(
    rootfs: &Path,
    disk_path: &Path,
    size_bytes: Option<u64>,
) -> Result<()> {
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

    let file = File::create(path).context("Failed to create disk file")?;

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

    let rootfs_abs = fs::canonicalize(rootfs).context("Failed to get absolute path for rootfs")?;
    let disk_abs = fs::canonicalize(disk_path).context("Failed to get absolute path for disk")?;

    // Fix permissions on execute-only files BEFORE running Docker
    // Files like sudo have ---s--x--x (execute-only, no read) which prevents
    // Docker from accessing them through bind mounts on macOS.
    // We add read permission on the macOS side so Docker/tar can read them.
    debug!("Fixing permissions on execute-only files in rootfs...");
    let chmod_output = Command::new("find")
        .arg(&rootfs_abs)
        .args([
            "-type", "f", "-perm", "+111", "!", "-perm", "+444", "-exec", "chmod", "u+r", "{}", ";",
        ])
        .output()
        .await
        .context("Failed to run find command to fix permissions")?;

    if !chmod_output.status.success() {
        debug!(
            "find/chmod warning (non-fatal): {}",
            String::from_utf8_lossy(&chmod_output.stderr)
        );
    }

    // Script to create GPT disk with EFI System Partition and root partition
    // This enables GRUB2 EFI boot instead of direct kernel boot
    let script = r#"
set -e

# Install required tools (kpartx for reliable partition mapping in Docker)
dnf install -y -q parted dosfstools e2fsprogs kpartx > /dev/null

# Find an available loop device
LOOP=$(losetup -f --show /disk.raw)

# Create GPT partition table with:
# - Partition 1: EFI System Partition (ESP), 128MB, FAT32
# - Partition 2: Root partition, rest of disk, ext4
parted -s "$LOOP" mklabel gpt
parted -s "$LOOP" mkpart ESP fat32 1MiB 129MiB
parted -s "$LOOP" set 1 esp on
parted -s "$LOOP" mkpart root ext4 129MiB 100%

# Use kpartx to create partition device mappings (more reliable in Docker)
kpartx -av "$LOOP"
sleep 1

# Get the device mapper names (e.g., /dev/mapper/loop0p1)
LOOP_NAME=$(basename "$LOOP")
ESP_DEV="/dev/mapper/${LOOP_NAME}p1"
ROOT_DEV="/dev/mapper/${LOOP_NAME}p2"

# Format partitions
mkfs.vfat -F 32 -n ESP "$ESP_DEV"
mkfs.ext4 -F -L rootfs "$ROOT_DEV"

# Mount root partition
mount "$ROOT_DEV" /mnt

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

# Mount ESP and set up GRUB2 EFI bootloader
mkdir -p /mnt/boot/efi
mount "$ESP_DEV" /mnt/boot/efi

# Create EFI boot directory structure
mkdir -p /mnt/boot/efi/EFI/BOOT

# Sync and unmount
sync
umount /mnt/boot/efi
umount /mnt

# Clean up kpartx mappings and loop device
kpartx -d "$LOOP"
losetup -d "$LOOP"
"#;

    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--privileged",
            "-v",
            &format!("{}:/rootfs", rootfs_abs.display()),
            "-v",
            &format!("{}:/disk.raw", disk_abs.display()),
            "fedora:43",
            "bash",
            "-c",
            script,
        ])
        .output()
        .await
        .context("Failed to run docker container for disk creation")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Docker stderr: {}", stderr);
        return Err(anyhow::anyhow!("Failed to create disk image: {}", stderr));
    }

    info!("Disk image created successfully");
    Ok(())
}

/// Create disk image using native tools (for Linux)
#[cfg(target_os = "linux")]
async fn create_disk_native(rootfs: &Path, disk_path: &Path) -> Result<()> {
    info!("Creating GPT disk with EFI partition...");

    // Create GPT partition table
    let output = Command::new("sudo")
        .args(["parted", "-s"])
        .arg(disk_path)
        .args(["mklabel", "gpt"])
        .output()
        .await
        .context("Failed to create GPT partition table")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "parted mklabel failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Create EFI System Partition (128MB)
    let _ = Command::new("sudo")
        .args(["parted", "-s"])
        .arg(disk_path)
        .args(["mkpart", "ESP", "fat32", "1MiB", "129MiB"])
        .output()
        .await?;

    let _ = Command::new("sudo")
        .args(["parted", "-s"])
        .arg(disk_path)
        .args(["set", "1", "esp", "on"])
        .output()
        .await?;

    // Create root partition
    let _ = Command::new("sudo")
        .args(["parted", "-s"])
        .arg(disk_path)
        .args(["mkpart", "root", "ext4", "129MiB", "100%"])
        .output()
        .await?;

    // Set up loop device with partition support
    let loop_output = Command::new("sudo")
        .args(["losetup", "-f", "--show", "-P"])
        .arg(disk_path)
        .output()
        .await
        .context("Failed to set up loop device")?;

    let loop_dev = String::from_utf8_lossy(&loop_output.stdout)
        .trim()
        .to_string();

    // Format partitions
    let _ = Command::new("sudo")
        .args(["mkfs.vfat", "-F", "32", "-n", "ESP"])
        .arg(format!("{}p1", loop_dev))
        .output()
        .await?;

    let _ = Command::new("sudo")
        .args(["mkfs.ext4", "-F", "-L", "rootfs"])
        .arg(format!("{}p2", loop_dev))
        .output()
        .await?;

    // Mount and copy
    let mount_dir = tempfile::tempdir().context("Failed to create temp mount directory")?;

    let output = Command::new("sudo")
        .args(["mount"])
        .arg(format!("{}p2", loop_dev))
        .arg(mount_dir.path())
        .output()
        .await
        .context("Failed to mount disk image")?;

    if !output.status.success() {
        let _ = Command::new("sudo")
            .args(["losetup", "-d", &loop_dev])
            .output()
            .await;
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

    // Mount ESP
    let esp_mount = mount_dir.path().join("boot/efi");
    let _ = Command::new("sudo")
        .args(["mkdir", "-p"])
        .arg(&esp_mount)
        .output()
        .await;

    let _ = Command::new("sudo")
        .args(["mount"])
        .arg(format!("{}p1", loop_dev))
        .arg(&esp_mount)
        .output()
        .await;

    // Create EFI boot directory
    let _ = Command::new("sudo")
        .args(["mkdir", "-p"])
        .arg(esp_mount.join("EFI/BOOT"))
        .output()
        .await;

    // Unmount ESP
    let _ = Command::new("sudo")
        .args(["umount"])
        .arg(&esp_mount)
        .output()
        .await;

    // Unmount root
    let _ = Command::new("sudo")
        .args(["umount"])
        .arg(mount_dir.path())
        .output()
        .await;

    // Detach loop device
    let _ = Command::new("sudo")
        .args(["losetup", "-d", &loop_dev])
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
pub async fn install_bootloader(
    disk_path: &Path,
    kernel_path: &Path,
    initrd_path: &Path,
) -> Result<()> {
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

    let disk_abs = fs::canonicalize(disk_path).context("Failed to get absolute path for disk")?;
    let kernel_abs =
        fs::canonicalize(kernel_path).context("Failed to get absolute path for kernel")?;
    let initrd_abs =
        fs::canonicalize(initrd_path).context("Failed to get absolute path for initrd")?;

    // Script to install GRUB2 EFI bootloader with kernel and initrd
    // Uses GPT disk with EFI System Partition created by create_disk_via_docker
    // Uses grub-mkstandalone to create a self-contained EFI binary with embedded config
    let script = r#"
set -e

# Install required packages for GRUB (kpartx for reliable partition mapping in Docker)
dnf install -y -q grub2-efi-aa64-modules grub2-tools dosfstools kpartx > /dev/null

# Set up loop device and create partition mappings with kpartx
LOOP=$(losetup -f --show /disk.raw)
kpartx -av "$LOOP"
sleep 1

# Get the device mapper names
LOOP_NAME=$(basename "$LOOP")
ESP_DEV="/dev/mapper/${LOOP_NAME}p1"
ROOT_DEV="/dev/mapper/${LOOP_NAME}p2"

# Mount root partition (partition 2)
mount "$ROOT_DEV" /mnt

# Create boot directory and copy kernel/initrd
mkdir -p /mnt/boot
cp /kernel /mnt/boot/vmlinuz
cp /initrd /mnt/boot/initrd.img

# Mount EFI System Partition
mkdir -p /mnt/boot/efi
mount "$ESP_DEV" /mnt/boot/efi

# Create the EFI boot directory structure
mkdir -p /mnt/boot/efi/EFI/BOOT

# Create an initial config that will be embedded directly into GRUB
# This is executed immediately when GRUB starts (before searching for configfile)
# Uses LABEL=rootfs for reliable root filesystem identification
cat > /tmp/grub-early.cfg << 'GRUBCFG'
set root=(hd0,gpt2)
linux /boot/vmlinuz root=LABEL=rootfs rw console=hvc0
initrd /boot/initrd.img
boot
GRUBCFG

# Build GRUB EFI binary using grub2-mkimage with embedded initial config (-c flag)
# The -c flag embeds a config that runs at startup before any configfile search
grub2-mkimage \
    -o /mnt/boot/efi/EFI/BOOT/BOOTAA64.EFI \
    -O arm64-efi \
    -c /tmp/grub-early.cfg \
    -p "" \
    part_gpt fat ext2 linux boot

sync
umount /mnt/boot/efi
umount /mnt

# Clean up kpartx mappings and loop device
kpartx -d "$LOOP"
losetup -d "$LOOP"
"#;

    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--privileged",
            "-v",
            &format!("{}:/disk.raw", disk_abs.display()),
            "-v",
            &format!("{}:/kernel:ro", kernel_abs.display()),
            "-v",
            &format!("{}:/initrd:ro", initrd_abs.display()),
            "fedora:43",
            "bash",
            "-c",
            script,
        ])
        .output()
        .await
        .context("Failed to install bootloader")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Docker stderr: {}", stderr);
        return Err(anyhow::anyhow!("Failed to install bootloader: {}", stderr));
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
    // Set up loop device with partition support
    let loop_output = Command::new("sudo")
        .args(["losetup", "-f", "--show", "-P"])
        .arg(disk_path)
        .output()
        .await
        .context("Failed to set up loop device")?;

    let loop_dev = String::from_utf8_lossy(&loop_output.stdout)
        .trim()
        .to_string();

    let mount_dir = tempfile::tempdir().context("Failed to create temp mount directory")?;

    // Mount root partition (partition 2)
    let output = Command::new("sudo")
        .args(["mount"])
        .arg(format!("{}p2", loop_dev))
        .arg(mount_dir.path())
        .output()
        .await
        .context("Failed to mount disk image")?;

    if !output.status.success() {
        let _ = Command::new("sudo")
            .args(["losetup", "-d", &loop_dev])
            .output()
            .await;
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

        // Mount ESP
        let esp_mount = mount_dir.path().join("boot/efi");
        Command::new("sudo")
            .args(["mkdir", "-p"])
            .arg(&esp_mount)
            .status()
            .await?;

        Command::new("sudo")
            .args(["mount"])
            .arg(format!("{}p1", loop_dev))
            .arg(&esp_mount)
            .status()
            .await?;

        // Create EFI boot directory
        Command::new("sudo")
            .args(["mkdir", "-p"])
            .arg(esp_mount.join("EFI/BOOT"))
            .status()
            .await?;

        // Create GRUB config directory
        let grub_dir = boot_dir.join("grub");
        Command::new("sudo")
            .args(["mkdir", "-p"])
            .arg(&grub_dir)
            .status()
            .await?;

        // Write GRUB configuration
        let grub_cfg = r#"set timeout=0
set default=0

menuentry "VMM Linux" {
    linux /boot/vmlinuz root=/dev/vda2 rw console=hvc0 quiet
    initrd /boot/initrd.img
}
"#;
        let grub_cfg_path = grub_dir.join("grub.cfg");
        Command::new("sudo")
            .args(["sh", "-c"])
            .arg(format!("cat > {}", grub_cfg_path.display()))
            .stdin(std::process::Stdio::piped())
            .spawn()?
            .stdin
            .as_mut()
            .unwrap()
            .write_all(grub_cfg.as_bytes())?;

        // Install GRUB2 EFI bootloader
        // Try to use grub-mkimage to create the EFI binary
        let efi_binary = esp_mount.join("EFI/BOOT/BOOTAA64.EFI");
        let _ = Command::new("sudo")
            .args(["grub-mkimage", "-o"])
            .arg(&efi_binary)
            .args([
                "-O",
                "arm64-efi",
                "-p",
                "/boot/grub",
                "part_gpt",
                "part_msdos",
                "fat",
                "ext2",
                "normal",
                "boot",
                "linux",
                "configfile",
                "search",
                "search_fs_uuid",
            ])
            .status()
            .await;

        // Also copy grub config to EFI partition
        let efi_grub_dir = esp_mount.join("boot/grub");
        Command::new("sudo")
            .args(["mkdir", "-p"])
            .arg(&efi_grub_dir)
            .status()
            .await?;

        Command::new("sudo")
            .args(["cp"])
            .arg(&grub_cfg_path)
            .arg(efi_grub_dir.join("grub.cfg"))
            .status()
            .await?;

        // Unmount ESP
        Command::new("sudo")
            .args(["umount"])
            .arg(&esp_mount)
            .status()
            .await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Unmount root
    let _ = Command::new("sudo")
        .args(["umount"])
        .arg(mount_dir.path())
        .output()
        .await;

    // Detach loop device
    let _ = Command::new("sudo")
        .args(["losetup", "-d", &loop_dev])
        .output()
        .await;

    result?;
    info!("Bootloader installed successfully");
    Ok(())
}
