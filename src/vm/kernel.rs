//! Kernel management for VMs
//!
//! This module handles downloading and managing Linux kernels and initrd
//! images for different distributions.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

use crate::storage::VmmPaths;

/// Information about a kernel
#[derive(Debug, Clone)]
pub struct KernelInfo {
    pub kernel_path: PathBuf,
    pub initrd_path: PathBuf,
    pub cmdline: String,
}

/// Kernel source URLs for different distributions
struct KernelSource {
    kernel_url: &'static str,
    initrd_url: &'static str,
    cmdline: &'static str,
}

fn get_kernel_source(distro: &str, _arch: &str) -> Option<KernelSource> {
    // For now, we use a generic approach: extract kernel from container image
    // This is a placeholder - in production we'd download from official sources
    match distro {
        "ubuntu" => Some(KernelSource {
            // Ubuntu cloud kernel - these would need to be updated with actual URLs
            kernel_url: "",
            initrd_url: "",
            cmdline: "console=hvc0 root=/dev/vda rw quiet",
        }),
        "fedora" => Some(KernelSource {
            kernel_url: "",
            initrd_url: "",
            cmdline: "console=hvc0 root=/dev/vda rw quiet",
        }),
        _ => None,
    }
}

/// Ensure kernel and initrd are available for the given distro
pub async fn ensure_kernel(paths: &VmmPaths, distro: &str) -> Result<KernelInfo> {
    let arch = std::env::consts::ARCH;
    let kernel_dir = paths.kernels_dir().join(format!("{}-{}", distro, arch));

    std::fs::create_dir_all(&kernel_dir)
        .context("Failed to create kernel directory")?;

    let kernel_path = kernel_dir.join("vmlinuz");
    let initrd_path = kernel_dir.join("initrd.img");

    // Check if we already have the kernel
    if kernel_path.exists() && initrd_path.exists() {
        info!("Using cached kernel for {}", distro);
        return Ok(KernelInfo {
            kernel_path,
            initrd_path,
            cmdline: get_cmdline(distro),
        });
    }

    // For now, we'll extract the kernel from a Docker image
    // This is a more portable approach than trying to download from distro repos
    info!("Extracting kernel for {} (this may take a moment)...", distro);

    extract_kernel_from_image(distro, &kernel_dir).await?;

    if !kernel_path.exists() {
        return Err(anyhow::anyhow!(
            "Failed to extract kernel for {}. The container image may not include a kernel.",
            distro
        ));
    }

    Ok(KernelInfo {
        kernel_path,
        initrd_path,
        cmdline: get_cmdline(distro),
    })
}

fn get_cmdline(distro: &str) -> String {
    match distro {
        "ubuntu" => "console=hvc0 root=/dev/vda rw quiet loglevel=3".to_string(),
        "fedora" => "console=hvc0 root=/dev/vda rw quiet loglevel=3 systemd.show_status=0".to_string(),
        _ => "console=hvc0 root=/dev/vda rw quiet".to_string(),
    }
}

/// Extract kernel and initrd from a Docker image
async fn extract_kernel_from_image(distro: &str, dest: &Path) -> Result<()> {
    use tokio::process::Command;

    // Use a kernel-containing image
    let image = match distro {
        "ubuntu" => "ubuntu:24.04",
        "fedora" => "fedora:41",
        _ => return Err(anyhow::anyhow!("Unsupported distro: {}", distro)),
    };

    info!("Pulling kernel image {}...", image);

    // Pull the image first
    let pull_status = Command::new("docker")
        .args(["pull", image])
        .status()
        .await
        .context("Failed to pull Docker image")?;

    if !pull_status.success() {
        return Err(anyhow::anyhow!("Failed to pull image {}", image));
    }

    // Create a temporary container and copy kernel files
    let container_id = Command::new("docker")
        .args(["create", image])
        .output()
        .await
        .context("Failed to create container")?;

    if !container_id.status.success() {
        return Err(anyhow::anyhow!("Failed to create container"));
    }

    let container_id = String::from_utf8_lossy(&container_id.stdout)
        .trim()
        .to_string();

    debug!("Created temporary container: {}", container_id);

    // Try to find and copy kernel
    let kernel_paths = [
        "/boot/vmlinuz",
        "/boot/vmlinuz-*",
        "/vmlinuz",
    ];

    let initrd_paths = [
        "/boot/initrd.img",
        "/boot/initrd.img-*",
        "/boot/initramfs-*",
        "/initrd.img",
    ];

    // Try each kernel path
    for kpath in &kernel_paths {
        let result = Command::new("docker")
            .args(["cp", &format!("{}:{}", container_id, kpath), dest.join("vmlinuz").to_str().unwrap()])
            .status()
            .await;

        if result.is_ok() && result.unwrap().success() {
            debug!("Found kernel at {}", kpath);
            break;
        }
    }

    // Try each initrd path
    for ipath in &initrd_paths {
        let result = Command::new("docker")
            .args(["cp", &format!("{}:{}", container_id, ipath), dest.join("initrd.img").to_str().unwrap()])
            .status()
            .await;

        if result.is_ok() && result.unwrap().success() {
            debug!("Found initrd at {}", ipath);
            break;
        }
    }

    // Clean up container
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .status()
        .await;

    // If kernel extraction failed, we need an alternative approach
    // For base container images that don't have a kernel, we need to use a separate kernel image
    if !dest.join("vmlinuz").exists() {
        info!("Base image doesn't contain kernel, using cloud kernel...");
        download_cloud_kernel(distro, dest).await?;
    }

    Ok(())
}

/// Download a cloud kernel for the given distro
async fn download_cloud_kernel(distro: &str, dest: &Path) -> Result<()> {
    use tokio::process::Command;

    // For macOS ARM64, we need ARM64 kernels
    // We'll use a special kernel image that contains pre-built kernels
    let kernel_image = match distro {
        "ubuntu" => "ghcr.io/slp/libkrun-ubuntu-kernel:24.04",
        "fedora" => "ghcr.io/slp/libkrun-fedora-kernel:41",
        _ => return Err(anyhow::anyhow!("Unsupported distro for cloud kernel: {}", distro)),
    };

    info!("Attempting to pull kernel image {}...", kernel_image);

    // Try to pull the kernel image
    let pull_result = Command::new("docker")
        .args(["pull", kernel_image])
        .status()
        .await;

    if pull_result.is_err() || !pull_result.unwrap().success() {
        // Fall back to building a minimal kernel from a Fedora image
        info!("Could not find pre-built kernel, attempting to extract from distro image...");
        return extract_kernel_from_distro_image(distro, dest).await;
    }

    // Create container and copy kernel
    let container_id = Command::new("docker")
        .args(["create", kernel_image])
        .output()
        .await?;

    let container_id = String::from_utf8_lossy(&container_id.stdout)
        .trim()
        .to_string();

    // Copy kernel and initrd
    let _ = Command::new("docker")
        .args(["cp", &format!("{}:/vmlinuz", container_id), dest.join("vmlinuz").to_str().unwrap()])
        .status()
        .await;

    let _ = Command::new("docker")
        .args(["cp", &format!("{}:/initrd.img", container_id), dest.join("initrd.img").to_str().unwrap()])
        .status()
        .await;

    // Clean up
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .status()
        .await;

    Ok(())
}

/// Extract kernel from a full distro image (e.g., Fedora with kernel package)
async fn extract_kernel_from_distro_image(distro: &str, dest: &Path) -> Result<()> {
    use tokio::process::Command;

    info!("Building kernel extraction container for {}...", distro);

    // Create a Dockerfile that installs the kernel and copies it to a known location
    let dockerfile = match distro {
        "ubuntu" => r#"
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y linux-image-generic && \
    cp /boot/vmlinuz-* /vmlinuz && \
    cp /boot/initrd.img-* /initrd.img
"#,
        "fedora" => r#"
FROM fedora:41
RUN dnf install -y kernel-core dracut && \
    cp /lib/modules/*/vmlinuz /vmlinuz && \
    KVER=$(ls /lib/modules/) && \
    dracut --no-hostonly --add "bash shutdown" --force /initrd.img $KVER
"#,
        _ => return Err(anyhow::anyhow!("Unsupported distro: {}", distro)),
    };

    // Create temp dir for build context
    let temp_dir = tempfile::tempdir().context("Failed to create temp dir")?;
    let dockerfile_path = temp_dir.path().join("Dockerfile");
    std::fs::write(&dockerfile_path, dockerfile)?;

    // Build the image
    let image_name = format!("vmm-kernel-{}", distro);
    let build_status = Command::new("docker")
        .args(["build", "-t", &image_name, temp_dir.path().to_str().unwrap()])
        .status()
        .await
        .context("Failed to build kernel image")?;

    if !build_status.success() {
        return Err(anyhow::anyhow!("Failed to build kernel image"));
    }

    // Create container and extract
    let container_id = Command::new("docker")
        .args(["create", &image_name])
        .output()
        .await?;

    let container_id = String::from_utf8_lossy(&container_id.stdout)
        .trim()
        .to_string();

    // Copy kernel and initrd
    Command::new("docker")
        .args(["cp", &format!("{}:/vmlinuz", container_id), dest.join("vmlinuz").to_str().unwrap()])
        .status()
        .await?;

    Command::new("docker")
        .args(["cp", &format!("{}:/initrd.img", container_id), dest.join("initrd.img").to_str().unwrap()])
        .status()
        .await?;

    // Clean up
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .status()
        .await;

    info!("Kernel extracted successfully");
    Ok(())
}
