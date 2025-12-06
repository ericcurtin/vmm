//! Kernel management for VMs
//!
//! This module handles downloading and managing Linux kernels and initrd
//! images for different distributions.
//!
//! On macOS (Apple Silicon), 16k page size kernels are preferred for better
//! performance. On other platforms, 4k page size kernels are used.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

use crate::storage::VmmPaths;

/// Page size variants for kernels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PageSize {
    /// 4k page size (default for most Linux systems)
    Page4k,
    /// 16k page size (preferred on macOS/Apple Silicon)
    Page16k,
}

impl PageSize {
    /// Get the preferred page size for the current platform
    pub fn preferred() -> Self {
        if cfg!(target_os = "macos") {
            PageSize::Page16k
        } else {
            PageSize::Page4k
        }
    }

    /// Get the fallback page size
    pub fn fallback() -> Self {
        PageSize::Page4k
    }

    /// Get the suffix used in kernel image filenames
    pub fn suffix(&self) -> &'static str {
        match self {
            PageSize::Page4k => "-4k",
            PageSize::Page16k => "-16k",
        }
    }
}

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

    // Determine preferred and fallback page sizes
    let preferred = PageSize::preferred();
    let fallback = PageSize::fallback();

    // Try preferred page size first (16k on macOS, 4k elsewhere)
    if let Some(kernel_info) = try_get_kernel(&kernel_dir, distro, preferred).await? {
        let page_desc = if preferred == PageSize::Page16k { "16k" } else { "4k" };
        info!("Using cached {} page kernel for {}", page_desc, distro);
        return Ok(kernel_info);
    }

    // Try fallback page size if preferred isn't available
    if preferred != fallback {
        if let Some(kernel_info) = try_get_kernel(&kernel_dir, distro, fallback).await? {
            info!("Using cached 4k page kernel for {} (16k not available)", distro);
            return Ok(kernel_info);
        }
    }

    // Also check for legacy kernel files without page size suffix
    let legacy_kernel = kernel_dir.join("vmlinuz");
    let legacy_initrd = kernel_dir.join("initrd.img");
    if legacy_kernel.exists() && legacy_initrd.exists() {
        info!("Using cached kernel for {}", distro);
        return Ok(KernelInfo {
            kernel_path: legacy_kernel,
            initrd_path: legacy_initrd,
            cmdline: get_cmdline(distro),
        });
    }

    // No cached kernel found, need to download
    info!("Extracting kernel for {} (this may take a moment)...", distro);

    // Try to get preferred page size kernel first
    if extract_kernel_from_image(distro, &kernel_dir, preferred).await.is_ok() {
        if let Some(kernel_info) = try_get_kernel(&kernel_dir, distro, preferred).await? {
            let page_desc = if preferred == PageSize::Page16k { "16k" } else { "4k" };
            info!("Using {} page kernel for {}", page_desc, distro);
            return Ok(kernel_info);
        }
    }

    // Fall back to other page size if preferred failed
    if preferred != fallback {
        info!("16k kernel not available, trying 4k kernel...");
        if extract_kernel_from_image(distro, &kernel_dir, fallback).await.is_ok() {
            if let Some(kernel_info) = try_get_kernel(&kernel_dir, distro, fallback).await? {
                return Ok(kernel_info);
            }
        }
    }

    // Check legacy kernel one more time
    if legacy_kernel.exists() {
        return Ok(KernelInfo {
            kernel_path: legacy_kernel,
            initrd_path: legacy_initrd,
            cmdline: get_cmdline(distro),
        });
    }

    Err(anyhow::anyhow!(
        "Failed to extract kernel for {}. The container image may not include a kernel.",
        distro
    ))
}

/// Try to get a kernel with a specific page size
async fn try_get_kernel(kernel_dir: &Path, distro: &str, page_size: PageSize) -> Result<Option<KernelInfo>> {
    let suffix = page_size.suffix();
    let kernel_path = kernel_dir.join(format!("vmlinuz{}", suffix));
    let initrd_path = kernel_dir.join(format!("initrd{}.img", suffix));

    if kernel_path.exists() && initrd_path.exists() {
        return Ok(Some(KernelInfo {
            kernel_path,
            initrd_path,
            cmdline: get_cmdline(distro),
        }));
    }

    Ok(None)
}

fn get_cmdline(distro: &str) -> String {
    match distro {
        "ubuntu" => "console=hvc0 root=/dev/vda rw quiet loglevel=3".to_string(),
        "fedora" => "console=hvc0 root=/dev/vda rw quiet loglevel=3 systemd.show_status=0".to_string(),
        _ => "console=hvc0 root=/dev/vda rw quiet".to_string(),
    }
}

/// Extract kernel and initrd from a Docker image
async fn extract_kernel_from_image(distro: &str, dest: &Path, page_size: PageSize) -> Result<()> {
    use tokio::process::Command;

    let suffix = page_size.suffix();
    let kernel_filename = format!("vmlinuz{}", suffix);
    let initrd_filename = format!("initrd{}.img", suffix);

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
            .args(["cp", &format!("{}:{}", container_id, kpath), dest.join(&kernel_filename).to_str().unwrap()])
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
            .args(["cp", &format!("{}:{}", container_id, ipath), dest.join(&initrd_filename).to_str().unwrap()])
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
    if !dest.join(&kernel_filename).exists() {
        info!("Base image doesn't contain kernel, using cloud kernel...");
        download_cloud_kernel(distro, dest, page_size).await?;
    }

    Ok(())
}

/// Download a cloud kernel for the given distro
async fn download_cloud_kernel(distro: &str, dest: &Path, page_size: PageSize) -> Result<()> {
    use tokio::process::Command;

    let suffix = page_size.suffix();
    let kernel_filename = format!("vmlinuz{}", suffix);
    let initrd_filename = format!("initrd{}.img", suffix);

    // For macOS ARM64, we need ARM64 kernels
    // We'll use a special kernel image that contains pre-built kernels
    // The image tag includes the page size (e.g., 24.04-16k for 16k page size)
    let page_size_tag = match page_size {
        PageSize::Page16k => "-16k",
        PageSize::Page4k => "",  // Default/4k doesn't have a suffix in tags
    };

    let kernel_image = match distro {
        "ubuntu" => format!("ghcr.io/slp/libkrun-ubuntu-kernel:24.04{}", page_size_tag),
        "fedora" => format!("ghcr.io/slp/libkrun-fedora-kernel:41{}", page_size_tag),
        _ => return Err(anyhow::anyhow!("Unsupported distro for cloud kernel: {}", distro)),
    };

    let page_desc = if page_size == PageSize::Page16k { "16k page" } else { "4k page" };
    info!("Attempting to pull {} kernel image {}...", page_desc, kernel_image);

    // Try to pull the kernel image
    let pull_result = Command::new("docker")
        .args(["pull", &kernel_image])
        .status()
        .await;

    if pull_result.is_err() || !pull_result.unwrap().success() {
        // Fall back to building a minimal kernel from a Fedora image
        // Only fall back for 4k kernels (we can build those)
        if page_size == PageSize::Page4k {
            info!("Could not find pre-built kernel, attempting to extract from distro image...");
            return extract_kernel_from_distro_image(distro, dest, page_size).await;
        } else {
            return Err(anyhow::anyhow!("16k kernel image not available for {}", distro));
        }
    }

    // Create container and copy kernel
    let container_id = Command::new("docker")
        .args(["create", &kernel_image])
        .output()
        .await?;

    let container_id = String::from_utf8_lossy(&container_id.stdout)
        .trim()
        .to_string();

    // Copy kernel and initrd - try page-size-specific filenames first, then generic
    let kernel_copied = try_copy_kernel_files(&container_id, dest, &kernel_filename, &initrd_filename).await;

    if !kernel_copied {
        // Try generic names and rename
        let _ = Command::new("docker")
            .args(["cp", &format!("{}:/vmlinuz", container_id), dest.join(&kernel_filename).to_str().unwrap()])
            .status()
            .await;

        let _ = Command::new("docker")
            .args(["cp", &format!("{}:/initrd.img", container_id), dest.join(&initrd_filename).to_str().unwrap()])
            .status()
            .await;
    }

    // Clean up
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .status()
        .await;

    // Verify kernel was copied
    if !dest.join(&kernel_filename).exists() {
        return Err(anyhow::anyhow!("Failed to copy kernel from image"));
    }

    Ok(())
}

/// Try to copy kernel files with specific names from container
async fn try_copy_kernel_files(
    container_id: &str,
    dest: &Path,
    kernel_filename: &str,
    initrd_filename: &str,
) -> bool {
    use tokio::process::Command;

    // Try to copy with the specific page-size filename
    let kernel_result = Command::new("docker")
        .args(["cp", &format!("{}:/{}", container_id, kernel_filename), dest.join(kernel_filename).to_str().unwrap()])
        .status()
        .await;

    let initrd_result = Command::new("docker")
        .args(["cp", &format!("{}:/{}", container_id, initrd_filename), dest.join(initrd_filename).to_str().unwrap()])
        .status()
        .await;

    kernel_result.is_ok() && kernel_result.unwrap().success() &&
        initrd_result.is_ok() && initrd_result.unwrap().success()
}

/// Extract kernel from a full distro image (e.g., Fedora with kernel package)
async fn extract_kernel_from_distro_image(distro: &str, dest: &Path, page_size: PageSize) -> Result<()> {
    use tokio::process::Command;

    let suffix = page_size.suffix();
    let kernel_filename = format!("vmlinuz{}", suffix);
    let initrd_filename = format!("initrd{}.img", suffix);

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
        .args(["cp", &format!("{}:/vmlinuz", container_id), dest.join(&kernel_filename).to_str().unwrap()])
        .status()
        .await?;

    Command::new("docker")
        .args(["cp", &format!("{}:/initrd.img", container_id), dest.join(&initrd_filename).to_str().unwrap()])
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
