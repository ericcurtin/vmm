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
///
/// # Arguments
/// * `paths` - VMM paths configuration
/// * `distro` - The detected distro name (e.g., "ubuntu", "fedora")
/// * `image` - Optional full image name with tag (e.g., "ubuntu:24.04", "fedora:41")
///             If not provided, uses "latest" tag
/// * `verbose` - Whether to show verbose output (docker build progress, etc.)
pub async fn ensure_kernel(paths: &VmmPaths, distro: &str, image: Option<&str>, verbose: bool) -> Result<KernelInfo> {
    let arch = std::env::consts::ARCH;

    // Extract version from image tag for kernel caching
    let version = image
        .and_then(|img| img.split(':').nth(1))
        .unwrap_or("latest");
    let kernel_dir = paths.kernels_dir().join(format!("{}-{}-{}", distro, version, arch));

    std::fs::create_dir_all(&kernel_dir)
        .context("Failed to create kernel directory")?;

    // Determine preferred and fallback page sizes
    let preferred = PageSize::preferred();
    let fallback = PageSize::fallback();

    // Try preferred page size first (16k on macOS, 4k elsewhere)
    if let Some(kernel_info) = try_get_kernel(&kernel_dir, distro, preferred).await? {
        let page_desc = if preferred == PageSize::Page16k { "16k" } else { "4k" };
        debug!("Using cached {} page kernel for {}", page_desc, distro);
        return Ok(kernel_info);
    }

    // Try fallback page size if preferred isn't available
    if preferred != fallback {
        if let Some(kernel_info) = try_get_kernel(&kernel_dir, distro, fallback).await? {
            debug!("Using cached 4k page kernel for {} (16k not available)", distro);
            return Ok(kernel_info);
        }
    }

    // Also check for legacy kernel files without page size suffix
    let legacy_kernel = kernel_dir.join("vmlinuz");
    let legacy_initrd = kernel_dir.join("initrd.img");
    if legacy_kernel.exists() && legacy_initrd.exists() {
        debug!("Using cached kernel for {}", distro);
        return Ok(KernelInfo {
            kernel_path: legacy_kernel,
            initrd_path: legacy_initrd,
            cmdline: get_cmdline(distro),
        });
    }

    // No cached kernel found, need to download
    debug!("Extracting kernel for {} (this may take a moment)...", distro);

    // Build the image reference to use for kernel extraction
    let image_ref = image.unwrap_or_else(|| match distro {
        "ubuntu" => "ubuntu:latest",
        "fedora" => "fedora:latest",
        _ => "unknown:latest",
    });

    // Try to get preferred page size kernel first
    if extract_kernel_from_image(distro, image_ref, &kernel_dir, preferred, verbose).await.is_ok() {
        if let Some(kernel_info) = try_get_kernel(&kernel_dir, distro, preferred).await? {
            let page_desc = if preferred == PageSize::Page16k { "16k" } else { "4k" };
            debug!("Using {} page kernel for {}", page_desc, distro);
            return Ok(kernel_info);
        }
    }

    // Fall back to other page size if preferred failed
    if preferred != fallback {
        debug!("16k kernel not available, trying 4k kernel...");
        if extract_kernel_from_image(distro, image_ref, &kernel_dir, fallback, verbose).await.is_ok() {
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
async fn extract_kernel_from_image(distro: &str, image: &str, dest: &Path, page_size: PageSize, verbose: bool) -> Result<()> {
    use tokio::process::Command;
    use std::process::Stdio;

    let suffix = page_size.suffix();
    let kernel_filename = format!("vmlinuz{}", suffix);
    let initrd_filename = format!("initrd{}.img", suffix);

    debug!("Pulling kernel image {}...", image);

    // Pull the image first
    let mut pull_cmd = Command::new("docker");
    if verbose {
        pull_cmd.args(["pull", image]);
    } else {
        pull_cmd.args(["pull", "-q", image])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    let pull_status = pull_cmd.status().await
        .context("Failed to pull Docker image")?;

    if !pull_status.success() {
        return Err(anyhow::anyhow!("Failed to pull image {}", image));
    }

    // Create a temporary container and copy kernel files
    let mut create_cmd = Command::new("docker");
    create_cmd.args(["create", image]);
    if !verbose {
        create_cmd.stderr(Stdio::null());
    }
    let container_id = create_cmd.output().await
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

    // Try each kernel path (suppress error output)
    for kpath in &kernel_paths {
        let result = Command::new("docker")
            .args(["cp", &format!("{}:{}", container_id, kpath), dest.join(&kernel_filename).to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        if result.is_ok() && result.unwrap().success() {
            debug!("Found kernel at {}", kpath);
            break;
        }
    }

    // Try each initrd path (suppress error output)
    for ipath in &initrd_paths {
        let result = Command::new("docker")
            .args(["cp", &format!("{}:{}", container_id, ipath), dest.join(&initrd_filename).to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        if result.is_ok() && result.unwrap().success() {
            debug!("Found initrd at {}", ipath);
            break;
        }
    }

    // Clean up container (suppress output)
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    // If kernel extraction failed, we need an alternative approach
    // Build a kernel by installing kernel packages in the user's container image
    if !dest.join(&kernel_filename).exists() {
        debug!("Base image doesn't contain kernel, building kernel from image...");
        build_kernel_from_image(distro, image, dest, page_size, verbose).await?;
    }

    Ok(())
}

/// Build a kernel by installing kernel packages in the user's container image
///
/// This builds a kernel from the same container image the user specified,
/// ensuring version compatibility.
async fn build_kernel_from_image(distro: &str, image: &str, dest: &Path, page_size: PageSize, verbose: bool) -> Result<()> {
    use tokio::process::Command;
    use std::process::Stdio;

    let suffix = page_size.suffix();
    let kernel_filename = format!("vmlinuz{}", suffix);
    let initrd_filename = format!("initrd{}.img", suffix);

    debug!("Building kernel from image {}...", image);

    // Create a Dockerfile that installs the kernel and copies it to a known location
    // Uses the user's specified image as the base
    let dockerfile = match distro {
        "ubuntu" | "debian" => format!(r#"
FROM {}
RUN apt-get update && apt-get install -y linux-image-generic && \
    cp /boot/vmlinuz-* /vmlinuz && \
    cp /boot/initrd.img-* /initrd.img
"#, image),
        "fedora" => format!(r#"
FROM {}
RUN dnf install -y kernel-core dracut && \
    cp /lib/modules/*/vmlinuz /vmlinuz && \
    KVER=$(ls /lib/modules/) && \
    dracut --no-hostonly --add "bash shutdown" --force /initrd.img $KVER
"#, image),
        "alpine" => format!(r#"
FROM {}
RUN apk add --no-cache linux-lts && \
    cp /boot/vmlinuz-* /vmlinuz && \
    cp /boot/initramfs-* /initrd.img || true
"#, image),
        _ => return Err(anyhow::anyhow!("Unsupported distro for kernel extraction: {}", distro)),
    };

    // Create temp dir for build context
    let temp_dir = tempfile::tempdir().context("Failed to create temp dir")?;
    let dockerfile_path = temp_dir.path().join("Dockerfile");
    std::fs::write(&dockerfile_path, dockerfile)?;

    // Build the image
    let image_name = format!("vmm-kernel-{}", distro);
    let mut build_cmd = Command::new("docker");
    if verbose {
        build_cmd.args(["build", "-t", &image_name, temp_dir.path().to_str().unwrap()]);
    } else {
        build_cmd.args(["build", "-q", "-t", &image_name, temp_dir.path().to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    let build_status = build_cmd.status().await
        .context("Failed to build kernel image")?;

    if !build_status.success() {
        return Err(anyhow::anyhow!("Failed to build kernel image"));
    }

    // Create container and extract
    let mut create_cmd = Command::new("docker");
    create_cmd.args(["create", &image_name]);
    if !verbose {
        create_cmd.stderr(Stdio::null());
    }
    let container_id = create_cmd.output().await?;

    let container_id = String::from_utf8_lossy(&container_id.stdout)
        .trim()
        .to_string();

    // Copy kernel and initrd
    let mut cp_kernel_cmd = Command::new("docker");
    cp_kernel_cmd.args(["cp", &format!("{}:/vmlinuz", container_id), dest.join(&kernel_filename).to_str().unwrap()]);
    if !verbose {
        cp_kernel_cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }
    cp_kernel_cmd.status().await?;

    let mut cp_initrd_cmd = Command::new("docker");
    cp_initrd_cmd.args(["cp", &format!("{}:/initrd.img", container_id), dest.join(&initrd_filename).to_str().unwrap()]);
    if !verbose {
        cp_initrd_cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }
    cp_initrd_cmd.status().await?;

    // Clean up (always suppress output)
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    debug!("Kernel extracted successfully");
    Ok(())
}
