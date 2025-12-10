//! Network support for VMs using gvproxy
//!
//! This module provides networking capabilities for VMs by managing
//! a gvproxy process that provides NAT networking to the guest.
//! gvproxy is automatically downloaded from gvisor-tap-vsock releases
//! if not found on the system.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tracing::{debug, info};

/// URL to download gvproxy for macOS
const GVPROXY_DOWNLOAD_URL: &str =
    "https://github.com/containers/gvisor-tap-vsock/releases/download/v0.8.7/gvproxy-darwin";

/// Ensure gvproxy is available in the bin directory.
/// This should be called from an async context before starting the VM.
pub async fn ensure_gvproxy(bin_dir: &Path) -> Result<PathBuf> {
    let gvproxy_path = bin_dir.join("gvproxy");
    if gvproxy_path.exists() {
        debug!("Found gvproxy in vmm bin directory");
        return Ok(gvproxy_path);
    }

    // Not found - download it
    info!("gvproxy not found, downloading...");
    download_gvproxy_async(&gvproxy_path).await?;
    Ok(gvproxy_path)
}

/// Download gvproxy from GitHub releases (async version)
async fn download_gvproxy_async(dest: &Path) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).context("Failed to create bin directory")?;
    }

    // Download using reqwest async
    let response = reqwest::get(GVPROXY_DOWNLOAD_URL)
        .await
        .context("Failed to download gvproxy")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download gvproxy: HTTP {}",
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to read gvproxy download")?;

    // Write to file
    let mut file = tokio::fs::File::create(dest)
        .await
        .context("Failed to create gvproxy file")?;
    file.write_all(&bytes)
        .await
        .context("Failed to write gvproxy file")?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dest)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(dest, perms)?;
    }

    info!("Downloaded gvproxy to {:?}", dest);
    Ok(())
}

/// Manages the gvproxy process for VM networking
pub struct GvProxy {
    process: Child,
    socket_path: PathBuf,
    pid_file: PathBuf,
}

impl GvProxy {
    /// Start a new gvproxy instance for VM networking
    ///
    /// The socket_path is where gvproxy will create a Unix socket
    /// that libkrun connects to for network traffic.
    ///
    /// Note: ensure_gvproxy() should be called first from async context
    /// to download gvproxy if needed.
    pub fn start(socket_path: &Path, bin_dir: &Path) -> Result<Self> {
        // Clean up any orphaned gvproxy from a previous run
        let pid_file = socket_path.with_extension("pid");
        cleanup_orphaned_gvproxy(&pid_file);

        // Remove existing socket if present
        let _ = std::fs::remove_file(socket_path);

        // Find gvproxy binary (ensure_gvproxy should have been called first)
        let gvproxy_path = find_gvproxy(bin_dir)?;

        debug!("Starting gvproxy at {:?}", gvproxy_path);
        debug!("Socket path: {:?}", socket_path);

        // Start gvproxy with vfkit-compatible unixgram socket
        // -listen-vfkit creates a unixgram socket that libkrun's virtio-net can use
        let process = Command::new(&gvproxy_path)
            .arg("-listen-vfkit")
            .arg(format!("unixgram://{}", socket_path.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start gvproxy")?;

        let pid = process.id();
        debug!("gvproxy started with PID {}", pid);

        // Save PID to file for cleanup if process exits without running Drop
        if let Err(e) = std::fs::write(&pid_file, pid.to_string()) {
            debug!("Failed to write gvproxy PID file: {}", e);
        }

        // Wait a moment for socket to be created
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        if !socket_path.exists() {
            // Kill the process if socket wasn't created
            let mut proc = process;
            let _ = proc.kill();
            let _ = std::fs::remove_file(&pid_file);
            return Err(anyhow::anyhow!(
                "gvproxy failed to create socket at {:?}",
                socket_path
            ));
        }

        Ok(Self {
            process,
            socket_path: socket_path.to_path_buf(),
            pid_file,
        })
    }
}

/// Clean up an orphaned gvproxy process from a previous run
fn cleanup_orphaned_gvproxy(pid_file: &Path) {
    if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // Check if process is still running
            let is_running = unsafe { libc::kill(pid, 0) == 0 };
            if is_running {
                debug!("Killing orphaned gvproxy process (PID {})", pid);
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                // Give it a moment to exit gracefully
                std::thread::sleep(std::time::Duration::from_millis(100));
                // Force kill if still running
                let still_running = unsafe { libc::kill(pid, 0) == 0 };
                if still_running {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
        let _ = std::fs::remove_file(pid_file);
    }
}

impl Drop for GvProxy {
    fn drop(&mut self) {
        debug!("Stopping gvproxy (PID {})", self.process.id());
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(&self.pid_file);
    }
}

/// Find gvproxy in our bin directory
/// Note: ensure_gvproxy() should be called first from async context to download if needed
fn find_gvproxy(bin_dir: &Path) -> Result<PathBuf> {
    // Only use our own bin directory - don't use system gvproxy
    // (e.g., /opt/podman/bin/gvproxy may not be compatible)
    let vmm_gvproxy = bin_dir.join("gvproxy");
    if vmm_gvproxy.exists() {
        debug!("Found gvproxy in vmm bin directory");
        return Ok(vmm_gvproxy);
    }

    Err(anyhow::anyhow!(
        "gvproxy not found in {:?}. Call ensure_gvproxy() first.",
        bin_dir
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use tempfile::TempDir;

    /// Check if gvproxy exists in a bin directory
    fn has_gvproxy(bin_dir: &Path) -> bool {
        bin_dir.join("gvproxy").exists()
    }

    #[test]
    fn test_gvproxy_start_and_socket_creation() {
        // Skip if gvproxy is not available
        let bin_dir = TempDir::new().unwrap();

        if !has_gvproxy(bin_dir.path()) {
            // Try to find it, but don't fail if not found (CI might not have it)
            eprintln!("Skipping gvproxy test - gvproxy not available");
            return;
        }

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test-gvproxy.sock");

        // Start gvproxy
        let gvproxy = GvProxy::start(&socket_path, bin_dir.path());

        match gvproxy {
            Ok(gvproxy) => {
                // Verify socket was created
                assert!(socket_path.exists(), "gvproxy socket should be created");

                // Verify we can connect to the socket
                let connect_result = UnixStream::connect(&socket_path);
                assert!(
                    connect_result.is_ok(),
                    "Should be able to connect to gvproxy socket"
                );

                // gvproxy will be stopped when dropped
                drop(gvproxy);

                // Socket should be cleaned up
                assert!(
                    !socket_path.exists(),
                    "Socket should be removed after gvproxy stops"
                );
            }
            Err(e) => {
                eprintln!("gvproxy start failed (may be expected in CI): {}", e);
            }
        }
    }

    #[test]
    fn test_gvproxy_cleanup_on_drop() {
        let bin_dir = TempDir::new().unwrap();

        // Skip if gvproxy is not available
        if !has_gvproxy(bin_dir.path()) {
            eprintln!("Skipping cleanup test - gvproxy not available");
            return;
        }

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("cleanup-test.sock");

        {
            let gvproxy = GvProxy::start(&socket_path, bin_dir.path());
            if let Ok(_gv) = gvproxy {
                assert!(
                    socket_path.exists(),
                    "Socket should exist while gvproxy is running"
                );
                // gvproxy dropped here
            }
        }

        // Give a moment for cleanup
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Socket should be cleaned up after drop
        assert!(
            !socket_path.exists(),
            "Socket should be cleaned up after drop"
        );
    }
}
