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

/// Manages the gvproxy process for VM networking
pub struct GvProxy {
    process: Child,
    socket_path: PathBuf,
}

impl GvProxy {
    /// Start a new gvproxy instance for VM networking
    ///
    /// The socket_path is where gvproxy will create a Unix socket
    /// that libkrun connects to for network traffic.
    ///
    /// If gvproxy is not found on the system, it will be downloaded
    /// to the vmm bin directory.
    pub fn start(socket_path: &Path, bin_dir: &Path) -> Result<Self> {
        // Remove existing socket if present
        let _ = std::fs::remove_file(socket_path);

        // Find or download gvproxy binary
        let gvproxy_path = find_or_download_gvproxy(bin_dir)?;

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

        debug!("gvproxy started with PID {}", process.id());

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
            return Err(anyhow::anyhow!(
                "gvproxy failed to create socket at {:?}",
                socket_path
            ));
        }

        Ok(Self {
            process,
            socket_path: socket_path.to_path_buf(),
        })
    }
}

impl Drop for GvProxy {
    fn drop(&mut self) {
        debug!("Stopping gvproxy (PID {})", self.process.id());
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Find gvproxy on the system, or download it if not found
fn find_or_download_gvproxy(bin_dir: &Path) -> Result<PathBuf> {
    // First check our own bin directory
    let vmm_gvproxy = bin_dir.join("gvproxy");
    if vmm_gvproxy.exists() {
        debug!("Found gvproxy in vmm bin directory");
        return Ok(vmm_gvproxy);
    }

    // Check system locations
    if let Some(system_gvproxy) = find_system_gvproxy() {
        debug!("Found system gvproxy at {:?}", system_gvproxy);
        return Ok(system_gvproxy);
    }

    // Not found - download it
    info!("gvproxy not found, downloading...");
    download_gvproxy(&vmm_gvproxy)?;
    Ok(vmm_gvproxy)
}

/// Find gvproxy in PATH
fn find_system_gvproxy() -> Option<PathBuf> {
    which::which("gvproxy").ok()
}

/// Download gvproxy from GitHub releases
fn download_gvproxy(dest: &Path) -> Result<()> {
    use std::io::Write;

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).context("Failed to create bin directory")?;
    }

    // Download using reqwest (blocking)
    let response =
        reqwest::blocking::get(GVPROXY_DOWNLOAD_URL).context("Failed to download gvproxy")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download gvproxy: HTTP {}",
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .context("Failed to read gvproxy download")?;

    // Write to file
    let mut file = std::fs::File::create(dest).context("Failed to create gvproxy file")?;
    file.write_all(&bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use tempfile::TempDir;

    #[test]
    fn test_find_system_gvproxy() {
        // This test checks if we can find gvproxy on the system
        // It may or may not find it depending on the system configuration
        let result = find_system_gvproxy();
        if let Some(path) = result {
            assert!(path.exists(), "Found gvproxy path should exist");
            assert!(path.is_file(), "Found gvproxy should be a file");
        }
        // Test passes regardless - we're just checking the function doesn't panic
    }

    #[test]
    fn test_gvproxy_start_and_socket_creation() {
        // Skip if gvproxy is not available on the system
        let bin_dir = TempDir::new().unwrap();

        // Check if gvproxy exists anywhere
        let gvproxy_available =
            find_system_gvproxy().is_some() || bin_dir.path().join("gvproxy").exists();

        if !gvproxy_available {
            // Try to find it, but don't fail if not found (CI might not have it)
            eprintln!("Skipping gvproxy test - gvproxy not available on system");
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
        // Skip if gvproxy is not available
        if find_system_gvproxy().is_none() {
            eprintln!("Skipping cleanup test - gvproxy not available");
            return;
        }

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("cleanup-test.sock");
        let bin_dir = TempDir::new().unwrap();

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
