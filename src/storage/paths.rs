//! Path management for vmm data directories

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Manages paths for vmm data storage
pub struct VmmPaths {
    base_dir: PathBuf,
}

impl VmmPaths {
    /// Create a new VmmPaths instance
    pub fn new() -> Result<Self> {
        // Use ~/.vmm for consistent path across Linux and macOS (no spaces)
        let base_dir = dirs::home_dir()
            .context("Could not find home directory")?
            .join(".vmm");

        Ok(Self { base_dir })
    }

    /// Get the base vmm directory
    #[allow(dead_code)]
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Get the VMs directory
    pub fn vms_dir(&self) -> PathBuf {
        self.base_dir.join("vms")
    }

    /// Get the kernels directory
    pub fn kernels_dir(&self) -> PathBuf {
        self.base_dir.join("kernels")
    }

    /// Get the bin directory for helper binaries (gvproxy, etc.)
    pub fn bin_dir(&self) -> PathBuf {
        self.base_dir.join("bin")
    }

    /// Get the images directory (extracted container images)
    pub fn images_dir(&self) -> PathBuf {
        self.base_dir.join("images")
    }

    /// Get the directory for a specific VM
    pub fn vm_dir(&self, vm_id: &str) -> PathBuf {
        self.vms_dir().join(vm_id)
    }

    /// Get the rootfs directory for a specific VM
    pub fn vm_rootfs(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("rootfs")
    }

    /// Get the disk image path for a specific VM
    pub fn vm_disk(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("disk.raw")
    }

    /// Get the vsock socket path for a specific VM
    pub fn vm_vsock(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("vsock.sock")
    }

    /// Get the gvproxy socket path for a specific VM
    pub fn vm_gvproxy(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("gvproxy.sock")
    }

    /// Get the state file path for a specific VM
    #[allow(dead_code)]
    pub fn vm_state_file(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("state.json")
    }

    /// Get the global state file path
    pub fn global_state_file(&self) -> PathBuf {
        self.base_dir.join("state.json")
    }

    /// Get the kernel path for a specific distro and architecture
    #[allow(dead_code)]
    pub fn kernel_path(&self, distro: &str, arch: &str) -> PathBuf {
        self.kernels_dir()
            .join(format!("{}-{}", distro, arch))
            .join("vmlinuz")
    }

    /// Get the initrd path for a specific distro and architecture
    #[allow(dead_code)]
    pub fn initrd_path(&self, distro: &str, arch: &str) -> PathBuf {
        self.kernels_dir()
            .join(format!("{}-{}", distro, arch))
            .join("initrd.img")
    }

    /// Ensure all required directories exist
    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.base_dir).context("Failed to create base directory")?;
        std::fs::create_dir_all(self.vms_dir()).context("Failed to create VMs directory")?;
        std::fs::create_dir_all(self.kernels_dir())
            .context("Failed to create kernels directory")?;
        std::fs::create_dir_all(self.images_dir()).context("Failed to create images directory")?;
        Ok(())
    }
}

impl Default for VmmPaths {
    fn default() -> Self {
        Self::new().expect("Failed to initialize paths")
    }
}
