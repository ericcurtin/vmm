//! FFI bindings to libkrun-efi
//!
//! These bindings provide access to libkrun's C API for creating and managing
//! lightweight virtual machines.

use libc::{c_char, gid_t, uid_t};
use std::ffi::CString;
use std::os::unix::io::RawFd;

// Log levels
pub const KRUN_LOG_LEVEL_OFF: u32 = 0;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_ERROR: u32 = 1;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_WARN: u32 = 2;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_INFO: u32 = 3;
pub const KRUN_LOG_LEVEL_DEBUG: u32 = 4;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_TRACE: u32 = 5;

// Kernel formats
pub const KRUN_KERNEL_FORMAT_RAW: u32 = 0;
pub const KRUN_KERNEL_FORMAT_ELF: u32 = 1;
#[allow(dead_code)]
pub const KRUN_KERNEL_FORMAT_PE_GZ: u32 = 2;
pub const KRUN_KERNEL_FORMAT_IMAGE_BZ2: u32 = 3;
pub const KRUN_KERNEL_FORMAT_IMAGE_GZ: u32 = 4;
pub const KRUN_KERNEL_FORMAT_IMAGE_ZSTD: u32 = 5;

// Disk formats
pub const KRUN_DISK_FORMAT_RAW: u32 = 0;
#[allow(dead_code)]
pub const KRUN_DISK_FORMAT_QCOW2: u32 = 1;

#[link(name = "krun-efi")]
#[allow(dead_code)]
extern "C" {
    /// Sets the log level for the library.
    pub fn krun_set_log_level(level: u32) -> i32;

    /// Creates a configuration context.
    /// Returns the context ID on success or a negative error number on failure.
    pub fn krun_create_ctx() -> i32;

    /// Frees an existing configuration context.
    pub fn krun_free_ctx(ctx_id: u32) -> i32;

    /// Sets the basic configuration parameters for the microVM.
    pub fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;

    /// Sets the path to be used as root for the microVM.
    pub fn krun_set_root(ctx_id: u32, root_path: *const c_char) -> i32;

    /// Adds a disk image to be used as a general partition.
    pub fn krun_add_disk(
        ctx_id: u32,
        block_id: *const c_char,
        disk_path: *const c_char,
        read_only: bool,
    ) -> i32;

    /// Adds a disk image with format specification.
    pub fn krun_add_disk2(
        ctx_id: u32,
        block_id: *const c_char,
        disk_path: *const c_char,
        disk_format: u32,
        read_only: bool,
    ) -> i32;

    /// Adds a virtio-fs device pointing to a host directory.
    pub fn krun_add_virtiofs(ctx_id: u32, tag: *const c_char, path: *const c_char) -> i32;

    /// Sets the kernel path, format, initramfs, and command line.
    pub fn krun_set_kernel(
        ctx_id: u32,
        kernel_path: *const c_char,
        kernel_format: u32,
        initramfs: *const c_char,
        cmdline: *const c_char,
    ) -> i32;

    /// Sets the executable path, arguments, and environment.
    pub fn krun_set_exec(
        ctx_id: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;

    /// Sets the working directory.
    pub fn krun_set_workdir(ctx_id: u32, workdir_path: *const c_char) -> i32;

    /// Sets environment variables.
    pub fn krun_set_env(ctx_id: u32, envp: *const *const c_char) -> i32;

    /// Configures console output to a file.
    pub fn krun_set_console_output(ctx_id: u32, filepath: *const c_char) -> i32;

    /// Returns the eventfd file descriptor for shutdown signaling.
    pub fn krun_get_shutdown_eventfd(ctx_id: u32) -> i32;

    /// Configures block device to be used as root filesystem.
    pub fn krun_set_root_disk_remount(
        ctx_id: u32,
        device: *const c_char,
        fstype: *const c_char,
        options: *const c_char,
    ) -> i32;

    /// Sets the UID to run as.
    pub fn krun_setuid(ctx_id: u32, uid: uid_t) -> i32;

    /// Sets the GID to run as.
    pub fn krun_setgid(ctx_id: u32, gid: gid_t) -> i32;

    /// Starts and enters the microVM.
    /// This function only returns on error; otherwise the process exits.
    pub fn krun_start_enter(ctx_id: u32) -> i32;

    /// Creates a port-path pairing for vsock communication.
    /// Maps a vsock port in the guest to a Unix socket on the host.
    pub fn krun_add_vsock_port(ctx_id: u32, port: u32, filepath: *const c_char) -> i32;

    /// Extended version of krun_add_vsock_port with listen flag.
    /// If listen is true, the host listens on the socket; otherwise the guest listens.
    pub fn krun_add_vsock_port2(
        ctx_id: u32,
        port: u32,
        filepath: *const c_char,
        listen: bool,
    ) -> i32;

    /// Adds a virtio-net device connected to a Unix datagram socket (for gvproxy).
    /// c_path: Path to the Unix socket
    /// fd: File descriptor (-1 to let libkrun connect)
    /// c_mac: Optional MAC address (6 bytes, or null for auto)
    /// features: virtio-net feature flags (0 for defaults)
    /// flags: Additional flags (0 for defaults)
    pub fn krun_add_net_unixgram(
        ctx_id: u32,
        c_path: *const c_char,
        fd: i32,
        c_mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;

    /// Adds a virtio-net device connected to a Unix stream socket (for passt).
    /// c_path: Path to the Unix socket
    /// fd: File descriptor (-1 to let libkrun connect)
    /// c_mac: Optional MAC address (6 bytes, or null for auto)
    /// features: virtio-net feature flags (0 for defaults)
    /// flags: Additional flags (0 for defaults)
    pub fn krun_add_net_unixstream(
        ctx_id: u32,
        c_path: *const c_char,
        fd: i32,
        c_mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;

    /// Sets the path to gvproxy for network connectivity (deprecated, use krun_add_net_unixdgram).
    pub fn krun_set_gvproxy_path(ctx_id: u32, c_path: *const c_char) -> i32;
}

/// Safe wrapper around libkrun functions
pub struct KrunContext {
    ctx_id: u32,
}

#[allow(dead_code)]
impl KrunContext {
    /// Create a new libkrun context
    pub fn new() -> Result<Self, i32> {
        unsafe {
            let ctx_id = krun_create_ctx();
            if ctx_id < 0 {
                Err(ctx_id)
            } else {
                Ok(Self {
                    ctx_id: ctx_id as u32,
                })
            }
        }
    }

    /// Get the context ID
    pub fn id(&self) -> u32 {
        self.ctx_id
    }

    /// Set log level
    pub fn set_log_level(level: u32) -> Result<(), i32> {
        unsafe {
            let ret = krun_set_log_level(level);
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Set VM configuration (vCPUs and RAM)
    pub fn set_vm_config(&self, num_vcpus: u8, ram_mib: u32) -> Result<(), i32> {
        unsafe {
            let ret = krun_set_vm_config(self.ctx_id, num_vcpus, ram_mib);
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Set root filesystem path
    pub fn set_root(&self, root_path: &str) -> Result<(), i32> {
        let c_path = CString::new(root_path).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_set_root(self.ctx_id, c_path.as_ptr());
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Add a disk image
    pub fn add_disk(&self, block_id: &str, disk_path: &str, read_only: bool) -> Result<(), i32> {
        let c_block_id = CString::new(block_id).map_err(|_| -libc::EINVAL)?;
        let c_disk_path = CString::new(disk_path).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_add_disk(
                self.ctx_id,
                c_block_id.as_ptr(),
                c_disk_path.as_ptr(),
                read_only,
            );
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Add a disk image with format specification
    pub fn add_disk2(
        &self,
        block_id: &str,
        disk_path: &str,
        disk_format: u32,
        read_only: bool,
    ) -> Result<(), i32> {
        let c_block_id = CString::new(block_id).map_err(|_| -libc::EINVAL)?;
        let c_disk_path = CString::new(disk_path).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_add_disk2(
                self.ctx_id,
                c_block_id.as_ptr(),
                c_disk_path.as_ptr(),
                disk_format,
                read_only,
            );
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Add a virtio-fs share
    pub fn add_virtiofs(&self, tag: &str, path: &str) -> Result<(), i32> {
        let c_tag = CString::new(tag).map_err(|_| -libc::EINVAL)?;
        let c_path = CString::new(path).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_add_virtiofs(self.ctx_id, c_tag.as_ptr(), c_path.as_ptr());
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Set kernel, initramfs, and command line
    pub fn set_kernel(
        &self,
        kernel_path: &str,
        kernel_format: u32,
        initramfs: Option<&str>,
        cmdline: &str,
    ) -> Result<(), i32> {
        let c_kernel = CString::new(kernel_path).map_err(|_| -libc::EINVAL)?;
        let c_initramfs = initramfs
            .map(|s| CString::new(s).map_err(|_| -libc::EINVAL))
            .transpose()?;
        let c_cmdline = CString::new(cmdline).map_err(|_| -libc::EINVAL)?;

        unsafe {
            let ret = krun_set_kernel(
                self.ctx_id,
                c_kernel.as_ptr(),
                kernel_format,
                c_initramfs
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
                c_cmdline.as_ptr(),
            );
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Set executable, arguments, and environment
    pub fn set_exec(
        &self,
        exec_path: &str,
        argv: &[&str],
        envp: Option<&[&str]>,
    ) -> Result<(), i32> {
        let c_exec = CString::new(exec_path).map_err(|_| -libc::EINVAL)?;

        let c_argv: Vec<CString> = argv
            .iter()
            .map(|s| CString::new(*s).map_err(|_| -libc::EINVAL))
            .collect::<Result<Vec<_>, _>>()?;
        let mut argv_ptrs: Vec<*const c_char> = c_argv.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        let (_c_envp, envp_ptrs): (Vec<CString>, Vec<*const c_char>) = if let Some(env) = envp {
            let c_env: Vec<CString> = env
                .iter()
                .map(|s| CString::new(*s).map_err(|_| -libc::EINVAL))
                .collect::<Result<Vec<_>, _>>()?;
            let mut ptrs: Vec<*const c_char> = c_env.iter().map(|s| s.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            (c_env, ptrs)
        } else {
            (vec![], vec![std::ptr::null()])
        };

        unsafe {
            let ret = krun_set_exec(
                self.ctx_id,
                c_exec.as_ptr(),
                argv_ptrs.as_ptr(),
                if envp.is_some() {
                    envp_ptrs.as_ptr()
                } else {
                    std::ptr::null()
                },
            );
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Set working directory
    pub fn set_workdir(&self, workdir: &str) -> Result<(), i32> {
        let c_workdir = CString::new(workdir).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_set_workdir(self.ctx_id, c_workdir.as_ptr());
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Configure root disk remount
    pub fn set_root_disk_remount(
        &self,
        device: &str,
        fstype: Option<&str>,
        options: Option<&str>,
    ) -> Result<(), i32> {
        let c_device = CString::new(device).map_err(|_| -libc::EINVAL)?;
        let c_fstype = fstype
            .map(|s| CString::new(s).map_err(|_| -libc::EINVAL))
            .transpose()?;
        let c_options = options
            .map(|s| CString::new(s).map_err(|_| -libc::EINVAL))
            .transpose()?;

        unsafe {
            let ret = krun_set_root_disk_remount(
                self.ctx_id,
                c_device.as_ptr(),
                c_fstype
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
                c_options
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
            );
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Get shutdown eventfd
    pub fn get_shutdown_eventfd(&self) -> Result<RawFd, i32> {
        unsafe {
            let ret = krun_get_shutdown_eventfd(self.ctx_id);
            if ret < 0 {
                Err(ret)
            } else {
                Ok(ret as RawFd)
            }
        }
    }

    /// Add a vsock port mapping to a Unix socket
    /// Maps a vsock port in the guest to a Unix socket path on the host
    pub fn add_vsock_port(&self, port: u32, filepath: &str) -> Result<(), i32> {
        let c_filepath = CString::new(filepath).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_add_vsock_port(self.ctx_id, port, c_filepath.as_ptr());
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Add a vsock port mapping with listen flag
    /// If listen is true, the host side will listen on the socket
    pub fn add_vsock_port2(&self, port: u32, filepath: &str, listen: bool) -> Result<(), i32> {
        let c_filepath = CString::new(filepath).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_add_vsock_port2(self.ctx_id, port, c_filepath.as_ptr(), listen);
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Add a virtio-net device connected to a Unix datagram socket (for gvproxy)
    pub fn add_net_unixgram(&self, socket_path: &str) -> Result<(), i32> {
        let c_path = CString::new(socket_path).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_add_net_unixgram(
                self.ctx_id,
                c_path.as_ptr(),
                -1,               // Let libkrun connect
                std::ptr::null(), // Auto-generate MAC
                0,                // Default features
                0,                // Default flags
            );
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Add a virtio-net device connected to a Unix stream socket (for passt)
    pub fn add_net_unixstream(&self, socket_path: &str) -> Result<(), i32> {
        let c_path = CString::new(socket_path).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_add_net_unixstream(
                self.ctx_id,
                c_path.as_ptr(),
                -1,               // Let libkrun connect
                std::ptr::null(), // Auto-generate MAC
                0,                // Default features
                0,                // Default flags
            );
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Set gvproxy path (deprecated but simpler interface)
    pub fn set_gvproxy_path(&self, path: &str) -> Result<(), i32> {
        let c_path = CString::new(path).map_err(|_| -libc::EINVAL)?;
        unsafe {
            let ret = krun_set_gvproxy_path(self.ctx_id, c_path.as_ptr());
            if ret < 0 {
                Err(ret)
            } else {
                Ok(())
            }
        }
    }

    /// Start and enter the VM (does not return on success)
    pub fn start_enter(self) -> Result<(), i32> {
        unsafe {
            let ret = krun_start_enter(self.ctx_id);
            // Only returns on error
            Err(ret)
        }
    }
}

impl Drop for KrunContext {
    fn drop(&mut self) {
        unsafe {
            krun_free_ctx(self.ctx_id);
        }
    }
}
