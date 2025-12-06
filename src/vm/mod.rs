//! VM management module
//!
//! This module provides functionality to create, start, stop, and manage
//! lightweight VMs using libkrun-efi.

mod krun_ffi;
mod kernel;
pub mod disk;
pub mod runner;
pub mod setup;

pub use disk::create_disk_image;
pub use kernel::{ensure_kernel, KernelInfo};
pub use runner::run_vm;
pub use setup::{prepare_vm_rootfs, HostUserInfo};
