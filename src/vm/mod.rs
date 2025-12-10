//! VM management module
//!
//! This module provides functionality to create, start, stop, and manage
//! lightweight VMs using libkrun-efi.

pub mod disk;
mod kernel;
mod krun_ffi;
mod network;
pub mod runner;
pub mod setup;

pub use disk::create_disk_image;
pub use kernel::ensure_kernel;
pub use network::ensure_gvproxy;
pub use runner::run_vm;
pub use setup::{prepare_vm_rootfs, HostUserInfo};
