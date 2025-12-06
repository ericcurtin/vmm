//! Docker image handling module
//!
//! This module provides functionality to pull Docker images and extract their
//! filesystem layers into a directory suitable for use as a VM root filesystem.

mod image;

pub use image::{pull_image, extract_image, ImageInfo};
