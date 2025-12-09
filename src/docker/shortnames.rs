//! Short name resolution for container images
//!
//! This module provides short name resolution for common
//! container images. Short names like "centos" are resolved to their
//! full registry paths like "quay.io/centos/centos".

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Built-in short name mappings for common distributions
static SHORTNAMES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // CentOS - official images on Quay.io
    m.insert("centos", "quay.io/centos/centos");
    m.insert("centos-stream", "quay.io/centos/centos:stream");

    // Fedora - official images on Quay.io
    m.insert("fedora", "quay.io/fedora/fedora");

    // Ubuntu - Docker Hub (default, so no prefix needed)
    m.insert("ubuntu", "docker.io/library/ubuntu");

    // Debian
    m.insert("debian", "docker.io/library/debian");

    // Red Hat UBI (Universal Base Image)
    m.insert("ubi8", "registry.access.redhat.com/ubi8/ubi");
    m.insert("ubi9", "registry.access.redhat.com/ubi9/ubi");

    // Rocky Linux
    m.insert("rockylinux", "quay.io/rockylinux/rockylinux");
    m.insert("rocky", "quay.io/rockylinux/rockylinux");

    // AlmaLinux
    m.insert("almalinux", "quay.io/almalinuxorg/almalinux");
    m.insert("alma", "quay.io/almalinuxorg/almalinux");

    // Amazon Linux
    m.insert("amazonlinux", "public.ecr.aws/amazonlinux/amazonlinux");

    // Arch Linux
    m.insert("archlinux", "docker.io/library/archlinux");
    m.insert("arch", "docker.io/library/archlinux");

    // openSUSE
    m.insert("opensuse", "registry.opensuse.org/opensuse/leap");
    m.insert("opensuse-leap", "registry.opensuse.org/opensuse/leap");
    m.insert(
        "opensuse-tumbleweed",
        "registry.opensuse.org/opensuse/tumbleweed",
    );

    m
});

/// Resolve a short name to its full image reference
///
/// If the image name is a known short name, returns the full registry path.
/// If the image already contains a registry (has a slash or dot in the first component),
/// or is not a known short name, returns the original image unchanged.
///
/// # Examples
///
/// ```
/// use vmm::docker::shortnames::resolve_shortname;
///
/// // Short names are resolved
/// assert_eq!(resolve_shortname("centos"), "quay.io/centos/centos");
/// assert_eq!(resolve_shortname("centos:stream10"), "quay.io/centos/centos:stream10");
///
/// // Full references pass through unchanged
/// assert_eq!(resolve_shortname("docker.io/library/ubuntu"), "docker.io/library/ubuntu");
/// assert_eq!(resolve_shortname("myregistry.com/myimage"), "myregistry.com/myimage");
///
/// // Unknown short names pass through unchanged
/// assert_eq!(resolve_shortname("unknown"), "unknown");
/// ```
pub fn resolve_shortname(image: &str) -> String {
    // Split image into name and tag
    let (name, tag) = if let Some(pos) = image.rfind(':') {
        // Make sure the colon is not part of a port number (e.g., registry:5000/image)
        let before_colon = &image[..pos];
        if before_colon.contains('/') && !before_colon.split('/').last().unwrap_or("").contains('.')
        {
            // It's likely a tag separator
            (&image[..pos], Some(&image[pos + 1..]))
        } else if !before_colon.contains('/') {
            // Simple name:tag format
            (&image[..pos], Some(&image[pos + 1..]))
        } else {
            // Could be a port, treat the whole thing as the name
            (image, None)
        }
    } else {
        (image, None)
    };

    // Check if this looks like a full reference already
    // A full reference has either:
    // - A domain (contains a dot in the first path component)
    // - A path with a registry (contains a slash)
    let first_component = name.split('/').next().unwrap_or(name);
    if first_component.contains('.') || first_component.contains(':') || name.contains('/') {
        // Already a full reference
        return image.to_string();
    }

    // Try to resolve the short name
    if let Some(full_name) = SHORTNAMES.get(name) {
        // Apply tag if present
        if let Some(t) = tag {
            format!("{}:{}", full_name, t)
        } else {
            // For centos, we need a default tag since bare "centos" image is deprecated
            if name == "centos" {
                format!("{}:stream10", full_name)
            } else {
                full_name.to_string()
            }
        }
    } else {
        // Unknown short name, return as-is (Docker will use default registry)
        image.to_string()
    }
}

/// Get the base name (short name) for an image reference
///
/// This is useful for display purposes and VM naming.
/// Extracts just the image name without registry or tag.
#[allow(dead_code)]
pub fn get_base_name(image: &str) -> String {
    // Remove tag first
    let without_tag = image.split(':').next().unwrap_or(image);

    // Get the last path component
    without_tag
        .split('/')
        .last()
        .unwrap_or(without_tag)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_centos() {
        // "centos" without tag defaults to stream10
        assert_eq!(
            resolve_shortname("centos"),
            "quay.io/centos/centos:stream10"
        );
        // "centos:stream9" uses the explicit tag
        assert_eq!(
            resolve_shortname("centos:stream9"),
            "quay.io/centos/centos:stream9"
        );
    }

    #[test]
    fn test_resolve_fedora() {
        assert_eq!(resolve_shortname("fedora"), "quay.io/fedora/fedora");
        assert_eq!(resolve_shortname("fedora:43"), "quay.io/fedora/fedora:43");
    }

    #[test]
    fn test_full_reference_passthrough() {
        assert_eq!(
            resolve_shortname("quay.io/centos/centos:stream10"),
            "quay.io/centos/centos:stream10"
        );
        assert_eq!(
            resolve_shortname("docker.io/library/ubuntu:24.04"),
            "docker.io/library/ubuntu:24.04"
        );
    }

    #[test]
    fn test_unknown_shortname() {
        assert_eq!(resolve_shortname("unknown"), "unknown");
        assert_eq!(resolve_shortname("myimage:latest"), "myimage:latest");
    }

    #[test]
    fn test_get_base_name() {
        assert_eq!(get_base_name("quay.io/centos/centos:stream10"), "centos");
        assert_eq!(get_base_name("ubuntu:24.04"), "ubuntu");
        assert_eq!(get_base_name("centos"), "centos");
    }
}
