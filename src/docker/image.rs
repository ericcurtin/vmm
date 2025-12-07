//! Docker image pulling and extraction

use anyhow::{Context, Result};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures_util::StreamExt;
use std::path::Path;
use tokio::process::Command;
use tracing::{debug, info};

/// Information about a Docker image
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub id: String,
    pub repo_tags: Vec<String>,
    pub size: i64,
}

/// Pull a Docker image if not already present
pub async fn pull_image(image: &str) -> Result<ImageInfo> {
    let docker = Docker::connect_with_local_defaults()
        .context("Failed to connect to Docker daemon")?;

    // Parse image name and tag
    let (repo, tag) = if image.contains(':') {
        let parts: Vec<&str> = image.splitn(2, ':').collect();
        (parts[0], parts[1])
    } else {
        (image, "latest")
    };

    let full_image = format!("{}:{}", repo, tag);
    debug!("Pulling image: {}", full_image);

    // Create image (pull)
    let options = CreateImageOptions {
        from_image: repo,
        tag,
        ..Default::default()
    };

    let mut stream = docker.create_image(Some(options), None, None);

    while let Some(result) = stream.next().await {
        match result {
            Ok(info) => {
                if let Some(status) = info.status {
                    if let Some(progress) = info.progress {
                        debug!("{}: {}", status, progress);
                    } else {
                        debug!("{}", status);
                    }
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to pull image: {}", e));
            }
        }
    }

    // Get image info
    let inspect = docker
        .inspect_image(&full_image)
        .await
        .context("Failed to inspect image")?;

    Ok(ImageInfo {
        id: inspect.id.unwrap_or_default(),
        repo_tags: inspect.repo_tags.unwrap_or_default(),
        size: inspect.size.unwrap_or(0),
    })
}

/// Install systemd and essential packages into a container image
///
/// Container images typically don't include systemd since containers don't need init.
/// For VMs, we need systemd to be present. This function creates a new container,
/// installs the necessary packages, and commits it to a temporary image.
async fn install_systemd_packages(image: &str) -> Result<String> {
    use rand::Rng;

    debug!("Installing systemd packages into image: {}", image);

    // Generate a unique tag for the temporary image
    let random_suffix: u32 = rand::rng().random();
    let temp_image = format!("vmm-temp-{:08x}", random_suffix);

    // Detect package manager and install systemd
    // We run a container that installs systemd then commit the result
    let install_cmd = r#"
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y systemd systemd-libs util-linux passwd sudo
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y systemd systemd-sysv util-linux passwd sudo
        elif command -v apk >/dev/null 2>&1; then
            echo "Alpine is not supported - systemd required" && exit 1
        else
            echo "Unknown package manager" && exit 1
        fi
    "#;

    // Run the install command in a container
    let output = Command::new("docker")
        .args(["run", "--name", &temp_image, image, "sh", "-c", install_cmd])
        .output()
        .await
        .context("Failed to run docker container for systemd install")?;

    if !output.status.success() {
        // Clean up container on failure
        let _ = Command::new("docker")
            .args(["rm", "-f", &temp_image])
            .output()
            .await;
        return Err(anyhow::anyhow!(
            "Failed to install systemd: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    debug!("Systemd installed, committing container to image...");

    // Commit the container to a new image
    let output = Command::new("docker")
        .args(["commit", &temp_image, &temp_image])
        .output()
        .await
        .context("Failed to commit container")?;

    if !output.status.success() {
        // Clean up
        let _ = Command::new("docker")
            .args(["rm", "-f", &temp_image])
            .output()
            .await;
        return Err(anyhow::anyhow!(
            "Failed to commit container: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Remove the container (keep the image)
    let _ = Command::new("docker")
        .args(["rm", "-f", &temp_image])
        .output()
        .await;

    info!("Created temporary image with systemd: {}", temp_image);
    Ok(temp_image)
}

/// Extract a Docker image to a directory using docker export
///
/// This creates a container from the image and exports its filesystem.
/// If the image doesn't have systemd (typical for container images),
/// it will first install systemd before exporting.
pub async fn extract_image(image: &str, dest: &Path) -> Result<()> {
    let docker = Docker::connect_with_local_defaults()
        .context("Failed to connect to Docker daemon")?;

    debug!("Extracting image {} to {:?}", image, dest);

    // First, install systemd packages into the image
    let prepared_image = install_systemd_packages(image).await?;
    let cleanup_image = prepared_image.clone();

    // Create a temporary container from the prepared image
    let container_config = bollard::container::Config {
        image: Some(prepared_image.clone()),
        cmd: Some(vec!["/bin/true".to_string()]),
        ..Default::default()
    };

    let container = docker
        .create_container::<&str, String>(None, container_config)
        .await
        .context("Failed to create container for export")?;

    let container_id = container.id;
    debug!("Created temporary container: {}", container_id);

    // Export the container filesystem
    let export_result = async {
        // Use docker export command directly for simplicity
        let output = Command::new("docker")
            .args(["export", &container_id])
            .output()
            .await
            .context("Failed to run docker export")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "docker export failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Extract the tar archive to the destination
        std::fs::create_dir_all(dest).context("Failed to create destination directory")?;

        let mut archive = tar::Archive::new(output.stdout.as_slice());
        archive
            .unpack(dest)
            .context("Failed to extract tar archive")?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Clean up the container
    docker
        .remove_container(
            &container_id,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
        .context("Failed to remove temporary container")?;

    // Clean up the temporary image (with systemd installed)
    let _ = Command::new("docker")
        .args(["rmi", "-f", &cleanup_image])
        .output()
        .await;

    export_result?;

    info!("Successfully extracted image to {:?}", dest);
    Ok(())
}

/// Get list of available Docker images
pub async fn list_images() -> Result<Vec<ImageInfo>> {
    let docker = Docker::connect_with_local_defaults()
        .context("Failed to connect to Docker daemon")?;

    let images = docker
        .list_images::<String>(None)
        .await
        .context("Failed to list images")?;

    Ok(images
        .into_iter()
        .map(|img| ImageInfo {
            id: img.id,
            repo_tags: img.repo_tags,
            size: img.size,
        })
        .collect())
}
