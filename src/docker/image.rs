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
    info!("Pulling image: {}", full_image);

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

/// Extract a Docker image to a directory using docker export
///
/// This creates a container from the image and exports its filesystem.
pub async fn extract_image(image: &str, dest: &Path) -> Result<()> {
    let docker = Docker::connect_with_local_defaults()
        .context("Failed to connect to Docker daemon")?;

    info!("Extracting image {} to {:?}", image, dest);

    // Create a temporary container
    let container_config = bollard::container::Config {
        image: Some(image.to_string()),
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
