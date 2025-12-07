//! VM setup and rootfs preparation
//!
//! This module handles converting a container image's filesystem into a
//! bootable VM rootfs with auto-login configured.

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::{debug, info};

/// Information about the host user to create in the VM
#[derive(Debug, Clone)]
pub struct HostUserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home_dir: String,
}

impl HostUserInfo {
    /// Get the current user's information
    pub fn current() -> Result<Self> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Get username from environment or passwd entry
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| format!("user{}", uid));

        // Get home directory
        let home_dir = std::env::var("HOME")
            .unwrap_or_else(|_| format!("/home/{}", username));

        Ok(Self {
            username,
            uid,
            gid,
            home_dir,
        })
    }
}

/// Detect the distribution type from the rootfs
///
/// Only systemd-based distros are supported (Ubuntu, Fedora, Debian, CentOS, etc.)
pub fn detect_distro(rootfs: &Path) -> Result<String> {
    // Check /etc/os-release
    let os_release = rootfs.join("etc/os-release");
    if os_release.exists() {
        let content = std::fs::read_to_string(&os_release)?;

        if content.contains("Ubuntu") || content.contains("ubuntu") {
            return Ok("ubuntu".to_string());
        }
        if content.contains("Fedora") || content.contains("fedora") {
            return Ok("fedora".to_string());
        }
        // CentOS Stream uses dnf like Fedora, treat it as centos for kernel extraction
        if content.contains("CentOS") || content.contains("centos") {
            return Ok("centos".to_string());
        }
        // RHEL and Rocky/Alma are CentOS-compatible
        if content.contains("Red Hat Enterprise") || content.contains("Rocky") || content.contains("AlmaLinux") {
            return Ok("centos".to_string());
        }
        if content.contains("Debian") || content.contains("debian") {
            return Ok("ubuntu".to_string()); // Debian-like, uses same setup
        }
    }

    // Check for package managers (systemd distros only)
    if rootfs.join("usr/bin/apt").exists() || rootfs.join("usr/bin/apt-get").exists() {
        return Ok("ubuntu".to_string());
    }
    if rootfs.join("usr/bin/dnf").exists() || rootfs.join("usr/bin/yum").exists() {
        // Could be Fedora or CentOS - check /etc/centos-release or /etc/redhat-release
        if rootfs.join("etc/centos-release").exists() {
            return Ok("centos".to_string());
        }
        if rootfs.join("etc/redhat-release").exists() {
            let content = std::fs::read_to_string(rootfs.join("etc/redhat-release")).unwrap_or_default();
            if content.contains("CentOS") || content.contains("Red Hat") || content.contains("Rocky") || content.contains("Alma") {
                return Ok("centos".to_string());
            }
        }
        return Ok("fedora".to_string());
    }

    // Default to generic (will require systemd)
    Ok("generic".to_string())
}

/// Prepare the VM rootfs with auto-login and necessary configurations
pub async fn prepare_vm_rootfs(rootfs: &Path, distro: &str) -> Result<()> {
    // Get host user info for creating matching user in VM
    let host_user = HostUserInfo::current()?;
    prepare_vm_rootfs_with_user(rootfs, distro, &host_user).await
}

/// Prepare the VM rootfs with a specific user configuration
pub async fn prepare_vm_rootfs_with_user(
    rootfs: &Path,
    distro: &str,
    host_user: &HostUserInfo,
) -> Result<()> {
    info!("Preparing VM rootfs for {} at {:?}", distro, rootfs);

    // Create essential directories if missing
    create_essential_dirs(rootfs)?;

    // Create the host user in the VM
    setup_host_user(rootfs, host_user)?;

    // Set up auto-login for the host user (not root)
    setup_auto_login_user(rootfs, host_user)?;

    // Create init system configuration
    setup_init_with_user(rootfs, distro, host_user)?;

    // Set up networking
    setup_networking(rootfs, distro)?;

    // Set up console for the host user
    setup_console_user(rootfs, host_user)?;

    // Set proper permissions
    fix_permissions(rootfs)?;

    info!("VM rootfs preparation complete");
    Ok(())
}

fn create_essential_dirs(rootfs: &Path) -> Result<()> {
    let dirs = [
        "proc", "sys", "dev", "dev/pts", "run", "tmp", "var/log",
        "etc/init.d", "etc/rc.d", "root", "home",
    ];

    for dir in dirs {
        let path = rootfs.join(dir);
        // Skip if path exists (including as a symlink)
        if path.exists() || path.is_symlink() {
            continue;
        }
        std::fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create {}", dir))?;
    }

    // Handle var/run specially - it's often a symlink to /run
    let var_run = rootfs.join("var/run");
    if !var_run.exists() && !var_run.is_symlink() {
        // Try to create it, but don't fail if it already exists
        let _ = std::fs::create_dir_all(&var_run);
    }

    // Set tmp permissions
    let tmp = rootfs.join("tmp");
    if tmp.exists() && !tmp.is_symlink() {
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o1777));
    }

    Ok(())
}

/// Create the host user in the VM with matching UID/GID
fn setup_host_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    debug!("Creating user {} with UID {} GID {}", user.username, user.uid, user.gid);

    // Create user's home directory (will be mount point for virtiofs)
    let user_home = rootfs.join(user.home_dir.trim_start_matches('/'));
    std::fs::create_dir_all(&user_home)?;

    // Add user's group to /etc/group
    let group_path = rootfs.join("etc/group");
    let mut group_content = if group_path.exists() {
        std::fs::read_to_string(&group_path).unwrap_or_default()
    } else {
        String::new()
    };

    // Ensure root group exists
    if !group_content.contains("root:") {
        group_content = format!("root:x:0:\n{}", group_content);
    }

    // Add user's group if not exists
    let user_group_entry = format!("{}:x:{}:", user.username, user.gid);
    if !group_content.contains(&format!("{}:", user.username)) && !group_content.contains(&format!(":{}:", user.gid)) {
        group_content.push_str(&format!("{}\n", user_group_entry));
    }

    std::fs::write(&group_path, group_content)?;

    // Add user to /etc/passwd
    let passwd_path = rootfs.join("etc/passwd");
    let mut passwd_content = if passwd_path.exists() {
        std::fs::read_to_string(&passwd_path).unwrap_or_default()
    } else {
        String::new()
    };

    // Ensure root user exists
    if !passwd_content.contains("root:") {
        passwd_content = format!("root:x:0:0:root:/root:/bin/bash\n{}", passwd_content);
    }

    // Add user if not exists
    // Use /bin/bash as shell since that's what we set up in the VM
    let user_passwd_entry = format!(
        "{}:x:{}:{}:{}:{}:/bin/bash",
        user.username,
        user.uid,
        user.gid,
        user.username,
        user.home_dir
    );
    if !passwd_content.contains(&format!("{}:", user.username)) {
        passwd_content.push_str(&format!("{}\n", user_passwd_entry));
    }

    std::fs::write(&passwd_path, passwd_content)?;

    // Add user to /etc/shadow with empty password
    let shadow_path = rootfs.join("etc/shadow");
    let _ = std::fs::set_permissions(&shadow_path, std::fs::Permissions::from_mode(0o640));

    let mut shadow_content = if shadow_path.exists() {
        std::fs::read_to_string(&shadow_path).unwrap_or_default()
    } else {
        String::new()
    };

    // Ensure root shadow entry
    if !shadow_content.contains("root:") {
        shadow_content = format!("root::19000:0:99999:7:::\n{}", shadow_content);
    }

    // Add user shadow entry if not exists
    let user_shadow_entry = format!("{}::19000:0:99999:7:::", user.username);
    if !shadow_content.contains(&format!("{}:", user.username)) {
        shadow_content.push_str(&format!("{}\n", user_shadow_entry));
    }

    std::fs::write(&shadow_path, shadow_content)?;

    // Set ownership of home directory
    // Note: This won't actually change ownership since we're running as a user,
    // but it sets up the structure. The virtiofs mount will handle actual ownership.
    let _ = std::fs::set_permissions(&user_home, std::fs::Permissions::from_mode(0o755));

    // Set up passwordless sudo for the user
    setup_passwordless_sudo(rootfs, user)?;

    Ok(())
}

/// Configure passwordless sudo for the user
fn setup_passwordless_sudo(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    // Ensure sudoers.d directory exists
    let sudoers_d = rootfs.join("etc/sudoers.d");
    std::fs::create_dir_all(&sudoers_d)?;

    // Create a sudoers file for the user with NOPASSWD
    let sudoers_file = sudoers_d.join(&user.username);
    let sudoers_content = format!("{} ALL=(ALL) NOPASSWD: ALL\n", user.username);
    std::fs::write(&sudoers_file, &sudoers_content)?;

    // Set correct permissions (sudoers files must be 0440)
    std::fs::set_permissions(&sudoers_file, std::fs::Permissions::from_mode(0o440))?;

    // Also add user to wheel/sudo group in /etc/group
    let group_path = rootfs.join("etc/group");
    if group_path.exists() {
        let mut content = std::fs::read_to_string(&group_path)?;

        // Add user to wheel group if it exists
        if content.contains("wheel:") {
            content = content.replace(
                "wheel:x:10:",
                &format!("wheel:x:10:{}", user.username)
            );
        }

        // Add user to sudo group if it exists (Debian/Ubuntu)
        if content.contains("sudo:") && !content.contains(&format!("sudo:x:27:{}", user.username)) {
            content = content.replace(
                "sudo:x:27:",
                &format!("sudo:x:27:{}", user.username)
            );
        }

        std::fs::write(&group_path, content)?;
    }

    debug!("Configured passwordless sudo for user {}", user.username);
    Ok(())
}

/// Set up auto-login for the host user
fn setup_auto_login_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    debug!("Setting up auto-login for user {}", user.username);

    // Also ensure root can login (needed for some operations)
    let shadow_path = rootfs.join("etc/shadow");
    if shadow_path.exists() {
        let _ = std::fs::set_permissions(&shadow_path, std::fs::Permissions::from_mode(0o640));
    }

    // Set up systemd getty auto-login (all supported distros use systemd)
    setup_systemd_autologin_user(rootfs, user)?;

    Ok(())
}

fn setup_systemd_autologin_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    // Create override for serial-getty on hvc0
    let getty_dir = rootfs.join("etc/systemd/system/serial-getty@hvc0.service.d");
    std::fs::create_dir_all(&getty_dir)?;

    let override_content = format!(r#"[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin {} --noclear %I $TERM
"#, user.username);

    std::fs::write(getty_dir.join("autologin.conf"), &override_content)?;

    // Also set up for ttyS0 as fallback
    let getty_dir_serial = rootfs.join("etc/systemd/system/serial-getty@ttyS0.service.d");
    std::fs::create_dir_all(&getty_dir_serial)?;
    std::fs::write(getty_dir_serial.join("autologin.conf"), &override_content)?;

    // Set up console-getty.service for Ubuntu (uses /dev/console instead of serial)
    let console_getty_dir = rootfs.join("etc/systemd/system/console-getty.service.d");
    std::fs::create_dir_all(&console_getty_dir)?;
    let console_override = format!(r#"[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin {} --noclear --keep-baud console 115200,38400,9600 $TERM
"#, user.username);
    std::fs::write(console_getty_dir.join("autologin.conf"), &console_override)?;

    // Create symlink to enable the service
    let wants_dir = rootfs.join("etc/systemd/system/multi-user.target.wants");
    std::fs::create_dir_all(&wants_dir)?;

    let service_link = wants_dir.join("serial-getty@hvc0.service");
    if !service_link.exists() {
        let _ = std::os::unix::fs::symlink(
            "/lib/systemd/system/serial-getty@.service",
            &service_link,
        );
    }

    Ok(())
}

/// Set up init to run as the host user and mount home directory
fn setup_init_with_user(rootfs: &Path, distro: &str, user: &HostUserInfo) -> Result<()> {
    debug!("Setting up systemd for {} with user {}", distro, user.username);

    // Check if systemd exists
    let has_systemd = rootfs.join("lib/systemd/systemd").exists()
        || rootfs.join("usr/lib/systemd/systemd").exists();

    if !has_systemd {
        debug!("Systemd not found, it will be installed during kernel extraction");
        // Systemd will be installed when the kernel is extracted
        // Just set up the configuration directories
    }

    // For systemd, create a mount unit for the home directory
    setup_systemd_home_mount(rootfs, user)?;

    // Ensure systemd is the init - create symlink only if missing
    let init_link = rootfs.join("sbin/init");
    if !init_link.exists() {
        std::fs::create_dir_all(rootfs.join("sbin"))?;
        // Try both common paths for systemd
        if rootfs.join("lib/systemd/systemd").exists() {
            let _ = std::os::unix::fs::symlink("/lib/systemd/systemd", &init_link);
        } else {
            let _ = std::os::unix::fs::symlink("/usr/lib/systemd/systemd", &init_link);
        }
    }

    // Disable unnecessary services for faster boot
    let mask_services = [
        "systemd-networkd-wait-online.service",
        "NetworkManager-wait-online.service",
        "apt-daily.service",
        "apt-daily-upgrade.service",
        "unattended-upgrades.service",
    ];

    let mask_dir = rootfs.join("etc/systemd/system");
    std::fs::create_dir_all(&mask_dir)?;

    for service in mask_services {
        let link = mask_dir.join(service);
        if !link.exists() {
            let _ = std::os::unix::fs::symlink("/dev/null", &link);
        }
    }

    // Set default target to multi-user (console)
    let default_target = mask_dir.join("default.target");
    if !default_target.exists() {
        let _ = std::os::unix::fs::symlink(
            "/lib/systemd/system/multi-user.target",
            &default_target,
        );
    }

    Ok(())
}

fn setup_systemd_home_mount(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    // Create a systemd mount unit for the home directory
    let mount_dir = rootfs.join("etc/systemd/system");
    std::fs::create_dir_all(&mount_dir)?;

    // Convert home path to mount unit name (e.g., /home/user -> home-user.mount)
    let mount_unit_name = user.home_dir
        .trim_start_matches('/')
        .replace('/', "-");
    let mount_unit_file = mount_dir.join(format!("{}.mount", mount_unit_name));

    // The mount unit should:
    // - Wait for systemd-modules-load.service to ensure virtiofs module is available
    // - Not block boot if mount fails (nofail)
    // - Use x-systemd.device-timeout to avoid long hangs
    // Note: Don't use ConditionPathExists as the path varies between distros
    let mount_content = format!(r#"[Unit]
Description=Mount host home directory
After=systemd-modules-load.service
After=local-fs-pre.target
Before=local-fs.target
DefaultDependencies=no

[Mount]
What=home
Where={}
Type=virtiofs
Options=rw,nofail,x-systemd.device-timeout=5

[Install]
WantedBy=local-fs.target
"#, user.home_dir);

    std::fs::write(&mount_unit_file, mount_content)?;

    // Enable the mount unit
    let wants_dir = rootfs.join("etc/systemd/system/local-fs.target.wants");
    std::fs::create_dir_all(&wants_dir)?;
    let link = wants_dir.join(format!("{}.mount", mount_unit_name));
    if !link.exists() {
        let _ = std::os::unix::fs::symlink(
            format!("/etc/systemd/system/{}.mount", mount_unit_name),
            &link,
        );
    }

    Ok(())
}

/// Set up console/shell environment for the host user
fn setup_console_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    debug!("Setting up console for user {}", user.username);

    // Create /etc/securetty if it doesn't exist (allow user login on console)
    let securetty = rootfs.join("etc/securetty");
    if !securetty.exists() {
        let content = "console\ntty1\nttyS0\nhvc0\n";
        std::fs::write(&securetty, content)?;
    } else {
        let _ = std::fs::set_permissions(&securetty, std::fs::Permissions::from_mode(0o644));
        if let Ok(content) = std::fs::read_to_string(&securetty) {
            if !content.contains("hvc0") {
                let _ = std::fs::write(&securetty, format!("{}\nhvc0\n", content));
            }
        }
    }

    // Ensure user home directory exists and is writable
    let user_home = rootfs.join(user.home_dir.trim_start_matches('/'));
    if user_home.exists() {
        let _ = std::fs::set_permissions(&user_home, std::fs::Permissions::from_mode(0o755));
    } else {
        std::fs::create_dir_all(&user_home)?;
    }

    // Set up user's bash profile for interactive mode
    let bashrc = user_home.join(".bashrc");
    if bashrc.exists() {
        let _ = std::fs::set_permissions(&bashrc, std::fs::Permissions::from_mode(0o644));
    }

    // Interactive mode - write normal bashrc
    let bashrc_content = format!(r#"# ~/.bashrc
export PS1='\[\033[01;32m\]\u@vmm\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
export TERM=xterm-256color
export HOME={home_dir}
alias ls='ls --color=auto'
alias ll='ls -la'
alias grep='grep --color=auto'
cd {home_dir}
"#, home_dir = user.home_dir);
    let _ = std::fs::write(&bashrc, bashrc_content);

    // Create .profile
    let profile = user_home.join(".profile");
    if profile.exists() {
        let _ = std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o644));
    }
    let _ = std::fs::write(&profile, "# .profile\n");

    Ok(())
}






fn setup_networking(rootfs: &Path, distro: &str) -> Result<()> {
    debug!("Setting up networking for {}", distro);

    // Create /etc/hosts
    let hosts = rootfs.join("etc/hosts");
    if !hosts.exists() {
        std::fs::write(
            &hosts,
            "127.0.0.1 localhost\n::1 localhost\n",
        )?;
    }

    // Create /etc/hostname
    let hostname = rootfs.join("etc/hostname");
    if !hostname.exists() {
        std::fs::write(&hostname, "vmm\n")?;
    }

    // Create /etc/resolv.conf
    let resolv = rootfs.join("etc/resolv.conf");
    if !resolv.exists() {
        std::fs::write(&resolv, "nameserver 8.8.8.8\nnameserver 8.8.4.4\n")?;
    }

    // For systemd-based systems, configure networkd
    if rootfs.join("lib/systemd/systemd").exists() {
        let network_dir = rootfs.join("etc/systemd/network");
        std::fs::create_dir_all(&network_dir)?;

        // DHCP configuration for all ethernet interfaces
        let network_conf = r#"[Match]
Name=e*

[Network]
DHCP=yes
"#;
        std::fs::write(network_dir.join("80-dhcp.network"), network_conf)?;
    }

    Ok(())
}

fn fix_permissions(rootfs: &Path) -> Result<()> {
    // Fix permissions on sensitive files - ignore errors since they may already have correct perms
    let shadow = rootfs.join("etc/shadow");
    if shadow.exists() {
        let _ = std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o640));
    }

    let passwd = rootfs.join("etc/passwd");
    if passwd.exists() {
        let _ = std::fs::set_permissions(&passwd, std::fs::Permissions::from_mode(0o644));
    }

    // Make sure /root is accessible
    let root_home = rootfs.join("root");
    if root_home.exists() {
        let _ = std::fs::set_permissions(&root_home, std::fs::Permissions::from_mode(0o700));
    }

    Ok(())
}
