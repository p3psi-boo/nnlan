use crate::config::Config;
use crate::identity::Identity;
use crate::runtime::admin;
use crate::ui::Style;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Warn,
    Error,
    Info,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub category: String,
    pub title: String,
    pub status: Status,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

pub struct DoctorReport {
    pub checks: Vec<DiagnosticCheck>,
}

impl DoctorReport {
    pub fn is_healthy(&self) -> bool {
        !self.checks.iter().any(|c| c.status == Status::Error)
    }

    pub fn format_human(&self, use_color: bool) -> String {
        let s = Style::new(use_color);
        let mut out = String::new();
        out.push_str(&format!(
            "{}\n{}\n\n",
            s.bold("nnlan System Diagnostics & Health Check"),
            "=".repeat(50)
        ));

        let mut current_category = "";
        for check in &self.checks {
            if check.category != current_category {
                current_category = &check.category;
                out.push_str(&format!("\n[{}]\n", s.bold(current_category)));
            }

            let badge = match check.status {
                Status::Ok => s.green("[✓]"),
                Status::Warn => s.yellow("[!]"),
                Status::Error => s.red("[✗]"),
                Status::Info => s.cyan("[i]"),
            };

            out.push_str(&format!("  {} {}: {}\n", badge, check.title, check.message));
            if let Some(rec) = &check.recommendation {
                out.push_str(&format!("      {} {}\n", s.dim("→ Recommendation:"), rec));
            }
        }

        let errors = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Error)
            .count();
        let warns = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Warn)
            .count();

        out.push_str(&format!("\n{}\n", "-".repeat(50)));
        if errors == 0 && warns == 0 {
            out.push_str(&format!(
                "{}\n",
                s.green("Verdict: All checks passed. System is fully ready for nnlan!")
            ));
        } else if errors == 0 {
            out.push_str(&format!(
                "{}\n",
                s.yellow(&format!(
                    "Verdict: Passed with {warns} warning(s). Check recommendations above."
                ))
            ));
        } else {
            out.push_str(&format!(
                "{}\n",
                s.red(&format!(
                    "Verdict: Found {errors} error(s) and {warns} warning(s). Please fix the issues before running nnlan."
                ))
            ));
        }

        out
    }
}

pub fn check(config_path: &Path) -> DoctorReport {
    let mut checks = Vec::new();

    // 1. Operating System
    let os_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    checks.push(DiagnosticCheck {
        category: "Operating System".into(),
        title: "Linux Kernel".into(),
        status: Status::Ok,
        message: format!("Linux {os_release}"),
        recommendation: None,
    });

    // 2. Linux TUN Device
    let tun_path = Path::new("/dev/net/tun");
    if !tun_path.exists() {
        checks.push(DiagnosticCheck {
            category: "Network Devices".into(),
            title: "TUN Interface".into(),
            status: Status::Error,
            message: "/dev/net/tun device node does not exist".into(),
            recommendation: Some("Load kernel module with 'sudo modprobe tun'".into()),
        });
    } else {
        match fs::OpenOptions::new().read(true).write(true).open(tun_path) {
            Ok(_) => {
                checks.push(DiagnosticCheck {
                    category: "Network Devices".into(),
                    title: "TUN Permissions".into(),
                    status: Status::Ok,
                    message: "/dev/net/tun is accessible with read/write permissions".into(),
                    recommendation: None,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                checks.push(DiagnosticCheck {
                    category: "Network Devices".into(),
                    title: "TUN Permissions".into(),
                    status: Status::Warn,
                    message: "permission denied accessing /dev/net/tun".into(),
                    recommendation: Some(
                        "Run as root (sudo) or grant CAP_NET_ADMIN. Use 'run --no-tun' for unprivileged control plane."
                            .into(),
                    ),
                });
            }
            Err(e) => {
                checks.push(DiagnosticCheck {
                    category: "Network Devices".into(),
                    title: "TUN Permissions".into(),
                    status: Status::Warn,
                    message: format!("error accessing /dev/net/tun: {e}"),
                    recommendation: None,
                });
            }
        }
    }

    // 3. System Utilities
    let ip_found = Command::new("ip").arg("-V").output().is_ok();
    if ip_found {
        checks.push(DiagnosticCheck {
            category: "System Utilities".into(),
            title: "iproute2 (ip)".into(),
            status: Status::Ok,
            message: "available in PATH".into(),
            recommendation: None,
        });
    } else {
        checks.push(DiagnosticCheck {
            category: "System Utilities".into(),
            title: "iproute2 (ip)".into(),
            status: Status::Warn,
            message: "'ip' command not found in PATH".into(),
            recommendation: Some("Install iproute2 package".into()),
        });
    }

    let nft_found = Command::new("nft").arg("-v").output().is_ok();
    if nft_found {
        checks.push(DiagnosticCheck {
            category: "System Utilities".into(),
            title: "nftables (nft)".into(),
            status: Status::Ok,
            message: "available in PATH".into(),
            recommendation: None,
        });
    } else {
        checks.push(DiagnosticCheck {
            category: "System Utilities".into(),
            title: "nftables (nft)".into(),
            status: Status::Info,
            message: "'nft' command not found in PATH".into(),
            recommendation: Some(
                "Install nftables if you plan to use Exit Node or boot guard features".into(),
            ),
        });
    }

    // 4. Configuration and Identity
    let config_res = Config::load(config_path);
    match config_res {
        Ok(config) => {
            checks.push(DiagnosticCheck {
                category: "Configuration".into(),
                title: "Config File".into(),
                status: Status::Ok,
                message: format!(
                    "{} (name: '{}', max neighbors: {})",
                    config_path.display(),
                    config.name,
                    config.max_neighbors
                ),
                recommendation: None,
            });

            // Identity file check
            let key_path = config.identity_path(config_path);
            if !key_path.exists() {
                checks.push(DiagnosticCheck {
                    category: "Identity".into(),
                    title: "Identity Key".into(),
                    status: Status::Error,
                    message: format!("identity file not found at {}", key_path.display()),
                    recommendation: Some("Run 'nnlan init' to generate node identity".into()),
                });
            } else {
                if let Ok(meta) = fs::metadata(&key_path) {
                    let mode = meta.permissions().mode();
                    if mode & 0o077 != 0 {
                        checks.push(DiagnosticCheck {
                            category: "Identity".into(),
                            title: "Key Permissions".into(),
                            status: Status::Warn,
                            message: format!(
                                "file permissions are {:04o} (too open)",
                                mode & 0o777
                            ),
                            recommendation: Some(format!("Run 'chmod 600 {}'", key_path.display())),
                        });
                    }
                }

                match Identity::load(&key_path) {
                    Ok(identity) => {
                        checks.push(DiagnosticCheck {
                            category: "Identity".into(),
                            title: "Node Identity".into(),
                            status: Status::Ok,
                            message: format!("valid key (Node ID: {})", identity.node_id()),
                            recommendation: None,
                        });
                    }
                    Err(e) => {
                        checks.push(DiagnosticCheck {
                            category: "Identity".into(),
                            title: "Node Identity".into(),
                            status: Status::Error,
                            message: format!("invalid identity key: {e:#}"),
                            recommendation: Some("Regenerate key or reinitialize".into()),
                        });
                    }
                }
            }

            // Port check
            match UdpSocket::bind(config.listen) {
                Ok(_) => {
                    checks.push(DiagnosticCheck {
                        category: "Network".into(),
                        title: "Listen Port".into(),
                        status: Status::Ok,
                        message: format!("UDP port {} is free and bindable", config.listen),
                        recommendation: None,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    // Check if daemon is running
                    let sock_path = admin::socket_path(config_path);
                    if sock_path.exists() {
                        checks.push(DiagnosticCheck {
                            category: "Network".into(),
                            title: "Listen Port".into(),
                            status: Status::Ok,
                            message: format!(
                                "UDP port {} is currently in use (likely by active nnlan daemon)",
                                config.listen
                            ),
                            recommendation: None,
                        });
                    } else {
                        checks.push(DiagnosticCheck {
                            category: "Network".into(),
                            title: "Listen Port".into(),
                            status: Status::Warn,
                            message: format!(
                                "UDP port {} is in use by another process",
                                config.listen
                            ),
                            recommendation: Some(
                                "Change 'listen' address in config or stop competing service"
                                    .into(),
                            ),
                        });
                    }
                }
                Err(e) => {
                    checks.push(DiagnosticCheck {
                        category: "Network".into(),
                        title: "Listen Port".into(),
                        status: Status::Warn,
                        message: format!("could not bind {}: {e}", config.listen),
                        recommendation: None,
                    });
                }
            }

            // Peers check
            if config.peers.is_empty() {
                checks.push(DiagnosticCheck {
                    category: "Peers".into(),
                    title: "Bootstrap Peers".into(),
                    status: Status::Info,
                    message: "no bootstrap peers configured".into(),
                    recommendation: Some(
                        "Add a peer with 'nnlan peer add <ENDPOINT> <PUBLIC_KEY>'".into(),
                    ),
                });
            } else {
                checks.push(DiagnosticCheck {
                    category: "Peers".into(),
                    title: "Bootstrap Peers".into(),
                    status: Status::Ok,
                    message: format!("{} bootstrap peer(s) configured", config.peers.len()),
                    recommendation: None,
                });
            }
        }
        Err(e) => {
            if !config_path.exists() {
                checks.push(DiagnosticCheck {
                    category: "Configuration".into(),
                    title: "Config File".into(),
                    status: Status::Info,
                    message: format!("no config found at {}", config_path.display()),
                    recommendation: Some("Run 'nnlan init' to create configuration".into()),
                });
            } else {
                checks.push(DiagnosticCheck {
                    category: "Configuration".into(),
                    title: "Config File".into(),
                    status: Status::Error,
                    message: format!("syntax/policy error: {e:#}"),
                    recommendation: Some("Check configuration syntax or run 'nnlan check'".into()),
                });
            }
        }
    }

    // 5. Daemon Control Socket
    let sock_path = admin::socket_path(config_path);
    if sock_path.exists() {
        match std::os::unix::net::UnixStream::connect(&sock_path) {
            Ok(_) => {
                checks.push(DiagnosticCheck {
                    category: "Daemon".into(),
                    title: "Daemon Status".into(),
                    status: Status::Ok,
                    message: format!(
                        "daemon is running and control socket is active ({})",
                        sock_path.display()
                    ),
                    recommendation: None,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                checks.push(DiagnosticCheck {
                    category: "Daemon".into(),
                    title: "Daemon Status".into(),
                    status: Status::Warn,
                    message: format!(
                        "stale control socket detected at {} (daemon not running)",
                        sock_path.display()
                    ),
                    recommendation: Some(
                        "Start daemon with 'nnlan run' or remove stale socket".into(),
                    ),
                });
            }
            Err(e) => {
                checks.push(DiagnosticCheck {
                    category: "Daemon".into(),
                    title: "Daemon Status".into(),
                    status: Status::Info,
                    message: format!("control socket found ({e})"),
                    recommendation: None,
                });
            }
        }
    } else {
        checks.push(DiagnosticCheck {
            category: "Daemon".into(),
            title: "Daemon Status".into(),
            status: Status::Info,
            message: "daemon is not currently running".into(),
            recommendation: Some("Start with 'sudo nnlan run'".into()),
        });
    }

    // 6. Kernel Firewall / Guard
    if nft_found {
        let nft_out = Command::new("nft")
            .args(["list", "table", "inet", "nnlan"])
            .output();
        if let Ok(out) = nft_out {
            if out.status.success() {
                checks.push(DiagnosticCheck {
                    category: "Firewall & Guards".into(),
                    title: "Kernel Guard".into(),
                    status: Status::Info,
                    message: "active nnlan table found in nftables".into(),
                    recommendation: None,
                });
            } else {
                checks.push(DiagnosticCheck {
                    category: "Firewall & Guards".into(),
                    title: "Kernel Guard".into(),
                    status: Status::Ok,
                    message: "clean (no lingering kernel guard tables)".into(),
                    recommendation: None,
                });
            }
        }
    }

    DoctorReport { checks }
}
