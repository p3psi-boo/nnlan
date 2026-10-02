use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use nnlan::{config::Config, identity::Identity, plan::Plan};
use std::{
    fs,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(version, about = "Decentralized encrypted overlay network")]
struct Cli {
    #[arg(
        short,
        long,
        global = true,
        default_value = "nnlan.toml",
        help = "Path to configuration file [default: nnlan.toml]"
    )]
    config: PathBuf,
    /// Force JSON output for all commands (default when piped or non-interactive)
    #[arg(long, global = true)]
    json: bool,
    /// Force human-readable formatted output for all commands
    #[arg(long, global = true)]
    human: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
}

impl OutputFormat {
    fn from_flags(json_flag: bool, human_flag: bool) -> Self {
        use std::io::IsTerminal;
        if json_flag {
            Self::Json
        } else if human_flag
            || std::env::var("NNLAN_FORMAT").as_deref() == Ok("human")
            || std::io::stdout().is_terminal()
        {
            Self::Human
        } else {
            Self::Json
        }
    }

    fn use_color(&self) -> bool {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err()
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create a configuration and persistent identity; never overwrite existing files.
    Init,
    /// Validate configuration syntax and policy (does not require an identity file).
    Check,
    /// Print the node's public key only. Never prints private material.
    Identity,
    /// Print the desired configuration as JSON without applying network changes.
    Plan,
    /// Install persistent kernel guards without starting TUN, DNS or the daemon.
    Guard,
    /// Run system diagnostics and health checks on environment, TUN and configuration.
    Doctor,
    /// Start the Linux daemon; --dry-run only prints the plan.
    Run {
        #[arg(long)]
        dry_run: bool,
        /// Run the real overlay without creating TUN or modifying kernel routes.
        #[arg(long)]
        no_tun: bool,
    },
    Exit {
        #[command(subcommand)]
        action: ExitCommand,
    },
    Status,
    /// Inspect connected/known peers or manage bootstrap peers in configuration.
    #[command(alias = "peer")]
    Peers {
        #[command(subcommand)]
        action: Option<PeerSubcommand>,
    },
    /// Inspect membership or change persistent local denial by full public key or name.
    Members {
        #[command(subcommand)]
        action: Option<MemberCommand>,
    },
    Routes {
        #[command(subcommand)]
        action: Option<RouteCommand>,
    },
    Trace {
        target: String,
    },
    Ping {
        target: String,
        #[arg(long, default_value_t = 32)]
        size: usize,
    },
    Shutdown,
}

#[derive(Subcommand)]
enum PeerSubcommand {
    /// Add a bootstrap peer to the configuration file
    Add {
        endpoint: String,
        public_key: String,
    },
    /// Remove a bootstrap peer from the configuration file
    Remove { target: String },
    /// List configured bootstrap peers in configuration file
    List,
}

#[derive(Subcommand)]
enum ExitCommand {
    Use {
        target: String,
    },
    Off {
        #[arg(long)]
        offline: bool,
    },
    Serve {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

#[derive(Subcommand)]
enum MemberCommand {
    Deny { node: String },
    Allow { node: String },
}

#[derive(Clone, Subcommand)]
enum RouteCommand {
    Advertise {
        prefix: ipnet::IpNet,
    },
    Withdraw {
        prefix: ipnet::IpNet,
    },
    Accept {
        prefix: ipnet::IpNet,
        #[arg(long)]
        via: String,
        #[arg(long)]
        replace: bool,
    },
    Reject {
        prefix: ipnet::IpNet,
    },
}

impl From<RouteCommand> for nnlan::runtime::admin::RouteAction {
    fn from(command: RouteCommand) -> Self {
        match command {
            RouteCommand::Advertise { prefix } => Self::Advertise { prefix },
            RouteCommand::Withdraw { prefix } => Self::Withdraw { prefix },
            RouteCommand::Accept {
                prefix,
                via,
                replace,
            } => Self::Accept {
                prefix,
                via,
                replace,
            },
            RouteCommand::Reject { prefix } => Self::Reject { prefix },
        }
    }
}

fn resolve_config_path(path: &Path) -> PathBuf {
    if path != Path::new("nnlan.toml") || path.exists() {
        return path.to_path_buf();
    }
    if let Ok(env_path) = std::env::var("NNLAN_CONFIG")
        && !env_path.is_empty()
    {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return p;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let user_config = PathBuf::from(home).join(".config/nnlan/nnlan.toml");
        if user_config.exists() {
            return user_config;
        }
    }
    let sys_config = PathBuf::from("/etc/nnlan/nnlan.toml");
    if sys_config.exists() {
        return sys_config;
    }
    path.to_path_buf()
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<()> {
    use nnlan::runtime::admin::Request;
    let format = OutputFormat::from_flags(cli.json, cli.human);
    let config_path = resolve_config_path(&cli.config);

    fn runtime() -> Result<tokio::runtime::Runtime> {
        Ok(tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?)
    }

    match cli.command {
        Command::Init => initialize(&config_path, format),
        Command::Check => {
            Config::load(&config_path)?;
            println!("configuration valid (syntax and policy only; no network changes)");
            Ok(())
        }
        Command::Identity => {
            let config = Config::load(&config_path)?;
            println!(
                "{}",
                Identity::load(&config.identity_path(&config_path))?.node_id()
            );
            Ok(())
        }
        Command::Doctor => {
            let report = nnlan::doctor::check(&config_path);
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&report.checks)?);
            } else {
                print!("{}", report.format_human(format.use_color()));
            }
            if !report.is_healthy() {
                bail!("doctor detected one or more critical issues");
            }
            Ok(())
        }
        Command::Plan | Command::Run { dry_run: true, .. } => {
            let config = Config::load(&config_path)?;
            let identity = Identity::load(&config.identity_path(&config_path))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&Plan::build(&config, &identity)?)?
            );
            Ok(())
        }
        Command::Run {
            dry_run: false,
            no_tun,
        } => runtime()?.block_on(nnlan::runtime::run(&config_path, no_tun)),
        Command::Guard => {
            let result = nnlan::runtime::guard(&config_path)?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", nnlan::ui::format_guard(&result, format.use_color()));
            }
            Ok(())
        }
        Command::Exit {
            action: ExitCommand::Off { offline: true },
        } => {
            let response = nnlan::runtime::exit_offline(&config_path)?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!("{}", nnlan::ui::format_exit(&response, format.use_color()));
            }
            Ok(())
        }
        Command::Exit {
            action: ExitCommand::Off { offline: false },
        } => {
            let req = Request::Exit {
                action: nnlan::runtime::admin::ExitAction::Off,
            };
            match runtime()?.block_on(nnlan::runtime::admin::request(&config_path, req)) {
                Ok(response) => {
                    if format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&response)?);
                    } else {
                        println!("{}", nnlan::ui::format_exit(&response, format.use_color()));
                    }
                    Ok(())
                }
                Err(e) => {
                    let sock = nnlan::runtime::admin::socket_path(&config_path);
                    if !sock.exists() {
                        eprintln!(
                            "note: daemon is not running; falling back to offline kernel exit cleanup..."
                        );
                        let response = nnlan::runtime::exit_offline(&config_path)?;
                        if format == OutputFormat::Json {
                            println!("{}", serde_json::to_string_pretty(&response)?);
                        } else {
                            println!("{}", nnlan::ui::format_exit(&response, format.use_color()));
                        }
                        Ok(())
                    } else {
                        Err(e)
                    }
                }
            }
        }
        Command::Peers {
            action: Some(peer_action),
        } => match peer_action {
            PeerSubcommand::Add {
                endpoint,
                public_key,
            } => {
                let mut config = Config::load(&config_path)?;
                let key: nnlan::identity::NodeId = public_key
                    .parse()
                    .context("invalid public key (must be 64-character hex)")?;
                if config.peers.iter().any(|p| p.public_key == key) {
                    bail!("peer with public key {key} is already configured");
                }
                config.peers.push(nnlan::config::PeerConfig {
                    endpoint: endpoint.clone(),
                    public_key: key,
                });
                config.save(&config_path)?;
                println!("added peer {endpoint} ({key}) to {}", config_path.display());
                println!("note: restart nnlan daemon to connect to the new peer");
                Ok(())
            }
            PeerSubcommand::Remove { target } => {
                let mut config = Config::load(&config_path)?;
                let before = config.peers.len();
                config.peers.retain(|p| {
                    let id_str = p.public_key.to_string();
                    id_str != target && !id_str.starts_with(&target) && p.endpoint != target
                });
                if config.peers.len() == before {
                    bail!(
                        "no configured peer matching '{target}' was found in {}",
                        config_path.display()
                    );
                }
                config.save(&config_path)?;
                println!("removed matching peer from {}", config_path.display());
                println!("note: restart nnlan daemon to apply configuration changes");
                Ok(())
            }
            PeerSubcommand::List => {
                let config = Config::load(&config_path)?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&config.peers)?);
                } else {
                    let s = nnlan::ui::Style::new(format.use_color());
                    println!(
                        "{} in {} ({} total):",
                        s.bold("Configured Bootstrap Peers"),
                        config_path.display(),
                        config.peers.len()
                    );
                    if config.peers.is_empty() {
                        println!(
                            "  (none configured; use 'nnlan peer add <ENDPOINT> <PUBLIC_KEY>')"
                        );
                    } else {
                        println!("  {:<26} {:<66}", "ENDPOINT", "PUBLIC KEY");
                        println!("  {}", "-".repeat(92));
                        for p in &config.peers {
                            println!("  {:<26} {:<66}", p.endpoint, p.public_key);
                        }
                    }
                }
                Ok(())
            }
        },
        command => {
            let request = match &command {
                Command::Exit { action } => Request::Exit {
                    action: match action {
                        ExitCommand::Use { target } => nnlan::runtime::admin::ExitAction::Use {
                            target: target.clone(),
                        },
                        ExitCommand::Serve { state } => nnlan::runtime::admin::ExitAction::Serve {
                            enabled: state == "on",
                        },
                        ExitCommand::Off { .. } => {
                            unreachable!("offline and off cases handled above")
                        }
                    },
                },
                Command::Status => Request::Status,
                Command::Peers { action: None } => Request::Peers,
                Command::Members { action: None } => Request::Members,
                Command::Members {
                    action: Some(action),
                } => {
                    let (node_str, is_deny) = match action {
                        MemberCommand::Deny { node } => (node.as_str(), true),
                        MemberCommand::Allow { node } => (node.as_str(), false),
                    };
                    let resolved_node = resolve_member_node(&config_path, node_str)?;
                    Request::Member {
                        action: if is_deny {
                            nnlan::runtime::admin::MemberAction::Deny {
                                node: resolved_node,
                            }
                        } else {
                            nnlan::runtime::admin::MemberAction::Allow {
                                node: resolved_node,
                            }
                        },
                    }
                }
                Command::Routes { action: None } => Request::Routes,
                Command::Routes {
                    action: Some(action),
                } => Request::Route {
                    action: action.clone().into(),
                },
                Command::Trace { target } => Request::Trace {
                    target: target.clone(),
                },
                Command::Ping { target, size } => Request::Ping {
                    target: target.clone(),
                    size: *size,
                },
                Command::Shutdown => Request::Shutdown,
                _ => unreachable!("offline and local commands handled above"),
            };
            let response =
                runtime()?.block_on(nnlan::runtime::admin::request(&config_path, request))?;

            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                let use_color = format.use_color();
                match command {
                    Command::Status => {
                        println!("{}", nnlan::ui::format_status(&response, use_color))
                    }
                    Command::Peers { .. } => {
                        println!("{}", nnlan::ui::format_peers(&response, use_color))
                    }
                    Command::Routes { .. } => {
                        println!("{}", nnlan::ui::format_routes(&response, use_color))
                    }
                    Command::Members { .. } => {
                        println!("{}", nnlan::ui::format_members(&response, use_color))
                    }
                    Command::Ping { target, .. } => {
                        println!("{}", nnlan::ui::format_ping(&response, &target, use_color))
                    }
                    Command::Trace { target } => {
                        println!("{}", nnlan::ui::format_trace(&response, &target, use_color))
                    }
                    Command::Exit { .. } => {
                        println!("{}", nnlan::ui::format_exit(&response, use_color))
                    }
                    Command::Shutdown => println!("daemon shutting down..."),
                    _ => println!("{}", serde_json::to_string_pretty(&response)?),
                }
            }
            Ok(())
        }
    }
}

fn resolve_member_node(config_path: &Path, node_str: &str) -> Result<nnlan::identity::NodeId> {
    if let Ok(id) = node_str.parse::<nnlan::identity::NodeId>() {
        return Ok(id);
    }
    // Try resolving via daemon peers list if available
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let peers_res = rt.block_on(nnlan::runtime::admin::request(
        config_path,
        nnlan::runtime::admin::Request::Peers,
    ));
    if let Ok(response) = peers_res
        && let Some(records) = response.as_array()
    {
        let lower = node_str.to_ascii_lowercase();
        let mut matches = Vec::new();
        for item in records {
            let desc = &item["record"]["descriptor"];
            let full_id = desc["node"].as_str().unwrap_or("");
            let name = desc["name"].as_str().unwrap_or("");
            let ipv4 = item["address"]["ipv4"].as_str().unwrap_or("");
            let matched = full_id.to_ascii_lowercase().starts_with(&lower)
                || name == node_str
                || ipv4 == node_str;
            if matched
                && let Ok(id) = full_id.parse::<nnlan::identity::NodeId>()
                && !matches.contains(&id)
            {
                matches.push(id);
            }
        }
        match matches.as_slice() {
            [id] => return Ok(*id),
            [] => (),
            _ => bail!("ambiguous member target '{node_str}'; matches multiple nodes"),
        }
    }
    bail!(
        "could not resolve node target '{node_str}' (use 64-character public key, name, or short id)"
    )
}

fn initialize(path: &Path, format: OutputFormat) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("configuration already exists: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let config = Config::default();
    let key_path = config.identity_path(path);
    ensure!(
        path != key_path,
        "configuration and identity file must differ"
    );
    let identity = match fs::symlink_metadata(&key_path) {
        Ok(_) => {
            Identity::load(&key_path).context("existing identity is preserved and must be valid")?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let identity = Identity::generate()?;
            identity.save_new(&key_path)?;
            identity
        }
        Err(error) => return Err(error.into()),
    };
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let mut toml_str = toml::to_string_pretty(&config)?;
    toml_str.push_str(
        "\n# Bootstrap peers (add peers with `nnlan peer add` or uncomment below):\n# [[peers]]\n# endpoint = \"203.0.113.1:7331\"\n# public_key = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
    );
    file.write_all(toml_str.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;

    if format == OutputFormat::Json {
        let res = serde_json::json!({
            "created": path.display().to_string(),
            "identity_file": key_path.display().to_string(),
            "public_key": identity.node_id().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        println!(
            "created {}\npublic_key = {}",
            path.display(),
            identity.node_id()
        );
        let s = nnlan::ui::Style::new(format.use_color());
        println!("\n{}", s.bold("Quick Start:"));
        println!("  1. View node diagnostics:   {}", s.cyan("nnlan doctor"));
        println!(
            "  2. Add a bootstrap peer:    {}",
            s.cyan("nnlan peer add <HOST:PORT> <PEER_PUBLIC_KEY>")
        );
        println!("  3. Start overlay node:      {}", s.cyan("sudo nnlan run"));
    }
    Ok(())
}
