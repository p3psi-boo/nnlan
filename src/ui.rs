//! Human-readable terminal UI formatting for CLI output.
use serde_json::Value;

pub struct Style {
    pub enabled: bool,
}

impl Style {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
    pub fn bold(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn green(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[32m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn red(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[31m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn yellow(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[33m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn cyan(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[36m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn dim(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[2m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

pub fn format_status(val: &Value, use_color: bool) -> String {
    let s = Style::new(use_color);
    let mut out = String::new();
    let running = val["network_running"].as_bool().unwrap_or(false);
    if running {
        out.push_str(&format!(
            "{} {}\n",
            s.green("●"),
            s.bold("nnlan daemon is running")
        ));
    } else {
        out.push_str(&format!(
            "{} {}\n",
            s.red("○"),
            s.bold("nnlan daemon is stopped")
        ));
    }

    let node = val["node"].as_str().unwrap_or("-");
    let name = val["name"].as_str().unwrap_or("-");
    out.push_str(&format!(
        "  {:<14} {} ({})\n",
        "Node ID:",
        s.cyan(node),
        s.dim(&format!("name: {name}"))
    ));

    let ipv4 = val["address"]["ipv4"].as_str().unwrap_or("-");
    let ipv6 = val["address"]["ipv6"].as_str().unwrap_or("-");
    let claimed = if val["addresses_claimed"].as_bool().unwrap_or(false) {
        "claimed"
    } else {
        "pending"
    };
    out.push_str(&format!(
        "  {:<14} IPv4: {} ({})  IPv6: {}\n",
        "Overlay IP:",
        s.bold(ipv4),
        claimed,
        s.bold(ipv6)
    ));

    let wire = val["wire_protocol"].as_str().unwrap_or("GGB3");
    let enc = val["encryption"].as_str().unwrap_or("hop-by-hop");
    out.push_str(&format!(
        "  {:<14} {} ({} noise encrypted)\n",
        "Protocol:", wire, enc
    ));

    let tun_enabled = val["tun_enabled"].as_bool().unwrap_or(false);
    let routes_ready = val["kernel_routes_ready"].as_bool().unwrap_or(false);
    out.push_str(&format!(
        "  {:<14} enabled: {}, routes ready: {}\n",
        "TUN Device:", tun_enabled, routes_ready
    ));

    let neighbors = val["neighbors"].as_array();
    let neighbor_count = neighbors.map_or(0, |n| n.len());
    let nodes_count = val["nodes"].as_u64().unwrap_or(0);
    out.push_str(&format!(
        "  {:<14} {} active direct neighbor(s) / {} known network nodes\n",
        "Topology:",
        s.bold(&neighbor_count.to_string()),
        s.bold(&nodes_count.to_string())
    ));

    let relay = if val["relay"].as_bool().unwrap_or(false) {
        "enabled"
    } else {
        "disabled"
    };
    out.push_str(&format!("  {:<14} {}\n", "Relay:", relay));

    let exit_node = val["exit_node"].as_str();
    let exit_str = match exit_node {
        Some(target) => format!("using {target}"),
        None => "disabled".to_string(),
    };
    out.push_str(&format!("  {:<14} {}\n", "Exit Node:", exit_str));

    let ip_sent = val["ip_sent"].as_u64().unwrap_or(0);
    let ip_received = val["ip_received"].as_u64().unwrap_or(0);
    let forwarded = val["forwarded"].as_u64().unwrap_or(0);
    let dropped = val["dropped"].as_u64().unwrap_or(0);
    out.push_str(&format!(
        "  {:<14} sent {} pkts, recv {} pkts (forwarded: {}, dropped: {})\n",
        "Traffic:", ip_sent, ip_received, forwarded, dropped
    ));

    let fec = val["repair"]["fec"].as_bool().unwrap_or(false);
    let rtx = val["repair"]["rtx"].as_bool().unwrap_or(false);
    out.push_str(&format!(
        "  {:<14} FEC: {}, RTX: {}\n",
        "Link Repair:",
        if fec { "on" } else { "off" },
        if rtx { "on" } else { "off" }
    ));

    if let Some(neighbors) = neighbors
        && !neighbors.is_empty()
    {
        out.push_str(&format!("\n{}\n", s.bold("Direct Neighbors:")));
        out.push_str(&format!(
            "  {:<12} {:<24} {:<10} {:<8} {:<10} {:<6}\n",
            "NODE ID", "ENDPOINT", "RTT", "LOSS", "RATE", "PMTU"
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        for n in neighbors {
            let node_id = n["node"].as_str().unwrap_or("-");
            let short_id = if node_id.len() >= 8 {
                format!("{}..", &node_id[..8])
            } else {
                node_id.to_string()
            };
            let ep = n["endpoint"].as_str().unwrap_or("-");
            let rtt_val = n["link"]["rtt_ms"].as_f64();
            let rtt = rtt_val.map_or("-".to_string(), |r| format!("{:.1} ms", r));
            let loss_val = n["link"]["loss_rate"].as_f64();
            let loss = loss_val.map_or("-".to_string(), |l| format!("{:.1}%", l * 100.0));
            let rate_bps = n["link"]["rate_bps"].as_u64().unwrap_or(0);
            let rate = if rate_bps >= 1_000_000 {
                format!("{} Mbps", rate_bps / 1_000_000)
            } else {
                format!("{} Kbps", rate_bps / 1_000)
            };
            let pmtu = n["pmtu"]["mtu"]
                .as_u64()
                .map_or("-".to_string(), |m| m.to_string());
            out.push_str(&format!(
                "  {:<12} {:<24} {:<10} {:<8} {:<10} {:<6}\n",
                short_id, ep, rtt, loss, rate, pmtu
            ));
        }
    }
    out
}

pub fn format_peers(val: &Value, use_color: bool) -> String {
    let s = Style::new(use_color);
    let mut out = String::new();
    let records = val.as_array();
    let count = records.map_or(0, |r| r.len());
    out.push_str(&format!(
        "{} ({} total):\n",
        s.bold("Known Nodes & Peers"),
        count
    ));
    out.push_str(&format!(
        "  {:<12} {:<16} {:<16} {:<24} {:<10} {:<8}\n",
        "NODE ID", "NAME", "OVERLAY IP", "ENDPOINT / PATH", "TYPE", "STATUS"
    ));
    out.push_str(&format!("  {}\n", "-".repeat(90)));
    if let Some(records) = records {
        for item in records {
            let desc = &item["record"]["descriptor"];
            let node_id = desc["node"].as_str().unwrap_or("-");
            let short_id = if node_id.len() >= 8 {
                format!("{}..", &node_id[..8])
            } else {
                node_id.to_string()
            };
            let name = desc["name"].as_str().unwrap_or("-");
            let ipv4 = item["address"]["ipv4"].as_str().unwrap_or("-");
            let direct = item["direct"].as_bool().unwrap_or(false);
            let trusted = item["trusted"].as_bool().unwrap_or(false);
            let conn_type = if direct { "direct" } else { "relay" };
            let status = if trusted {
                s.green("trusted")
            } else {
                s.red("untrusted")
            };
            let endpoint_str = if direct {
                let endpoints = desc["endpoints"].as_array();
                endpoints
                    .and_then(|eps| eps.first())
                    .and_then(|e| e.as_str())
                    .unwrap_or("-")
                    .to_string()
            } else if let Some(path) = item["path"].as_array() {
                if path.len() > 2 {
                    let next = path[1].as_str().unwrap_or("");
                    if next.len() >= 8 {
                        format!("via {}..", &next[..8])
                    } else {
                        "multi-hop".to_string()
                    }
                } else {
                    "-".to_string()
                }
            } else {
                "-".to_string()
            };
            out.push_str(&format!(
                "  {:<12} {:<16} {:<16} {:<24} {:<10} {}\n",
                short_id, name, ipv4, endpoint_str, conn_type, status
            ));
        }
    }
    out
}

pub fn format_routes(val: &Value, use_color: bool) -> String {
    let s = Style::new(use_color);
    let mut out = String::new();
    out.push_str(&format!("{}\n", s.bold("Overlay Routes & Subnets:")));

    out.push_str(&format!("\n  {}\n", s.bold("Accepted Subnets:")));
    if let Some(selected) = val["selected"].as_array() {
        if selected.is_empty() {
            out.push_str("    (none)\n");
        } else {
            for route in selected {
                let prefix = route["prefix"].as_str().unwrap_or("-");
                let via = route["via"].as_str().unwrap_or("-");
                let short_via = if via.len() >= 8 {
                    format!("{}..", &via[..8])
                } else {
                    via.to_string()
                };
                let state = route["state"].as_str().unwrap_or("unknown");
                let state_str = if state == "forward" {
                    s.green(state)
                } else {
                    s.red(state)
                };
                out.push_str(&format!(
                    "    {:<20} via {:<12} [state: {}]\n",
                    prefix, short_via, state_str
                ));
            }
        }
    }

    out.push_str(&format!("\n  {}\n", s.bold("Advertised Subnets by Peers:")));
    if let Some(adv) = val["advertised"].as_array() {
        let mut count = 0;
        for item in adv {
            let via = item["via"].as_str().unwrap_or("-");
            let short_via = if via.len() >= 8 {
                format!("{}..", &via[..8])
            } else {
                via.to_string()
            };
            if let Some(prefixes) = item["prefixes"].as_array() {
                for p in prefixes {
                    count += 1;
                    out.push_str(&format!(
                        "    {:<20} published by {}\n",
                        p.as_str().unwrap_or("-"),
                        short_via
                    ));
                }
            }
        }
        if count == 0 {
            out.push_str("    (none)\n");
        }
    }

    out.push_str(&format!("\n  {}\n", s.bold("Exit Node:")));
    let exit_node = val["exit_node"].as_str().unwrap_or("none");
    let exit_state = val["exit_state"].as_str().unwrap_or("disabled");
    let state_styled = match exit_state {
        "active" => s.green(exit_state),
        "disabled" => s.dim(exit_state),
        _ => s.red(exit_state),
    };
    out.push_str(&format!(
        "    Selected:     {} [state: {}]\n",
        exit_node, state_styled
    ));
    let serve = if val["serve_exit"].as_bool().unwrap_or(false) {
        "yes"
    } else {
        "no"
    };
    out.push_str(&format!("    Serving exit: {}\n", serve));
    let kernel_guard = if val["kernel_subnet_policy_installed"]
        .as_bool()
        .unwrap_or(false)
    {
        "installed"
    } else {
        "not installed"
    };
    out.push_str(&format!("    Kernel guard: {}\n", kernel_guard));
    out
}

pub fn format_members(val: &Value, use_color: bool) -> String {
    let s = Style::new(use_color);
    let mut out = String::new();
    out.push_str(&format!("{}\n", s.bold("Overlay Membership:")));

    out.push_str(&format!("\n  {}\n", s.bold("Trusted Members:")));
    if let Some(trusted) = val["trusted"].as_array() {
        if trusted.is_empty() {
            out.push_str("    (none)\n");
        } else {
            for m in trusted {
                out.push_str(&format!(
                    "    {} {}\n",
                    s.green("•"),
                    m.as_str().unwrap_or("-")
                ));
            }
        }
    }

    out.push_str(&format!(
        "\n  {}\n",
        s.bold("Denied Members (Local Blocklist):")
    ));
    if let Some(denied) = val["denied"].as_array() {
        if denied.is_empty() {
            out.push_str("    (none)\n");
        } else {
            for m in denied {
                out.push_str(&format!(
                    "    {} {}\n",
                    s.red("•"),
                    m.as_str().unwrap_or("-")
                ));
            }
        }
    }
    out
}

pub fn format_ping(val: &Value, target: &str, use_color: bool) -> String {
    let s = Style::new(use_color);
    if let Some(err) = val.get("error").and_then(Value::as_str) {
        format!("{}: {}", s.red("Ping failed"), err)
    } else {
        let bytes = val["bytes"].as_u64().unwrap_or(32);
        let rtt = val["rtt_ms"].as_f64().unwrap_or(0.0);
        let target_id = val["target"].as_str().unwrap_or(target);
        format!(
            "Reply from {}: bytes={} rtt={:.2} ms {}",
            s.cyan(target_id),
            bytes,
            rtt,
            s.dim("[hop-encrypted]")
        )
    }
}

pub fn format_trace(val: &Value, target: &str, use_color: bool) -> String {
    let s = Style::new(use_color);
    let mut out = String::new();
    let complete = val["complete"].as_bool().unwrap_or(false);
    out.push_str(&format!("Trace route to {}:\n", s.bold(target)));
    if let Some(hops) = val["hops"].as_array() {
        for h in hops {
            let ttl = h["ttl"].as_u64().unwrap_or(0);
            if h["timeout"].as_bool().unwrap_or(false) {
                out.push_str(&format!(
                    "  {:>2}  *  *  *  {}\n",
                    ttl,
                    s.dim("Request timed out")
                ));
            } else {
                let node = h["node"].as_str().unwrap_or("-");
                let short_node = if node.len() >= 8 {
                    format!("{}..", &node[..8])
                } else {
                    node.to_string()
                };
                let rtt = h["rtt_ms"]
                    .as_f64()
                    .map_or("-".to_string(), |r| format!("{:.2} ms", r));
                out.push_str(&format!("  {:>2}  {:<12}  {:<10}\n", ttl, short_node, rtt));
            }
        }
    }
    if complete {
        out.push_str(&s.green("Destination reached."));
        out.push('\n');
    } else {
        out.push_str(&s.yellow("Trace incomplete or timed out."));
        out.push('\n');
    }
    out
}

pub fn format_exit(val: &Value, use_color: bool) -> String {
    let s = Style::new(use_color);
    if let Some(err) = val.get("error").and_then(Value::as_str) {
        format!("{}: {}", s.red("Exit command error"), err)
    } else {
        s.green("Exit configuration updated successfully.")
    }
}

pub fn format_guard(val: &Value, use_color: bool) -> String {
    let s = Style::new(use_color);
    if let Some(err) = val.get("error").and_then(Value::as_str) {
        format!("{}: {}", s.red("Guard installation failed"), err)
    } else {
        s.green("Kernel exit guards installed successfully (nftables: table nnlan).")
    }
}
