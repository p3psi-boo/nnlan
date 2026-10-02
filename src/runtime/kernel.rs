//! Owned Linux subnet and exit policy. The persistent guard outlives TUN and the daemon.
//! One instance per network namespace; other tables and host sysctls are untouched.
use crate::{address::AddressCandidate, config::RouteConfig, identity::NodeId};
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::Write,
    process::{Command, Stdio},
};

mod dhcp;
mod firewall;

pub const MARK: u32 = 0x336733;
const TABLE: &str = "33033";
const PRIORITY: &str = "23333";
const NFT_TABLE: &str = "nnlan";

pub struct Policy {
    owner: String,
    tun: String,
    udp_port: u16,
    prefixes: BTreeSet<IpNet>,
    dhcp_client_uid: Option<u32>,
}

fn output(program: &str, args: &[&str]) -> Result<String> {
    let result = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    ensure!(
        result.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn ip(args: &[&str]) -> Result<()> {
    output("ip", args).map(|_| ())
}
fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("run nftables")?;
    let write = child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(script.as_bytes());
    let result = child.wait_with_output()?;
    write?;
    ensure!(
        result.status.success(),
        "nftables policy: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
fn family(prefix: IpNet) -> &'static str {
    if prefix.addr().is_ipv4() { "-4" } else { "-6" }
}

fn own_table(value: &Value) -> bool {
    value.as_str() == Some(TABLE) || value.as_u64() == Some(33033)
}
fn own_rule(rule: &Value) -> bool {
    own_table(&rule["table"])
        && rule.get("not").is_some_and(|v| v.is_null() || v == true)
        && rule["fwmark"] == format!("0x{MARK:x}")
        && rule.get("fwmask").is_none_or(|v| v == "0xffffffff")
        && rule["src"] == "all"
        && rule.as_object().is_some_and(|fields| {
            fields.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "priority" | "not" | "fwmark" | "fwmask" | "src" | "table" | "protocol"
                )
            })
        })
}

impl Policy {
    pub fn open(
        node: NodeId,
        tun: &str,
        udp_port: u16,
        dhcp_client_uid: Option<u32>,
        create: bool,
    ) -> Result<Self> {
        let owner = format!("nnlan:subnet:v1:{node}:{tun}");
        let tables: Value = serde_json::from_str(&output("nft", &["-j", "list", "tables"])?)?;
        let entries = tables["nftables"].as_array().context("nft table list")?;
        let mut existing = BTreeSet::new();
        for family in ["inet", "arp"] {
            if !entries
                .iter()
                .any(|e| e["table"]["family"] == family && e["table"]["name"] == NFT_TABLE)
            {
                continue;
            }
            let table: Value =
                serde_json::from_str(&output("nft", &["-j", "list", "table", family, NFT_TABLE])?)?;
            ensure!(
                table["nftables"]
                    .as_array()
                    .context("nft table")?
                    .iter()
                    .any(|e| e["table"]["comment"] == owner),
                "nft table nnlan belongs to another instance; use a separate network namespace"
            );
            existing.insert(family);
        }
        let exists = !existing.is_empty();
        ensure!(
            exists || create,
            "no owned kernel policy in this network namespace"
        );
        let mut prefixes = BTreeSet::new();
        for family in ["-4", "-6"] {
            let rules: Value =
                serde_json::from_str(&output("ip", &[family, "-j", "rule", "show"])?)?;
            dhcp::current(&rules, exists, family)?;
            let own: Vec<_> = rules
                .as_array()
                .context("IP rules")?
                .iter()
                .filter(|r| r["priority"] == 23333)
                .collect();
            ensure!(
                own.is_empty() || (exists && own.len() == 1 && own_rule(own[0])),
                "policy rule priority 23333 is occupied"
            );
            // 'table all' also works when the dedicated table has never existed.
            let routes: Value = serde_json::from_str(&output(
                "ip",
                &[family, "-j", "route", "show", "table", "all"],
            )?)?;
            for r in routes
                .as_array()
                .context("IP routes")?
                .iter()
                .filter(|r| own_table(&r["table"]))
            {
                ensure!(exists, "routing table 33033 is already occupied");
                let destination = r["dst"].as_str().context("owned route destination")?;
                let prefix: IpNet = if destination == "default" {
                    if family == "-4" { "0.0.0.0/0" } else { "::/0" }.parse()?
                } else {
                    destination
                        .parse()
                        .or_else(|_| destination.parse::<std::net::IpAddr>().map(IpNet::from))?
                };
                if prefix.prefix_len() != 0 {
                    crate::config::validate_subnet(prefix)?;
                }
                ensure!(
                    (r["type"] == "blackhole" && r["metric"] == 32760)
                        || (r["dev"] == tun && r["metric"] == 1),
                    "unexpected route in owned table"
                );
                prefixes.insert(prefix);
            }
        }
        let mut creation = String::new();
        for family in ["inet", "arp"] {
            if !existing.contains(family) {
                creation.push_str(&format!(
                    "create table {family} {NFT_TABLE} {{ comment \"{owner}\"; }}\n"
                ));
            }
        }
        if !creation.is_empty() {
            nft(&creation)?;
        }
        Ok(Self {
            owner,
            tun: tun.into(),
            udp_port,
            prefixes,
            dhcp_client_uid,
        })
    }
    pub fn preflight(routes: &RouteConfig) -> Result<()> {
        // Like other Linux VPN routers, forwarding is an administrator-owned host
        // setting. Do not silently reset global sysctls (IPv4 ip_forward does so).
        for (v4, path, setting) in [
            (
                true,
                "/proc/sys/net/ipv4/ip_forward",
                "net.ipv4.ip_forward=1",
            ),
            (
                false,
                "/proc/sys/net/ipv6/conf/all/forwarding",
                "net.ipv6.conf.all.forwarding=1",
            ),
        ] {
            if routes.serve_exit || routes.advertise.iter().any(|p| p.addr().is_ipv4() == v4) {
                ensure!(
                    std::fs::read_to_string(path)?.trim() == "1",
                    "Subnet Router / Exit Node requires {setting}"
                );
            }
        }
        if routes.exit_node.is_some() || !routes.accept.is_empty() {
            let conf = std::path::Path::new("/proc/sys/net/ipv4/conf");
            let read = |path: std::path::PathBuf| -> Result<u8> {
                Ok(std::fs::read_to_string(path)?.trim().parse()?)
            };
            let all_filter = read(conf.join("all/rp_filter"))?;
            let all_mark = read(conf.join("all/src_valid_mark"))?;
            if all_mark == 0 && all_filter != 2 {
                for entry in std::fs::read_dir(conf)? {
                    let entry = entry?;
                    if entry.file_name() == "all" || entry.file_name() == "default" {
                        continue;
                    }
                    if all_filter.max(read(entry.path().join("rp_filter"))?) == 1 {
                        ensure!(
                            read(entry.path().join("src_valid_mark"))? == 1,
                            "strict IPv4 reverse-path filtering requires net.ipv4.conf.all.src_valid_mark=1 for marked underlay recovery"
                        );
                    }
                }
            }
        }
        Ok(())
    }
    pub fn protect(&mut self, routes: &RouteConfig) -> Result<()> {
        // Install the persistent output guard BEFORE TUN, DNS, or peer setup.
        nft(&self.script(routes))?;
        // nft is authoritative before adding any main-table routing exception.
        dhcp::reconcile(self.dhcp_client_uid)?;
        let desired = desired_prefixes(routes);
        for prefix in &desired {
            ip(&[
                family(*prefix),
                "route",
                "replace",
                "blackhole",
                &prefix.to_string(),
                "table",
                TABLE,
                "metric",
                "32760",
            ])?;
        }
        for family in ["-4", "-6"] {
            let rules: Value =
                serde_json::from_str(&output("ip", &[family, "-j", "rule", "show"])?)?;
            let current: Vec<_> = rules
                .as_array()
                .context("IP rules")?
                .iter()
                .filter(|r| r["priority"] == 23333)
                .collect();
            if current.is_empty() {
                ip(&[
                    family,
                    "rule",
                    "add",
                    "priority",
                    PRIORITY,
                    "not",
                    "fwmark",
                    &MARK.to_string(),
                    "lookup",
                    TABLE,
                ])?;
            } else {
                ensure!(
                    current.len() == 1 && own_rule(current[0]),
                    "owned policy rule changed externally"
                );
            }
        }
        Ok(())
    }
    pub fn apply(&mut self, routes: &RouteConfig, address: AddressCandidate) -> Result<()> {
        self.protect(routes)?;
        Self::preflight(routes)?;
        let desired = desired_prefixes(routes);
        for prefix in &desired {
            let source = if prefix.addr().is_ipv4() {
                address.ipv4.to_string()
            } else {
                address.ipv6.to_string()
            };
            ip(&[
                family(*prefix),
                "route",
                "replace",
                &prefix.to_string(),
                "table",
                TABLE,
                "dev",
                &self.tun,
                "src",
                &source,
                "metric",
                "1",
            ])?;
        }
        self.finish(desired)
    }
    pub fn offline(&mut self, routes: &RouteConfig) -> Result<()> {
        self.protect(routes)?;
        self.finish(desired_prefixes(routes))
    }
    fn finish(&mut self, desired: BTreeSet<IpNet>) -> Result<()> {
        for prefix in self.prefixes.difference(&desired) {
            ip(&[
                family(*prefix),
                "route",
                "flush",
                "table",
                TABLE,
                "exact",
                &prefix.to_string(),
            ])?;
        }
        self.prefixes = desired;
        Ok(())
    }
}
fn desired_prefixes(routes: &RouteConfig) -> BTreeSet<IpNet> {
    let mut prefixes: BTreeSet<_> = routes.accept.iter().map(|r| r.prefix).collect();
    if routes.exit_node.is_some() {
        prefixes.extend([
            "0.0.0.0/0".parse::<IpNet>().expect("IPv4 default"),
            "::/0".parse::<IpNet>().expect("IPv6 default"),
        ]);
    }
    prefixes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn iproute_json_ownership_is_exact_for_both_encodings() {
        let mut rule =
            json!({"priority":23333,"not":null,"src":"all","fwmark":"0x336733","table":"33033"});
        assert!(own_rule(&rule));
        rule["not"] = json!(true);
        rule["table"] = json!(33033);
        assert!(own_rule(&rule));
        rule["fwmask"] = json!("0xff");
        assert!(!own_rule(&rule));
        rule.as_object_mut().unwrap().remove("fwmask");
        rule["iif"] = json!("eth0");
        assert!(!own_rule(&rule));
        rule.as_object_mut().unwrap().remove("iif");
        rule["not"] = json!(false);
        assert!(!own_rule(&rule));
        rule.as_object_mut().unwrap().remove("not");
        assert!(!own_rule(&rule));
    }
}
