//! Narrow OS-client exceptions: UID AND protocol AND exact ports, never all UDP.
use super::*;
const PRIORITY: &str = "23332";

pub(super) fn ports(family: &str) -> (u16, u16) {
    if family == "-4" { (68, 67) } else { (546, 547) }
}

fn owned(rule: &Value, family: &str) -> Option<u32> {
    let uid = u32::try_from(rule["uid_start"].as_u64()?).ok()?;
    let (source, destination) = ports(family);
    let valid = uid != u32::MAX
        && rule["uid_end"] == uid
        && rule["src"] == "all"
        && (rule["table"] == "main" || rule["table"] == 254)
        && rule["ipproto"] == "udp"
        && rule["sport"] == source
        && rule["dport"] == destination
        && ["sport_mask", "dport_mask"]
            .iter()
            .all(|k| rule.get(*k).is_none_or(|v| v == "0xffff"))
        && rule.as_object()?.keys().all(|k| {
            matches!(
                k.as_str(),
                "priority"
                    | "src"
                    | "table"
                    | "uid_start"
                    | "uid_end"
                    | "ipproto"
                    | "sport"
                    | "dport"
                    | "sport_mask"
                    | "dport_mask"
                    | "protocol"
            )
        });
    valid.then_some(uid)
}

pub(super) fn current(rules: &Value, exists: bool, family: &str) -> Result<Option<u32>> {
    let rules: Vec<_> = rules
        .as_array()
        .context("IP rules")?
        .iter()
        .filter(|r| r["priority"] == 23332)
        .collect();
    if rules.is_empty() {
        return Ok(None);
    }
    ensure!(
        exists && rules.len() == 1,
        "DHCP policy priority 23332 is occupied"
    );
    Ok(Some(
        owned(rules[0], family).context("unexpected DHCP policy rule")?,
    ))
}

pub(super) fn reconcile(desired: Option<u32>) -> Result<()> {
    for family in ["-4", "-6"] {
        let rules: Value = serde_json::from_str(&output("ip", &[family, "-j", "rule", "show"])?)?;
        let old = current(&rules, true, family)?;
        if old == desired {
            continue;
        }
        let (source, destination) = ports(family);
        for (action, uid) in [("del", old), ("add", desired)] {
            if let Some(uid) = uid {
                ip(&[
                    family,
                    "rule",
                    action,
                    "priority",
                    PRIORITY,
                    "uidrange",
                    &format!("{uid}-{uid}"),
                    "ipproto",
                    "udp",
                    "sport",
                    &source.to_string(),
                    "dport",
                    &destination.to_string(),
                    "lookup",
                    "main",
                ])?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn dhcp_rule_ownership_requires_exact_uid_family_ports_and_selectors() {
        for (family, source, destination) in [("-4", 68, 67), ("-6", 546, 547)] {
            let rule = json!({"priority":23332,"src":"all","uid_start":123,"uid_end":123,
                "ipproto":"udp","sport":source,"dport":destination,
                "sport_mask":"0xffff","dport_mask":"0xffff","table":"main"});
            assert_eq!(current(&json!([rule]), true, family).unwrap(), Some(123));
            assert!(current(&json!([rule]), false, family).is_err());
            assert!(current(&json!([rule, rule]), true, family).is_err());
            for (field, value) in [
                ("uid_end", json!(124)),
                ("ipproto", json!("tcp")),
                ("sport", json!(0)),
                ("sport_mask", json!("0xff")),
                ("table", json!(33033)),
                ("iif", json!("eth0")),
                ("dst", json!("192.0.2.0/24")),
            ] {
                let mut changed = rule.clone();
                changed[field] = value;
                assert!(owned(&changed, family).is_none(), "{field}");
            }
        }
    }
}
