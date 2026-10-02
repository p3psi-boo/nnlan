//! A single atomic nft transaction; no flush of unrelated tables or rules.
use super::*;
impl Policy {
    pub(super) fn script(&self, routes: &RouteConfig) -> String {
        let tun = &self.tun;
        let mut script = format!(
            "delete table inet {NFT_TABLE}\ntable inet {NFT_TABLE} {{\n comment \"{}\";\n",
            self.owner
        );
        // Restore the socket mark before source validation. New incoming overlay
        // handshakes get the same routing mark, but are still authenticated in Noise.
        // Run after dstnat so local UDP port forwards also match the daemon port.
        script.push_str(&format!(" chain underlay_in {{ type filter hook prerouting priority -90; policy accept;\n ct mark {MARK} meta mark set {MARK}\n iifname != \"{tun}\" udp dport {} meta mark set {MARK}\n", self.udp_port));
        if self.dhcp_client_uid.is_some() {
            for (family, proto) in [("-4", "ipv4"), ("-6", "ipv6")] {
                let (client, server) = dhcp::ports(family);
                script.push_str(&format!(" iifname != \"{tun}\" meta nfproto {proto} udp sport {server} udp dport {client} meta mark set {MARK}\n"));
            }
        }
        script.push_str(
            " }\n chain underlay_out { type route hook output priority mangle; policy accept;\n",
        );
        if let Some(uid) = self.dhcp_client_uid {
            for (family, proto) in [("-4", "ipv4"), ("-6", "ipv6")] {
                let (client, server) = dhcp::ports(family);
                script.push_str(&format!(" oifname != \"{tun}\" meta skuid {uid} meta nfproto {proto} udp sport {client} udp dport {server} meta mark set {MARK} counter\n"));
            }
        }
        script.push_str(&format!(" meta mark {MARK} ct mark set {MARK}\n }}\n"));
        script.push_str(&format!(" chain output {{ type filter hook output priority -10; policy accept;\n meta mark {MARK} return\n oifname \"lo\" return\n"));
        if routes.exit_node.is_some() {
            // Necessary IPv6 link maintenance, not an application/DNS exemption.
            script.push_str(" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } ip6 hoplimit 255 return\n");
            script.push_str(&format!(" oifname != \"{tun}\" counter drop\n"));
        }
        self.prefix_guards(routes, &mut script);
        script.push_str(
            " }\n chain overlay_input { type filter hook input priority -10; policy accept;\n",
        );
        for (family, pool) in [("ip", "33.0.0.0/8"), ("ip6", "fd33::/16")] {
            script.push_str(&format!(
                " iifname != \"{tun}\" iifname != \"lo\" {family} daddr {pool} counter drop\n"
            ));
        }
        script.push_str(
            " }\n chain forward { type filter hook forward priority -10; policy accept;\n",
        );
        if routes.exit_node.is_some() {
            script.push_str(&format!(" oifname != \"{tun}\" counter drop\n"));
        }
        self.prefix_guards(routes, &mut script);
        script.push_str(&format!(" iifname \"{tun}\" oifname \"{tun}\" counter drop\n oifname \"{tun}\" ct state established,related accept\n oifname \"{tun}\" counter drop\n"));
        for (family, pool) in [("ip", "33.0.0.0/8"), ("ip6", "fd33::/16")] {
            if routes.serve_exit {
                script.push_str(&format!(
                    " iifname \"{tun}\" {family} saddr {pool} accept\n"
                ));
            }
            for prefix in routes
                .advertise
                .iter()
                .filter(|p| p.addr().is_ipv4() == (family == "ip"))
            {
                script.push_str(&format!(
                    " iifname \"{tun}\" {family} saddr {pool} {family} daddr {prefix} accept\n"
                ));
            }
        }
        script.push_str(&format!(" iifname \"{tun}\" counter drop\n }}\n chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;\n"));
        for (family, pool) in [("ip", "33.0.0.0/8"), ("ip6", "fd33::/16")] {
            if routes.serve_exit {
                script.push_str(&format!(
                    " iifname \"{tun}\" oifname != \"{tun}\" {family} saddr {pool} masquerade\n"
                ));
            }
            for prefix in routes
                .advertise
                .iter()
                .filter(|p| p.addr().is_ipv4() == (family == "ip"))
            {
                script.push_str(&format!(" iifname \"{tun}\" oifname != \"{tun}\" {family} saddr {pool} {family} daddr {prefix} masquerade\n"));
            }
        }
        script.push_str(" }\n");
        if routes.serve_exit {
            let port = crate::runtime::dns::PORT;
            script.push_str(&format!(" chain dns_input {{ type filter hook input priority -10; policy accept;\n iifname != \"{tun}\" udp dport {port} counter drop\n iifname != \"{tun}\" tcp dport {port} counter drop\n }}\n"));
            script.push_str(&format!(" chain dns_redirect {{ type nat hook prerouting priority dstnat; policy accept;\n iifname \"{tun}\" udp dport 53 redirect to :{port}\n iifname \"{tun}\" tcp dport 53 redirect to :{port}\n }}\n"));
        }
        script.push_str("}\n");
        // arp_process() calls ip_route_input_noref(), including strict rp_filter.
        // ARP is not inet traffic: mark requests in its own family so a TUN default
        // does not silently stop physical neighbor refresh. No IP packet exemption.
        script.push_str(&format!("delete table arp {NFT_TABLE}\ntable arp {NFT_TABLE} {{\n comment \"{}\";\n chain underlay {{ type filter hook input priority -10; policy accept;\n arp operation request meta mark set {MARK} counter\n }}\n}}\n", self.owner));
        script
    }
    fn prefix_guards(&self, routes: &RouteConfig, script: &mut String) {
        // Known node routes can expire too. Never leak overlay VIPs to the WAN.
        for (family, prefix) in [("ip", "33.0.0.0/8"), ("ip6", "fd33::/16")] {
            script.push_str(&format!(
                " {family} daddr {prefix} oifname != \"{}\" counter drop\n",
                self.tun
            ));
        }
        for r in &routes.accept {
            let family = if r.prefix.addr().is_ipv4() {
                "ip"
            } else {
                "ip6"
            };
            script.push_str(&format!(
                " {family} daddr {} oifname != \"{}\" counter drop\n",
                r.prefix, self.tun
            ));
        }
    }
}
