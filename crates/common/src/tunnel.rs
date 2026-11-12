// SPDX-License-Identifier: MIT OR Apache-2.0
//! Customer tunnel script (spec section 11.6, ADR 0012).
//!
//! The script runs on the customer's server (the origin). It creates the
//! tunnel device that decapsulates traffic from the PoPs, puts the protected
//! prefix on the loopback, and routes replies either back through the tunnel
//! to the anycast tunnel endpoint (default; works behind BCP38 filtering) or
//! directly with the protected IP as source (DSR) with a lowered MSS.
//!
//! Every interpolated value is typed (addresses, numbers) or validated
//! (device names), so the output cannot carry shell injection.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::pin::validate_ifname;
use crate::prefix::Prefix;

/// Tunnel MTU on the origin: a 1500-byte path minus the 20-byte outer header.
pub const TUNNEL_MTU: u32 = 1480;
/// Policy-routing rule priority (before the main table at 32766).
pub const RULE_PRIORITY: u32 = 1000;
/// Routing table = TABLE_BASE + asset id.
pub const TABLE_BASE: u32 = 20000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnMode {
    /// Replies go back through the tunnel to the anycast endpoint.
    Tunnel,
    /// Replies leave directly with the protected IP as source.
    Dsr,
}

#[derive(Clone, Debug)]
pub struct TunnelScript<'a> {
    pub asset_id: u32,
    pub prefix: Prefix,
    pub origin: Ipv4Addr,
    /// Required for `ReturnMode::Tunnel`.
    pub tunnel_ep: Option<Ipv4Addr>,
    /// MTU of the PoP uplinks; decides the MSS clients may use (DSR).
    pub pop_mtu: u32,
    pub return_mode: ReturnMode,
    /// Use an existing device (e.g. the kernel's fallback `tunl0` / `sit0`)
    /// instead of creating `sentinel0` / `sentinel6`.
    pub device: Option<&'a str>,
}

impl TunnelScript<'_> {
    /// Largest MSS a client may use so its packets fit the tunnel.
    pub fn client_mss(&self) -> u32 {
        let ip = if self.prefix.is_v4() { 20 } else { 40 };
        self.pop_mtu.saturating_sub(20 + ip + 20)
    }

    pub fn render(&self) -> Result<String, String> {
        let v4 = self.prefix.is_v4();
        let dev = match self.device {
            Some(d) => {
                validate_ifname(d).map_err(|e| e.to_string())?;
                d
            }
            None if v4 => "sentinel0",
            None => "sentinel6",
        };
        if self.return_mode == ReturnMode::Tunnel && self.tunnel_ep.is_none() {
            return Err("tunnel return needs the PoP tunnel endpoint \
                        (sentinelctl config set --tunnel-ep4)"
                .into());
        }
        if self.client_mss() < 536 {
            return Err(format!("PoP MTU {} is too small", self.pop_mtu));
        }
        let (ip, mode) = if v4 { ("ip", "ipip") } else { ("ip -6", "sit") };
        let p = self.prefix;
        let origin = self.origin;
        let table = TABLE_BASE + self.asset_id;
        let prio = RULE_PRIORITY;
        let mut s = String::new();

        let _ = writeln!(s, "#!/bin/sh");
        let _ = writeln!(
            s,
            "# Sentinel-Edge tunnel for protected prefix {p} (asset {})",
            self.asset_id
        );
        let _ = writeln!(s, "#   this server (origin): {origin}");
        let _ = match (self.return_mode, self.tunnel_ep) {
            (ReturnMode::Tunnel, Some(ep)) => {
                writeln!(s, "#   replies: back through the tunnel to {ep} (anycast)")
            }
            _ => writeln!(
                s,
                "#   replies: directly from this server (DSR), MSS {}",
                self.client_mss()
            ),
        };
        let _ = writeln!(
            s,
            "# Usage (as root): sh $0 [up|down]   (default: up). Safe to re-run."
        );
        let _ = writeln!(s, "set -eu");
        let _ = writeln!(s, "DEV={dev}");
        let _ = writeln!(s, "TABLE={table}");
        s.push('\n');

        // ---- up
        let _ = writeln!(s, "up() {{");
        match self.device {
            Some(_) => {
                let _ = writeln!(s, "\t# existing device; decapsulates from any PoP");
                let _ = writeln!(s, "\tip link show \"$DEV\" >/dev/null");
            }
            None => {
                let _ = writeln!(s, "\t# decapsulates traffic from any PoP (no fixed remote)");
                let _ = writeln!(s, "\tip link show \"$DEV\" >/dev/null 2>&1 ||");
                let _ = writeln!(s, "\t\tip tunnel add \"$DEV\" mode {mode} local {origin}");
            }
        }
        let _ = writeln!(s, "\tip link set \"$DEV\" up mtu {TUNNEL_MTU}");
        let _ = writeln!(s, "\t{ip} addr replace {p} dev lo");
        if v4 {
            let _ = writeln!(s, "\tsysctl -qw net.ipv4.conf.all.rp_filter=0");
            let _ = writeln!(s, "\tsysctl -qw \"net.ipv4.conf.$DEV.rp_filter=0\"");
        }
        match (self.return_mode, self.tunnel_ep) {
            (ReturnMode::Tunnel, Some(ep)) => {
                let via = if v4 {
                    ep.to_string()
                } else {
                    format!("::{ep}")
                };
                let _ = writeln!(
                    s,
                    "\t# replies from the protected prefix go back through the tunnel"
                );
                let _ = writeln!(
                    s,
                    "\t{ip} route replace default via {via} dev \"$DEV\" onlink table \"$TABLE\""
                );
            }
            _ => {
                let fam = if v4 { "-4" } else { "-6" };
                let _ = writeln!(
                    s,
                    "\t# replies leave directly; lower the MSS so client packets fit the tunnel"
                );
                let _ = writeln!(
                    s,
                    "\tGW=$(ip {fam} route show default | awk '{{print $3; exit}}')"
                );
                let _ = writeln!(
                    s,
                    "\tOUT=$(ip {fam} route show default | awk '{{print $5; exit}}')"
                );
                let _ = writeln!(
                    s,
                    "\t[ -n \"$GW\" ] || {{ echo \"sentinel: no default route\" >&2; exit 1; }}"
                );
                let _ = writeln!(
                    s,
                    "\t{ip} route replace default via \"$GW\" dev \"$OUT\" advmss {} table \"$TABLE\"",
                    self.client_mss()
                );
            }
        }
        let _ = writeln!(
            s,
            "\t{ip} rule del from {p} table \"$TABLE\" priority {prio} 2>/dev/null || true"
        );
        let _ = writeln!(
            s,
            "\t{ip} rule add from {p} table \"$TABLE\" priority {prio}"
        );
        let _ = writeln!(s, "\techo \"sentinel: tunnel up for {p}\"");
        let _ = writeln!(s, "}}");
        s.push('\n');

        // ---- down
        let _ = writeln!(s, "down() {{");
        let _ = writeln!(
            s,
            "\t{ip} rule del from {p} table \"$TABLE\" priority {prio} 2>/dev/null || true"
        );
        let _ = writeln!(s, "\t{ip} route flush table \"$TABLE\" 2>/dev/null || true");
        let _ = writeln!(s, "\t{ip} addr del {p} dev lo 2>/dev/null || true");
        if self.device.is_none() {
            let _ = writeln!(s, "\tip tunnel del \"$DEV\" 2>/dev/null || true");
        }
        let _ = writeln!(s, "\techo \"sentinel: tunnel down for {p}\"");
        let _ = writeln!(s, "}}");
        s.push('\n');
        let _ = writeln!(s, "case \"${{1:-up}}\" in");
        let _ = writeln!(s, "up) up ;;");
        let _ = writeln!(s, "down) down ;;");
        let _ = writeln!(s, "*) echo \"usage: $0 [up|down]\" >&2; exit 2 ;;");
        let _ = writeln!(s, "esac");
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(prefix: &str, mode: ReturnMode, dev: Option<&'static str>) -> TunnelScript<'static> {
        TunnelScript {
            asset_id: 7,
            prefix: prefix.parse().unwrap(),
            origin: Ipv4Addr::new(192, 0, 2, 10),
            tunnel_ep: Some(Ipv4Addr::new(198, 51, 100, 1)),
            pop_mtu: 1500,
            return_mode: mode,
            device: dev,
        }
    }

    /// The script must at least be valid POSIX shell.
    fn sh_syntax_ok(s: &str) {
        let dir = std::env::temp_dir().join(format!("sentinel-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join(format!("t{}.sh", s.len()));
        std::fs::write(&f, s).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-n")
            .arg(&f)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "sh -n: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn ipv4_tunnel_return() {
        let s = script("198.51.100.10/32", ReturnMode::Tunnel, None)
            .render()
            .unwrap();
        for want in [
            "ip tunnel add \"$DEV\" mode ipip local 192.0.2.10",
            "ip link set \"$DEV\" up mtu 1480",
            "ip addr replace 198.51.100.10/32 dev lo",
            "net.ipv4.conf.$DEV.rp_filter=0",
            "ip route replace default via 198.51.100.1 dev \"$DEV\" onlink table \"$TABLE\"",
            "ip rule add from 198.51.100.10/32 table \"$TABLE\" priority 1000",
            "DEV=sentinel0",
            "TABLE=20007",
            "ip tunnel del \"$DEV\"",
        ] {
            assert!(s.contains(want), "missing {want:?} in\n{s}");
        }
        sh_syntax_ok(&s);
    }

    #[test]
    fn ipv6_dsr() {
        let t = script("2001:db8:100::10/128", ReturnMode::Dsr, None);
        assert_eq!(t.client_mss(), 1420);
        let s = t.render().unwrap();
        for want in [
            "ip tunnel add \"$DEV\" mode sit local 192.0.2.10",
            "ip -6 addr replace 2001:db8:100::10/128 dev lo",
            "ip -6 route show default",
            "advmss 1420",
            "ip -6 rule add from 2001:db8:100::10/128",
            "DEV=sentinel6",
        ] {
            assert!(s.contains(want), "missing {want:?} in\n{s}");
        }
        assert!(!s.contains("rp_filter"), "IPv4 sysctls in an IPv6 script");
        sh_syntax_ok(&s);
    }

    #[test]
    fn ipv6_tunnel_return_uses_v4_compatible_nexthop() {
        let s = script("2001:db8:100::/64", ReturnMode::Tunnel, None)
            .render()
            .unwrap();
        assert!(s.contains("via ::198.51.100.1 dev \"$DEV\" onlink"), "{s}");
        sh_syntax_ok(&s);
    }

    #[test]
    fn existing_device() {
        let s = script("198.51.100.10/32", ReturnMode::Tunnel, Some("tunl0"))
            .render()
            .unwrap();
        assert!(s.contains("DEV=tunl0"));
        assert!(!s.contains("ip tunnel add"));
        assert!(!s.contains("ip tunnel del"));
        sh_syntax_ok(&s);
        assert!(
            script("198.51.100.10/32", ReturnMode::Tunnel, Some("bad;rm -rf /"))
                .render()
                .is_err()
        );
    }

    #[test]
    fn dsr_v4_mss_and_errors() {
        let t = script("198.51.100.10/32", ReturnMode::Dsr, None);
        assert_eq!(t.client_mss(), 1440);
        assert!(t.render().unwrap().contains("advmss 1440"));
        let mut no_ep = script("198.51.100.10/32", ReturnMode::Tunnel, None);
        no_ep.tunnel_ep = None;
        assert!(no_ep.render().unwrap_err().contains("tunnel-ep4"));
        let mut tiny = script("198.51.100.10/32", ReturnMode::Dsr, None);
        tiny.pop_mtu = 500;
        assert!(tiny.render().is_err());
    }
}
