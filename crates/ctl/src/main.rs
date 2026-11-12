// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sentinelctl`: operator CLI for a Sentinel-Edge PoP.
//!
//! Argument parsing and validation live here (and are tested on every OS);
//! map access lives in the Linux-only `linux` module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use sentinel_common::abi::{
    Reason, XsPolicy, XsSvcKey, XS_P_ALLOW_FRAG, XS_P_MITIGATE, XS_P_SERVICES, XS_P_SYNCOOKIE,
};
use sentinel_common::pin::{PinLayout, DEFAULT_PIN_DIR, ENV_PIN_DIR};
use sentinel_common::prefix::Prefix;
use sentinel_common::tunnel::ReturnMode;
use sentinel_common::units::{parse_duration, parse_proto, proto_has_ports, proto_name};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Parser, Debug)]
#[command(name = "sentinelctl", version, about = "Sentinel-Edge operator CLI")]
pub struct Cli {
    /// bpffs directory holding the pinned maps and links.
    #[arg(long, global = true, env = ENV_PIN_DIR, default_value = DEFAULT_PIN_DIR)]
    pub pin_dir: PathBuf,

    /// Machine-readable JSON output (stats, show and list commands).
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Driver (native) XDP. Required for production.
    Native,
    /// Generic (skb) XDP. Slow; only with --allow-generic.
    Generic,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

impl OnOff {
    pub fn on(self) -> bool {
        self == OnOff::On
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum AllowDrop {
    Allow,
    Drop,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Load the XDP program and attach it to an interface.
    Attach(AttachArgs),
    /// Detach the XDP program from an interface.
    Detach {
        #[arg(long, env = "XS_IFACE")]
        iface: String,
    },
    /// Show per-(tenant, verdict) packet and byte counters.
    Stats {
        /// Refresh every --interval seconds until interrupted.
        #[arg(long)]
        watch: bool,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
    },
    /// Global kill switch: count every verdict but never drop.
    Observe {
        #[arg(value_enum)]
        state: OnOff,
    },
    /// PoP-wide settings (xs_cfg).
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Protected prefixes (assets): owner, origin server, tunnel script.
    #[command(subcommand)]
    Asset(AssetCmd),
    /// Per-asset policy: observe/mitigate, SYN cookies, rate limit, ...
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Allowed services of an asset (protocol + destination port).
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Allowlist: sources that skip blocklist, services and rate limits.
    #[command(subcommand)]
    Allow(RuleCmd),
    /// Blocklist: sources that are dropped until the rule expires.
    #[command(subcommand)]
    Block(RuleCmd),
    /// SYN-cookie key management.
    #[command(subcommand)]
    Syncookie(SyncookieCmd),
    /// Delete expired rules and verified-source entries.
    Gc,
}

#[derive(Args, Debug)]
pub struct AttachArgs {
    /// Interface to attach to.
    #[arg(long, env = "XS_IFACE")]
    pub iface: String,
    /// Compiled XDP object.
    #[arg(
        long,
        env = "SENTINEL_BPF_OBJ",
        default_value = "build/ebpf/xdp_main.o"
    )]
    pub obj: PathBuf,
    #[arg(long, value_enum, default_value_t = Mode::Native)]
    pub mode: Mode,
    /// Permit generic (skb) mode. Never use this on a production PoP.
    #[arg(long)]
    pub allow_generic: bool,
    /// PoP unicast IPv4 (traffic to it bypasses filtering).
    #[arg(long, env = "XS_POP_IP4")]
    pub pop_ip4: Option<Ipv4Addr>,
    /// PoP unicast IPv6.
    #[arg(long, env = "XS_POP_IP6")]
    pub pop_ip6: Option<Ipv6Addr>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    Show,
    Set {
        #[arg(long)]
        pop_ip4: Option<Ipv4Addr>,
        #[arg(long)]
        pop_ip6: Option<Ipv6Addr>,
        /// How long a SYN-cookie verified source stays verified (e.g. 5m).
        #[arg(long, value_parser = parse_duration)]
        verify_ttl: Option<Duration>,
        /// Anycast tunnel endpoint origins send replies to (ADR 0012).
        #[arg(long)]
        tunnel_ep4: Option<Ipv4Addr>,
        /// MAC of the uplink router (00:00:00:00:00:00 = reply to the sender).
        #[arg(long, value_parser = parse_mac)]
        nexthop_mac: Option<[u8; 6]>,
        /// Uplink MTU (set automatically on attach).
        #[arg(long, value_parser = clap::value_parser!(u16).range(576..=9216))]
        mtu: Option<u16>,
    },
}

/// An asset by id or by its exact protected prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetRef {
    Id(u32),
    Prefix(Prefix),
}

impl FromStr for AssetRef {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if let Ok(id) = s.parse::<u32>() {
            return Ok(AssetRef::Id(id));
        }
        s.parse()
            .map(AssetRef::Prefix)
            .map_err(|e: sentinel_common::prefix::PrefixError| {
                format!("{e} (expected an asset id or a protected prefix)")
            })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ReturnArg {
    /// Replies go back through the tunnel (works behind BCP38 filters).
    Tunnel,
    /// Replies leave the origin directly with the protected IP as source.
    Dsr,
}

impl From<ReturnArg> for ReturnMode {
    fn from(r: ReturnArg) -> Self {
        match r {
            ReturnArg::Tunnel => ReturnMode::Tunnel,
            ReturnArg::Dsr => ReturnMode::Dsr,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum AssetCmd {
    /// Protect a prefix: traffic to it is filtered and tunnelled to --origin.
    /// New assets start in observe mode.
    Add(AssetAdd),
    /// Stop protecting a prefix (also removes its services).
    Del {
        asset: AssetRef,
    },
    List,
    /// Print the tunnel script the customer runs on the origin server.
    Script(ScriptArgs),
}

#[derive(Args, Debug)]
pub struct AssetAdd {
    /// Protected prefix, e.g. 198.51.100.10/32.
    #[arg(value_parser = parse_rule_prefix)]
    pub prefix: Prefix,
    /// Owning tenant (not 0, which means "global").
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub tenant: u32,
    /// The customer's server: tunnel destination.
    #[arg(long)]
    pub origin: Ipv4Addr,
    /// Asset id (default: next free).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub id: Option<u32>,
}

#[derive(Args, Debug)]
pub struct ScriptArgs {
    pub asset: AssetRef,
    #[arg(long = "return", value_enum, default_value_t = ReturnArg::Tunnel)]
    pub return_mode: ReturnArg,
    /// Use an existing tunnel device (e.g. tunl0) instead of creating one.
    #[arg(long)]
    pub tunnel_dev: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    Show {
        #[arg(long)]
        asset: AssetRef,
    },
    Set {
        #[arg(long)]
        asset: AssetRef,
        #[command(flatten)]
        change: PolicySet,
    },
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
pub struct PolicySet {
    /// on = drop and challenge; off = observe (count only).
    #[arg(long, value_enum)]
    pub mitigate: Option<OnOff>,
    /// Authenticate TCP sources with SYN cookies.
    #[arg(long, value_enum)]
    pub syncookies: Option<OnOff>,
    /// Drop everything that is not an allowed service.
    #[arg(long, value_enum)]
    pub enforce_services: Option<OnOff>,
    /// Non-first IP fragments.
    #[arg(long, value_enum)]
    pub fragments: Option<AllowDrop>,
    /// Packets per second per source (IPv6: per /64); 0 = no limit.
    #[arg(long)]
    pub pps_per_src: Option<u32>,
    /// Token-bucket size in packets; 0 = same as --pps-per-src.
    #[arg(long)]
    pub burst: Option<u32>,
}

impl PolicySet {
    pub fn is_empty(&self) -> bool {
        *self == PolicySet::default()
    }

    /// Applies the requested changes to an existing policy.
    pub fn apply(&self, mut p: XsPolicy) -> XsPolicy {
        let set = |flags: &mut u32, bit: u32, on: Option<bool>| match on {
            Some(true) => *flags |= bit,
            Some(false) => *flags &= !bit,
            None => {}
        };
        set(&mut p.flags, XS_P_MITIGATE, self.mitigate.map(OnOff::on));
        set(&mut p.flags, XS_P_SYNCOOKIE, self.syncookies.map(OnOff::on));
        set(
            &mut p.flags,
            XS_P_SERVICES,
            self.enforce_services.map(OnOff::on),
        );
        set(
            &mut p.flags,
            XS_P_ALLOW_FRAG,
            self.fragments.map(|f| f == AllowDrop::Allow),
        );
        if let Some(v) = self.pps_per_src {
            p.pps_per_src = v;
        }
        if let Some(v) = self.burst {
            p.burst = v;
        }
        p
    }
}

#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// Allow a protocol, optionally only one destination port (TCP/UDP).
    Add(ServiceArgs),
    Del(ServiceArgs),
    List {
        #[arg(long)]
        asset: Option<AssetRef>,
    },
}

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[arg(long)]
    pub asset: AssetRef,
    /// tcp, udp, icmp, icmpv6 or a protocol number.
    #[arg(long, value_parser = parse_proto)]
    pub proto: u8,
    /// Destination port (TCP/UDP). Omit to allow every port.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
}

impl ServiceArgs {
    pub fn check(&self) -> Result<()> {
        if self.port.is_some() && !proto_has_ports(self.proto) {
            anyhow::bail!("{} has no ports; omit --port", proto_name(self.proto));
        }
        Ok(())
    }

    pub fn key(&self, asset_id: u32) -> XsSvcKey {
        XsSvcKey::new(asset_id, self.proto, self.port.unwrap_or(0))
    }
}

#[derive(Subcommand, Debug)]
pub enum RuleCmd {
    Add(RuleAdd),
    Del {
        #[arg(value_parser = parse_rule_prefix)]
        prefix: Prefix,
        #[arg(long, default_value_t = 0)]
        tenant: u32,
    },
    List,
}

#[derive(Args, Debug)]
pub struct RuleAdd {
    /// Source address or prefix, e.g. 203.0.113.0/24.
    #[arg(value_parser = parse_rule_prefix)]
    pub prefix: Prefix,
    /// Lifetime (e.g. 10m). Required for blocks; allows without it are permanent.
    #[arg(long, value_parser = parse_duration)]
    pub ttl: Option<Duration>,
    /// Tenant the rule belongs to; 0 = global.
    #[arg(long, default_value_t = 0)]
    pub tenant: u32,
    #[arg(long, default_value = "manual", value_parser = parse_reason)]
    pub reason: Reason,
}

#[derive(Subcommand, Debug)]
pub enum SyncookieCmd {
    /// Replace the SYN-cookie key. Outstanding challenges become invalid
    /// (clients simply get a new challenge); verified sources stay verified.
    Rotate,
}

fn parse_rule_prefix(s: &str) -> Result<Prefix, String> {
    let p: Prefix = s
        .parse()
        .map_err(|e: sentinel_common::prefix::PrefixError| e.0)?;
    p.check_rule(1, 1).map_err(|e| e.0)?;
    Ok(p)
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    sentinel_common::units::parse_mac(s)
}

/// An origin must be a routable unicast address outside the protected prefix.
pub fn check_origin(origin: Ipv4Addr, prefix: &Prefix) -> Result<()> {
    if origin.is_unspecified()
        || origin.is_loopback()
        || origin.is_multicast()
        || origin.is_broadcast()
        || origin.is_link_local()
    {
        anyhow::bail!("origin {origin} is not a routable unicast address");
    }
    if prefix.contains(IpAddr::V4(origin)) {
        anyhow::bail!("origin {origin} is inside the protected prefix {prefix}");
    }
    Ok(())
}

fn parse_reason(s: &str) -> Result<Reason, String> {
    Reason::from_name(s).ok_or_else(|| {
        let names: Vec<_> = Reason::ALL.iter().map(|r| r.name()).collect();
        format!("unknown reason {s:?} (one of: {})", names.join(", "))
    })
}

/// Rejects generic mode unless explicitly allowed (spec: native only).
pub fn check_mode(mode: Mode, allow_generic: bool) -> Result<()> {
    if mode == Mode::Generic && !allow_generic {
        anyhow::bail!(
            "generic XDP mode is refused: it is slow and not suitable for a PoP; \
             pass --allow-generic if you really mean it (tests/labs only)"
        );
    }
    Ok(())
}

/// Checks that do not need the kernel, so they also run on macOS.
fn validate(cli: &Cli) -> Result<()> {
    use sentinel_common::pin::validate_ifname;
    match &cli.cmd {
        Cmd::Attach(a) => {
            check_mode(a.mode, a.allow_generic)?;
            validate_ifname(&a.iface)?;
        }
        Cmd::Detach { iface } => validate_ifname(iface)?,
        Cmd::Block(RuleCmd::Add(r)) if r.ttl.is_none() => {
            anyhow::bail!("a block needs --ttl: every block must expire (e.g. --ttl 10m)")
        }
        Cmd::Service(ServiceCmd::Add(s) | ServiceCmd::Del(s)) => s.check()?,
        Cmd::Policy(PolicyCmd::Set { change, .. }) if change.is_empty() => {
            anyhow::bail!("nothing to change; see `sentinelctl policy set --help`")
        }
        Cmd::Asset(AssetCmd::Add(a)) => check_origin(a.origin, &a.prefix)?,
        Cmd::Asset(AssetCmd::Script(sc)) => {
            if let Some(d) = &sc.tunnel_dev {
                validate_ifname(d)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = validate(&cli).and_then(|_| run(cli)) {
        eprintln!("sentinelctl: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run(cli: Cli) -> Result<()> {
    linux::run(PinLayout::new(&cli.pin_dir), cli)
}

/// Non-Linux builds compile (so `cargo test` works on a Mac) but cannot act.
#[cfg(not(target_os = "linux"))]
fn run(cli: Cli) -> Result<()> {
    let _ = PinLayout::new(&cli.pin_dir);
    anyhow::bail!("this command needs Linux (run it on a PoP or via `make docker-shell`)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("sentinelctl").chain(args.iter().copied()))
    }

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn generic_needs_flag() {
        assert!(check_mode(Mode::Native, false).is_ok());
        assert!(check_mode(Mode::Generic, false).is_err());
        assert!(check_mode(Mode::Generic, true).is_ok());
        let cli = parse(&["attach", "--iface", "eth0", "--mode", "generic"]).unwrap();
        assert!(validate(&cli).is_err());
    }

    #[test]
    fn parses_attach() {
        let cli = parse(&[
            "--pin-dir",
            "/sys/fs/bpf/x",
            "attach",
            "--iface",
            "eth0",
            "--pop-ip4",
            "10.10.1.1",
            "--pop-ip6",
            "2001:db8:100::1",
        ])
        .unwrap();
        assert_eq!(cli.pin_dir, PathBuf::from("/sys/fs/bpf/x"));
        let Cmd::Attach(a) = cli.cmd else { panic!() };
        assert_eq!(a.iface, "eth0");
        assert_eq!(a.mode, Mode::Native);
        assert_eq!(a.pop_ip4, Some(Ipv4Addr::new(10, 10, 1, 1)));
        assert!(a.pop_ip6.is_some());
    }

    #[test]
    fn json_is_global() {
        assert!(parse(&["stats", "--json"]).unwrap().json);
        assert!(parse(&["--json", "block", "list"]).unwrap().json);
        assert!(parse(&["stats", "--interval", "0"]).is_err());
    }

    #[test]
    fn rules_validated() {
        assert!(parse(&["block", "add", "0.0.0.0/0", "--ttl", "5m"]).is_err());
        assert!(parse(&["allow", "add", "::/0"]).is_err());
        assert!(parse(&["block", "add", "203.0.113.7/24", "--ttl", "5m"]).is_err());
        assert!(parse(&["block", "add", "203.0.113.0/24", "--ttl", "0s"]).is_err());
        assert!(parse(&[
            "block",
            "add",
            "203.0.113.0/24",
            "--reason",
            "x",
            "--ttl",
            "1m"
        ])
        .is_err());

        let no_ttl = parse(&["block", "add", "203.0.113.0/24"]).unwrap();
        assert!(validate(&no_ttl).unwrap_err().to_string().contains("--ttl"));

        let ok = parse(&[
            "block",
            "add",
            "203.0.113.0/24",
            "--ttl",
            "10m",
            "--tenant",
            "7",
        ])
        .unwrap();
        assert!(validate(&ok).is_ok());
        let Cmd::Block(RuleCmd::Add(r)) = ok.cmd else {
            panic!()
        };
        assert_eq!(r.ttl, Some(Duration::from_secs(600)));
        assert_eq!(r.tenant, 7);
        assert_eq!(r.reason, Reason::Manual);

        // Allows may be permanent.
        assert!(validate(&parse(&["allow", "add", "2001:db8:100::/48"]).unwrap()).is_ok());
    }

    #[test]
    fn services_validated() {
        let ok = parse(&[
            "service", "add", "--asset", "3", "--proto", "tcp", "--port", "443",
        ])
        .unwrap();
        assert!(validate(&ok).is_ok());
        let Cmd::Service(ServiceCmd::Add(s)) = ok.cmd else {
            panic!()
        };
        assert_eq!(s.asset, AssetRef::Id(3));
        assert_eq!(s.key(3), XsSvcKey::new(3, 6, 443));

        let icmp = parse(&[
            "service",
            "add",
            "--asset",
            "198.51.100.10/32",
            "--proto",
            "icmp",
        ]);
        assert!(validate(&icmp.unwrap()).is_ok());
        let bad = parse(&[
            "service", "add", "--asset", "1", "--proto", "icmp", "--port", "1",
        ]);
        assert!(validate(&bad.unwrap()).is_err());
        assert!(
            parse(&["service", "add", "--asset", "1", "--proto", "tcp", "--port", "0"]).is_err()
        );
        assert!(parse(&["service", "add", "--asset", "1", "--proto", "bogus"]).is_err());
        assert!(
            parse(&["service", "add", "--proto", "tcp"]).is_err(),
            "--asset is required"
        );
    }

    #[test]
    fn assets_validated() {
        let ok = parse(&[
            "asset",
            "add",
            "198.51.100.10/32",
            "--tenant",
            "42",
            "--origin",
            "192.0.2.10",
        ])
        .unwrap();
        assert!(validate(&ok).is_ok());
        assert!(parse(&[
            "asset",
            "add",
            "198.51.100.10",
            "--tenant",
            "0",
            "--origin",
            "192.0.2.10"
        ])
        .is_err());
        assert!(parse(&[
            "asset",
            "add",
            "0.0.0.0/0",
            "--tenant",
            "1",
            "--origin",
            "192.0.2.10"
        ])
        .is_err());
        for origin in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.1.1",
            "198.51.100.10",
        ] {
            let c = parse(&[
                "asset",
                "add",
                "198.51.100.10/32",
                "--tenant",
                "1",
                "--origin",
                origin,
            ])
            .unwrap();
            assert!(validate(&c).is_err(), "origin {origin} accepted");
        }
        let sc = parse(&[
            "asset",
            "script",
            "7",
            "--return",
            "dsr",
            "--tunnel-dev",
            "tunl0",
        ])
        .unwrap();
        assert!(validate(&sc).is_ok());
        let Cmd::Asset(AssetCmd::Script(sc)) = sc.cmd else {
            panic!()
        };
        assert_eq!(
            (sc.asset, sc.return_mode),
            (AssetRef::Id(7), ReturnArg::Dsr)
        );
        let bad = parse(&["asset", "script", "7", "--tunnel-dev", "a/b"]).unwrap();
        assert!(validate(&bad).is_err());
        assert_eq!(
            "2001:db8:100::/48".parse::<AssetRef>(),
            Ok(AssetRef::Prefix("2001:db8:100::/48".parse().unwrap()))
        );
        assert!("nonsense".parse::<AssetRef>().is_err());
    }

    #[test]
    fn config_set_parses_mac_and_mtu() {
        let c = parse(&[
            "config",
            "set",
            "--nexthop-mac",
            "02:00:00:00:00:fe",
            "--mtu",
            "1500",
            "--tunnel-ep4",
            "198.51.100.1",
        ])
        .unwrap();
        let Cmd::Config(ConfigCmd::Set {
            nexthop_mac,
            mtu,
            tunnel_ep4,
            ..
        }) = c.cmd
        else {
            panic!()
        };
        assert_eq!(nexthop_mac, Some([2, 0, 0, 0, 0, 0xfe]));
        assert_eq!(mtu, Some(1500));
        assert_eq!(tunnel_ep4, Some(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(parse(&["config", "set", "--nexthop-mac", "02:00:00:00:00"]).is_err());
        assert!(parse(&["config", "set", "--mtu", "100"]).is_err());
    }

    #[test]
    fn policy_set_applies_only_given_fields() {
        let cli = parse(&[
            "policy",
            "set",
            "--asset",
            "1",
            "--mitigate",
            "on",
            "--syncookies",
            "on",
            "--fragments",
            "allow",
            "--pps-per-src",
            "100",
        ])
        .unwrap();
        let Cmd::Policy(PolicyCmd::Set { change: set, .. }) = cli.cmd else {
            panic!()
        };
        let start = XsPolicy {
            flags: XS_P_SERVICES,
            pps_per_src: 1,
            burst: 50,
            _pad: 0,
        };
        let p = set.apply(start);
        assert_eq!(
            p.flags,
            XS_P_SERVICES | XS_P_MITIGATE | XS_P_SYNCOOKIE | XS_P_ALLOW_FRAG
        );
        assert_eq!((p.pps_per_src, p.burst), (100, 50));

        let off = PolicySet {
            mitigate: Some(OnOff::Off),
            ..Default::default()
        };
        assert_eq!(off.apply(p).flags & XS_P_MITIGATE, 0);

        let empty = parse(&["policy", "set", "--asset", "1"]).unwrap();
        assert!(validate(&empty).is_err());
    }
}
