// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sentinel-gen`: lab-only traffic generator.
//!
//! Sends SYN, ACK or UDP floods from (optionally spoofed) sources through a
//! raw IP socket. LAB ONLY: the destination and every source must be inside
//! the lab address plan unless `--allow-non-lab-destination` is given.

mod packet;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};

use sentinel_common::lab;
use sentinel_common::prefix::Prefix;
use sentinel_common::units::parse_duration;

use packet::{Fields, Kind};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum KindArg {
    /// TCP SYN (handshake flood)
    Syn,
    /// TCP ACK (out-of-state flood)
    Ack,
    /// UDP
    Udp,
}

#[derive(Parser, Debug)]
#[command(name = "sentinel-gen", version, about = "Lab-only traffic generator")]
struct Args {
    #[arg(value_enum)]
    kind: KindArg,
    /// Destination address (must be in the lab ranges).
    #[arg(long)]
    dst: IpAddr,
    #[arg(long, default_value_t = 80)]
    dport: u16,
    /// Source address or prefix; each packet uses a random address from it.
    #[arg(long, value_parser = parse_prefix, default_value = "203.0.113.128/25")]
    src: Prefix,
    /// Fixed source port (default: random per packet).
    #[arg(long)]
    sport: Option<u16>,
    /// Number of packets (default 1000 unless --duration is given).
    #[arg(long)]
    count: Option<u64>,
    /// Stop after this long (e.g. 3s).
    #[arg(long, value_parser = parse_duration)]
    duration: Option<Duration>,
    /// Packets per second; 0 = as fast as possible.
    #[arg(long, default_value_t = 0)]
    pps: u64,
    /// Payload bytes after the TCP/UDP header.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u16).range(0..=1400))]
    payload: u16,
    /// Seed for the pseudo-random source addresses/ports (default: time).
    #[arg(long)]
    seed: Option<u64>,
    /// Disable the lab-range safety check. Never use outside a sealed lab.
    #[arg(long)]
    allow_non_lab_destination: bool,
}

fn parse_prefix(s: &str) -> Result<Prefix, String> {
    s.parse()
        .map_err(|e: sentinel_common::prefix::PrefixError| e.0)
}

/// The safety check required by the spec (section 1).
fn check_lab(a: &Args) -> Result<()> {
    if a.dst.is_ipv4() != a.src.is_v4() {
        bail!("--dst and --src must be the same address family");
    }
    if a.allow_non_lab_destination {
        eprintln!("sentinel-gen: WARNING: lab range check disabled");
        return Ok(());
    }
    if !lab::is_lab_addr(a.dst) {
        bail!(
            "refusing destination {}: outside the lab ranges {:?} (override: {})",
            a.dst,
            lab::LAB_RANGES,
            lab::OVERRIDE_FLAG
        );
    }
    if !lab::is_lab_prefix(&a.src) {
        bail!(
            "refusing source {}: outside the lab ranges (override: {})",
            a.src,
            lab::OVERRIDE_FLAG
        );
    }
    Ok(())
}

/// xorshift64*: fast, deterministic per seed; not for cryptography.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// A random address inside `p`.
fn random_in(p: &Prefix, rng: &mut Rng) -> IpAddr {
    match p.network() {
        Prefix::V4(a, l) => {
            let host = if l == 32 { 0 } else { (rng.next() as u32) >> l };
            IpAddr::V4((u32::from(a) | host).into())
        }
        Prefix::V6(a, l) => {
            let r = ((rng.next() as u128) << 64) | rng.next() as u128;
            let host = if l == 128 { 0 } else { r >> l };
            IpAddr::V6((u128::from(a) | host).into())
        }
    }
}

fn fields(a: &Args, rng: &mut Rng) -> Fields {
    Fields {
        src: random_in(&a.src, rng),
        dst: a.dst,
        sport: a
            .sport
            .unwrap_or(1024 + (rng.next() % (65536 - 1024)) as u16),
        dport: a.dport,
        seq: rng.next() as u32,
        ack: rng.next() as u32,
        ip_id: rng.next() as u16,
    }
}

fn main() {
    let a = Args::parse();
    if let Err(e) = check_lab(&a).and_then(|_| run(&a)) {
        eprintln!("sentinel-gen: {e:#}");
        std::process::exit(1);
    }
}

fn run(a: &Args) -> Result<()> {
    let kind = match a.kind {
        KindArg::Syn => Kind::Syn,
        KindArg::Ack => Kind::Ack,
        KindArg::Udp => Kind::Udp,
    };
    let count = a
        .count
        .unwrap_or(if a.duration.is_some() { u64::MAX } else { 1000 });
    let seed = a.seed.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1)
    });
    let mut rng = Rng::new(seed);
    let sock = raw::RawSocket::new(a.dst)?;
    let start = Instant::now();
    let mut sent = 0u64;
    let mut errors = 0u64;
    while sent + errors < count {
        if let Some(d) = a.duration {
            if start.elapsed() >= d {
                break;
            }
        }
        let pkt = packet::build(kind, &fields(a, &mut rng), a.payload as usize);
        match sock.send(&pkt, a.dst) {
            Ok(()) => sent += 1,
            Err(_) => errors += 1, // e.g. ENOBUFS under load; keep going
        }
        if a.pps > 0 {
            let due = Duration::from_secs_f64((sent + errors) as f64 / a.pps as f64);
            if let Some(wait) = due.checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
        }
    }
    let secs = start.elapsed().as_secs_f64().max(1e-9);
    println!(
        "sent {sent} {:?} packets to {}:{} from {} in {secs:.2}s ({:.0} pps), {errors} send errors",
        a.kind,
        a.dst,
        a.dport,
        a.src,
        sent as f64 / secs
    );
    if sent == 0 {
        bail!("no packets could be sent");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod raw {
    use std::io;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use anyhow::{Context, Result};

    /// IPPROTO_RAW socket: the packet includes the IP header (implicit
    /// IP_HDRINCL for IPv4; header-included for IPv6 too).
    pub struct RawSocket(OwnedFd);

    impl RawSocket {
        pub fn new(dst: IpAddr) -> Result<Self> {
            let family = if dst.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            };
            // SAFETY: plain socket(2) call.
            let fd = unsafe { libc::socket(family, libc::SOCK_RAW, libc::IPPROTO_RAW) };
            if fd < 0 {
                return Err(io::Error::last_os_error())
                    .context("raw socket (needs root/CAP_NET_RAW)");
            }
            // SAFETY: fd was just returned by socket(2).
            Ok(RawSocket(unsafe { OwnedFd::from_raw_fd(fd) }))
        }

        pub fn send(&self, pkt: &[u8], dst: IpAddr) -> io::Result<()> {
            let rc = match dst {
                IpAddr::V4(a) => {
                    // SAFETY: zeroed sockaddr_in is valid; fields set below.
                    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                    sa.sin_family = libc::AF_INET as _;
                    sa.sin_addr.s_addr = u32::from_ne_bytes(a.octets());
                    // SAFETY: pointers and lengths describe valid memory.
                    unsafe {
                        libc::sendto(
                            self.0.as_raw_fd(),
                            pkt.as_ptr().cast(),
                            pkt.len(),
                            0,
                            (&sa as *const libc::sockaddr_in).cast(),
                            std::mem::size_of::<libc::sockaddr_in>() as _,
                        )
                    }
                }
                IpAddr::V6(a) => {
                    // SAFETY: zeroed sockaddr_in6 is valid; fields set below.
                    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                    sa.sin6_family = libc::AF_INET6 as _;
                    sa.sin6_addr.s6_addr = a.octets();
                    // SAFETY: pointers and lengths describe valid memory.
                    unsafe {
                        libc::sendto(
                            self.0.as_raw_fd(),
                            pkt.as_ptr().cast(),
                            pkt.len(),
                            0,
                            (&sa as *const libc::sockaddr_in6).cast(),
                            std::mem::size_of::<libc::sockaddr_in6>() as _,
                        )
                    }
                }
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod raw {
    use std::net::IpAddr;

    pub struct RawSocket;

    impl RawSocket {
        pub fn new(_: IpAddr) -> anyhow::Result<Self> {
            anyhow::bail!("sentinel-gen sends raw packets and needs Linux")
        }
        pub fn send(&self, _: &[u8], _: IpAddr) -> std::io::Result<()> {
            unreachable!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn args(a: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("sentinel-gen").chain(a.iter().copied())).unwrap()
    }

    #[test]
    fn cli_is_consistent() {
        Args::command().debug_assert();
    }

    #[test]
    fn refuses_non_lab_destination() {
        let e = check_lab(&args(&["syn", "--dst", "8.8.8.8"])).unwrap_err();
        assert!(e.to_string().contains("refusing destination 8.8.8.8"));
        assert!(e.to_string().contains("--allow-non-lab-destination"));
        assert!(check_lab(&args(&["syn", "--dst", "198.51.100.10"])).is_ok());
        assert!(check_lab(&args(&[
            "syn",
            "--dst",
            "8.8.8.8",
            "--allow-non-lab-destination"
        ]))
        .is_ok());
    }

    #[test]
    fn refuses_non_lab_sources_and_mixed_families() {
        let a = args(&["syn", "--dst", "198.51.100.10", "--src", "1.2.3.0/24"]);
        assert!(check_lab(&a)
            .unwrap_err()
            .to_string()
            .contains("refusing source"));
        let a = args(&["syn", "--dst", "2001:db8:100::10"]);
        assert!(check_lab(&a)
            .unwrap_err()
            .to_string()
            .contains("same address family"));
        let a = args(&[
            "syn",
            "--dst",
            "2001:db8:100::10",
            "--src",
            "2001:db8:100:ff::/64",
        ]);
        assert!(check_lab(&a).is_ok());
    }

    #[test]
    fn random_sources_stay_in_prefix() {
        let mut rng = Rng::new(42);
        for s in [
            "203.0.113.128/25",
            "203.0.113.7/32",
            "2001:db8:100:ff::/64",
            "2001:db8:100::1/128",
        ] {
            let p: Prefix = s.parse().unwrap();
            let mut seen = std::collections::HashSet::new();
            for _ in 0..500 {
                let ip = random_in(&p, &mut rng);
                assert!(p.contains(ip), "{ip} not in {p}");
                seen.insert(ip);
            }
            if p.prefix_len() < 32 {
                assert!(seen.len() > 50, "{s}: not random enough ({})", seen.len());
            }
        }
    }

    #[test]
    fn deterministic_per_seed() {
        let a = args(&["syn", "--dst", "198.51.100.10", "--seed", "7"]);
        let (mut r1, mut r2) = (Rng::new(7), Rng::new(7));
        let (f1, f2) = (fields(&a, &mut r1), fields(&a, &mut r2));
        assert_eq!((f1.src, f1.sport, f1.seq), (f2.src, f2.sport, f2.seq));
        assert!(f1.sport >= 1024);
    }
}
