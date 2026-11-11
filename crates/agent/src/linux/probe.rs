// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tunnel test (ADR 0020): answers `probe.<pop>` requests from the API.
//!
//! The agent sends ICMP echo requests to the protected IP through the same
//! IPIP tunnel the dataplane uses (outer: PoP IP -> origin; inner: PoP IP ->
//! protected IP). The customer's server decapsulates and answers from the
//! protected IP back through its return tunnel; XDP validates and
//! decapsulates the reply like any other return traffic and forwards it to
//! the PoP's own address, where a raw ICMP socket picks it up. A reply
//! therefore proves both directions of the tunnel.
//!
//! The request names only an asset id: the agent probes only origins it has
//! applied from KV, so a compromised API cannot aim it at arbitrary hosts.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use futures::StreamExt;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use sentinel_bpf::maps;
use sentinel_common::msg::{subject_probe, ProbeReq, ProbeResp, SCHEMA_V};
use sentinel_common::prefix::Prefix;

use super::Shared;

/// How long to wait for each echo reply.
const REPLY_TIMEOUT: Duration = Duration::from_millis(800);

pub async fn run(sh: Arc<Shared>) {
    // One probe at a time per PoP: they are rare and cheap, and this bounds
    // what a flood of requests could make the agent send.
    let gate = Arc::new(Semaphore::new(1));
    loop {
        match sh.nats.subscribe(subject_probe(sh.pop())).await {
            Ok(mut sub) => {
                while let Some(msg) = sub.next().await {
                    let Some(reply) = msg.reply.clone() else {
                        continue;
                    };
                    let (sh, gate) = (sh.clone(), gate.clone());
                    tokio::spawn(async move {
                        let resp = match gate.try_acquire() {
                            Ok(_permit) => handle(&sh, &msg.payload).await,
                            Err(_) => error_resp(&sh, 0, "another probe is running"),
                        };
                        if let Ok(body) = serde_json::to_vec(&resp) {
                            if let Err(e) = sh.nats.publish(reply, body.into()).await {
                                warn!("probe reply: {e}");
                            }
                        }
                    });
                }
            }
            Err(e) => warn!("subscribing to probes: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn error_resp(sh: &Shared, asset: u32, e: &str) -> ProbeResp {
    ProbeResp {
        v: SCHEMA_V,
        pop: sh.pop().to_string(),
        asset,
        sent: 0,
        received: 0,
        rtt_ms: None,
        error: Some(e.to_string()),
    }
}

async fn handle(sh: &Shared, payload: &[u8]) -> ProbeResp {
    let req: ProbeReq = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => return error_resp(sh, 0, &format!("invalid request: {e}")),
    };
    if req.v != SCHEMA_V || !(1..=5).contains(&req.count) {
        return error_resp(sh, req.asset, "unsupported request");
    }
    let target = match maps::assets(&sh.pins) {
        Ok(all) => all.into_iter().find_map(|(p, a)| match p {
            Prefix::V4(ip, 32) if a.asset == req.asset => Some((ip, a)),
            _ => None,
        }),
        Err(e) => return error_resp(sh, req.asset, &format!("reading assets: {e:#}")),
    };
    let Some((protected, a)) = target else {
        return error_resp(sh, req.asset, "no IPv4 /32 asset with this id on this PoP");
    };
    let origin = Ipv4Addr::from(a.origin4);
    let pop_ip = sh.cfg.pop.pop_ip4;
    let count = req.count;
    let result =
        tokio::task::spawn_blocking(move || echo(pop_ip, origin, protected, count, REPLY_TIMEOUT))
            .await;
    let mut resp = error_resp(sh, req.asset, "");
    resp.error = None;
    match result {
        Ok(Ok(rtts)) => {
            resp.sent = count;
            resp.received = rtts.len() as u8;
            if !rtts.is_empty() {
                let sum: f64 = rtts.iter().map(|d| d.as_secs_f64() * 1000.0).sum();
                resp.rtt_ms = Some((sum / rtts.len() as f64 * 100.0).round() / 100.0);
            } else {
                resp.error = Some("no reply from the protected IP through the tunnel".into());
            }
        }
        Ok(Err(e)) => resp.error = Some(format!("{e:#}")),
        Err(e) => resp.error = Some(format!("probe task: {e}")),
    }
    info!(asset = req.asset, %origin, sent = resp.sent, received = resp.received, "tunnel probe");
    resp
}

/// Internet checksum (RFC 1071).
pub fn csum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The inner packet: IPv4 (src -> dst) + ICMP echo request.
pub fn echo_packet(src: Ipv4Addr, dst: Ipv4Addr, ident: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8u8, 0, 0, 0];
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"sentinel-probe..");
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let total = (20 + icmp.len()) as u16;
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&ident.wrapping_add(seq).to_be_bytes()); // IP id
    ip.extend_from_slice(&[0, 0, 64, 1, 0, 0]); // frag, ttl, proto ICMP, csum
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// True when `pkt` (IPv4 header + ICMP, as a raw socket returns it) is the
/// echo reply from `from` for (ident, seq).
pub fn is_reply(pkt: &[u8], from: Ipv4Addr, ident: u16, seq: u16) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 || pkt[9] != 1 || pkt[12..16] != from.octets() {
        return false;
    }
    let icmp = &pkt[ihl..];
    icmp[0] == 0
        && icmp[1] == 0
        && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
}

struct Fd(libc::c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn raw_socket(proto: libc::c_int) -> Result<Fd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
    if fd < 0 {
        bail!("raw socket: {}", std::io::Error::last_os_error());
    }
    Ok(Fd(fd))
}

fn sockaddr(ip: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}

/// Sends `count` probes; returns the round trips of those answered.
fn echo(
    pop_ip: Ipv4Addr,
    origin: Ipv4Addr,
    protected: Ipv4Addr,
    count: u8,
    timeout: Duration,
) -> Result<Vec<Duration>> {
    let rx = raw_socket(libc::IPPROTO_ICMP).context("ICMP receive socket")?;
    let tx = raw_socket(libc::IPPROTO_IPIP).context("IPIP send socket")?;
    // Outer source = the PoP's unicast address, as for delivered traffic.
    let local = sockaddr(pop_ip);
    if unsafe {
        libc::bind(
            tx.0,
            &local as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } < 0
    {
        bail!("bind {pop_ip}: {}", std::io::Error::last_os_error());
    }
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    unsafe {
        libc::setsockopt(
            rx.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    let mut ident = [0u8; 2];
    getrandom_fill(&mut ident);
    let ident = u16::from_ne_bytes(ident);
    let dst = sockaddr(origin);
    let mut rtts = Vec::new();
    let mut buf = [0u8; 1500];
    for seq in 1..=count as u16 {
        let pkt = echo_packet(pop_ip, protected, ident, seq);
        let start = Instant::now();
        let n = unsafe {
            libc::sendto(
                tx.0,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            bail!("send to {origin}: {}", std::io::Error::last_os_error());
        }
        while start.elapsed() < timeout {
            let n =
                unsafe { libc::recv(rx.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n > 0 && is_reply(&buf[..n as usize], protected, ident, seq) {
                rtts.push(start.elapsed());
                break;
            }
        }
    }
    Ok(rtts)
}

fn getrandom_fill(buf: &mut [u8]) {
    // /dev/urandom is enough for an echo identifier.
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_and_reply() {
        let src = Ipv4Addr::new(10, 10, 1, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);
        let p = echo_packet(src, dst, 0x1234, 7);
        assert_eq!(p.len(), 20 + 8 + 16);
        assert_eq!(csum(&p[..20]), 0, "IP header checksum");
        assert_eq!(csum(&p[20..]), 0, "ICMP checksum");
        assert_eq!(&p[16..20], &dst.octets());

        // The reply: swap addresses, type 0.
        let mut r = p.clone();
        r[12..16].copy_from_slice(&dst.octets());
        r[16..20].copy_from_slice(&src.octets());
        r[20] = 0;
        assert!(is_reply(&r, dst, 0x1234, 7));
        assert!(!is_reply(&r, dst, 0x1234, 8), "other sequence");
        assert!(!is_reply(&r, src, 0x1234, 7), "other source");
        assert!(!is_reply(&p, dst, 0x1234, 7), "a request is no reply");
        assert!(!is_reply(&r[..25], dst, 0x1234, 7), "truncated");
    }
}
