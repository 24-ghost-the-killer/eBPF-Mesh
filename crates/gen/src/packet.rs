// SPDX-License-Identifier: MIT OR Apache-2.0
//! IPv4/IPv6 + TCP/UDP packet construction with correct checksums.

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Syn,
    Ack,
    Udp,
}

pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

/// Per-packet variable fields.
#[derive(Clone, Copy, Debug)]
pub struct Fields {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub ip_id: u16,
}

fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum()
}

pub fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_sum(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum16(&s.octets()) + sum16(&d.octets()) + proto as u32 + len as u32
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum16(&s.octets()) + sum16(&d.octets()) + proto as u32 + len as u32
        }
        _ => panic!("source and destination must be the same family"),
    }
}

/// L4 segment (TCP or UDP) with checksum.
pub fn l4(kind: Kind, f: &Fields, payload: usize) -> (u8, Vec<u8>) {
    let (proto, mut seg) = match kind {
        Kind::Syn | Kind::Ack => {
            let mut h = vec![0u8; 20 + payload];
            h[0..2].copy_from_slice(&f.sport.to_be_bytes());
            h[2..4].copy_from_slice(&f.dport.to_be_bytes());
            h[4..8].copy_from_slice(&f.seq.to_be_bytes());
            if kind == Kind::Ack {
                h[8..12].copy_from_slice(&f.ack.to_be_bytes());
            }
            h[12] = 5 << 4;
            h[13] = if kind == Kind::Syn { TCP_SYN } else { TCP_ACK };
            h[14..16].copy_from_slice(&64240u16.to_be_bytes());
            (6u8, h)
        }
        Kind::Udp => {
            let mut h = vec![0u8; 8 + payload];
            h[0..2].copy_from_slice(&f.sport.to_be_bytes());
            h[2..4].copy_from_slice(&f.dport.to_be_bytes());
            h[4..6].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
            (17u8, h)
        }
    };
    let csum = fold(pseudo_sum(f.src, f.dst, proto, seg.len()) + sum16(&seg));
    // UDP: a computed 0 is sent as 0xffff (0 means "no checksum").
    let csum = if proto == 17 && csum == 0 {
        0xffff
    } else {
        csum
    };
    let at = if proto == 6 { 16 } else { 6 };
    seg[at..at + 2].copy_from_slice(&csum.to_be_bytes());
    (proto, seg)
}

/// Full IP packet (header + segment), as given to a raw IPPROTO_RAW socket.
pub fn build(kind: Kind, f: &Fields, payload: usize) -> Vec<u8> {
    let (proto, seg) = l4(kind, f, payload);
    match (f.src, f.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = vec![0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
            h[4..6].copy_from_slice(&f.ip_id.to_be_bytes());
            h[8] = 64;
            h[9] = proto;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let c = fold(sum16(&h));
            h[10..12].copy_from_slice(&c.to_be_bytes());
            h.extend_from_slice(&seg);
            h
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0u8; 40];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&(seg.len() as u16).to_be_bytes());
            h[6] = proto;
            h[7] = 64;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
            h.extend_from_slice(&seg);
            h
        }
        _ => panic!("source and destination must be the same family"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(src: &str, dst: &str) -> Fields {
        Fields {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            sport: 40000,
            dport: 80,
            seq: 0x01020304,
            ack: 0x0a0b0c0d,
            ip_id: 7,
        }
    }

    /// A packet with a correct checksum sums to 0xffff (fold gives 0).
    fn verify_l4(pkt: &[u8], ihl: usize, f: &Fields) {
        let seg = &pkt[ihl..];
        let proto = if ihl == 20 { pkt[9] } else { pkt[6] };
        assert_eq!(
            fold(pseudo_sum(f.src, f.dst, proto, seg.len()) + sum16(seg)),
            0
        );
    }

    #[test]
    fn ipv4_syn() {
        let f = fields("203.0.113.7", "198.51.100.10");
        let p = build(Kind::Syn, &f, 0);
        assert_eq!(p.len(), 40);
        assert_eq!(fold(sum16(&p[..20])), 0, "IPv4 header checksum");
        assert_eq!(p[9], 6);
        assert_eq!(p[20 + 13], TCP_SYN);
        assert_eq!(&p[20 + 8..20 + 12], &[0, 0, 0, 0], "SYN has no ack");
        verify_l4(&p, 20, &f);
    }

    #[test]
    fn ipv4_ack_and_udp() {
        let f = fields("203.0.113.7", "198.51.100.10");
        let a = build(Kind::Ack, &f, 0);
        assert_eq!(a[20 + 13], TCP_ACK);
        assert_eq!(&a[28..32], &0x0a0b0c0du32.to_be_bytes());
        verify_l4(&a, 20, &f);

        let u = build(Kind::Udp, &f, 33);
        assert_eq!(u.len(), 20 + 8 + 33);
        assert_eq!(u[9], 17);
        assert_eq!(u16::from_be_bytes([u[24], u[25]]), 41);
        verify_l4(&u, 20, &f);
    }

    #[test]
    fn ipv6_syn_and_udp() {
        let f = fields("2001:db8:ffff::7", "2001:db8:100::10");
        let p = build(Kind::Syn, &f, 0);
        assert_eq!(p.len(), 60);
        assert_eq!(p[0] >> 4, 6);
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 20);
        verify_l4(&p, 40, &f);
        let u = build(Kind::Udp, &f, 1);
        verify_l4(&u, 40, &f);
    }

    #[test]
    #[should_panic(expected = "same family")]
    fn mixed_families_panic() {
        build(Kind::Syn, &fields("203.0.113.7", "2001:db8:100::10"), 0);
    }
}
