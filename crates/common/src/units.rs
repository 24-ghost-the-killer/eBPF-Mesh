// SPDX-License-Identifier: MIT OR Apache-2.0
//! Small parsers shared by the CLI and (later) the agent: durations, IP
//! protocol names, and conversion between TTLs and kernel expiry times.

use std::time::Duration;

/// Parses `300`, `300s`, `5m`, `2h`, `1d`. Zero is rejected.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86400),
        Some(_) => (s, 1),
        None => return Err("empty duration".into()),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration {s:?} (examples: 90, 90s, 5m, 2h, 1d)"))?;
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| format!("duration {s:?} is too large"))?;
    if secs == 0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(Duration::from_secs(secs))
}

/// Human form of a remaining time in nanoseconds: `4m59s`, `expired`.
pub fn format_remaining(expires_ns: u64, now_ns: u64) -> String {
    if expires_ns == 0 {
        return "permanent".into();
    }
    if expires_ns <= now_ns {
        return "expired".into();
    }
    let s = (expires_ns - now_ns) / 1_000_000_000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{}s", s / 60, s % 60),
        3600..=86399 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        _ => format!("{}d{}h", s / 86400, (s % 86400) / 3600),
    }
}

/// Absolute CLOCK_BOOTTIME expiry for a TTL.
pub fn expires_at(now_boot_ns: u64, ttl: Duration) -> u64 {
    now_boot_ns.saturating_add(ttl.as_nanos().min(u64::MAX as u128) as u64)
}

/// Converts an absolute Unix time (ms) into CLOCK_BOOTTIME ns using a pair of
/// clock readings taken together. None if it is already in the past.
pub fn unix_ms_to_boot_ns(expires_ms: u64, now_unix_ms: u64, now_boot_ns: u64) -> Option<u64> {
    let left_ms = expires_ms.checked_sub(now_unix_ms).filter(|l| *l > 0)?;
    Some(now_boot_ns.saturating_add(left_ms.saturating_mul(1_000_000)))
}

/// Current Unix time in milliseconds.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `aa:bb:cc:dd:ee:ff` -> bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let err = || format!("invalid MAC {s:?} (expected aa:bb:cc:dd:ee:ff)");
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(err());
    }
    let mut mac = [0u8; 6];
    for (b, p) in mac.iter_mut().zip(parts) {
        if p.len() != 2 {
            return Err(err());
        }
        *b = u8::from_str_radix(p, 16).map_err(|_| err())?;
    }
    Ok(mac)
}

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// `tcp`, `udp`, `icmp`, `icmpv6`, or a protocol number.
pub fn parse_proto(s: &str) -> Result<u8, String> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(IPPROTO_TCP),
        "udp" => Ok(IPPROTO_UDP),
        "icmp" => Ok(IPPROTO_ICMP),
        "icmpv6" | "ipv6-icmp" => Ok(IPPROTO_ICMPV6),
        n => n
            .parse()
            .map_err(|_| format!("unknown protocol {s:?} (tcp, udp, icmp, icmpv6 or 0-255)")),
    }
}

pub fn proto_name(p: u8) -> String {
    match p {
        IPPROTO_TCP => "tcp".into(),
        IPPROTO_UDP => "udp".into(),
        IPPROTO_ICMP => "icmp".into(),
        IPPROTO_ICMPV6 => "icmpv6".into(),
        n => n.to_string(),
    }
}

/// Only TCP and UDP have ports; other protocols are allowed as a whole.
pub fn proto_has_ports(p: u8) -> bool {
    p == IPPROTO_TCP || p == IPPROTO_UDP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86400)));
        for bad in ["", "0", "0s", "5x", "m", "-1", "99999999999999999999d"] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn remaining() {
        let s = 1_000_000_000;
        assert_eq!(format_remaining(0, 5), "permanent");
        assert_eq!(format_remaining(5, 5), "expired");
        assert_eq!(format_remaining(10 * s, 0), "10s");
        assert_eq!(format_remaining(299 * s, 0), "4m59s");
        assert_eq!(format_remaining(7260 * s, 0), "2h1m");
        assert_eq!(format_remaining(90000 * s, 0), "1d1h");
        assert_eq!(expires_at(u64::MAX - 1, Duration::from_secs(1)), u64::MAX);
        assert_eq!(expires_at(5, Duration::from_secs(1)), s + 5);
    }

    #[test]
    fn unix_to_boot() {
        assert_eq!(unix_ms_to_boot_ns(10_500, 10_000, 7), Some(7 + 500_000_000));
        assert_eq!(unix_ms_to_boot_ns(10_000, 10_000, 7), None, "now = expired");
        assert_eq!(unix_ms_to_boot_ns(9_000, 10_000, 7), None);
        assert_eq!(unix_ms_to_boot_ns(u64::MAX, 0, 1), Some(u64::MAX));
    }

    #[test]
    fn protocols() {
        assert_eq!(parse_proto("TCP"), Ok(6));
        assert_eq!(parse_proto("icmpv6"), Ok(58));
        assert_eq!(parse_proto("47"), Ok(47));
        assert!(parse_proto("256").is_err());
        assert!(parse_proto("sctpx").is_err());
        assert_eq!(proto_name(17), "udp");
        assert_eq!(proto_name(47), "47");
        assert!(proto_has_ports(6) && !proto_has_ports(1));
    }
}
