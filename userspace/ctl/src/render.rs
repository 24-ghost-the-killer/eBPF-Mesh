//! Output formatting for `meshctl stats` (platform independent, unit tested).

use std::fmt::Write as _;

use em_common::Stats;
use em_common::abi::named_slots;
use serde_json::{Map, Value, json};

/// Rates over an interval: the counter delta and its length in seconds.
#[derive(Clone, Copy, Debug)]
pub struct Rates<'a> {
    pub delta: &'a Stats,
    pub secs: f64,
}

fn per_sec(v: u64, secs: f64) -> f64 {
    if secs > 0.0 { v as f64 / secs } else { 0.0 }
}

/// One JSON object: every named counter (zero or not) so consumers can rely
/// on the keys, plus per-second rates when an interval is given.
pub fn json(iface: &str, snap: &Stats, rates: Option<Rates<'_>>, ts_ms: u128) -> Value {
    let mut counters = Map::new();
    for (slot, name) in named_slots() {
        let c = snap.c[slot];
        counters.insert(name.to_string(), json!({ "packets": c.packets, "bytes": c.bytes }));
    }
    let mut out = json!({ "iface": iface, "ts_ms": ts_ms, "counters": counters });
    if let Some(r) = rates {
        let mut m = Map::new();
        for (slot, name) in named_slots() {
            let d = r.delta.c[slot];
            m.insert(
                name.to_string(),
                json!({ "pps": per_sec(d.packets, r.secs), "bps": per_sec(d.bytes, r.secs) * 8.0 }),
            );
        }
        out["rates"] = Value::Object(m);
    }
    out
}

/// Human-readable table. Zero counters are hidden unless `all`; with rates,
/// a counter is shown when it is non-zero in total.
pub fn table(iface: &str, snap: &Stats, rates: Option<Rates<'_>>, all: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "interface {iface}");
    match rates {
        Some(_) => {
            let _ = writeln!(
                s,
                "{:<28} {:>16} {:>18} {:>14} {:>14}",
                "counter", "packets", "bytes", "pps", "Mbit/s"
            );
        }
        None => {
            let _ = writeln!(s, "{:<28} {:>16} {:>18}", "counter", "packets", "bytes");
        }
    }
    for (slot, name) in named_slots() {
        let c = snap.c[slot];
        if !all && c.packets == 0 {
            continue;
        }
        match rates {
            Some(r) => {
                let d = r.delta.c[slot];
                let _ = writeln!(
                    s,
                    "{:<28} {:>16} {:>18} {:>14.1} {:>14.3}",
                    name,
                    c.packets,
                    c.bytes,
                    per_sec(d.packets, r.secs),
                    per_sec(d.bytes, r.secs) * 8.0 / 1e6
                );
            }
            None => {
                let _ = writeln!(s, "{:<28} {:>16} {:>18}", name, c.packets, c.bytes);
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use em_common::Counter;
    use em_common::abi::{COUNTERS, PARSE_RCS, slot_of};

    fn sample() -> Stats {
        let mut s = Stats::default();
        s.c[slot_of("rx").unwrap()] = Counter { packets: 10, bytes: 1000 };
        s.c[slot_of("verdict_pass").unwrap()] = Counter { packets: 10, bytes: 1000 };
        s.c[slot_of("parse_ok").unwrap()] = Counter { packets: 10, bytes: 1000 };
        s
    }

    #[test]
    fn json_has_every_counter_and_values() {
        let v = json("eth1", &sample(), None, 42);
        assert_eq!(v["iface"], "eth1");
        assert_eq!(v["ts_ms"], 42);
        let c = v["counters"].as_object().unwrap();
        assert_eq!(c.len(), COUNTERS.len() + PARSE_RCS.len());
        assert_eq!(v["counters"]["rx"]["packets"], 10);
        assert_eq!(v["counters"]["rx"]["bytes"], 1000);
        assert_eq!(v["counters"]["l4_tcp"]["packets"], 0);
        assert!(v.get("rates").is_none());
    }

    #[test]
    fn json_rates() {
        let snap = sample();
        let v = json("eth1", &snap, Some(Rates { delta: &snap, secs: 2.0 }), 0);
        assert_eq!(v["rates"]["rx"]["pps"], 5.0);
        assert_eq!(v["rates"]["rx"]["bps"], 4000.0);
        let v = json("eth1", &snap, Some(Rates { delta: &snap, secs: 0.0 }), 0);
        assert_eq!(v["rates"]["rx"]["pps"], 0.0);
    }

    #[test]
    fn table_hides_zero_rows_unless_all() {
        let t = table("eth1", &sample(), None, false);
        assert!(t.contains("rx"));
        assert!(t.contains("parse_ok"));
        assert!(!t.contains("l4_tcp"));
        let t = table("eth1", &sample(), None, true);
        assert!(t.contains("l4_tcp"));
        assert_eq!(t.lines().count(), 2 + COUNTERS.len() + PARSE_RCS.len());
    }

    #[test]
    fn table_with_rates_has_rate_columns() {
        let snap = sample();
        let t = table("eth1", &snap, Some(Rates { delta: &snap, secs: 1.0 }), false);
        assert!(t.contains("pps"));
        assert!(t.lines().any(|l| l.starts_with("rx") && l.contains("10.0")));
    }
}
