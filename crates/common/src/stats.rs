// SPDX-License-Identifier: MIT OR Apache-2.0
//! Aggregation and rendering of `xs_stats` (per-CPU counters).

use serde::Serialize;

use crate::abi::{Verdict, XsStatsKey, XsStatsVal};

/// Sums per-CPU values into one total.
pub fn sum_percpu(per_cpu: &[XsStatsVal]) -> XsStatsVal {
    per_cpu
        .iter()
        .fold(XsStatsVal::default(), |acc, v| XsStatsVal {
            pkts: acc.pkts.wrapping_add(v.pkts),
            bytes: acc.bytes.wrapping_add(v.bytes),
        })
}

/// Name of a raw verdict id; unknown ids (newer kernel object) stay visible.
pub fn verdict_name(id: u32) -> String {
    match Verdict::try_from(id) {
        Ok(v) => v.name().to_string(),
        Err(id) => format!("unknown_{id}"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatEntry {
    pub tenant: u32,
    pub verdict: String,
    pub verdict_id: u32,
    pub pkts: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub entries: Vec<StatEntry>,
}

impl Snapshot {
    /// Builds a snapshot from (key, per-CPU values) pairs, sorted by
    /// (tenant, verdict).
    pub fn from_percpu<I>(rows: I) -> Snapshot
    where
        I: IntoIterator<Item = (XsStatsKey, Vec<XsStatsVal>)>,
    {
        let mut entries: Vec<StatEntry> = rows
            .into_iter()
            .map(|(k, vals)| {
                let total = sum_percpu(&vals);
                StatEntry {
                    tenant: k.tenant,
                    verdict: verdict_name(k.verdict),
                    verdict_id: k.verdict,
                    pkts: total.pkts,
                    bytes: total.bytes,
                }
            })
            .collect();
        entries.sort_by_key(|e| (e.tenant, e.verdict_id));
        Snapshot { entries }
    }

    /// Total packets for a verdict across all tenants.
    pub fn pkts(&self, verdict: Verdict) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.verdict_id == verdict as u32)
            .map(|e| e.pkts)
            .sum()
    }

    pub fn render_table(&self) -> String {
        let mut out = format!(
            "{:<8} {:<16} {:>14} {:>16}\n",
            "TENANT", "VERDICT", "PACKETS", "BYTES"
        );
        if self.entries.is_empty() {
            out.push_str("(no packets counted yet)\n");
        }
        for e in &self.entries {
            out.push_str(&format!(
                "{:<8} {:<16} {:>14} {:>16}\n",
                e.tenant, e.verdict, e.pkts, e.bytes
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(pkts: u64, bytes: u64) -> XsStatsVal {
        XsStatsVal { pkts, bytes }
    }

    #[test]
    fn sums_across_cpus() {
        assert_eq!(sum_percpu(&[]), v(0, 0));
        assert_eq!(sum_percpu(&[v(1, 60), v(2, 120), v(0, 0)]), v(3, 180));
    }

    #[test]
    fn snapshot_sorted_and_named() {
        let s = Snapshot::from_percpu([
            (
                XsStatsKey {
                    tenant: 0,
                    verdict: 1,
                },
                vec![v(2, 100)],
            ),
            (
                XsStatsKey {
                    tenant: 0,
                    verdict: 0,
                },
                vec![v(5, 300), v(5, 300)],
            ),
            (
                XsStatsKey {
                    tenant: 0,
                    verdict: 99,
                },
                vec![v(1, 1)],
            ),
        ]);
        let names: Vec<_> = s.entries.iter().map(|e| e.verdict.as_str()).collect();
        assert_eq!(names, ["pass", "drop_malformed", "unknown_99"]);
        assert_eq!(s.pkts(Verdict::Pass), 10);
        assert_eq!(s.pkts(Verdict::DropMalformed), 2);
        assert_eq!(s.pkts(Verdict::Fragment), 0);
    }

    #[test]
    fn json_shape() {
        let s = Snapshot::from_percpu([(
            XsStatsKey {
                tenant: 0,
                verdict: 0,
            },
            vec![v(1, 64)],
        )]);
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["entries"][0]["verdict"], "pass");
        assert_eq!(j["entries"][0]["pkts"], 1);
        assert_eq!(j["entries"][0]["bytes"], 64);
    }

    #[test]
    fn table_rendering() {
        assert!(Snapshot::default().render_table().contains("no packets"));
        let s = Snapshot::from_percpu([(
            XsStatsKey {
                tenant: 7,
                verdict: 3,
            },
            vec![v(4, 256)],
        )]);
        let t = s.render_table();
        assert!(t.lines().nth(1).unwrap().contains("fragment"));
    }
}
