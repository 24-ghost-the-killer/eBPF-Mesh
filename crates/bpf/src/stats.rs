// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reading the per-CPU verdict counters.

use anyhow::{anyhow, Result};
use libbpf_rs::{MapCore, MapFlags};

use sentinel_common::abi::{MapBytes, XsStatsKey, XsStatsVal};
use sentinel_common::pin::PinLayout;
use sentinel_common::stats::Snapshot;

use crate::maps;

pub fn read(pins: &PinLayout) -> Result<Snapshot> {
    let map = maps::open(pins, "xs_stats")?;
    let mut rows = Vec::new();
    for key in map.keys() {
        let k = XsStatsKey::from_bytes(&key).ok_or_else(|| {
            anyhow!(
                "xs_stats key has unexpected size {} (ABI mismatch)",
                key.len()
            )
        })?;
        // An entry can vanish between keys() and lookup; skip it.
        let Some(per_cpu) = map.lookup_percpu(&key, MapFlags::ANY)? else {
            continue;
        };
        let vals = per_cpu
            .iter()
            .map(|b| {
                XsStatsVal::from_bytes(b)
                    .ok_or_else(|| anyhow!("xs_stats value has unexpected size {}", b.len()))
            })
            .collect::<Result<Vec<_>>>()?;
        rows.push((k, vals));
    }
    Ok(Snapshot::from_percpu(rows))
}
