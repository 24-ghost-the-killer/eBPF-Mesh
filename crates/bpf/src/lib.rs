// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux access to the Sentinel-Edge XDP program, shared by `sentinelctl`
//! and `sentinel-agent`: attach/detach (pinned bpf_link), typed access to the
//! pinned maps, rules and garbage collection, counters, sampled events.
//!
//! Linux only: on other systems the crate is empty.
#![cfg(target_os = "linux")]

pub mod attach;
pub mod maps;
pub mod rules;
pub mod stats;
