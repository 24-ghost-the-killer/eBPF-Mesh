//! Types shared by the eBPF Mesh userspace crates: the dataplane ABI mirror,
//! the bpffs pin layout and counter snapshots.

pub mod abi;
pub mod pin;

use std::path::PathBuf;

pub use abi::{Counter, Stats};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AbiError {
    #[error("{what}: value is {got} bytes, expected {want} (ABI mismatch)")]
    Size { what: &'static str, got: usize, want: usize },
    #[error("invalid interface name {0:?}")]
    InvalidIfname(String),
    #[error("pin root {0:?} must be an absolute path")]
    RelativePinRoot(PathBuf),
}
