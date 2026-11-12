// SPDX-License-Identifier: MIT OR Apache-2.0
//! Draining through BIRD (spec 11.2, ADR 0023): the drain include file
//! holds `define DRAIN = 0|1;`, the BIRD config prepends the AS path when it
//! is 1, and `birdc configure` applies it. The file is rewritten only when
//! the value changes, atomically (temp file + rename).

use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::info;

use crate::config::drain_conf;

use super::Shared;

pub fn current_drain(sh: &Shared) -> Option<bool> {
    let b = sh.cfg.bird.as_ref()?;
    let text = std::fs::read_to_string(&b.drain_file).ok()?;
    Some(text.contains("DRAIN = 1"))
}

pub fn set_drain(sh: &Shared, drain: bool) -> Result<()> {
    let Some(b) = &sh.cfg.bird else {
        return Ok(());
    };
    let want = drain_conf(drain);
    if std::fs::read_to_string(&b.drain_file).ok().as_deref() == Some(want.as_str()) {
        return Ok(());
    }
    let tmp = b.drain_file.with_extension("tmp");
    std::fs::write(&tmp, &want).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &b.drain_file)
        .with_context(|| format!("replacing {}", b.drain_file.display()))?;
    let mut cmd = Command::new(&b.birdc);
    if let Some(s) = &b.socket {
        cmd.arg("-s").arg(s);
    }
    let out = cmd
        .arg("configure")
        .output()
        .with_context(|| format!("running {}", b.birdc.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !text.contains("Reconfigur") {
        bail!(
            "birdc configure failed: {} {}",
            text.trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    info!(drain, "BIRD reconfigured");
    Ok(())
}
