// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux implementation of every command.

mod cmds;

use anyhow::Result;

use sentinel_common::pin::PinLayout;

use crate::{Cli, Cmd, SyncookieCmd};
use sentinel_bpf::rules::RuleKind;

/// While an agent runs (fresh heartbeat), maps it manages are reconciled
/// to NATS KV: manual changes to them are overwritten at the next resync.
fn warn_if_agent_owns(cmd: &Cmd) {
    let mutates_agent_maps = matches!(
        cmd,
        Cmd::Asset(crate::AssetCmd::Add(_) | crate::AssetCmd::Del { .. })
            | Cmd::Policy(crate::PolicyCmd::Set { .. })
            | Cmd::Service(crate::ServiceCmd::Add(_) | crate::ServiceCmd::Del(_))
            | Cmd::Allow(crate::RuleCmd::Add(_) | crate::RuleCmd::Del { .. })
            | Cmd::Block(crate::RuleCmd::Add(_) | crate::RuleCmd::Del { .. })
            | Cmd::Observe { .. }
    );
    if !mutates_agent_maps {
        return;
    }
    let path = std::env::var("SENTINEL_HEARTBEAT_FILE")
        .unwrap_or_else(|_| "/run/sentinel/heartbeat".into());
    let fresh = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_some_and(|t| sentinel_common::units::now_unix_ms() / 1000 < t + 30);
    if fresh {
        eprintln!(
            "sentinelctl: warning: sentinel-agent is running ({path}); it reconciles assets, \
             services, rules and the kill switch to NATS KV and will overwrite this change"
        );
    }
}

pub fn run(pins: PinLayout, cli: Cli) -> Result<()> {
    let json = cli.json;
    warn_if_agent_owns(&cli.cmd);
    match cli.cmd {
        Cmd::Attach(a) => cmds::attach(&pins, &a),
        Cmd::Detach { iface } => cmds::detach(&pins, &iface),
        Cmd::Stats { watch, interval } => cmds::stats(&pins, json, watch, interval),
        Cmd::Observe { state } => cmds::observe(&pins, state.on()),
        Cmd::Config(c) => cmds::config(&pins, c, json),
        Cmd::Asset(c) => cmds::asset(&pins, c, json),
        Cmd::Policy(c) => cmds::policy(&pins, c, json),
        Cmd::Service(c) => cmds::service(&pins, c, json),
        Cmd::Allow(c) => cmds::rules(&pins, RuleKind::Allow, c, json),
        Cmd::Block(c) => cmds::rules(&pins, RuleKind::Block, c, json),
        Cmd::Syncookie(SyncookieCmd::Rotate) => cmds::rotate(&pins),
        Cmd::Gc => cmds::gc(&pins, json),
    }
}
