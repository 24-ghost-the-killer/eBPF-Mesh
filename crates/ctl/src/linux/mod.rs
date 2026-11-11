// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux implementation of every command.

mod attach;
mod cmds;
mod maps;

use anyhow::Result;

use sentinel_common::pin::PinLayout;

use crate::{Cli, Cmd, SyncookieCmd};
use cmds::RuleKind;

pub fn run(pins: PinLayout, cli: Cli) -> Result<()> {
    let json = cli.json;
    match cli.cmd {
        Cmd::Attach(a) => attach::attach(&pins, &a),
        Cmd::Detach { iface } => attach::detach(&pins, &iface),
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
