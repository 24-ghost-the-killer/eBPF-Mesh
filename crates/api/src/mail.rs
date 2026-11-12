// SPDX-License-Identifier: MIT OR Apache-2.0
//! Outgoing mail behind a small trait: files for labs/tests, the log for
//! development. SMTP is a later addition.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::info;

use crate::config::{MailCfg, MailMode};

#[derive(Debug, Serialize)]
pub struct Mail {
    pub to: String,
    pub from: String,
    pub subject: String,
    pub body: String,
}

pub trait Mailer: Send + Sync {
    fn send(&self, mail: Mail) -> Result<()>;
}

pub struct FileMailer {
    dir: PathBuf,
    seq: AtomicU64,
}

impl Mailer for FileMailer {
    fn send(&self, mail: Mail) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let ts = sentinel_common::units::now_unix_ms();
        let path = self.dir.join(format!("{ts}-{n:06}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&mail)?)
            .with_context(|| format!("writing {}", path.display()))
    }
}

/// Logs subject and recipient only: bodies carry secret tokens.
pub struct LogMailer;

impl Mailer for LogMailer {
    fn send(&self, mail: Mail) -> Result<()> {
        info!(to = %mail.to, subject = %mail.subject, "mail (log mode, body not shown)");
        Ok(())
    }
}

pub fn from_config(c: &MailCfg) -> Box<dyn Mailer> {
    match c.mode {
        MailMode::File => Box::new(FileMailer {
            dir: c.dir.clone().expect("validated: file mode has a dir"),
            seq: AtomicU64::new(0),
        }),
        MailMode::Log => Box::new(LogMailer),
    }
}
