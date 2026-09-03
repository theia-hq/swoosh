//! `swoosh grant ls`: list the grants this node has issued, grouped by service.
//!
//! A local, offline read of swoosh's own mint-log ledger (dir-derived from `--key` like the rest of its
//! store). It reports only what this node DIRECTLY issued, never the narrower leaves a holder may have
//! delegated onward: those never touch this machine, so no issuer can enumerate them. Reading the ledger
//! grants no access and needs no identity or transport.

use std::path::Path;
use std::time::SystemTime;

use clap::Args;

use crate::grants::{self, GrantRecord, Grants};

/// List the grants you have issued, grouped by service.
#[derive(Debug, Args)]
pub struct LsCmd {}

impl LsCmd {
    /// Read the ledger under this `--key` dir and print each issued grant, grouped by service, as
    /// `kind  holder  lifetime  caveat`. An empty ledger prints a friendly line, not a blank.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        let mut records = Grants::at(crate::config::grants_path(key)?).load().await?;
        if records.is_empty() {
            println!("no grants issued yet");
            return Ok(());
        }
        // Group by service by sorting on it, keeping append order within a service (a stable sort) so the
        // most recent grant for a service reads last.
        records.sort_by(|a, b| a.service.as_str().cmp(b.service.as_str()));
        let now = SystemTime::now();
        // Materialize each row's lifetime once, so both the display and the column width read the same value.
        let rows: Vec<(&GrantRecord, String)> = records
            .iter()
            .map(|record| (record, remaining(record, now)))
            .collect();
        // Pad the holder and lifetime columns to a common CHAR width (not byte length, which would misalign a
        // multibyte petname) so the caveat column lines up.
        let holder_width = rows
            .iter()
            .map(|(record, _)| record.holder.chars().count())
            .max()
            .unwrap_or_default();
        let lifetime_width = rows
            .iter()
            .map(|(_, lifetime)| lifetime.chars().count())
            .max()
            .unwrap_or_default();
        let mut current: Option<&str> = None;
        for (record, lifetime) in &rows {
            if current != Some(record.service.as_str()) {
                println!("{}", record.service.as_str());
                current = Some(record.service.as_str());
            }
            println!(
                "  {kind:<6}  {holder:<holder_width$}  {lifetime:<lifetime_width$}  {caveat}",
                kind = record.kind.as_str(),
                holder = record.holder,
                caveat = record.caveat(),
            );
        }
        Ok(())
    }
}

/// A grant's remaining lifetime as a compact span (`2d`, `1h`, `30m`, `45s`), or `expired` once its expiry
/// has passed. Reads what a holder cares about: how long the grant still opens the door.
fn remaining(record: &GrantRecord, now: SystemTime) -> String {
    match record.expiry.duration_since(now) {
        Ok(left) => grants::humanize(left),
        Err(_past) => "expired".to_owned(),
    }
}
