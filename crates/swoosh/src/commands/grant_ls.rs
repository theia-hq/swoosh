//! `swoosh grant ls`: list the grants this node has issued, grouped by target.
//!
//! A local, offline read of swoosh's own mint-log ledger (in the node home like the rest of its store). It
//! reports only what this node DIRECTLY issued, never the narrower leaves a holder may have delegated
//! onward: those never touch this machine, so no issuer can enumerate them. Reading the ledger grants no
//! access and needs no identity or transport.
//!
//! The gate NEVER reads the ledger: this view is issuer-side audit only (see [`Grants`]). The import list
//! below is the mechanical proof a reviewer can rerun: `serve` and the `nauthy`/`tightbeam` admit paths
//! hold no `Grants` import, and the ledger is reached only from these grant verbs (`ls`, `issue`,
//! `revoke`) and `mint`.

use std::time::SystemTime;

use clap::Args;

use crate::grants::{self, GrantRecord, GrantTarget, Grants};
use crate::home::Home;

/// List the grants you have issued, grouped by target: family membership first, then services A to Z.
#[derive(Debug, Args)]
pub struct LsCmd {}

impl LsCmd {
    /// Read the ledger in the home and print each issued grant, grouped by target, as
    /// `kind  holder  lifetime  caveat`. Membership heads the view (who is in the family before who can
    /// reach what); services follow A to Z. An empty ledger prints a friendly line, not a blank.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        let mut records = Grants::at(home.grants()).load().await?;
        if records.is_empty() {
            println!("no grants issued yet");
            return Ok(());
        }
        // Group by target: membership first (the family before what it can reach), then services A
        // to Z, keeping append order within a group (a stable sort) so the most recent grant reads last.
        records.sort_by(|a, b| group_key(&a.target).cmp(&group_key(&b.target)));
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
            if current != Some(record.target.as_str()) {
                println!("{}", record.target.as_str());
                current = Some(record.target.as_str());
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

/// The sort key that puts membership first and services A to Z after it. `None` sorts before any
/// `Some`, so the membership group heads the view and every service name orders after it.
fn group_key(target: &GrantTarget) -> Option<&str> {
    match target {
        GrantTarget::Membership => None,
        GrantTarget::Service(service) => Some(service.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::time::UNIX_EPOCH;

    use nauthy::RevocationId;

    use super::*;
    use crate::grants::{Delegation, GrantKind};

    fn record(target: GrantTarget, holder: &str) -> GrantRecord {
        GrantRecord {
            target,
            kind: GrantKind::Device,
            delegation: Delegation::Sealed,
            holder: holder.to_owned(),
            root_id: RevocationId::from_bytes(vec![0xde, 0xad]),
            expiry: UNIX_EPOCH + Duration::from_secs(1_788_400_000),
        }
    }

    /// The ledger is issuer-side audit only: the gate never consults it, so it must never appear on the
    /// admit path. This test fails the moment `serve` or the bin root names [`Grants`]. Rerun by hand
    /// with: `rg -n Grants crates/swoosh/src/commands/serve.rs crates/swoosh/src/main.rs` from the
    /// workspace root and confirm no hits; the same holds for the nauthy gate and tightbeam tunnel
    /// sources, which live in sibling repos and cannot be included here.
    #[test]
    fn the_gate_never_reads_the_ledger() {
        for (name, text) in [
            ("serve.rs", include_str!("serve.rs")),
            ("main.rs", include_str!("../main.rs")),
        ] {
            assert!(
                !text.contains("Grants"),
                "{name} must not name the mint-log ledger: the gate never reads it"
            );
        }
    }

    /// Membership heads the view, then services A to Z: the sorted ledger reads `membership`, `ssh`,
    /// `web` even when appended in another order.
    #[test]
    fn ls_sorts_membership_first_then_services() {
        let ssh: nauthy::Service = "ssh".parse().expect("valid service");
        let web: nauthy::Service = "web".parse().expect("valid service");
        let mut records = [
            record(GrantTarget::Service(web), "holder-a"),
            record(GrantTarget::Membership, "holder-b"),
            record(GrantTarget::Service(ssh), "holder-c"),
        ];
        records.sort_by(|a, b| group_key(&a.target).cmp(&group_key(&b.target)));
        let headings: Vec<&str> = records
            .iter()
            .map(|record| record.target.as_str())
            .collect();
        assert_eq!(
            headings,
            vec!["membership", "ssh", "web"],
            "membership first, then services A to Z"
        );
    }
}
