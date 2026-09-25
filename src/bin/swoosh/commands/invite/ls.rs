//! `swoosh invite ls`: list the device invites this node has issued.
//!
//! A local, offline read of swoosh's own mint-log ledger, filtered to MEMBERSHIP rows: one row per
//! HOLDER (not per badge), with the label it was recorded under. Columns are `label  bound-to  expires`,
//! designed so a future fleet row (a signet, no token) fills the same second column as `fleet:<signet>`
//! without a re-render. The ledger is issuer-side audit only; the gate never reads it.
//!
//! One row per holder, because renewal is re-enrolment: re-running `invite add` for a key already on
//! file APPENDS a badge row rather than editing one, so a five-device fleet renewed quarterly reads as
//! twenty rows within a year, most of them `expired`, and the surface that is supposed to carry the
//! expiry warning becomes the surface renewal ruins. Only the latest-expiring row describes the
//! credential a device actually carries, so only that row shows. The superseded rows stay in the ledger
//! and stay auditable in the ledger.

use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use swoosh::contacts::Contacts;
use swoosh::grants::{self, GrantKind, GrantRecord, GrantTarget, Grants};
use swoosh::home::Home;

/// The reserved petname the operator's own devices live under (`me/<label>`).
const ME: &str = "me";

/// List the invites you have issued.
#[derive(Debug, Args)]
pub struct LsCmd {}

impl LsCmd {
    /// Read the ledger in the home and print one line per HOLDER: the label it is addressable as (or
    /// `-`), the key it admits, and the remaining lifetime of the live badge it holds. An empty ledger
    /// prints a friendly line, not a blank.
    pub async fn run(self, contacts: &Contacts, home: &Home) -> eyre::Result<()> {
        let records: Vec<GrantRecord> = Grants::at(home.links())
            .load()
            .await?
            .into_iter()
            .filter(|record| record.target == GrantTarget::Membership)
            .collect();
        if records.is_empty() {
            println!("no invites created yet");
            return Ok(());
        }
        let records = live_per_holder(records);
        let now = SystemTime::now();
        // Materialize each row once, so the column widths and the printed cells read the same values.
        let rows: Vec<(String, String, String)> = records
            .iter()
            .map(|record| {
                (
                    label_for(contacts, &record.holder),
                    bound_to(record),
                    remaining(record, now),
                )
            })
            .collect();
        // Pad the first two columns to a common CHAR width (not byte length, which would misalign a
        // multibyte label) so the lifetime column lines up.
        let label_width = rows
            .iter()
            .map(|(label, _, _)| label.chars().count())
            .max()
            .unwrap_or_default();
        let bound_width = rows
            .iter()
            .map(|(_, bound, _)| bound.chars().count())
            .max()
            .unwrap_or_default();
        for (label, bound, lifetime) in &rows {
            println!("{label:<label_width$}  {bound:<bound_width$}  {lifetime}");
        }
        Ok(())
    }
}

/// A badge's remaining lifetime as a compact span (`2d`, `1h`, `30m`, `45s`), or `expired` once its
/// expiry has passed.
fn remaining(record: &GrantRecord, now: SystemTime) -> String {
    match record.expiry.duration_since(now) {
        Ok(left) => grants::humanize(left),
        Err(_past) => "expired".to_owned(),
    }
}

/// Collapse the membership rows to the LIVE badge per holder: the latest-expiring row for each key, in
/// the order each key first appears in the ledger.
///
/// Renewal APPENDS (it is re-enrolment, not an edit), so a device renewed on the quarterly cadence
/// accumulates a row per renewal and only the last one describes the badge it presents. First-appearance
/// order is kept rather than re-sorting by expiry, so a renewal does not reshuffle a fleet the operator
/// has learned to read; the view changes only when a device joins or leaves.
///
/// A linear scan, deliberately: the collection is one row per device per renewal for one person's
/// homelab, and a map would cost the stable order this view is built on.
fn live_per_holder(records: Vec<GrantRecord>) -> Vec<GrantRecord> {
    let mut live: Vec<GrantRecord> = Vec::with_capacity(records.len());
    for record in records {
        match live.iter().position(|kept| kept.holder == record.holder) {
            // A later badge for a holder already listed supersedes the row kept for it: the last
            // credential minted for a device is the one that device presents.
            Some(kept) if live[kept].expiry < record.expiry => live[kept] = record,
            // A row that does not outlive the one already kept IS a superseded row. It is not lost: the
            // ledger keeps every membership row.
            Some(_) => {}
            None => live.push(record),
        }
    }
    live
}

/// The label this invite was recorded under: the `me/<label>` contact(s) whose node is the badge's
/// holder, in label order, comma-joined when the same key was invited under more than one name. `-` when
/// no contact names it any more (the ledger row survives a `contact rm`, and a raw key still cancels it).
fn label_for(contacts: &Contacts, holder: &str) -> String {
    let Some(wanted) = holder.parse::<NodeId>().ok() else {
        return "-".to_owned();
    };
    let mut labels: Vec<&str> = Vec::new();
    for petname in contacts.petnames() {
        if petname.as_str() != ME {
            continue;
        }
        if let Some(bindings) = contacts.bindings(petname) {
            for (label, binding) in bindings {
                if binding.node == wanted {
                    labels.push(label.as_str());
                }
            }
        }
    }
    if labels.is_empty() {
        "-".to_owned()
    } else {
        labels.join(",")
    }
}

/// The key an invite admits, as the second column. A device row shows the short key; a fleet row would
/// show `fleet:<short signet>` (its bind is a signet, not a token); a bearer row cannot be a membership
/// badge and shows `-`.
fn bound_to(record: &GrantRecord) -> String {
    match record.kind {
        GrantKind::Device => short_or_raw(&record.holder),
        GrantKind::Fleet => format!("fleet:{}", short_or_raw(&record.holder)),
        GrantKind::Bearer => "-".to_owned(),
    }
}

/// A recorded holder rendered as a short key when it parses (the normal case), else verbatim: the ledger
/// is a text file a human may have edited, and the view never fails on one odd row.
fn short_or_raw(holder: &str) -> String {
    holder
        .parse::<NodeId>()
        .map(|node| node.short())
        .unwrap_or_else(|_| holder.to_owned())
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::time::UNIX_EPOCH;

    use nauthy::RevocationId;
    use swoosh::contacts::{Contacts, DeviceLabel, Petname};
    use swoosh::grants::Delegation;

    use super::*;

    fn petname(name: &str) -> Petname {
        name.parse().expect("valid petname in test")
    }

    fn label(name: &str) -> DeviceLabel {
        name.parse().expect("valid device label in test")
    }

    fn membership(holder: NodeId) -> GrantRecord {
        GrantRecord {
            target: GrantTarget::Membership,
            kind: GrantKind::Device,
            delegation: Delegation::Sealed,
            holder: holder.to_string(),
            root_id: RevocationId::from_bytes(vec![0xde, 0xad]),
            expiry: UNIX_EPOCH + Duration::from_secs(1_788_400_000),
        }
    }

    /// A `me/<label>` contact names the row; a key invited under two labels shows both; an unnamed key
    /// falls back to `-` so the row still lists (and a raw key still cancels it).
    #[test]
    fn labels_resolve_under_me_and_fall_back_to_dash() {
        let node = NodeId::from_ed25519_secret(&[3u8; 32]);
        let other = NodeId::from_ed25519_secret(&[4u8; 32]);
        let mut contacts = Contacts::default();
        contacts.add(petname("me"), Some(label("desk")), node);
        contacts.add(petname("me"), Some(label("lappy")), node);
        contacts.add(petname("me"), Some(label("other")), other);

        assert_eq!(label_for(&contacts, &node.to_string()), "desk,lappy");
        assert_eq!(label_for(&contacts, &other.to_string()), "other");
        assert_eq!(
            label_for(
                &contacts,
                &NodeId::from_ed25519_secret(&[5u8; 32]).to_string()
            ),
            "-"
        );
    }

    /// A renewal APPENDS a row, so the ledger holds one per mint. The view collapses to the
    /// latest-expiring row per holder, which is the badge that device actually presents, and keeps the
    /// order each holder first appeared in so a renewal does not reshuffle the fleet. Without the
    /// collapse a five-device fleet renewed quarterly reads as twenty rows, most of them `expired`.
    #[test]
    fn a_renewed_device_reads_as_one_row_carrying_its_live_badge() {
        let desk = NodeId::from_ed25519_secret(&[10u8; 32]);
        let lappy = NodeId::from_ed25519_secret(&[11u8; 32]);
        let at = |holder: NodeId, secs: u64| GrantRecord {
            expiry: UNIX_EPOCH + Duration::from_secs(secs),
            ..membership(holder)
        };
        // desk enrolled, then renewed twice; lappy enrolled between the two, and its row must not move.
        let rows = live_per_holder(vec![
            at(desk, 1_000),
            at(lappy, 2_000),
            at(desk, 3_000),
            at(desk, 2_500),
        ]);

        assert_eq!(
            rows.iter()
                .map(|row| row.holder.as_str())
                .collect::<Vec<_>>(),
            vec![desk.to_string().as_str(), lappy.to_string().as_str()],
            "one row per holder, in first-appearance order"
        );
        assert_eq!(
            rows[0].expiry,
            UNIX_EPOCH + Duration::from_secs(3_000),
            "the row shown for a renewed device is its LATEST-expiring badge, not its newest ledger \
             row and not its first"
        );
    }

    /// The collapse must key on the HOLDER, never on the label: two devices are two rows even when the
    /// ledger interleaves them, and a fleet that never renewed reads exactly as it did before.
    #[test]
    fn distinct_holders_each_keep_their_row() {
        let rows = live_per_holder(vec![
            membership(NodeId::from_ed25519_secret(&[12u8; 32])),
            membership(NodeId::from_ed25519_secret(&[13u8; 32])),
        ]);
        assert_eq!(rows.len(), 2, "two devices are two rows");
    }

    /// The second column: a device shows its short key; a fleet row (the parked arm) shows
    /// `fleet:<short signet>` with no token column anywhere.
    #[test]
    fn bound_column_carries_a_fleet_row_without_a_token() {
        let signet = NodeId::from_ed25519_secret(&[6u8; 32]);
        let device = membership(signet);
        assert_eq!(bound_to(&device), signet.short());

        let fleet = GrantRecord {
            kind: GrantKind::Fleet,
            ..membership(signet)
        };
        assert_eq!(bound_to(&fleet), format!("fleet:{}", signet.short()));
    }
}
