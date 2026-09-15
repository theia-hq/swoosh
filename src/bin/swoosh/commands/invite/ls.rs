//! `swoosh invite ls`: list the device invites this node has issued.
//!
//! A local, offline read of swoosh's own mint-log ledger, filtered to MEMBERSHIP rows: one row per badge
//! this node signed (a derived invite and a bound invite record the same way), with the label it was
//! recorded under. Columns are `label  bound-to  expires`, designed so a future fleet row (a signet, no
//! token) fills the same second column as `fleet:<signet>` without a re-render. The ledger is
//! issuer-side audit only; the gate never reads it.

use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use swoosh::contacts::Contacts;
use swoosh::grants::{GrantKind, GrantRecord, GrantTarget, Grants};
use swoosh::home::Home;

use crate::commands::grant_ls::remaining;

/// The reserved petname the operator's own devices live under (`me/<label>`).
const ME: &str = "me";

/// List the invites you have issued.
#[derive(Debug, Args)]
pub struct LsCmd {}

impl LsCmd {
    /// Read the ledger in the home and print one line per membership row: the label it is addressable as
    /// (or `-`), the key it admits, and the badge's remaining lifetime. An empty ledger prints a friendly
    /// line, not a blank.
    pub async fn run(self, contacts: &Contacts, home: &Home) -> eyre::Result<()> {
        let records: Vec<GrantRecord> = Grants::at(home.grants())
            .load()
            .await?
            .into_iter()
            .filter(|record| record.target == GrantTarget::Membership)
            .collect();
        if records.is_empty() {
            println!("no invites created yet");
            return Ok(());
        }
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
