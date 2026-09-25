//! The ledger: an append then load returns exactly what was issued, one corrupt line is skipped (not
//! fatal) while good rows survive, each malformed field is its own typed parse error, the `membership`
//! target round-trips, the file is written owner-only, and concurrent writers never lose a row to a prune.

use core::time::Duration;
use std::time::UNIX_EPOCH;

use nauthy::RevocationId;

use super::{ANYONE, Delegation, GrantKind, GrantRecord, GrantTarget, Grants, LedgerError};

/// A ledger backed by a unique temp path, so parallel tests never share a file.
fn ledger(tag: &str) -> (Grants, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "swoosh-grants-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    (Grants::at(path.clone()), path)
}

fn service_target(name: &str) -> GrantTarget {
    GrantTarget::Service(name.parse().expect("valid service"))
}

fn record(
    service: &str,
    kind: GrantKind,
    delegation: Delegation,
    holder: &str,
    expiry_secs: u64,
) -> GrantRecord {
    GrantRecord {
        target: service_target(service),
        kind,
        delegation,
        holder: holder.to_owned(),
        root_id: RevocationId::from_bytes(vec![0xde, 0xad, 0xbe, 0xef, expiry_secs as u8]),
        // Whole seconds, so the round trip through the ledger's unix-seconds encoding is exact.
        expiry: UNIX_EPOCH + Duration::from_secs(expiry_secs),
    }
}

fn membership_record(kind: GrantKind, holder: &str, expiry_secs: u64) -> GrantRecord {
    GrantRecord {
        target: GrantTarget::Membership,
        kind,
        delegation: Delegation::Sealed,
        holder: holder.to_owned(),
        root_id: RevocationId::from_bytes(vec![0xde, 0xad, 0xbe, 0xef, expiry_secs as u8]),
        expiry: UNIX_EPOCH + Duration::from_secs(expiry_secs),
    }
}

#[tokio::test]
async fn an_absent_ledger_loads_no_grants() {
    let (grants, _path) = ledger("absent");
    assert!(
        grants.load().await.expect("load absent").is_empty(),
        "an unwritten ledger is no grants, not an error"
    );
}

#[tokio::test]
async fn append_then_load_returns_every_record_in_order() {
    let (grants, _path) = ledger("round-trip");
    let bearer = record(
        "ssh",
        GrantKind::Bearer,
        Delegation::Delegable,
        ANYONE,
        1_788_400_000,
    );
    let device = record(
        "web",
        GrantKind::Device,
        Delegation::Sealed,
        "bf01deadbeef",
        1_788_405_000,
    );
    grants.append(&bearer).await.expect("append bearer");
    grants.append(&device).await.expect("append device");

    let loaded = grants.load().await.expect("load");
    // GrantRecord is Eq but not Debug (it holds a Service, which is not Debug), so compare by value rather
    // than through assert_eq's Debug formatting.
    assert!(
        loaded.len() == 2 && loaded[0] == bearer && loaded[1] == device,
        "the ledger returns exactly what was issued, in append order, every field intact"
    );
}

#[tokio::test]
async fn a_corrupt_line_is_skipped_and_the_good_rows_survive() {
    // One bad byte must NOT wedge the whole ledger: `grant ls`/`revoke <holder>` still need the good rows.
    let (grants, path) = ledger("resilient");
    let good = record(
        "ssh",
        GrantKind::Device,
        Delegation::Sealed,
        "bf01deadbeef",
        1_788_400_000,
    );
    grants.append(&good).await.expect("append the good record");
    // Hand-write a file with a blank line, a corrupt line, and the good record.
    let mut body = String::from("\nthis\tis\tnot\ta\tvalid\tline\textra\n");
    body.push_str(&std::fs::read_to_string(&path).expect("read the good line"));
    std::fs::write(&path, body).expect("write a mixed ledger");

    let loaded = grants.load().await.expect("load survives a corrupt line");
    assert!(
        loaded.len() == 1 && loaded[0] == good,
        "the good row survives; the blank line is skipped and the corrupt line is dropped with a warning"
    );
    let _ = std::fs::remove_file(&path);
}

/// Each malformed field is its own typed parse error, so a caller (and a warning) can name what is wrong. A
/// valid reference line is `kind, delegation, service, holder, expiry (secs), root id (hex)`; each case below
/// corrupts exactly one field. `matches!` avoids needing `GrantRecord: Debug` (it holds a non-Debug Service).
#[test]
fn each_malformed_field_is_its_own_parse_error() {
    assert!(GrantRecord::from_line("bearer\tsealed\tssh\t-\t1788400000\tdeadbeef").is_ok());
    assert!(matches!(
        GrantRecord::from_line("nope\tsealed\tssh\t-\t1\tde"),
        Err(LedgerError::Kind(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tmaybe\tssh\t-\t1\tde"),
        Err(LedgerError::Delegation(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tBAD!!\t-\t1\tde"),
        Err(LedgerError::Service(_))
    ));
    // `membership` is the Membership target (asserted in the membership test below), never a service.
    assert!(!GrantTarget::is_issuable_service_name("membership"));
    assert!(GrantTarget::is_issuable_service_name("ssh"));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh\t-\tnotanumber\tde"),
        Err(LedgerError::Expiry(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh\t-\t1\tzz"),
        Err(LedgerError::RootId)
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh"),
        Err(LedgerError::Malformed)
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh\t-\t1\tde\textra"),
        Err(LedgerError::Malformed)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn the_created_ledger_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let (grants, path) = ledger("perms");
    grants
        .append(&record(
            "ssh",
            GrantKind::Bearer,
            Delegation::Sealed,
            ANYONE,
            1_788_400_000,
        ))
        .await
        .expect("append creates the ledger");
    let mode = std::fs::metadata(&path)
        .expect("stat the ledger")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "the ledger is created 0600 (owner read/write only)"
    );
    let _ = std::fs::remove_file(&path);
}

/// The membership word `membership` parses to the Membership target and round-trips through the ledger.
#[tokio::test]
async fn membership_round_trips_as_membership() {
    let (grants, path) = ledger("membership");
    let badge = membership_record(GrantKind::Device, "bf01deadbeef", 1_788_400_000);
    let slip = record(
        "ssh",
        GrantKind::Bearer,
        Delegation::Sealed,
        ANYONE,
        1_788_400_001,
    );
    grants.append(&badge).await.expect("append the badge");
    grants
        .append(&slip)
        .await
        .expect("append the service grant");

    let loaded = grants.load().await.expect("load");
    assert!(
        loaded.len() == 2
            && loaded[0].target == GrantTarget::Membership
            && loaded[0] == badge
            && loaded[1] == slip,
        "a membership record round-trips as Membership alongside a service record"
    );

    assert_eq!(
        GrantTarget::Membership.as_str(),
        "membership",
        "Membership writes the new word"
    );
    assert!(matches!(
        "membership".parse::<GrantTarget>(),
        Ok(GrantTarget::Membership)
    ));
    let _ = std::fs::remove_file(&path);
}

/// A row for `service` from writer `writer`'s `index`th issue, expired or live.
fn issued(writer: u8, index: u8, live: bool) -> GrantRecord {
    let expiry = if live {
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch");
        UNIX_EPOCH + Duration::from_secs(now.as_secs() + 3600)
    } else {
        UNIX_EPOCH + Duration::from_secs(1)
    };
    GrantRecord {
        target: service_target("ssh"),
        kind: GrantKind::Bearer,
        delegation: Delegation::Sealed,
        holder: ANYONE.to_owned(),
        root_id: RevocationId::from_bytes(vec![writer, index, u8::from(live)]),
        expiry,
    }
}

/// Two writers, each with its own handle as two processes would have, issue 100 links each while a prune
/// runs on nearly every append (each writer adds an expired row before each live one, and the threshold
/// is one). A prune reads the file, writes `grants.new` and renames it over `grants`, so without the lock
/// an append landing in between goes to the replaced file and is lost.
#[test]
fn concurrent_issues_never_lose_a_ledger_row() {
    let (_, path) = ledger("concurrent");
    let writers: Vec<_> = [1u8, 2]
        .into_iter()
        .map(|writer| {
            let path = path.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime");
                runtime.block_on(async {
                    let grants = Grants::at(path).pruning_at(1);
                    for index in 0..100u8 {
                        grants
                            .append(&issued(writer, index, false))
                            .await
                            .expect("append an expired row");
                        grants
                            .append(&issued(writer, index, true))
                            .await
                            .expect("append a live row");
                    }
                });
            })
        })
        .collect();
    for writer in writers {
        writer.join().expect("the writer ends");
    }

    let rows = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(Grants::at(path.clone()).load())
        .expect("load");
    let live = rows
        .iter()
        .filter(|row| row.expiry > std::time::SystemTime::now())
        .count();
    assert_eq!(live, 200, "every issued link keeps its row");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(super::sibling(&path, ".lock"));
}

/// A prune waits for [`PRUNE_AT`](super::PRUNE_AT) expired rows, then drops every expired row and keeps
/// every live one and every line it cannot read.
#[tokio::test]
async fn a_prune_drops_only_expired_rows_once_enough_have_expired() {
    let (grants, path) = ledger("prune");
    for index in 0..u8::try_from(super::PRUNE_AT - 1).expect("fits") {
        grants
            .append(&issued(3, index, false))
            .await
            .expect("append an expired row");
    }
    grants
        .append(&issued(3, 200, true))
        .await
        .expect("append a live row");
    assert_eq!(
        grants.load().await.expect("load").len(),
        super::PRUNE_AT,
        "one short of the threshold, nothing is pruned"
    );

    std::fs::write(
        &path,
        format!(
            "{}not a row\n",
            std::fs::read_to_string(&path).expect("read")
        ),
    )
    .expect("add an unreadable line");
    grants
        .append(&issued(3, 250, false))
        .await
        .expect("append the expired row that reaches the threshold");
    grants
        .append(&issued(3, 201, true))
        .await
        .expect("append a live row, which prunes first");
    let rows = grants.load().await.expect("load");
    assert_eq!(rows.len(), 2, "only the live rows are left");
    assert!(
        std::fs::read_to_string(&path)
            .expect("read")
            .contains("not a row"),
        "a line the prune cannot read is kept"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(super::sibling(&path, ".lock"));
}
