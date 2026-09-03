//! The mint-log ledger: an append then load returns exactly what was issued, one corrupt line is skipped
//! (not fatal) while good rows survive, each malformed field is its own typed parse error, and the file is
//! written owner-only.

use core::time::Duration;
use std::time::UNIX_EPOCH;

use nauthy::RevocationId;

use super::{ANYONE, Delegation, GrantKind, GrantRecord, Grants, LedgerError};

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

fn record(
    service: &str,
    kind: GrantKind,
    delegation: Delegation,
    holder: &str,
    expiry_secs: u64,
) -> GrantRecord {
    GrantRecord {
        service: service.parse().expect("valid service"),
        kind,
        delegation,
        holder: holder.to_owned(),
        root_id: RevocationId::from_bytes(vec![0xde, 0xad, 0xbe, 0xef, expiry_secs as u8]),
        // Whole seconds, so the round trip through the ledger's unix-seconds encoding is exact.
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
