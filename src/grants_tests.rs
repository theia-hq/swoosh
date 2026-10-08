//! The ledger: an append then load returns exactly what was issued, one corrupt line is skipped (not
//! fatal) while good rows survive, each malformed field is its own typed parse error, the file is written
//! owner-only, and concurrent writers never lose a row to a prune.

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

fn service_target(name: &str) -> nauthy::Service {
    name.parse().expect("valid service")
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
        serves: None,
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
        "ed01deadbeef",
        1_788_405_000,
    );
    grants
        .append(&crate::testkit::lock(), &bearer)
        .expect("append bearer");
    grants
        .append(&crate::testkit::lock(), &device)
        .expect("append device");

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
    // One bad byte must NOT wedge the whole ledger: `status`/`revoke <holder>` still need the good rows.
    let (grants, path) = ledger("resilient");
    let good = record(
        "ssh",
        GrantKind::Device,
        Delegation::Sealed,
        "ed01deadbeef",
        1_788_400_000,
    );
    grants
        .append(&crate::testkit::lock(), &good)
        .expect("append the good record");
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
/// valid reference line is `kind, delegation, service, served target, holder, expiry (secs), root id (hex)`; each case below
/// corrupts exactly one field. `matches!` avoids needing `GrantRecord: Debug` (it holds a non-Debug Service).
#[test]
fn each_malformed_field_is_its_own_parse_error() {
    assert!(GrantRecord::from_line("bearer\tsealed\tssh\tsshd:\t-\t1788400000\tdeadbeef").is_ok());
    assert!(matches!(
        GrantRecord::from_line("nope\tsealed\tssh\t-\t-\t1\tde"),
        Err(LedgerError::Kind(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tmaybe\tssh\t-\t-\t1\tde"),
        Err(LedgerError::Delegation(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tBAD!!\t-\t-\t1\tde"),
        Err(LedgerError::Service(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh\t-\t-\tnotanumber\tde"),
        Err(LedgerError::Expiry(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh\t-\t-\t1\tzz"),
        Err(LedgerError::RootId)
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh\tsshd\t-\t1\tde"),
        Err(LedgerError::Served(_))
    ));
    assert!(matches!(
        GrantRecord::from_line("once\tdelegable\tssh\t-\t-\t1\tde"),
        Err(LedgerError::Malformed)
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh"),
        Err(LedgerError::Malformed)
    ));
    assert!(matches!(
        GrantRecord::from_line("bearer\tsealed\tssh\t-\t-\t1\tde\textra"),
        Err(LedgerError::Malformed)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn the_created_ledger_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let (grants, path) = ledger("perms");
    grants
        .append(
            &crate::testkit::lock(),
            &record(
                "ssh",
                GrantKind::Bearer,
                Delegation::Sealed,
                ANYONE,
                1_788_400_000,
            ),
        )
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
        serves: None,
        kind: GrantKind::Bearer,
        delegation: Delegation::Sealed,
        holder: ANYONE.to_owned(),
        root_id: RevocationId::from_bytes(vec![writer, index, u8::from(live)]),
        expiry,
    }
}

/// Two writers, each with its own handle as two processes would have, issue 100 links each while a prune
/// runs on nearly every append (each writer adds an expired row before each live one, and the threshold
/// is one). A prune reads the file and replaces it, so without `home.lock` an append landing in between
/// goes to the replaced file and is lost.
#[test]
fn concurrent_issues_never_lose_a_ledger_row() {
    let dir = std::env::temp_dir().join(format!("swoosh-grants-concurrent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = crate::home::Home::resolve(Some(dir.clone())).expect("a scratch home");
    let path = home.links();
    let writers: Vec<_> = [1u8, 2]
        .into_iter()
        .map(|writer| {
            let path = path.clone();
            let home = home.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime");
                runtime.block_on(async {
                    let grants = Grants::at(path).pruning_at(1);
                    for index in 0..100u8 {
                        let home_lock = crate::home::HomeWrite::take(&home).await.expect("lock");
                        grants
                            .append(&home_lock, &issued(writer, index, false))
                            .expect("append an expired row");
                        grants
                            .append(&home_lock, &issued(writer, index, true))
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// A prune waits for [`PRUNE_AT`](super::PRUNE_AT) expired rows, then drops every expired row and keeps
/// every live one and every line it cannot read.
#[tokio::test]
async fn a_prune_drops_only_expired_rows_once_enough_have_expired() {
    let (grants, path) = ledger("prune");
    for index in 0..u8::try_from(super::PRUNE_AT - 1).expect("fits") {
        grants
            .append(&crate::testkit::lock(), &issued(3, index, false))
            .expect("append an expired row");
    }
    grants
        .append(&crate::testkit::lock(), &issued(3, 200, true))
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
        .append(&crate::testkit::lock(), &issued(3, 250, false))
        .expect("append the expired row that reaches the threshold");
    grants
        .append(&crate::testkit::lock(), &issued(3, 201, true))
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
}

/// A row keeps what its name served when the link was made, `sshd:` or nothing, and a one-use link's
/// kind, through the file.
#[tokio::test]
async fn a_row_keeps_its_served_target_and_its_one_use() {
    let (grants, path) = ledger("served");
    let shell = GrantRecord {
        serves: Some("sshd:".parse().expect("a target")),
        ..record(
            "ssh",
            GrantKind::Once,
            Delegation::Sealed,
            ANYONE,
            1_788_400_000,
        )
    };
    let nothing = record(
        "demo",
        GrantKind::Device,
        Delegation::Sealed,
        "ed01beef",
        1_788_400_001,
    );
    for row in [&shell, &nothing] {
        grants.append(&crate::testkit::lock(), row).expect("append");
    }
    let loaded = grants.load().await.expect("load");
    assert!(
        loaded.len() == 2 && loaded[0] == shell && loaded[1] == nothing,
        "both rows come back with every field"
    );
    assert!(
        std::fs::read_to_string(&path)
            .expect("read")
            .starts_with("once\tsealed\tssh\tsshd:\t-\t"),
        "the target is its own field, after the service"
    );
    let _ = std::fs::remove_file(&path);
}

/// A scratch home holding the ledger rows `records`, for the gate's reading of it.
fn home_with(tag: &str, records: &[GrantRecord]) -> crate::home::Home {
    let dir = std::env::temp_dir().join(format!("swoosh-issued-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    crate::config::create_store_dir(&dir).expect("a scratch home");
    let home = crate::home::Home::resolve(Some(dir)).expect("the scratch home resolves");
    for record in records {
        Grants::at(home.links())
            .append(&crate::testkit::lock(), record)
            .expect("record the row");
    }
    home
}

/// A live one-use link to `ssh`, made while it served `sshd:`, its root id from `id`.
fn once_row(id: u8) -> GrantRecord {
    GrantRecord {
        serves: Some("sshd:".parse().expect("a target")),
        root_id: RevocationId::from_bytes(vec![0x0e, id]),
        expiry: std::time::SystemTime::now() + Duration::from_secs(15 * 60),
        ..record("ssh", GrantKind::Once, Delegation::Sealed, ANYONE, 0)
    }
}

/// The gate's reading of `home`'s ledger for a `serve` that binds `ssh=sshd:`.
fn issued_ledger(home: &crate::home::Home) -> super::IssuedLedger {
    super::IssuedLedger::open(home, crate::serve::BoundTargets::of(["ssh=sshd:"]))
        .expect("the used links read")
}

/// Wait out the ledger's stat debounce, so the next ask re-reads it.
fn past_the_debounce() {
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(50));
}

/// A one-use link spent before a restart stays spent after it: the use is on disk before the admission,
/// and a `serve` started later reads it.
#[test]
fn a_one_use_link_stays_used_across_a_restart() {
    use nauthy::IssuedIds as _;

    let row = once_row(1);
    let home = home_with("once-restart", core::slice::from_ref(&row));
    let first = issued_ledger(&home);
    assert!(first.is_issued(&row.root_id), "the first use");
    assert!(
        !first.is_issued(&row.root_id),
        "the second, in the same run"
    );
    drop(first);
    let restarted = issued_ledger(&home);
    assert!(
        !restarted.is_issued(&row.root_id),
        "a restart does not re-arm it"
    );
}

/// A use that cannot be recorded is refused: the link stays unspent, and works once its use can be written.
#[test]
fn a_one_use_link_whose_use_cannot_be_recorded_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    use nauthy::IssuedIds as _;

    let row = once_row(2);
    let home = home_with("once-unwritable", core::slice::from_ref(&row));
    std::fs::write(home.links_used(), "").expect("make the used file");
    std::fs::set_permissions(home.links_used(), std::fs::Permissions::from_mode(0o400))
        .expect("make it read-only");
    let ledger = issued_ledger(&home);
    assert!(
        !ledger.is_issued(&row.root_id),
        "a use that cannot be written is refused"
    );
    std::fs::set_permissions(home.links_used(), std::fs::Permissions::from_mode(0o600))
        .expect("make it writable");
    assert!(
        ledger.is_issued(&row.root_id),
        "the refused ask spent nothing"
    );
}

/// Two first uses at the same moment admit one: the check and the mark are one step under the lock.
#[test]
fn two_first_uses_at_once_admit_one() {
    use nauthy::IssuedIds as _;

    let row = once_row(3);
    let home = home_with("once-race", core::slice::from_ref(&row));
    let ledger = std::sync::Arc::new(issued_ledger(&home));
    let start = std::sync::Arc::new(std::sync::Barrier::new(8));
    let admitted: usize = (0..8)
        .map(|_| {
            let (ledger, start, id) = (
                std::sync::Arc::clone(&ledger),
                std::sync::Arc::clone(&start),
                row.root_id.clone(),
            );
            std::thread::spawn(move || {
                start.wait();
                ledger.is_issued(&id)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| usize::from(thread.join().expect("the use ends")))
        .sum();
    assert_eq!(admitted, 1, "exactly one first use is admitted");
}

/// A spent mark is dropped from memory once its row leaves the ledger, so the set never outgrows it.
#[test]
fn a_used_mark_is_trimmed_when_its_row_leaves_the_ledger() {
    use nauthy::IssuedIds as _;

    let (spent, kept) = (once_row(4), once_row(5));
    let home = home_with("once-trim", &[spent.clone(), kept.clone()]);
    let ledger = issued_ledger(&home);
    assert!(ledger.is_issued(&spent.root_id), "the use");
    let used = |ledger: &super::IssuedLedger| {
        ledger
            .state
            .lock()
            .expect("the ledger's lock")
            .used
            .contains(&spent.root_id)
    };
    assert!(used(&ledger), "marked while its row is on file");

    std::fs::write(home.links(), format!("{}\n", kept.to_line())).expect("drop the row");
    past_the_debounce();
    assert!(
        ledger.is_issued(&kept.root_id),
        "the other row is read again"
    );
    assert!(!used(&ledger), "the mark left with its row");
}

/// A link is admitted only against the target its service's name is bound to in this run: one made while
/// `ssh` was a forward is refused by a `serve` that binds a shell there.
#[test]
fn a_link_made_for_another_target_is_refused_by_the_gate() {
    use nauthy::IssuedIds as _;

    let forward = GrantRecord {
        serves: Some("tcp:localhost:22".parse().expect("a target")),
        root_id: RevocationId::from_bytes(vec![0x0f, 1]),
        expiry: std::time::SystemTime::now() + Duration::from_secs(3600),
        ..record("ssh", GrantKind::Bearer, Delegation::Delegable, ANYONE, 0)
    };
    let home = home_with("retarget", core::slice::from_ref(&forward));
    assert!(
        !issued_ledger(&home).is_issued(&forward.root_id),
        "a shell is bound under ssh"
    );
    let as_forward = super::IssuedLedger::open(
        &home,
        crate::serve::BoundTargets::of(["ssh=tcp:localhost:22"]),
    )
    .expect("the used links read");
    assert!(
        as_forward.is_issued(&forward.root_id),
        "the forward it was made for"
    );
}

/// Used links that cannot be read leave which one-use links were spent unknown, so the gate is not built.
#[test]
fn unreadable_used_links_build_no_gate() {
    let home = home_with("once-unreadable", &[]);
    std::fs::create_dir(home.links_used()).expect("a directory where the file goes");
    assert!(
        super::IssuedLedger::open(&home, crate::serve::BoundTargets::default()).is_err(),
        "no gate over unreadable used links"
    );
}
