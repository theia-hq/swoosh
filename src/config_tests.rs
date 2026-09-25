//! The store's private posture on disk: a trust file (`signet`, `badge`) written beside the identity is
//! created owner-only (`0600`) and the store dir owner-only (`0700`), so a co-tenant local user cannot read
//! this node's trust graph. The bug this guards: bare `write`/`create_dir_all` left these `0644` in a
//! likely-`0755` dir whenever the mint-log did not happen to create the dir first.
//!
//! The badge round trip is pinned here too: it is the one credential the store parses on the way out, so
//! what a write puts down a read must give back as the same link, and a file holding anything else must
//! refuse with the escape named rather than hand a reach path a badge the far gate will silently drop.

use std::path::PathBuf;

use nauthy::Link;

use crate::home::Home;
use crate::identity::Secret;

/// A unique store dir under the temp dir, resolved as an explicit [`Home`] (so its trust files derive from
/// that dir). Returns `(home, store_dir)`; the store dir does not exist yet, so a write under it exercises
/// the `0700` create.
fn store(tag: &str) -> (Home, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-config-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");
    (home, dir)
}

/// A real signed membership badge: the store parses what it reads now, so a stand-in string would
/// only prove the reader is lenient.
fn minted_badge() -> Link {
    crate::testkit::TestRoot::seeded(0xb0)
        .device_badge(
            crate::testkit::TestNode::seeded(0xb1).node_id(),
            nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
        )
        .expect("mint a membership badge")
}

#[cfg(unix)]
#[tokio::test]
async fn a_written_badge_is_owner_only_in_an_owner_only_store() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = store("badge-perms");
    super::write_badge(&home, &minted_badge())
        .await
        .expect("write the badge into a fresh store");

    let dir_mode = std::fs::metadata(&dir)
        .expect("stat the store dir")
        .permissions()
        .mode();
    assert_eq!(
        dir_mode & 0o777,
        0o700,
        "the store dir is created 0700 (owner-only), not left group/world-traversable"
    );

    let file_mode = std::fs::metadata(home.badge())
        .expect("stat the badge")
        .permissions()
        .mode();
    assert_eq!(
        file_mode & 0o777,
        0o600,
        "the badge is written 0600 (owner read/write only), never world-readable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[tokio::test]
async fn a_loosened_trust_file_is_retightened_on_rewrite() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = store("badge-retighten");
    super::write_badge(&home, &minted_badge())
        .await
        .expect("first badge write");
    let badge = home.badge();
    // Simulate a file loosened after an earlier write; the next write must reassert 0600.
    std::fs::set_permissions(&badge, std::fs::Permissions::from_mode(0o644))
        .expect("loosen the badge");
    super::write_badge(&home, &minted_badge())
        .await
        .expect("second badge write");

    let mode = std::fs::metadata(&badge)
        .expect("stat the badge")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "a rewrite reasserts 0600 even on a pre-existing, loosened file"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An unprovisioned home reads as no badge, and so does an EMPTY badge file: neither is a corrupt store,
/// so both dial presenting no badge rather than failing the dial. The empty case is the one a truncated
/// write leaves behind, so it must stay a `None` and not reach the parser.
#[tokio::test]
async fn an_absent_or_empty_badge_file_reads_as_none() {
    let (home, dir) = store("badge-absent");
    assert!(
        super::load_badge(&home)
            .await
            .expect("an unprovisioned home is not an error")
            .is_none(),
        "a home with no badge file has no badge, it is not a failure"
    );

    super::create_store_dir(&dir).expect("create the store dir");
    std::fs::write(home.badge(), "   \n").expect("write a blank badge file");
    assert!(
        super::load_badge(&home)
            .await
            .expect("a blank badge file is not an error")
            .is_none(),
        "a blank badge file reads as no badge, never as an empty link"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The store's round trip: what `write_badge` puts down, `load_badge` gives back as the SAME link, so the
/// credential a dial presents is byte-identical to the one `adopt` stored (the far gate re-parses the exact
/// text, so a decode/re-encode drift would be a refusal nobody could explain).
#[tokio::test]
async fn a_written_badge_reads_back_as_the_same_link() {
    let (home, dir) = store("badge-round-trip");
    let minted = minted_badge();
    super::write_badge(&home, &minted)
        .await
        .expect("write the minted badge");

    let loaded = super::load_badge(&home)
        .await
        .expect("the stored badge loads")
        .expect("a written badge is present");
    assert_eq!(
        loaded.as_str(),
        minted.as_str(),
        "the badge reads back verbatim, the exact bytes the far gate re-parses"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A badge file holding something that is not a link FAILS CLOSED at the load, naming the file and
/// the escape (`adopt --force`, the only adopt that does not itself run this load). Before the parse moved
/// to the edge, the junk travelled the whole reach path and the peer refused it with nothing said.
#[tokio::test]
async fn a_corrupt_badge_file_fails_closed_and_names_the_fix() {
    let (home, dir) = store("badge-corrupt");
    super::create_store_dir(&dir).expect("create the store dir");
    std::fs::write(home.badge(), "not-a-real-link\n").expect("write a corrupt badge file");

    let error = super::load_badge(&home)
        .await
        .expect_err("a badge that does not decode must refuse, never be carried as if valid");
    let chain = format!("{error:#}");
    assert!(
        chain.contains(&home.badge().display().to_string()),
        "the message names the file to fix: {chain}"
    );
    assert!(
        chain.contains("swoosh adopt --force"),
        "the message names the escape that does not loop back through this same load: {chain}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Disable `key` in `home`'s latch the way a writer on this machine would.
async fn disable(home: &Home, dir: &std::path::Path, key: bifrost::NodeId) {
    use tightbeam::identity::AsVerifyKey as _;

    super::create_store_dir(dir).expect("create the store dir");
    nauthy::DisabledRoots::open_for_repair(home.disabled_roots())
        .disable(key.verify_key())
        .await
        .expect("disable the key");
}

#[tokio::test]
async fn a_disabled_key_reads_disabled_and_no_other_does() {
    let (home, dir) = store("disabled-roots");
    let (disabled, other) = (Secret::ephemeral().node_id(), Secret::ephemeral().node_id());
    assert!(
        !super::is_disabled(&home, disabled)
            .await
            .expect("no latch reads"),
        "a home that never disabled anything disables nothing"
    );
    disable(&home, &dir, disabled).await;
    assert!(
        super::is_disabled(&home, disabled).await.expect("read"),
        "the disabled key"
    );
    assert!(
        !super::is_disabled(&home, other).await.expect("read"),
        "and only that key"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_unreadable_latch_is_an_error_not_an_empty_set() {
    // Fail closed: a verb that cannot tell whether a key is disabled must not follow it.
    let (home, dir) = store("disabled-roots-bad");
    super::create_store_dir(&dir).expect("create the store dir");
    std::fs::write(home.disabled_roots(), "not a key\n").expect("write a bad latch");
    assert!(
        super::is_disabled(&home, Secret::ephemeral().node_id())
            .await
            .is_err(),
        "a malformed latch refuses rather than reading as nothing disabled"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pin write is durable in its directory, not only in its bytes: after the rename the parent is
/// synced, so the pin (the commit point) can never be on disk while a file ordered before it is not.
/// Counted through the sync seam, on a current-thread runtime so every sync lands on this thread.
#[tokio::test(flavor = "current_thread")]
async fn the_atomic_write_fsyncs_its_directory() {
    let (home, dir) = store("dir-fsync");
    super::SYNCS.with_borrow_mut(Vec::clear);
    super::write_signet(&home, crate::testkit::TestRoot::seeded(0xd1).node_id())
        .await
        .expect("write the pin");
    let syncs = super::SYNCS.with_borrow(Clone::clone);
    assert_eq!(
        syncs,
        vec![super::Synced::File, super::Synced::Dir],
        "the bytes, then the directory that names them"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
