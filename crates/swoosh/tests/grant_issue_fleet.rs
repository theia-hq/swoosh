// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `swoosh grant issue <svc> --for fleet:<who>`: mint a signet-bound slip for a whole fleet, recorded in the
//! mint-log ledger as a `Fleet` grant keyed by the signet, and revocable by holder exactly like every other
//! grant. `fleet:<raw-signet>` binds the pasted key; `fleet:<petname>` binds that person's STORED signet
//! (`swoosh contact signet`). Plus the two guards: a fleet bind refuses `--delegable` (a bound grant is
//! non-delegable), and `fleet:<petname>` with no signet on file bails with a teaching error that names the
//! hand-add recipe, never a paste-a-raw-key dead end.
//!
//! This drives the real [`ShareCmd`] the CLI dispatches, so the ledger record and its revocation key are the
//! product path, not a reconstruction.

use bifrost::NodeId;
use nauthy::Service;
use swoosh::commands::share::{GrantFor, ShareCmd};
use swoosh::config;
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, Grants};
use tightbeam::duration::Lifetime;

/// A `ShareCmd` for `svc`, with the `--for` token and `--delegable` set explicitly. The token parses through
/// the real `GrantFor` boundary, exactly as clap would.
fn share(service: &str, bind: Option<&str>, delegable: bool) -> ShareCmd {
    ShareCmd {
        service: service.parse::<Service>().unwrap(),
        expires: "1h".parse::<Lifetime>().unwrap(),
        bind: bind.map(|token| token.parse::<GrantFor>().unwrap()),
        delegable,
    }
}

async fn store_at(dir: &std::path::Path) -> ContactsStore {
    ContactsStore::open(dir.join("contacts.toml"))
        .await
        .unwrap()
}

#[tokio::test]
async fn issuing_for_a_raw_signet_records_a_fleet_grant_keyed_by_the_signet() {
    let dir = std::env::temp_dir().join(format!("swoosh-grant-fleet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("identity.key");

    // The hire's signet, handed over out of band as a raw node id.
    let hire_signet = NodeId::from_ed25519_secret(&[2u8; 32]);

    share("ssh", Some(&format!("fleet:{hire_signet}")), false)
        .run(store_at(&dir).await, Some(&key))
        .await
        .expect("issuing a fleet grant for a raw signet succeeds");

    // The ledger records exactly one Fleet grant, sealed, keyed by the signet key string.
    let records = Grants::at(config::grants_path(Some(&key)).unwrap())
        .load()
        .await
        .unwrap();
    let [record] = records.as_slice() else {
        panic!("expected exactly one recorded grant, got {}", records.len());
    };
    assert_eq!(
        record.kind,
        GrantKind::Fleet,
        "a --for fleet: grant is Fleet"
    );
    assert_eq!(
        record.delegation,
        Delegation::Sealed,
        "a fleet grant is sealed (theft-resistant, non-delegable)"
    );
    assert!(
        !record.root_id.to_hex().is_empty(),
        "the ledger records a root revocation id so `grant revoke <signet>` can cut it"
    );
    assert_eq!(
        record.holder,
        hire_signet.to_string(),
        "the holder is the resolved signet key, so `grant revoke <signet>` matches it"
    );
    assert_eq!(
        record.service.as_str(),
        "ssh",
        "the grant records the service it was issued for"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn issuing_for_a_petname_binds_that_persons_stored_signet() {
    let dir = std::env::temp_dir().join(format!("swoosh-grant-fleet-name-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("identity.key");

    // Alice's signet, recorded locally by hand (`swoosh contact signet alice <key>`).
    let alice_signet = NodeId::from_ed25519_secret(&[4u8; 32]);
    let mut store = store_at(&dir).await;
    store
        .contacts_mut()
        .set_signet("alice".parse().unwrap(), alice_signet);
    store.save().await.unwrap();

    // `--for fleet:alice` resolves alice's stored signet and binds the fleet grant to it.
    share("ssh", Some("fleet:alice"), false)
        .run(store_at(&dir).await, Some(&key))
        .await
        .expect("a petname with a stored signet resolves and mints");

    let records = Grants::at(config::grants_path(Some(&key)).unwrap())
        .load()
        .await
        .unwrap();
    let [record] = records.as_slice() else {
        panic!("expected exactly one recorded grant, got {}", records.len());
    };
    assert_eq!(record.kind, GrantKind::Fleet);
    assert_eq!(
        record.holder,
        alice_signet.to_string(),
        "the holder is alice's STORED signet, resolved from her petname"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn for_fleet_refuses_delegable() {
    let dir = std::env::temp_dir().join(format!("swoosh-grant-fleet-deleg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("identity.key");
    let hire_signet = NodeId::from_ed25519_secret(&[3u8; 32]);

    let error = share("ssh", Some(&format!("fleet:{hire_signet}")), true)
        .run(store_at(&dir).await, Some(&key))
        .await
        .expect_err("a bound fleet grant cannot be delegable");
    let message = format!("{error:#}");
    assert!(
        message.contains("delegated") || message.contains("delegable"),
        "the refusal explains a bound grant cannot be delegated: {message}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn for_fleet_with_an_unknown_petname_teaches_the_hand_add_recipe() {
    let dir =
        std::env::temp_dir().join(format!("swoosh-grant-fleet-petname-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("identity.key");

    // `--for fleet:alice` with NO signet on file: a teaching error naming the hand-add recipe, never a
    // paste-a-raw-key dead end.
    let error = share("ssh", Some("fleet:alice"), false)
        .run(store_at(&dir).await, Some(&key))
        .await
        .expect_err("a petname with no stored signet cannot resolve");
    let message = format!("{error:#}");
    assert!(
        message.contains("alice") && message.contains("swoosh contact signet"),
        "the bail teaches how to record alice's signet, not to paste a raw key: {message}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
