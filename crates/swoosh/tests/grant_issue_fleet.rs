// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `swoosh grant issue <svc> --for-fleet <signet>`: mint a signet-bound slip for a whole fleet, recorded in
//! the mint-log ledger as a `Fleet` grant keyed by the signet, and revocable by holder exactly like every
//! other grant. Plus the two guards: `--for-fleet` refuses `--delegable` (a bound grant is non-delegable),
//! and `--for-fleet <petname>` bails (a petname resolves to device keys, not a person's signet root).
//!
//! This drives the real [`ShareCmd`] the CLI dispatches, so the ledger record and its revocation key are the
//! product path, not a reconstruction.

use bifrost::NodeId;
use nauthy::Service;
use swoosh::commands::share::ShareCmd;
use swoosh::config;
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, Grants};
use tightbeam::duration::Lifetime;

/// A `ShareCmd` for `svc`, with the fleet/device/delegable knobs set explicitly.
fn share(
    service: &str,
    bind_fleet: Option<String>,
    bind_device: Option<String>,
    delegable: bool,
) -> ShareCmd {
    ShareCmd {
        service: service.parse::<Service>().unwrap(),
        expires: "1h".parse::<Lifetime>().unwrap(),
        bind_device,
        bind_fleet,
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

    share("ssh", Some(hire_signet.to_string()), None, false)
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
        "a --for-fleet grant is Fleet"
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
async fn for_fleet_refuses_delegable() {
    let dir = std::env::temp_dir().join(format!("swoosh-grant-fleet-deleg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("identity.key");
    let hire_signet = NodeId::from_ed25519_secret(&[3u8; 32]);

    let error = share("ssh", Some(hire_signet.to_string()), None, true)
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
async fn for_fleet_with_a_petname_bails_with_a_teaching_message() {
    let dir =
        std::env::temp_dir().join(format!("swoosh-grant-fleet-petname-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("identity.key");

    let error = share("ssh", Some("alice".to_owned()), None, false)
        .run(store_at(&dir).await, Some(&key))
        .await
        .expect_err("a petname cannot resolve to a foreign signet in v1");
    let message = format!("{error:#}");
    assert!(
        message.contains("SIGNET") && message.contains("alice"),
        "the bail teaches that --for-fleet needs a signet key, not a petname: {message}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
