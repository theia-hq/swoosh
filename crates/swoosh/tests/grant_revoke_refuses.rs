// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Issue a device-bound grant, revoke it BY HOLDER through the mint-log ledger, and prove the gate's
//! revocation check then refuses the very cap that was issued. This is the load-bearing seam behind
//! `swoosh grant revoke <holder>`: the link leaves the machine, but its ROOT revocation id is recorded in
//! the ledger, so naming the holder later cuts the cap off at the gate without ever seeing the link again.
//!
//! The flow mirrors the product path exactly: `grant issue --for` mints a bound link and records the grant;
//! `grant revoke <holder>` (driven here through the real [`RevokeCmd`]) loads the ledger, finds the root id,
//! and denylists it. A live exposer's gate consults [`FileDenylist::is_revoked`] on every dial, so asserting it
//! now refuses the cap is asserting the gate refuses it.

use core::time::Duration;

use bifrost::NodeId;
use nauthy::{Cap, FileDenylist, Request, Service};
use swoosh::commands::revoke::RevokeCmd;
use swoosh::config;
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, GrantRecord, Grants};
use swoosh::identity::{self, Identity};
use tightbeam::identity::AsVerifyKey as _;

#[tokio::test]
async fn revoking_by_holder_makes_the_gate_refuse_the_cap() {
    let dir = std::env::temp_dir().join(format!("swoosh-grant-revoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("identity.key");

    // The issuer identity, persisted at `key` exactly as `grant issue` resolves it.
    let secret = identity::resolve(Identity::Persisted, Some(&key))
        .await
        .unwrap();
    let cap_identity = secret.cap_identity().unwrap();
    let service: Service = "ssh".parse().unwrap();

    // The device the grant binds to; its canonical node id is the holder the ledger records.
    let device = NodeId::from_ed25519_secret(&[7u8; 32]);
    let holder = device.to_string();

    // Mint the device-bound link the issuer hands off, then recover the cap and its root revocation id.
    let link = tightbeam::tunnel::mint_bound_link(
        &cap_identity,
        &service,
        device.verify_key(),
        Duration::from_secs(3600),
    )
    .unwrap();
    let cap = Cap::parse(&link).unwrap();
    let root_id = cap.root_revocation_id().unwrap();

    // Record the grant in the mint-log ledger, as `grant issue --for` does.
    let record = GrantRecord {
        service: service.clone(),
        kind: GrantKind::Device,
        delegation: Delegation::Sealed,
        holder: holder.clone(),
        root_id,
        expiry: nauthy::Request::expires_in(Duration::from_secs(3600)),
    };
    Grants::at(config::grants_path(Some(&key)).unwrap())
        .append(&record)
        .await
        .unwrap();

    // Before revocation: the cap is a valid grant for the bound device, and nothing revokes it.
    let request = Request::now(service.clone()).bound_to(device.verify_key());
    assert!(
        cap_identity.verify(&cap, &request).is_ok(),
        "the freshly minted device-bound cap grants its service to its device"
    );
    let denylist = FileDenylist::load(config::revoked_path(Some(&key)).unwrap())
        .await
        .unwrap();
    assert!(
        !denylist.is_revoked(&cap),
        "the cap is not revoked before `grant revoke`"
    );

    // Revoke BY HOLDER (the raw node id) through the real command path: loads the ledger, finds the root id,
    // denylists it. An empty address book suffices, since the target is already a canonical node id.
    let store = ContactsStore::open(dir.join("contacts.toml"))
        .await
        .unwrap();
    RevokeCmd {
        target: holder.clone(),
    }
    .run(store, Some(&key))
    .await
    .unwrap();

    // After revocation: the gate's revocation check (the seam a live exposer consults) now refuses the cap.
    let denylist = FileDenylist::load(config::revoked_path(Some(&key)).unwrap())
        .await
        .unwrap();
    assert!(
        denylist.is_revoked(&cap),
        "once the holder is revoked, the gate refuses the very cap that was issued"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
