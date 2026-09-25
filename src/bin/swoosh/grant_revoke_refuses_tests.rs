// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Issue a device-bound grant, revoke it BY HOLDER through the mint-log ledger, and prove the gate's
//! revocation check then refuses the very cap that was issued. This is the load-bearing seam behind
//! `swoosh grant revoke <holder>`: the link leaves the machine, but its ROOT revocation id is recorded in
//! the ledger, so naming the holder later cuts the cap off at the gate without ever seeing the link again.
//!
//! The flow mirrors the product path exactly: `grant issue --for` mints a bound link and records the grant;
//! `grant revoke <holder>` (driven here through the real [`RevokeCmd`](revoke::RevokeCmd)) loads the ledger, finds the root id,
//! and denylists it. A live exposer's gate consults [`FileDenylist::is_revoked`] on every dial, so asserting it
//! now refuses the cap is asserting the gate refuses it.

use core::time::Duration;

use bifrost::NodeId;
use nauthy::{Cap, FileDenylist, Request, Service};
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::testkit::TestRoot;
use tightbeam::identity::AsVerifyKey as _;

use crate::commands::revoke;

/// How long every grant here lives.
const HOUR: Duration = Duration::from_secs(3600);

#[tokio::test]
async fn revoking_by_holder_makes_the_gate_refuse_the_cap() {
    let dir = std::env::temp_dir().join(format!("swoosh-grant-revoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = Home::resolve(Some(dir.clone())).unwrap();

    // The issuer's key.
    let issuer = TestRoot::seeded(3);
    let service: Service = "ssh".parse().unwrap();

    // The device the grant binds to; its canonical node id is the holder the ledger records.
    let device = NodeId::from_ed25519_secret(&[7u8; 32]);
    let holder = device.to_string();

    // Mint the device-bound link the issuer hands off, then recover the cap and its root revocation id.
    let link = issuer
        .bound_slip(
            &service,
            device.verify_key().expect("a usable key"),
            Request::expires_in(HOUR),
        )
        .unwrap();
    let cap = Cap::parse(link.as_str()).unwrap();
    let root_id = cap.root_revocation_id().unwrap();

    // Record the grant in the mint-log ledger, as `grant issue --for` does.
    let record = GrantRecord {
        target: service.clone(),
        kind: GrantKind::Device,
        delegation: Delegation::Sealed,
        holder: holder.clone(),
        root_id,
        expiry: nauthy::Request::expires_in(Duration::from_secs(3600)),
    };
    Grants::at(home.links()).append(&record).await.unwrap();

    // Before revocation: the cap is a valid grant for the bound device, and nothing revokes it.
    let request =
        Request::now(service.clone()).bound_to(device.verify_key().expect("a usable key"));
    assert!(
        cap.verify_at_root_without_revocation(&request, issuer.verify_key())
            .is_ok(),
        "the freshly minted device-bound cap grants its service to its device"
    );
    let denylist = FileDenylist::load(home.revoked()).await.unwrap();
    assert!(
        !denylist.is_revoked(&cap),
        "the cap is not revoked before `grant revoke`"
    );

    // Revoke BY HOLDER (the raw node id) through the real command path: loads the ledger, finds the root id,
    // denylists it. An empty address book suffices, since the target is already a canonical node id.
    let store = ContactsStore::open(home.contacts()).await.unwrap();
    revoke::RevokeCmd {
        target: holder.clone(),
    }
    .run(store, &home)
    .await
    .unwrap();

    // After revocation: the gate's revocation check (the seam a live exposer consults) now refuses the cap.
    let denylist = FileDenylist::load(home.revoked()).await.unwrap();
    assert!(
        denylist.is_revoked(&cap),
        "once the holder is revoked, the gate refuses the very cap that was issued"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
