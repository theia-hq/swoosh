use bifrost::NodeId;
use swoosh::contacts::{Contacts, DeviceLabel, Petname};
use swoosh::home::Home;
use swoosh::roster::Artifact;

use super::after_membership_change;

/// A scratch home with an identity key already written, so the helper LOADS one rather than minting it.
async fn provisioned_home(tag: &str) -> (Home, NodeId) {
    let dir = std::env::temp_dir().join(format!("swoosh-recut-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
    let seed = [21u8; 32];
    swoosh::identity::write(&seed, &home)
        .await
        .expect("write the key");
    (home, NodeId::from_ed25519_secret(&seed))
}

fn me_with(label: &str) -> Contacts {
    let mut contacts = Contacts::default();
    contacts.add(
        "me".parse::<Petname>().expect("me"),
        Some(label.parse::<DeviceLabel>().expect("a valid label")),
        NodeId::from_ed25519_secret(&[3u8; 32]),
    );
    contacts
}

/// The happy path: the signet's own machine cuts an artifact a puller can verify against it.
#[tokio::test]
async fn the_signets_machine_cuts_a_verifiable_roster() {
    let (home, signet) = provisioned_home("signet").await;
    after_membership_change(&home, &me_with("desk"))
        .await
        .expect("cut");
    let artifact = Artifact::open(home.roster()).await.expect("load");
    let doc = swoosh::roster::verify(
        &artifact.bytes(),
        tightbeam::identity::AsVerifyKey::verify_key(&signet),
    )
    .expect("the artifact verifies against the signet that cut it");
    assert_eq!(doc.members().len(), 1);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A MEMBER device (one that trusts a signet that is not its own key) writes NO artifact. This is the
/// property that makes a relay-only node physically unable to mis-cut: the old path signed with whatever
/// local key it held, so such a node served a blob every puller refused, silently.
#[tokio::test]
async fn a_member_device_cuts_nothing() {
    let (home, _) = provisioned_home("member").await;
    swoosh::config::write_signet(&home, NodeId::from_ed25519_secret(&[99u8; 32]))
        .await
        .expect("adopt a foreign signet");
    after_membership_change(&home, &me_with("desk"))
        .await
        .expect("a member device is a silent no-op, not an error");
    assert!(
        !home.roster().exists(),
        "a device that does not hold the signet must never write a roster"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// An UNVERSIONED book publishes nothing: there is no membership set worth a puller's floor yet, and
/// emitting the reserved epoch 0 is exactly what every stuck fleet in the field is already doing.
#[tokio::test]
async fn an_unversioned_book_cuts_nothing() {
    let (home, _) = provisioned_home("unversioned").await;
    after_membership_change(&home, &Contacts::default())
        .await
        .expect("no-op");
    assert!(!home.roster().exists());
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Editing an address book must never MINT the root key a later `serve` would gate a whole fleet on.
#[tokio::test]
async fn a_home_with_no_key_is_left_exactly_as_found() {
    let dir = std::env::temp_dir().join(format!("swoosh-recut-nokey-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
    after_membership_change(&home, &me_with("desk"))
        .await
        .expect("no-op");
    assert!(!home.identity_key().exists(), "no key was minted");
    assert!(!home.roster().exists(), "and no roster was cut");
    let _ = std::fs::remove_dir_all(home.dir());
}
