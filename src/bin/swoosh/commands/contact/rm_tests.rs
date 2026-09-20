use bifrost::NodeId;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;

use super::RmCmd;

/// A scratch home that is its own signet, with `me/desk` and `alice/macbook` on file and no roster cut
/// yet, so any cut a removal triggers is visible as the artifact appearing.
async fn populated_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-contact-rm-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
    swoosh::identity::write(&[41u8; 32], &home)
        .await
        .expect("write the key");
    let mut store = ContactsStore::open(home.contacts()).await.expect("open");
    store.contacts_mut().add(
        "me".parse().expect("me"),
        Some("desk".parse().expect("label")),
        NodeId::from_ed25519_secret(&[4u8; 32]),
    );
    store.contacts_mut().add(
        "alice".parse().expect("alice"),
        Some("macbook".parse().expect("label")),
        NodeId::from_ed25519_secret(&[5u8; 32]),
    );
    store.save().await.expect("save");
    home
}

async fn remove(home: &Home, name: &str) {
    let store = ContactsStore::open(home.contacts()).await.expect("open");
    RmCmd {
        name: name.parse().expect("a valid contact ref"),
    }
    .run(store, home)
    .await
    .expect("rm");
}

/// Removing a device under `me/` is how a machine LEAVES the fleet (`invite rm` cancels its badge and
/// deliberately keeps the name), so it re-cuts: the next pull drops the device everywhere.
#[tokio::test]
async fn removing_a_me_device_re_cuts_the_signed_roster() {
    let home = populated_home("me").await;
    assert!(!home.roster().exists(), "nothing is cut yet");
    remove(&home, "me/desk").await;
    assert!(
        home.roster().exists(),
        "a departure must publish a fresh signed roster"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Forgetting a peer's name is not a fleet change.
#[tokio::test]
async fn removing_a_peer_cuts_nothing() {
    let home = populated_home("peer").await;
    remove(&home, "alice/macbook").await;
    assert!(!home.roster().exists());
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Removing something that is not there changed no member, so it publishes nothing.
#[tokio::test]
async fn removing_an_absent_me_device_cuts_nothing() {
    let home = populated_home("absent").await;
    remove(&home, "me/ghost").await;
    assert!(!home.roster().exists());
    let _ = std::fs::remove_dir_all(home.dir());
}
