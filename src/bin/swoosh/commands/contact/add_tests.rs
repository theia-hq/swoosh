use bifrost::NodeId;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;

use super::AddCmd;

/// A scratch home holding an identity key (so it is its own signet) and a contacts book that is already
/// versioned, with NO roster artifact on disk. Any cut after this point is visible as the file appearing.
async fn versioned_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-contact-add-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
    swoosh::identity::write(&[31u8; 32], &home)
        .await
        .expect("write the key");
    let mut store = ContactsStore::open(home.contacts()).await.expect("open");
    store.contacts_mut().add(
        "me".parse().expect("me"),
        Some("desk".parse().expect("label")),
        NodeId::from_ed25519_secret(&[4u8; 32]),
    );
    store.save().await.expect("save");
    home
}

async fn add(home: &Home, name: &str, key: NodeId) {
    let store = ContactsStore::open(home.contacts()).await.expect("open");
    AddCmd {
        name: name.parse().expect("a valid contact ref"),
        key,
    }
    .run(store, home)
    .await
    .expect("add");
}

/// Adding a device under `me/` re-cuts the signed roster there and then, so the next pull sees the new
/// member with no restart and no second verb. This is the founder's exact loop: invite (or record) a
/// device from another terminal while a node is serving.
#[tokio::test]
async fn an_add_under_me_re_cuts_the_signed_roster() {
    let home = versioned_home("me").await;
    assert!(!home.roster().exists(), "nothing is cut yet");
    add(&home, "me/phone", NodeId::from_ed25519_secret(&[5u8; 32])).await;
    assert!(
        home.roster().exists(),
        "a fleet edit must publish a fresh signed roster"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Adding anyone ELSE is a purely local name and cuts nothing. Signing is bound to a CHANGE in the
/// member set, not to the verb that ran, so a book full of peers never re-publishes a fleet.
#[tokio::test]
async fn an_add_outside_me_cuts_nothing() {
    let home = versioned_home("other").await;
    add(
        &home,
        "alice/macbook",
        NodeId::from_ed25519_secret(&[6u8; 32]),
    )
    .await;
    assert!(
        !home.roster().exists(),
        "a contact who is not in your fleet is not a membership change"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Re-recording a `me/` device at the SAME key changes no member, so it publishes nothing. This is the
/// renewal shape at the verb level: the set is byte-identical, so the fleet is not asked to re-pull.
#[tokio::test]
async fn re_adding_me_at_the_same_key_cuts_nothing() {
    let home = versioned_home("same").await;
    add(&home, "me/desk", NodeId::from_ed25519_secret(&[4u8; 32])).await;
    assert!(
        !home.roster().exists(),
        "an unchanged member set must not publish a new roster"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}
