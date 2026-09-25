use bifrost::NodeId;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;

use super::RmCmd;

/// A scratch home with `me/desk` and `alice/macbook` on file.
async fn populated_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-contact-rm-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
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

async fn remove(home: &Home, name: &str) -> eyre::Result<()> {
    let store = ContactsStore::open(home.contacts()).await.expect("open");
    RmCmd {
        name: name.parse().expect("a valid contact ref"),
    }
    .run(store)
    .await
}

/// A device leaves `me/` by `revoke`, which its root records; a typed removal refuses and leaves the book
/// byte-identical.
#[tokio::test]
async fn contact_rm_me_is_refused() {
    let home = populated_home("me").await;
    let before = std::fs::read(home.contacts()).expect("read the book");
    let error = remove(&home, "me/desk")
        .await
        .expect_err("a removal under me/ refuses");
    assert!(
        format!("{error:#}").contains("swoosh revoke me/<name>"),
        "the refusal names revoke: {error:#}"
    );
    assert_eq!(
        std::fs::read(home.contacts()).expect("read the book"),
        before,
        "nothing is written"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Forgetting a peer's name is the address book's own edit.
#[tokio::test]
async fn removing_a_peer_is_saved() {
    let home = populated_home("peer").await;
    remove(&home, "alice/macbook")
        .await
        .expect("a removal outside me/ is saved");
    let store = ContactsStore::open(home.contacts()).await.expect("open");
    assert!(
        !store
            .contacts()
            .petnames()
            .any(|petname| petname.as_str() == "alice"),
        "alice is gone"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}
