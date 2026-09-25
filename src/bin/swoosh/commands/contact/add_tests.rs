use bifrost::NodeId;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;

use super::AddCmd;

/// A scratch home with a contacts book holding `me/desk`, as a fold of this person's devices leaves it.
async fn home_with_book(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-contact-add-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
    let mut store = ContactsStore::open(home.contacts()).await.expect("open");
    store.contacts_mut().add(
        "me".parse().expect("me"),
        Some("desk".parse().expect("label")),
        NodeId::from_ed25519_secret(&[4u8; 32]),
    );
    store.save().await.expect("save");
    home
}

async fn add(home: &Home, name: &str, key: NodeId) -> eyre::Result<()> {
    let store = ContactsStore::open(home.contacts()).await.expect("open");
    AddCmd {
        name: name.parse().expect("a valid contact ref"),
        key,
    }
    .run(store)
    .await
}

/// `me/` is decided by this person's root, so a typed add under it refuses, names the verbs that do add
/// and remove a device, and leaves the book byte-identical.
#[tokio::test]
async fn contact_add_me_is_refused_and_writes_nothing() {
    let home = home_with_book("me").await;
    let before = std::fs::read(home.contacts()).expect("read the book");
    let error = add(&home, "me/phone", NodeId::from_ed25519_secret(&[5u8; 32]))
        .await
        .expect_err("an add under me/ refuses");
    let message = format!("{error:#}");
    assert!(
        message.contains("swoosh invite <name> <key>")
            && message.contains("swoosh revoke me/<name>"),
        "the refusal names both verbs: {message}"
    );
    assert_eq!(
        std::fs::read(home.contacts()).expect("read the book"),
        before,
        "nothing is written"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Every other name is the address book's to keep.
#[tokio::test]
async fn an_add_outside_me_is_saved() {
    let home = home_with_book("other").await;
    add(
        &home,
        "alice/macbook",
        NodeId::from_ed25519_secret(&[6u8; 32]),
    )
    .await
    .expect("an add outside me/ is saved");
    let store = ContactsStore::open(home.contacts()).await.expect("open");
    assert!(
        store
            .contacts()
            .petnames()
            .any(|petname| petname.as_str() == "alice"),
        "alice is in the book"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}
