use bifrost::NodeId;
use clap::Parser as _;
use swoosh::contacts::{ContactRef, ContactsStore};
use swoosh::home::Home;
use swoosh::names::NameError;

use super::AddCmd;
use crate::Cli;

/// Parse `swoosh contact add <name> <key>` the way the binary does.
fn parse_add(name: &str) -> Result<Cli, clap::Error> {
    let key = NodeId::from_ed25519_secret(&[9u8; 32]).to_string();
    Cli::try_parse_from(["swoosh", "contact", "add", name, key.as_str()])
}

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
        name: super::super::new_contact(name).expect("a valid contact name"),
        key,
    }
    .run(store)
    .await
}

/// `me/` is decided by this person's root, so a typed add under it refuses at parse (exit 2, before the
/// book is opened) and names the verbs that do add and remove a device.
#[test]
fn contact_add_me_is_refused_and_writes_nothing() {
    for name in ["me/phone", "me"] {
        let error = parse_add(name).expect_err("an add under me/ refuses");
        assert_eq!(error.exit_code(), 2, "a refused name is a usage error");
        let message = error.to_string();
        assert!(
            message.contains("swoosh invite <name> <key>")
                && message.contains("swoosh revoke me/<name>"),
            "the refusal names both verbs: {message}"
        );
    }
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

/// A capital folds on input, so `contact add Alice <key>` saves `alice`, the one stored spelling.
#[tokio::test]
async fn a_capital_name_folds_to_lowercase() {
    let home = home_with_book("fold").await;
    add(
        &home,
        "Alice/MacBook",
        NodeId::from_ed25519_secret(&[6u8; 32]),
    )
    .await
    .expect("a capital name is saved");
    let store = ContactsStore::open(home.contacts()).await.expect("open");
    let names: Vec<_> = store
        .contacts()
        .petnames()
        .map(|petname| petname.as_str().to_owned())
        .collect();
    assert_eq!(names, ["alice", "me"], "saved folded");
    let devices: Vec<_> = store
        .contacts()
        .devices(&"alice".parse().expect("petname"))
        .expect("alice is saved")
        .map(|(label, _)| label.as_str().to_owned())
        .collect();
    assert_eq!(devices, ["macbook"]);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `me`, `root` and `anyone` never name a person or a device: each refuses at parse (exit 2) as a person
/// in `contact add` and `contact signet`, and as a device, with the one reserved-name line.
#[test]
fn a_reserved_name_refuses() {
    let key = NodeId::from_ed25519_secret(&[7u8; 32]).to_string();
    for word in ["me", "root", "anyone", "Root"] {
        let folded = word.to_ascii_lowercase();
        let signet = Cli::try_parse_from(["swoosh", "contact", "signet", word, key.as_str()])
            .expect_err("a reserved person refuses");
        let device = parse_add(&format!("alice/{word}")).expect_err("a reserved device refuses");
        for error in [signet, device] {
            assert_eq!(error.exit_code(), 2, "a reserved name is a usage error");
            assert!(
                error
                    .to_string()
                    .contains(&format!("{folded} is reserved: pick another name")),
                "the refusal names the reserved word: {error}"
            );
        }
        if folded != "me" {
            let person = parse_add(word).expect_err("a reserved person refuses");
            assert_eq!(person.exit_code(), 2, "a reserved name is a usage error");
            assert!(
                person
                    .to_string()
                    .contains(&format!("{folded} is reserved: pick another name")),
                "the refusal names the reserved word: {person}"
            );
        }
    }
    assert_eq!(
        "alice/root".parse::<ContactRef>(),
        Err(NameError::Reserved("root".to_owned()))
    );
}

/// A torsioned key is refused as a contact's key at parse, with a plain line and no panic.
#[test]
fn a_torsioned_key_is_refused_as_a_contact_key() {
    let key = swoosh::testkit::torsioned_text();
    let error = Cli::try_parse_from(["swoosh", "contact", "add", "alice", key.as_str()])
        .expect_err("a torsioned key is refused");
    assert_eq!(
        error.exit_code(),
        2,
        "a key that is not a key is a usage error"
    );
    assert!(
        error.to_string().contains("not a usable identity"),
        "the refusal says the key is not usable: {error}"
    );
}
