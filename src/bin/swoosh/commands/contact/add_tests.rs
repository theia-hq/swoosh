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

/// A scratch home with an empty contacts book.
async fn home_with_book(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-contact-add-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
    ContactsStore::open(&home)
        .await
        .expect("open")
        .save(&swoosh::testkit::lock())
        .expect("save");
    home
}

async fn add(home: &Home, name: &str, key: NodeId) -> eyre::Result<()> {
    AddCmd {
        name: super::super::new_contact(name).expect("a valid contact name"),
        key: super::TypedKey { key, root: false },
    }
    .run(home)
    .await
}

/// `swoosh contact add <args>` on `home`, through the parser the binary uses.
async fn add_typed(home: &Home, args: &[&str]) -> eyre::Result<()> {
    match Cli::try_parse_from(["swoosh", "contact", "add"].iter().chain(args).copied())
        .expect("contact add parses")
        .command
    {
        Some(crate::Command::Contact(super::super::ContactCmd::Add(cmd))) => cmd.run(home).await,
        other => panic!("contact add parses to contact add, not {other:?}"),
    }
}

/// Where `home`'s book saves alice and bob: each one's root, then their machines.
async fn book(home: &Home) -> Vec<(String, Option<NodeId>, Vec<(String, NodeId)>)> {
    let store = ContactsStore::open(home).await.expect("open");
    let contacts = store.contacts();
    contacts
        .petnames()
        .map(|person| {
            let machines = contacts
                .devices(person)
                .expect("a listed person is saved")
                .map(|(label, key)| (label.as_str().to_owned(), *key))
                .collect();
            let root = contacts.signet(person).map(|binding| binding.node);
            (person.as_str().to_owned(), root, machines)
        })
        .collect()
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
    let store = ContactsStore::open(&home).await.expect("open");
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
    let store = ContactsStore::open(&home).await.expect("open");
    let names: Vec<_> = store
        .contacts()
        .petnames()
        .map(|petname| petname.as_str().to_owned())
        .collect();
    assert_eq!(names, ["alice"], "saved folded");
    let devices: Vec<_> = store
        .contacts()
        .devices(&"alice".parse().expect("petname"))
        .expect("alice is saved")
        .map(|(label, _)| label.as_str().to_owned())
        .collect();
    assert_eq!(devices, ["macbook"]);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `me`, `root` and `anyone` never name a person or a device: each refuses at parse (exit 2), as a person and
/// as a device; `me` names the verbs that add and remove your own devices, the others the one reserved-name
/// line.
#[test]
fn contact_add_refuses_reserved_names() {
    for word in ["me", "root", "anyone", "Root"] {
        let folded = word.to_ascii_lowercase();
        let person = parse_add(word).expect_err("a reserved person refuses");
        let under = parse_add(&format!("{word}/laptop")).expect_err("a reserved person refuses");
        let device = parse_add(&format!("alice/{word}")).expect_err("a reserved device refuses");
        for error in [&person, &under, &device] {
            assert_eq!(
                error.exit_code(),
                2,
                "{word}: a reserved name is a usage error"
            );
        }
        assert!(
            device
                .to_string()
                .contains(&format!("{folded} is reserved: pick another name")),
            "the refusal names the reserved word: {device}"
        );
        let line = if folded == "me" {
            "swoosh invite <name> <key>".to_owned()
        } else {
            format!("{folded} is reserved: pick another name")
        };
        for error in [&person, &under] {
            assert!(error.to_string().contains(&line), "{word}: {error}");
        }
    }
    assert_eq!(
        "alice/root".parse::<ContactRef>(),
        Err(NameError::Reserved("root".to_owned()))
    );
}

/// The name's shape decides what is saved: a bare person is their root, which `share` binds a link to and no
/// dial reaches; `<person>/<name>` is one machine. `contact signet` is gone.
#[tokio::test]
async fn contact_add_saves_a_person_as_a_root_and_a_name_as_a_machine() {
    let home = home_with_book("shape").await;
    let root = NodeId::from_ed25519_secret(&[6u8; 32]);
    let laptop = NodeId::from_ed25519_secret(&[7u8; 32]);
    add(&home, "alice", root).await.expect("a person is saved");
    add(&home, "alice/laptop", laptop)
        .await
        .expect("a machine is saved");
    let store = ContactsStore::open(&home).await.expect("open");
    let alice = "alice".parse().expect("petname");
    assert_eq!(
        store.contacts().signet(&alice).map(|binding| binding.node),
        Some(root),
        "alice is saved with her root"
    );
    let machines: Vec<_> = store
        .contacts()
        .devices(&alice)
        .expect("alice is saved")
        .map(|(label, key)| (label.as_str().to_owned(), *key))
        .collect();
    assert_eq!(
        machines,
        [("laptop".to_owned(), laptop)],
        "the root is no machine"
    );
    let key = root.to_string();
    assert!(
        Cli::try_parse_from(["swoosh", "contact", "signet", "alice", key.as_str()]).is_err(),
        "`contact signet` is gone"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A torsioned key is refused as a contact's key at parse, with the line every typed key refuses with,
/// naming the check it failed.
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
        error.to_string().contains(&format!(
            "{key} is not a usable key: carries a torsion component"
        )),
        "the refusal names the key and the check: {error}"
    );
}

/// A contact name never starts with `.`, `/` or `~`, so a peer typed as a path can never shadow a name.
#[test]
fn a_contact_name_may_not_start_with_a_path_character() {
    for name in ["./x", ".x", "/x", "~/x", "~x"] {
        let error = parse_add(name).expect_err("a name starting with a path character refuses");
        assert_eq!(
            error.exit_code(),
            2,
            "{name}: a refused name is a usage error"
        );
    }
}

/// A name that holds a key never takes another: a different root under a saved person, and a different key
/// under a saved machine, each refuse (exit 1, not a usage error) and write nothing. The refusal names both
/// keys whole, so a person can compare them, and with no link given to the name, `contact rm` alone frees it.
#[tokio::test]
async fn contact_add_never_replaces_a_key() {
    let home = home_with_book("never-replaces").await;
    let (old, new) = (
        NodeId::from_ed25519_secret(&[6u8; 32]),
        NodeId::from_ed25519_secret(&[7u8; 32]),
    );
    let (laptop, other) = (
        NodeId::from_ed25519_secret(&[8u8; 32]),
        NodeId::from_ed25519_secret(&[9u8; 32]),
    );
    add(&home, "bob", old).await.expect("bob's root is saved");
    add(&home, "bob/laptop", laptop)
        .await
        .expect("bob's laptop is saved");
    let before = book(&home).await;

    let root = add(&home, "bob", new)
        .await
        .expect_err("a second root refuses");
    assert!(root.downcast_ref::<super::Usage>().is_none(), "exit 1");
    assert_eq!(
        format!("{root:#}"),
        format!(
            "bob's root is saved here as root:{old}, not root:{new}\n  a saved root is never replaced; to save \
             the new one, remove bob:\n    swoosh contact rm bob"
        )
    );
    let machine = add(&home, "bob/laptop", other)
        .await
        .expect_err("a second key for a machine refuses");
    assert_eq!(
        format!("{machine:#}"),
        format!(
            "bob/laptop is saved here as {laptop}, not {other}\n  a saved key is never replaced; to save the \
             new one, remove bob/laptop:\n    swoosh contact rm bob/laptop"
        )
    );
    assert_eq!(book(&home).await, before, "nothing is written");

    add(&home, "bob", old)
        .await
        .expect("the same root again is no change");
    add(&home, "bob/laptop", laptop)
        .await
        .expect("the same key again is no change");
    assert_eq!(book(&home).await, before);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A live link given to the name puts `revoke` first, since `contact rm` refuses until it is ended: for a
/// person, a link to their root or to any machine of theirs; for a machine, a link to that machine.
#[tokio::test]
async fn a_replace_refusal_names_revoke_while_links_to_the_name_are_live() {
    let home = home_with_book("replace-live").await;
    let (old, new) = (
        NodeId::from_ed25519_secret(&[6u8; 32]),
        NodeId::from_ed25519_secret(&[7u8; 32]),
    );
    let (laptop, other) = (
        NodeId::from_ed25519_secret(&[8u8; 32]),
        NodeId::from_ed25519_secret(&[9u8; 32]),
    );
    add(&home, "bob", old).await.expect("bob's root is saved");
    add(&home, "bob/laptop", laptop)
        .await
        .expect("bob's laptop is saved");
    given(&home, laptop).await;
    let before = book(&home).await;

    let root = add(&home, "bob", new)
        .await
        .expect_err("a second root refuses");
    assert_eq!(
        format!("{root:#}"),
        format!(
            "bob's root is saved here as root:{old}, not root:{new}\n  a saved root is never replaced; to save \
             the new one, end the links you gave bob, then remove bob:\n    swoosh revoke bob\n    swoosh \
             contact rm bob"
        )
    );
    let machine = add(&home, "bob/laptop", other)
        .await
        .expect_err("a second key for a machine refuses");
    assert_eq!(
        format!("{machine:#}"),
        format!(
            "bob/laptop is saved here as {laptop}, not {other}\n  a saved key is never replaced; to save the \
             new one, end the links you gave bob/laptop, then remove bob/laptop:\n    swoosh revoke \
             bob/laptop\n    swoosh contact rm bob/laptop"
        )
    );
    assert_eq!(book(&home).await, before, "nothing is written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A link given to `holder` that ends in an hour: the row `share` records.
async fn given(home: &Home, holder: NodeId) {
    let ends = std::time::SystemTime::now() + core::time::Duration::from_secs(3600);
    let link = swoosh::testkit::TestNode::seeded(0x41)
        .slip(&"ssh".parse().expect("a service"), ends)
        .expect("a slip");
    swoosh::grants::Grants::at(home.links())
        .append(
            &swoosh::testkit::lock(),
            &swoosh::grants::GrantRecord {
                target: "ssh".parse().expect("a service"),
                serves: None,
                kind: swoosh::grants::GrantKind::Device,
                delegation: swoosh::grants::Delegation::Sealed,
                holder: holder.to_string(),
                root_id: link.root_revocation_id().expect("an id"),
                expiry: ends,
            },
        )
        .expect("append the row");
}

/// One key has one name here: a key saved as a person's root or as a machine refuses under any other name,
/// root or machine, naming where it is saved, and nothing is written.
#[tokio::test]
async fn contact_add_refuses_a_key_under_a_second_name() {
    let home = home_with_book("second-name").await;
    let root = NodeId::from_ed25519_secret(&[6u8; 32]);
    let laptop = NodeId::from_ed25519_secret(&[7u8; 32]);
    add(&home, "bob", root).await.expect("bob's root is saved");
    add(&home, "bob/laptop", laptop)
        .await
        .expect("bob's laptop is saved");
    let before = book(&home).await;

    for (name, key, line) in [
        (
            "carol",
            root,
            format!("root:{root} is saved here already, as bob's root"),
        ),
        (
            "carol/desk",
            root,
            format!("root:{root} is saved here already, as bob's root"),
        ),
        (
            "bob/desk",
            root,
            format!("root:{root} is saved here already, as bob's root"),
        ),
        (
            "carol",
            laptop,
            format!("{laptop} is saved here already, as bob/laptop"),
        ),
        (
            "carol/desk",
            laptop,
            format!("{laptop} is saved here already, as bob/laptop"),
        ),
        (
            "bob/desk",
            laptop,
            format!("{laptop} is saved here already, as bob/laptop"),
        ),
    ] {
        let error = add(&home, name, key)
            .await
            .expect_err("a key under a second name refuses");
        assert!(
            error.downcast_ref::<super::Usage>().is_none(),
            "{name}: exit 1"
        );
        assert_eq!(format!("{error:#}"), line, "{name}");
    }
    assert_eq!(book(&home).await, before, "nothing is written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A person's root may be typed as `root:` prints it (any case), as `revoke`'s recipe types it; a machine
/// given a root key is a usage error that names the person's form, and writes nothing.
#[tokio::test]
async fn contact_add_takes_a_root_typed_with_its_prefix() {
    let home = home_with_book("root-prefix").await;
    let root = NodeId::from_ed25519_secret(&[6u8; 32]);
    add_typed(&home, &["bob", &format!("root:{root}")])
        .await
        .expect("root: is taken off");
    add_typed(&home, &["bob", &format!("ROOT:{root}")])
        .await
        .expect("in any case");
    assert_eq!(
        book(&home).await,
        [("bob".to_owned(), Some(root), Vec::new())]
    );

    let other = NodeId::from_ed25519_secret(&[7u8; 32]);
    let error = add_typed(&home, &["carol/laptop", &format!("root:{other}")])
        .await
        .expect_err("a machine takes no root");
    assert_eq!(
        error.downcast_ref::<super::Usage>().map(|usage| usage.0.as_str()),
        Some(
            format!(
                "root:{other} is a root key, which vouches for all of carol's machines: swoosh contact add \
                 carol root:{other}"
            )
            .as_str()
        ),
        "exit 2"
    );
    assert_eq!(book(&home).await.len(), 1, "nothing is written");
    let _ = std::fs::remove_dir_all(home.dir());
}
