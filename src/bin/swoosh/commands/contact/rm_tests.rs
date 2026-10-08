use bifrost::NodeId;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;

use super::RmCmd;

/// A scratch home with `alice/macbook` on file.
async fn populated_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-contact-rm-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let home = Home::resolve(Some(dir)).expect("resolve");
    let mut store = ContactsStore::open(&home).await.expect("open");
    store.contacts_mut().add(
        "alice".parse().expect("alice"),
        Some("macbook".parse().expect("label")),
        NodeId::from_ed25519_secret(&[5u8; 32]),
    );
    store.save(&swoosh::testkit::lock()).expect("save");
    home
}

async fn remove(home: &Home, name: &str) -> eyre::Result<()> {
    RmCmd {
        name: name.parse().expect("a valid contact ref"),
    }
    .run(home)
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
    assert!(
        !home.home_lock().exists(),
        "the refusal comes before the book is opened"
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
    let store = ContactsStore::open(&home).await.expect("open");
    assert!(
        !store
            .contacts()
            .petnames()
            .any(|petname| petname.as_str() == "alice"),
        "alice is gone"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A ledger row given to `holder` for an hour, ended or not: what `share` records.
async fn given(home: &Home, holder: NodeId, ends: std::time::SystemTime) -> nauthy::RevocationId {
    let link = swoosh::testkit::TestNode::seeded(0x41)
        .slip(&"ssh".parse().expect("a service"), ends)
        .expect("a slip");
    let root_id = link.root_revocation_id().expect("an id");
    swoosh::grants::Grants::at(home.links())
        .append(
            &swoosh::testkit::lock(),
            &swoosh::grants::GrantRecord {
                target: "ssh".parse().expect("a service"),
                kind: swoosh::grants::GrantKind::Device,
                delegation: swoosh::grants::Delegation::Sealed,
                holder: holder.to_string(),
                root_id: nauthy::RevocationId::clone(&root_id),
                expiry: ends,
            },
        )
        .expect("append the row");
    root_id
}

fn in_an_hour() -> std::time::SystemTime {
    std::time::SystemTime::now() + core::time::Duration::from_secs(3600)
}

/// A contact with live links refuses, naming how many and the revoke that ends them; the book is left as it
/// was. Links to the person's root count for the person, and a device's for the device.
#[tokio::test]
async fn contact_rm_with_live_links_refuses() {
    let home = populated_home("live").await;
    let root = NodeId::from_ed25519_secret(&[6u8; 32]);
    let mut store = ContactsStore::open(&home).await.expect("open");
    store
        .contacts_mut()
        .set_signet("alice".parse().expect("alice"), root);
    store.save(&swoosh::testkit::lock()).expect("save");
    given(&home, NodeId::from_ed25519_secret(&[5u8; 32]), in_an_hour()).await;
    given(&home, root, in_an_hour()).await;
    let before = std::fs::read(home.contacts()).expect("read the book");

    let error = remove(&home, "alice").await.expect_err("live links refuse");
    assert_eq!(
        format!("{error:#}"),
        "links you shared with alice are live (2): revoke them first: swoosh revoke alice"
    );
    let device = remove(&home, "alice/macbook")
        .await
        .expect_err("a device's live link refuses");
    assert_eq!(
        format!("{device:#}"),
        "links you shared with alice/macbook are live (1): revoke them first: swoosh revoke \
         alice/macbook"
    );
    assert_eq!(
        std::fs::read(home.contacts()).expect("read the book"),
        before,
        "nothing is written"
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// An ended link or a revoked one admits nobody, so it does not hold a contact in the book.
#[tokio::test]
async fn an_ended_or_revoked_link_does_not_block_rm() {
    let home = populated_home("dead").await;
    let macbook = NodeId::from_ed25519_secret(&[5u8; 32]);
    given(&home, macbook, std::time::SystemTime::now()).await;
    let revoked = given(&home, macbook, in_an_hour()).await;
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &home,
        [nauthy::Revocation::Id(revoked)],
    )
    .expect("revoke the link");
    remove(&home, "alice")
        .await
        .expect("no live link holds alice");
    let _ = std::fs::remove_dir_all(home.dir());
}
