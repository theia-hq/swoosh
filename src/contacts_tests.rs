//! Contact-store behaviour: petname/device parsing, add/list/remove, resolution, and persistence.

use std::sync::Arc;

use bifrost::NodeId;

use super::*;
use crate::names::NameError;

/// A deterministic node id from a seed, so tests can assert on distinct identities: the key the all-`seed`
/// secret binds, printed and parsed back through the real boundary rather than constructed, so the tests
/// exercise the same path a user's pasted key takes.
fn node(seed: u8) -> NodeId {
    crate::testkit::TestNode::seeded(seed)
        .node_id()
        .to_string()
        .parse()
        .expect("fixture node id parses")
}

/// The home whose contacts book is `path`.
fn home_at(path: &std::path::Path) -> crate::home::Home {
    crate::home::Home::resolve(path.parent().map(std::path::Path::to_path_buf)).expect("a home")
}

fn petname(name: &str) -> Petname {
    name.parse().expect("valid petname in test")
}

fn device(label: &str) -> DeviceLabel {
    label.parse().expect("valid device label in test")
}

/// Resolve a contact address to just its node ids, in order, for assertions that care about which
/// identities (and in what order) a reference resolves to, not the display labels.
fn resolve(contacts: &Contacts, target: &ContactRef) -> Result<Vec<NodeId>, ResolveError> {
    contacts
        .resolve_candidates(target)
        .map(|candidates| candidates.into_iter().map(|c| c.node).collect())
}

/// A petname follows the one name rule, and may be reserved: `me` addresses this person's own devices.
#[test]
fn a_petname_is_a_name_and_may_be_reserved() {
    for text in ["", "alice/macbook", "al ice", "fleet:alice"] {
        assert_eq!(
            text.parse::<Petname>(),
            Err(NameError::NotAName(text.to_owned()))
        );
    }
    assert_eq!(petname("Alice").as_str(), "alice");
    assert_eq!(petname("me").as_str(), "me");
    assert_eq!(
        petname("root").unreserved(),
        Err(NameError::Reserved("root".to_owned()))
    );
}

#[test]
fn contact_ref_splits_petname_and_device() {
    let person: ContactRef = "alice".parse().expect("plain petname");
    assert_eq!(person.petname(), &petname("alice"));
    assert_eq!(person.device(), None);

    let device_ref: ContactRef = "alice/macbook".parse().expect("device address");
    assert_eq!(device_ref.petname(), &petname("alice"));
    assert_eq!(device_ref.device(), Some(&device("macbook")));

    assert!("alice/".parse::<ContactRef>().is_err());
}

#[test]
fn add_creates_then_reports_unchanged_and_replaced() {
    let mut contacts = Contacts::default();

    let created = contacts.add(petname("alice"), None, node(1));
    assert_eq!(created, Added::Created);

    let unchanged = contacts.add(petname("alice"), None, node(1));
    assert_eq!(unchanged, Added::Unchanged);

    let replaced = contacts.add(petname("alice"), None, node(2));
    assert_eq!(replaced, Added::Replaced(node(1)));
}

#[test]
fn set_signet_creates_then_reports_unchanged_and_replaced() {
    let mut contacts = Contacts::default();

    let created = contacts.set_signet(petname("alice"), node(1));
    assert_eq!(created, Added::Created);

    let unchanged = contacts.set_signet(petname("alice"), node(1));
    assert_eq!(unchanged, Added::Unchanged);

    let replaced = contacts.set_signet(petname("alice"), node(2));
    assert_eq!(replaced, Added::Replaced(node(1)));
}

#[test]
fn resolve_maps_name_to_node_and_passes_through_device() {
    let mut contacts = Contacts::default();
    contacts.add(petname("alice"), Some(device("macbook")), node(1));
    contacts.add(petname("alice"), Some(device("iphone")), node(2));

    // The person resolves to every device, in label order (iphone before macbook).
    let person: ContactRef = "alice".parse().expect("person");
    assert_eq!(resolve(&contacts, &person), Ok(vec![node(2), node(1)]));

    // A specific device resolves to exactly that key.
    let one: ContactRef = "alice/macbook".parse().expect("device");
    assert_eq!(resolve(&contacts, &one), Ok(vec![node(1)]));
}

#[test]
fn resolve_unknown_name_is_a_clean_error_not_an_empty_dial() {
    let contacts = Contacts::default();
    let target: ContactRef = "ghost".parse().expect("name");
    assert_eq!(
        resolve(&contacts, &target),
        Err(ResolveError::UnknownPetname(petname("ghost")))
    );

    let mut contacts = Contacts::default();
    contacts.add(petname("alice"), Some(device("macbook")), node(1));
    let missing: ContactRef = "alice/desktop".parse().expect("device");
    assert_eq!(
        resolve(&contacts, &missing),
        Err(ResolveError::UnknownDevice {
            petname: petname("alice"),
            device: device("desktop"),
        })
    );
}

/// A device label follows the one name rule and is never reserved: no device is `me`, `root` or `anyone`.
#[test]
fn a_device_label_is_an_unreserved_name() {
    let too_long = "x".repeat(DeviceLabel::MAX_LEN + 1);
    for text in ["", "a/b", "a b", "a\nb", too_long.as_str(), "fleet:alice"] {
        assert_eq!(
            text.parse::<DeviceLabel>(),
            Err(NameError::NotAName(text.to_owned()))
        );
    }
    for text in ["me", "root", "anyone"] {
        assert_eq!(
            text.parse::<DeviceLabel>(),
            Err(NameError::Reserved(text.to_owned()))
        );
    }
    assert!("ci-runner".parse::<DeviceLabel>().is_ok());
    assert!("fleet".parse::<DeviceLabel>().is_ok());
}

#[test]
fn remove_drops_a_device_then_the_now_empty_person() {
    let mut contacts = Contacts::default();
    contacts.add(petname("alice"), Some(device("macbook")), node(1));
    contacts.add(petname("alice"), Some(device("iphone")), node(2));

    assert_eq!(
        contacts.remove(&petname("alice"), Some(&device("iphone"))),
        Removed::Removed
    );
    assert_eq!(
        resolve(&contacts, &"alice".parse().expect("person")),
        Ok(vec![node(1)])
    );

    // Removing the last device removes the person too.
    assert_eq!(
        contacts.remove(&petname("alice"), Some(&device("macbook"))),
        Removed::Removed
    );
    assert!(contacts.devices(&petname("alice")).is_none());

    // Removing something absent is a no-op, not an error.
    assert_eq!(contacts.remove(&petname("alice"), None), Removed::Absent);
}

#[tokio::test]
async fn store_roundtrips_across_reload() {
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    // Absent file loads as an empty book.
    let mut store = ContactsStore::open(&home_at(&path))
        .await
        .expect("open empty");
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("macbook")), node(1));
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("iphone")), node(2));
    store.contacts_mut().add(petname("bob"), None, node(3));
    store.save(&crate::testkit::lock()).expect("save");

    // A fresh open sees exactly what was saved.
    let reloaded = ContactsStore::open(&home_at(&path)).await.expect("reopen");
    let contacts = reloaded.contacts();
    assert_eq!(
        resolve(contacts, &"alice".parse().expect("person")),
        Ok(vec![node(2), node(1)])
    );
    assert_eq!(
        resolve(contacts, &"bob".parse().expect("person")),
        Ok(vec![node(3)])
    );

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

/// Each save writes its own temp, so saves that overlap never write into one temp or rename one away from
/// under another: every save lands, the book left is one whole book, and no temp stays behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_contacts_temp_is_unique_per_write() {
    const WRITERS: u8 = 8;

    let dir = std::env::temp_dir().join(format!("swoosh-contacts-temps-{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&dir).await;
    let path = dir.join("contacts.toml");
    // Every writer opens before any saves, so each opens the empty book and the book left holds one
    // writer's petname; a writer that opened after another's save would carry two.
    let opened = Arc::new(tokio::sync::Barrier::new(usize::from(WRITERS)));

    let writers = (0..WRITERS).map(|writer| {
        let path = path.clone();
        let opened = Arc::clone(&opened);
        tokio::spawn(async move {
            let mut store = ContactsStore::open(&home_at(&path)).await.expect("open");
            // A book of some size, so one write takes long enough for another to overlap it.
            for label in 0..100 {
                let _ = store.contacts_mut().add(
                    petname(&format!("writer-{writer}")),
                    Some(device(&format!("device-{label}"))),
                    node(writer.saturating_add(1)),
                );
            }
            opened.wait().await;
            for _ in 0..25 {
                store.save(&crate::testkit::lock())?;
            }
            Ok::<(), StoreError>(())
        })
    });
    for writer in futures::future::join_all(writers).await {
        writer.expect("the writer ran").expect("every save lands");
    }

    let book = ContactsStore::open(&home_at(&path))
        .await
        .expect("the book left is one whole book");
    assert_eq!(book.contacts().petnames().count(), 1, "one writer's book");
    let mut left = tokio::fs::read_dir(&dir).await.expect("list the store dir");
    while let Some(entry) = left.next_entry().await.expect("list the store dir") {
        assert_eq!(entry.file_name(), "contacts.toml", "no temp stays behind");
    }

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

#[cfg(unix)]
#[tokio::test]
async fn a_saved_book_is_owner_only_in_an_owner_only_store() {
    use std::os::unix::fs::PermissionsExt as _;

    // A nested store dir that does not exist yet, so the first save exercises the 0700 create. The address
    // book is this node's trust graph, so a co-tenant local user must not be able to read it.
    let dir = std::env::temp_dir().join(format!(
        "swoosh-contacts-perms-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = tokio::fs::remove_dir_all(&dir).await;
    let path = dir.join("contacts.toml");

    let mut store = ContactsStore::open(&home_at(&path))
        .await
        .expect("open empty into a fresh store dir");
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("macbook")), node(1));
    store
        .save(&crate::testkit::lock())
        .expect("save creates the store dir");

    let dir_mode = std::fs::metadata(&dir)
        .expect("stat the store dir")
        .permissions()
        .mode();
    assert_eq!(
        dir_mode & 0o777,
        0o700,
        "the store dir is created 0700 (owner-only), not left group/world-traversable"
    );

    let file_mode = std::fs::metadata(&path)
        .expect("stat the contacts book")
        .permissions()
        .mode();
    assert_eq!(
        file_mode & 0o777,
        0o600,
        "the saved contacts book is 0600 (owner read/write only) via its 0600 temp, never world-readable"
    );

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

/// A device may be named `signet`: the signet is stored under a key that is not a name, so the two never
/// collide on save.
#[tokio::test]
async fn a_device_named_signet_keeps_its_own_row_beside_the_signet() {
    let dir =
        std::env::temp_dir().join(format!("swoosh-contacts-signet-row-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(&home_at(&path)).await.expect("open");
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("signet")), node(1));
    let _ = store.contacts_mut().set_signet(petname("alice"), node(2));
    store.save(&crate::testkit::lock()).expect("save");

    let reloaded = ContactsStore::open(&home_at(&path)).await.expect("reopen");
    assert_eq!(
        resolve(reloaded.contacts(), &"alice/signet".parse().expect("addr")),
        Ok(vec![node(1)])
    );
    assert_eq!(
        reloaded
            .contacts()
            .signet(&petname("alice"))
            .map(|binding| binding.node),
        Some(node(2))
    );

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

/// The contacts file is read as stored: a capital in a person or a device key refuses rather than folding, so
/// `[Alice]` and `[alice]` can never merge into one person without a word.
#[tokio::test]
async fn a_stored_capital_name_refuses_on_load() {
    let dir =
        std::env::temp_dir().join(format!("swoosh-contacts-stored-cap-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await.expect("mkdir");
    let key = node(1).to_string();
    for text in [
        format!("[Alice]\nlaptop = \"{key}\"\n"),
        format!("[alice]\nLaptop = \"{key}\"\n"),
    ] {
        tokio::fs::write(&path, &text).await.expect("write");
        assert!(
            ContactsStore::open(&home_at(&path)).await.is_err(),
            "a capital on disk refuses: {text}"
        );
    }
    tokio::fs::write(&path, format!("[alice]\nlaptop = \"{key}\"\n"))
        .await
        .expect("write");
    assert!(
        ContactsStore::open(&home_at(&path)).await.is_ok(),
        "the stored spelling loads"
    );
    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

#[tokio::test]
async fn store_round_trips_a_signet_and_keeps_the_device_map() {
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-signet-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(&home_at(&path)).await.expect("open");
    store.contacts_mut().set_signet(petname("alice"), node(3));
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("laptop")), node(1));
    store.save(&crate::testkit::lock()).expect("save");

    // The signet persists under a key that is not a name, co-located in alice's own block.
    let text = tokio::fs::read_to_string(&path).await.expect("read file");
    assert!(
        text.contains("signet_root = "),
        "the signet round-trips as its own key in the person's table: {text}"
    );

    // Reload: the signet comes back, and the device map is unaffected.
    let reloaded = ContactsStore::open(&home_at(&path)).await.expect("reopen");
    let contacts = reloaded.contacts();
    let signet = contacts
        .signet(&petname("alice"))
        .expect("alice has a signet");
    assert_eq!(signet.node, node(3), "the signet key round-trips");
    assert_eq!(
        resolve(contacts, &"alice/laptop".parse().expect("addr")),
        Ok(vec![node(1)]),
        "the device map is unaffected by the signet"
    );

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

#[tokio::test]
async fn a_signet_only_person_survives_tidy_up_and_reload() {
    // A signet is a reason to keep a person even with no devices: removing a person's last DEVICE keeps a
    // signet-only person alive, and a signet-only person round-trips through persistence.
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-sonly-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(&home_at(&path)).await.expect("open");
    store.contacts_mut().set_signet(petname("bob"), node(2));
    store
        .contacts_mut()
        .add(petname("bob"), Some(device("laptop")), node(1));

    // Removing bob's only device does NOT sweep bob away: the signet keeps the person.
    assert_eq!(
        store
            .contacts_mut()
            .remove(&petname("bob"), Some(&device("laptop"))),
        Removed::Removed
    );
    assert!(
        store.contacts().signet(&petname("bob")).is_some(),
        "a signet-only person is not tidied away"
    );
    // Removing an absent device is a no-op that also leaves the signet-only person intact.
    assert_eq!(
        store
            .contacts_mut()
            .remove(&petname("bob"), Some(&device("ghost"))),
        Removed::Absent
    );
    store.save(&crate::testkit::lock()).expect("save");

    let reloaded = ContactsStore::open(&home_at(&path)).await.expect("reopen");
    assert_eq!(
        reloaded.contacts().signet(&petname("bob")).map(|b| b.node),
        Some(node(2)),
        "a signet-only person round-trips through encode/decode"
    );

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

/// A pin to a root revoked on this machine is no pin: the list that root signed names no device under
/// `me`, so `me/<name>` reaches nothing it listed.
#[tokio::test]
async fn a_revoked_pin_lists_no_device_under_me() {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-contacts-revoked-pin-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    crate::config::create_store_dir(&dir).expect("the home");
    let home = crate::home::Home::resolve(Some(dir.clone())).expect("a home");
    let root = crate::testkit::TestRoot::seeded(0x21);
    crate::config::write_signet(&crate::testkit::lock(), &home, root.node_id()).expect("the pin");
    let member = root
        .member(
            crate::testkit::TestNode::seeded(0x41).verify_key(),
            device("desk"),
        )
        .expect("a row");
    let list =
        crate::roster::RosterDoc::new(crate::roster::Epoch(1), vec![member]).expect("a list");
    std::fs::write(home.devices(), root.sign_update(&list)).expect("the list");
    let desk: ContactRef = "me/desk".parse().expect("an address");

    let live = ContactsStore::open(&home).await.expect("open");
    assert_eq!(resolve(live.contacts(), &desk), Ok(vec![node(0x41)]));

    crate::revoked::add(
        &crate::testkit::lock(),
        &home,
        [nauthy::Revocation::Key(root.verify_key())],
    )
    .expect("revoke the root here");
    assert_eq!(
        crate::config::load_signet(&home)
            .await
            .expect("the pin reads"),
        None
    );
    let revoked = ContactsStore::open(&home).await.expect("open");
    assert!(resolve(revoked.contacts(), &desk).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}
