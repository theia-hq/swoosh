//! Contact-store behaviour: petname/device parsing, add/list/remove, resolution, and persistence.

use bifrost::NodeId;

use super::*;

/// A deterministic node id from a seed, so tests can assert on distinct identities. Each seed maps to a
/// valid `bf01` base32 string (an all-`seed`-byte key), parsed through the real boundary rather than
/// constructed, so the tests exercise the same path a user's pasted key takes.
fn node(seed: u8) -> NodeId {
    let encoded = match seed {
        1 => "bf01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq",
        2 => "bf01aibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaiba",
        3 => "bf01ambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambq",
        7 => "bf01a4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dq",
        other => panic!("no fixture node id for seed {other}"),
    };
    encoded.parse().expect("fixture node id parses")
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

#[test]
fn petname_rejects_slash_whitespace_and_empty() {
    assert_eq!("".parse::<Petname>(), Err(PetnameParseError::Empty));
    assert_eq!(
        "alice/macbook".parse::<Petname>(),
        Err(PetnameParseError::Slash)
    );
    assert_eq!(
        "al ice".parse::<Petname>(),
        Err(PetnameParseError::Whitespace)
    );
    assert_eq!(petname("alice").as_str(), "alice");
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

#[test]
fn target_parses_raw_node_id_and_falls_back_to_petname() {
    let raw = node(7).to_string();
    assert_eq!(raw.parse::<Target>(), Ok(Target::Raw(node(7))));

    let named: Target = "alice/macbook".parse().expect("petname target");
    match named {
        Target::Named(reference) => {
            assert_eq!(reference.petname(), &petname("alice"));
            assert_eq!(reference.device(), Some(&device("macbook")));
        }
        Target::Raw(_) => panic!("expected a named target"),
    }
}

#[test]
fn target_resolve_passes_a_raw_key_through_without_the_store() {
    let contacts = Contacts::default();
    let target = Target::Raw(node(3));
    let candidates = target.candidates(&contacts).expect("raw key resolves");
    assert_eq!(
        candidates.iter().map(|c| c.node).collect::<Vec<_>>(),
        vec![node(3)]
    );
    // A raw key labels itself by its short form, since there is no petname to name it.
    assert_eq!(candidates[0].label, node(3).short());
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
    let mut store = ContactsStore::open(path.clone()).await.expect("open empty");
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("macbook")), node(1));
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("iphone")), node(2));
    store.contacts_mut().add(petname("bob"), None, node(3));
    store.save().await.expect("save");

    // A fresh open sees exactly what was saved.
    let reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
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
