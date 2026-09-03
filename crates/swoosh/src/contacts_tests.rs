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
fn device_label_rejects_length_and_control_bytes() {
    // The unified label type gains the length bound and control-byte reject the roster codec requires, so
    // these hold for local contacts and roster members alike.
    assert_eq!("".parse::<DeviceLabel>(), Err(DeviceLabelParseError::Empty));
    assert_eq!(
        "a/b".parse::<DeviceLabel>(),
        Err(DeviceLabelParseError::Slash)
    );
    assert_eq!(
        "a b".parse::<DeviceLabel>(),
        Err(DeviceLabelParseError::BadByte)
    );
    assert_eq!(
        "a\nb".parse::<DeviceLabel>(),
        Err(DeviceLabelParseError::BadByte)
    );
    assert_eq!(
        "x".repeat(DeviceLabel::MAX_LEN + 1).parse::<DeviceLabel>(),
        Err(DeviceLabelParseError::TooLong)
    );
    assert!("ci-runner".parse::<DeviceLabel>().is_ok());
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

use nauthy::VerifyKey;

use crate::roster::{Epoch, Member, RosterDoc};

/// A roster member whose node id is the all-`seed`-byte key, so it hydrates to the same [`node`] fixture,
/// which doubles as a check that the `VerifyKey -> NodeId` conversion preserves the bytes.
fn roster_member(seed: u8, label: &str) -> Member {
    Member {
        node: VerifyKey::new([seed; 32]),
        label: label.parse::<DeviceLabel>().expect("valid device label"),
    }
}

fn roster(epoch: u64, members: Vec<Member>) -> RosterDoc {
    RosterDoc::new(Epoch(epoch), members).expect("valid roster")
}

/// The provenance of every device under `me`, in label order.
fn me_sources(contacts: &Contacts) -> Vec<Source> {
    contacts
        .bindings(&petname("me"))
        .expect("me present")
        .map(|(_, binding)| binding.source)
        .collect()
}

#[test]
fn hydrate_adds_members_under_me_tagged_roster() {
    let mut contacts = Contacts::default();
    contacts.hydrate(&roster(
        3,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    ));
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(1)])
    );
    assert_eq!(
        resolve(&contacts, &"me/phone".parse().expect("addr")),
        Ok(vec![node(2)])
    );
    assert!(
        me_sources(&contacts)
            .iter()
            .all(|s| *s == Source::Roster { epoch: 3 })
    );
}

#[test]
fn hydrate_never_clobbers_a_hand_typed_binding() {
    // The operator hand-typed me/desk; a roster that claims something else must NOT overwrite the local
    // choice, and the entry stays HandTyped. This is the moat: a member never launders itself over a name
    // you set.
    let mut contacts = Contacts::default();
    contacts.add(petname("me"), Some(device("desk")), node(7));
    contacts.hydrate(&roster(9, vec![roster_member(1, "desk")]));
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(7)])
    );
    assert_eq!(me_sources(&contacts), vec![Source::HandTyped]);
}

#[test]
fn hydrate_refreshes_on_a_newer_epoch_and_ignores_a_stale_one() {
    let mut contacts = Contacts::default();
    contacts.hydrate(&roster(5, vec![roster_member(1, "desk")]));
    contacts.hydrate(&roster(6, vec![roster_member(2, "desk")])); // newer epoch refreshes
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(2)])
    );
    contacts.hydrate(&roster(4, vec![roster_member(3, "desk")])); // stale epoch is ignored
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(2)])
    );
    assert_eq!(me_sources(&contacts), vec![Source::Roster { epoch: 6 }]);
    // The floor advanced to the highest APPLIED epoch, not the last one seen: the stale 4 did not lower it.
    assert_eq!(contacts.roster_epoch(), Some(6));
}

#[test]
fn hydrate_drops_a_removed_member_on_a_forward_pull() {
    // F1 (the important one): a member removed in a newer roster must DISAPPEAR, not linger. A snapshot is a
    // full replace, so `phone` (absent from epoch 6) is dropped, and only `desk` survives.
    let mut contacts = Contacts::default();
    contacts.hydrate(&roster(
        5,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    ));
    assert_eq!(
        contacts
            .devices(&petname("me"))
            .expect("me")
            .map(|(label, _)| label.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec!["desk".to_owned(), "phone".to_owned()]
    );
    contacts.hydrate(&roster(6, vec![roster_member(1, "desk")])); // phone removed at epoch 6
    assert_eq!(
        contacts
            .devices(&petname("me"))
            .expect("me")
            .map(|(label, _)| label.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec!["desk".to_owned()]
    );
    assert!(contacts.devices(&petname("me")).expect("me").all(|_| true));
}

#[test]
fn hydrate_refuses_a_replayed_old_roster_and_never_re_adds_a_removed_member() {
    // F1: after `phone` is removed at epoch 6, a hostile/stale courier replays the genuinely-signed epoch-5
    // roster that still lists `phone`. The floor (6) refuses the whole doc, so `phone` is NOT resurrected.
    let mut contacts = Contacts::default();
    contacts.hydrate(&roster(
        5,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    ));
    assert!(contacts.hydrate(&roster(6, vec![roster_member(1, "desk")])));
    // Replay the OLD epoch-5 roster: refused (returns false), a no-op.
    let replayed = contacts.hydrate(&roster(
        5,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    ));
    assert!(!replayed, "a stale roster must be refused");
    assert!(
        contacts
            .devices(&petname("me"))
            .expect("me")
            .all(|(label, _)| label.as_str() == "desk"),
        "the removed member must not be re-added by a replay"
    );
    assert_eq!(contacts.roster_epoch(), Some(6));
}

#[test]
fn hydrate_refuses_a_same_epoch_re_cut() {
    // F1: a same-epoch doc is a no-op (not a merge), so a re-cut at the same epoch cannot overwrite.
    let mut contacts = Contacts::default();
    contacts.hydrate(&roster(6, vec![roster_member(1, "desk")]));
    let same = contacts.hydrate(&roster(6, vec![roster_member(2, "desk")]));
    assert!(!same, "a same-epoch roster must be refused");
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(1)])
    );
}

#[test]
fn hydrate_keeps_hand_typed_across_a_snapshot_replace() {
    // The snapshot-replace drops the prior roster-sourced set but NEVER a HandTyped binding: the operator's
    // local `me/laptop` survives a forward pull that does not list it.
    let mut contacts = Contacts::default();
    contacts.add(petname("me"), Some(device("laptop")), node(7)); // hand-typed
    contacts.hydrate(&roster(5, vec![roster_member(1, "desk")]));
    contacts.hydrate(&roster(6, vec![roster_member(2, "phone")])); // replaces desk, keeps laptop
    let devices: Vec<_> = contacts
        .devices(&petname("me"))
        .expect("me")
        .map(|(label, _)| label.as_str().to_owned())
        .collect();
    assert_eq!(devices, vec!["laptop".to_owned(), "phone".to_owned()]);
    assert_eq!(
        resolve(&contacts, &"me/laptop".parse().expect("addr")),
        Ok(vec![node(7)])
    );
}

#[tokio::test]
async fn store_round_trips_the_roster_epoch_floor() {
    // F1: the floor must survive a restart, else every reboot resets the anti-rollback high-water to zero
    // and a replay walks back in.
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-floor-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(path.clone()).await.expect("open");
    store
        .contacts_mut()
        .hydrate(&roster(6, vec![roster_member(1, "desk")]));
    store.save().await.expect("save");

    // A fresh open reloads the floor, so a replayed epoch-5 roster is still refused after a restart.
    let mut reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
    assert_eq!(reloaded.contacts().roster_epoch(), Some(6));
    let replayed = reloaded
        .contacts_mut()
        .hydrate(&roster(5, vec![roster_member(2, "desk")]));
    assert!(!replayed, "a replay must be refused after a reload too");

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

#[tokio::test]
async fn store_round_trips_roster_provenance() {
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-prov-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(path.clone()).await.expect("open");
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("macbook")), node(1)); // hand-typed peer
    store
        .contacts_mut()
        .hydrate(&roster(4, vec![roster_member(2, "desk")])); // roster member
    store.save().await.expect("save");

    // Reload: the hand-typed peer stays HandTyped, the fleet member stays Roster with its epoch. Provenance
    // survives persistence, so the moat is not a purely in-memory property.
    let reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
    let contacts = reloaded.contacts();
    assert_eq!(
        resolve(contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(2)])
    );
    assert_eq!(me_sources(contacts), vec![Source::Roster { epoch: 4 }]);
    let alice = contacts
        .bindings(&petname("alice"))
        .expect("alice present")
        .next()
        .expect("one device")
        .1
        .source;
    assert_eq!(alice, Source::HandTyped);

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}
