//! Contact-store behaviour: petname/device parsing, add/list/remove, resolution, and persistence.

use bifrost::NodeId;

use super::*;
use crate::names::NameError;

/// A deterministic node id from a seed, so tests can assert on distinct identities. Each seed maps to a
/// valid `ed01` base32 string (an all-`seed`-byte key), parsed through the real boundary rather than
/// constructed, so the tests exercise the same path a user's pasted key takes.
fn node(seed: u8) -> NodeId {
    let encoded = match seed {
        1 => "ed01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq",
        2 => "ed01aibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaiba",
        3 => "ed01ambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambq",
        7 => "ed01a4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dq",
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

    let mut store = ContactsStore::open(path.clone())
        .await
        .expect("open empty into a fresh store dir");
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("macbook")), node(1));
    store.save().await.expect("save creates the store dir");

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

use nauthy::VerifyKey;

use crate::roster::{Epoch, FormatError, Member, RosterDoc};

/// A roster member whose node id is the all-`seed`-byte key, so it hydrates to the same [`node`] fixture,
/// which doubles as a check that the `VerifyKey -> NodeId` conversion preserves the bytes.
fn roster_member(seed: u8, label: &str) -> Member {
    crate::testkit::TestRoot::seeded(SIGNET_SEED)
        .member(
            VerifyKey::new([seed; 32]),
            label.parse::<DeviceLabel>().expect("valid device label"),
        )
        .expect("a member")
}

/// The root the roster members' standings are signed by.
const SIGNET_SEED: u8 = 0x5e;

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
    let _ = contacts.hydrate(&roster(
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
    let _ = contacts.hydrate(&roster(9, vec![roster_member(1, "desk")]));
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(7)])
    );
    assert_eq!(me_sources(&contacts), vec![Source::HandTyped]);
}

#[test]
fn hydrate_refreshes_on_a_newer_epoch_and_ignores_a_stale_one() {
    let mut contacts = Contacts::default();
    let _ = contacts.hydrate(&roster(5, vec![roster_member(1, "desk")]));
    let _ = contacts.hydrate(&roster(6, vec![roster_member(2, "desk")])); // newer epoch refreshes
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(2)])
    );
    let _ = contacts.hydrate(&roster(4, vec![roster_member(3, "desk")])); // stale epoch is ignored
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(2)])
    );
    assert_eq!(me_sources(&contacts), vec![Source::Roster { epoch: 6 }]);
    // The floor advanced to the highest APPLIED epoch, not the last one seen: the stale 4 did not lower it.
    assert_eq!(contacts.roster_floor(), Some(Epoch(6)));
}

#[test]
fn hydrate_drops_a_removed_member_on_a_forward_pull() {
    // F1 (the important one): a member removed in a newer roster must DISAPPEAR, not linger. A snapshot is a
    // full replace, so `phone` (absent from epoch 6) is dropped, and only `desk` survives.
    let mut contacts = Contacts::default();
    let _ = contacts.hydrate(&roster(
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
    let _ = contacts.hydrate(&roster(6, vec![roster_member(1, "desk")])); // phone removed at epoch 6
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
    let _ = contacts.hydrate(&roster(
        5,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    ));
    assert!(matches!(
        contacts.hydrate(&roster(6, vec![roster_member(1, "desk")])),
        Hydrated::Applied(_)
    ));
    // Replay the OLD epoch-5 roster: refused as a not-newer doc, a no-op.
    let replayed = contacts.hydrate(&roster(
        5,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    ));
    assert_eq!(
        replayed,
        Hydrated::NotNewer { floor: Epoch(6) },
        "a stale roster must be refused"
    );
    assert!(
        contacts
            .devices(&petname("me"))
            .expect("me")
            .all(|(label, _)| label.as_str() == "desk"),
        "the removed member must not be re-added by a replay"
    );
    assert_eq!(contacts.roster_floor(), Some(Epoch(6)));
}

#[test]
fn hydrate_refuses_a_same_epoch_re_cut() {
    // F1: a same-epoch doc is a no-op (not a merge), so a re-cut at the same epoch cannot overwrite.
    let mut contacts = Contacts::default();
    let _ = contacts.hydrate(&roster(6, vec![roster_member(1, "desk")]));
    let same = contacts.hydrate(&roster(6, vec![roster_member(2, "desk")]));
    assert_eq!(
        same,
        Hydrated::NotNewer { floor: Epoch(6) },
        "a same-epoch roster must be refused"
    );
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
    let _ = contacts.hydrate(&roster(5, vec![roster_member(1, "desk")]));
    let _ = contacts.hydrate(&roster(6, vec![roster_member(2, "phone")])); // replaces desk, keeps laptop
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
    let _ = store
        .contacts_mut()
        .hydrate(&roster(6, vec![roster_member(1, "desk")]));
    store.save().await.expect("save");

    // A fresh open reloads the floor, so a replayed epoch-5 roster is still refused after a restart.
    let mut reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
    assert_eq!(reloaded.contacts().roster_floor(), Some(Epoch(6)));
    let replayed = reloaded
        .contacts_mut()
        .hydrate(&roster(5, vec![roster_member(2, "desk")]));
    assert_eq!(
        replayed,
        Hydrated::NotNewer { floor: Epoch(6) },
        "a replay must be refused after a reload too"
    );

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
    let _ = store
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

/// A device may be named `signet`: the signet is stored under a key that is not a name, so the two never
/// collide on save.
#[tokio::test]
async fn a_device_named_signet_keeps_its_own_row_beside_the_signet() {
    let dir =
        std::env::temp_dir().join(format!("swoosh-contacts-signet-row-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(path.clone()).await.expect("open");
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("signet")), node(1));
    let _ = store.contacts_mut().set_signet(petname("alice"), node(2));
    store.save().await.expect("save");

    let reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
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
            ContactsStore::open(path.clone()).await.is_err(),
            "a capital on disk refuses: {text}"
        );
    }
    tokio::fs::write(&path, format!("[alice]\nlaptop = \"{key}\"\n"))
        .await
        .expect("write");
    assert!(
        ContactsStore::open(path.clone()).await.is_ok(),
        "the stored spelling loads"
    );
    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

#[test]
fn hydrate_keeps_a_hand_typed_signet_and_touches_only_devices() {
    // The write-fence: `hydrate` folds a roster's DEVICES under `me` and never reads or writes the signet, so
    // a hand-typed `me` signet survives every pull while the roster devices land.
    let mut contacts = Contacts::default();
    contacts.set_signet(petname("me"), node(7));
    let _ = contacts.hydrate(&roster(
        9,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    ));

    assert_eq!(
        contacts.signet(&petname("me")).map(|binding| binding.node),
        Some(node(7)),
        "hydrate leaves the hand-typed signet untouched"
    );
    assert_eq!(
        resolve(&contacts, &"me/desk".parse().expect("addr")),
        Ok(vec![node(1)]),
        "the roster devices land under me"
    );
    assert_eq!(
        resolve(&contacts, &"me/phone".parse().expect("addr")),
        Ok(vec![node(2)])
    );
}

#[tokio::test]
async fn store_round_trips_a_signet_and_keeps_the_device_map() {
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-signet-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(path.clone()).await.expect("open");
    store.contacts_mut().set_signet(petname("alice"), node(3));
    store
        .contacts_mut()
        .add(petname("alice"), Some(device("laptop")), node(1));
    store.save().await.expect("save");

    // The signet persists under a key that is not a name, co-located in alice's own block.
    let text = tokio::fs::read_to_string(&path).await.expect("read file");
    assert!(
        text.contains("signet_root = "),
        "the signet round-trips as its own key in the person's table: {text}"
    );

    // Reload: the signet comes back HandTyped, and the device map is unaffected.
    let reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
    let contacts = reloaded.contacts();
    let signet = contacts
        .signet(&petname("alice"))
        .expect("alice has a signet");
    assert_eq!(signet.node, node(3), "the signet key round-trips");
    assert_eq!(
        signet.source,
        Source::HandTyped,
        "a hand-typed signet reloads HandTyped"
    );
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

    let mut store = ContactsStore::open(path.clone()).await.expect("open");
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
    store.save().await.expect("save");

    let reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
    assert_eq!(
        reloaded.contacts().signet(&petname("bob")).map(|b| b.node),
        Some(node(2)),
        "a signet-only person round-trips through encode/decode"
    );

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

/// The version counts CHANGES to the `me/*` member set, and nothing else.
///
/// The renewal case is the load-bearing one: `invite add` re-run for a device already on file at the same
/// key is a quarterly badge renewal, it leaves the member set byte-identical, and bumping there would weld
/// credential churn to the membership version and drive every device through a full re-pull four times a
/// year for no delta.
#[test]
fn the_version_bumps_on_a_member_set_change_and_never_on_a_renewal() {
    let mut contacts = Contacts::default();
    assert_eq!(contacts.roster_version(), RosterVersion::Unversioned);

    contacts.add(petname("me"), Some(device("desk")), node(1));
    let after_enrol = contacts.roster_version();
    assert_eq!(after_enrol.epoch(), Some(Epoch(1)), "the first edit is 1");

    // A RENEWAL: the same label, the same key. `Added::Unchanged`, so no bump.
    assert_eq!(
        contacts.add(petname("me"), Some(device("desk")), node(1)),
        Added::Unchanged
    );
    assert_eq!(
        contacts.roster_version(),
        after_enrol,
        "re-inviting a device at the same key changes no member and must not bump"
    );

    // A re-key IS a member change.
    assert_eq!(
        contacts.add(petname("me"), Some(device("desk")), node(2)),
        Added::Replaced(node(1))
    );
    assert_eq!(contacts.roster_version().epoch(), Some(Epoch(2)));

    // A peer who is not in your fleet is not a member.
    contacts.add(petname("alice"), Some(device("macbook")), node(3));
    assert_eq!(
        contacts.roster_version().epoch(),
        Some(Epoch(2)),
        "a contact outside `me` is not a fleet member"
    );

    // Removing a member is a change; removing nothing is not.
    assert_eq!(
        contacts.remove(&petname("me"), Some(&device("desk"))),
        Removed::Removed
    );
    assert_eq!(contacts.roster_version().epoch(), Some(Epoch(3)));
    assert_eq!(
        contacts.remove(&petname("me"), Some(&device("ghost"))),
        Removed::Absent
    );
    assert_eq!(
        contacts.roster_version().epoch(),
        Some(Epoch(3)),
        "an absent removal changed no member"
    );
}

/// Dropping a `me` that holds ONLY a signet changes no member, so it must not burn a version. A roster
/// carries devices and no signet, so the cut would be byte-identical at a higher epoch.
#[test]
fn dropping_a_signet_only_me_does_not_bump_the_version() {
    let mut contacts = Contacts::default();
    contacts.set_signet(petname("me"), node(1));
    assert_eq!(contacts.remove(&petname("me"), None), Removed::Removed);
    assert_eq!(contacts.roster_version(), RosterVersion::Unversioned);
}

/// Hydrating someone else's snapshot advances the FLOOR and never this book's own version. One fleet has
/// exactly one cutter, and a puller that bumped its version on every pull would be a second writer.
#[test]
fn a_pull_advances_the_floor_and_never_the_version() {
    let mut contacts = Contacts::default();
    assert!(matches!(
        contacts.hydrate(&roster(4, vec![roster_member(1, "desk")])),
        Hydrated::Applied(_)
    ));
    assert_eq!(contacts.roster_floor(), Some(Epoch(4)));
    assert_eq!(contacts.roster_version(), RosterVersion::Unversioned);
}

/// Epoch 0 is RESERVED for a pre-versioning cutter, so it is refused even by a book with NO floor.
///
/// This is the migration rule's other half. The first hydrate normally always applies, which is exactly
/// how every device in the field got pinned at floor 0 by a cutter that could only ever emit 0, after
/// which no pull ever applied again. Refusing 0 outright means a stuck fleet unsticks itself on the
/// owner's next edit instead of needing an operator to reset anything.
#[test]
fn an_unversioned_roster_is_refused_even_on_a_first_pull() {
    let mut contacts = Contacts::default();
    assert_eq!(
        contacts.hydrate(&roster(0, vec![roster_member(1, "desk")])),
        Hydrated::Unversioned
    );
    assert!(
        contacts.devices(&petname("me")).is_none(),
        "an unversioned roster writes nothing"
    );
    assert_eq!(
        contacts.roster_floor(),
        None,
        "and it must not pin the floor, which is what froze every fleet in the field"
    );
}

/// An applied pull reports what it actually did, because "pulled N member(s)" over a doc's member count
/// is how a fold that bound nothing (or DELETED devices) still read as a success.
#[test]
fn an_applied_pull_reports_what_it_bound_skipped_and_removed() {
    let mut contacts = Contacts::default();
    contacts.add(petname("me"), Some(device("laptop")), node(7)); // sovereign, hand-typed
    let Hydrated::Applied(first) = contacts.hydrate(&roster(
        1,
        vec![roster_member(1, "desk"), roster_member(2, "phone")],
    )) else {
        panic!("a versioned first pull applies");
    };
    assert_eq!(first.bound(), 2);
    assert_eq!(first.skipped(), 0);
    assert!(first.removed().is_empty(), "nothing was there to remove");

    // A THINNER snapshot: the owner removed `phone`, and claims a label the operator holds by hand.
    let Hydrated::Applied(second) = contacts.hydrate(&roster(
        2,
        vec![roster_member(1, "desk"), roster_member(3, "laptop")],
    )) else {
        panic!("a newer pull applies");
    };
    assert_eq!(second.bound(), 1, "only `desk` was actually bound");
    assert_eq!(
        second.skipped(),
        1,
        "`laptop` is a name the operator set, so the roster's member was not bound"
    );
    assert_eq!(
        second
            .removed()
            .iter()
            .map(DeviceLabel::as_str)
            .collect::<Vec<_>>(),
        vec!["phone"],
        "a snapshot-replace DELETES a device the new doc omits, and must name it"
    );
}

/// A refreshed member is not a removed one: the label was dropped and laid straight back down, at a new
/// key. Reporting it as a removal would make every re-key read as a device leaving the fleet.
#[test]
fn a_refreshed_member_is_not_reported_as_removed() {
    let mut contacts = Contacts::default();
    let _ = contacts.hydrate(&roster(1, vec![roster_member(1, "desk")]));
    let Hydrated::Applied(applied) = contacts.hydrate(&roster(2, vec![roster_member(2, "desk")]))
    else {
        panic!("a newer pull applies");
    };
    assert!(applied.removed().is_empty());
    assert_eq!(applied.bound(), 1);
}

/// THE regression, driven through the real product loop rather than hand-written epochs: cut, pull, EDIT,
/// cut, pull. The old single-field design passed every literal-epoch test and failed exactly here, because
/// the cutter stamped its doc with the PULLER's floor, which only a pull advanced, so a signet holder cut
/// epoch 0 forever and a device could learn its fleet exactly once, restart included.
#[tokio::test]
async fn a_device_keeps_learning_the_fleet_after_every_edit() {
    let signet = crate::testkit::TestRoot::seeded(5);

    // The owner's book: it CUTS and never pulls, so its floor stays None for the whole test.
    let mut owner = Contacts::default();
    owner.add(petname("me"), Some(device("desk")), node(1));

    let cut = |owner: &Contacts| {
        let doc = cut_roster(owner)
            .expect("a well-formed cut")
            .expect("a versioned book has something to cut");
        crate::roster::cut(signet.identity(), &doc)
    };

    // Pull 1: the fresh device learns the fleet.
    let mut device_zero = Contacts::default();
    let doc = crate::roster::verify(&cut(&owner), signet.verify_key()).expect("verify");
    assert!(matches!(
        device_zero.hydrate(&doc),
        Hydrated::Applied(ref applied) if applied.bound() == 1
    ));

    // The owner invites a second machine. No restart, no second verb: the edit IS the version bump.
    owner.add(petname("me"), Some(device("phone")), node(2));
    assert_eq!(
        owner.roster_floor(),
        None,
        "a cutter never pulls, so the floor is the wrong number to stamp a cut with"
    );

    // Pull 2: it applies, which is the whole fix.
    let doc = crate::roster::verify(&cut(&owner), signet.verify_key()).expect("verify");
    let Hydrated::Applied(applied) = device_zero.hydrate(&doc) else {
        panic!("the second pull must apply: a device learns its fleet more than once");
    };
    assert_eq!(applied.bound(), 2);
    assert_eq!(
        resolve(&device_zero, &"me/phone".parse().expect("addr")),
        Ok(vec![node(2)])
    );

    // And the floor still refuses a genuine replay of the earlier cut, so freshness did not cost safety.
    let stale = crate::roster::verify(
        &crate::roster::cut(
            signet.identity(),
            &RosterDoc::new(Epoch(1), vec![roster_member(1, "desk")]).expect("doc"),
        ),
        signet.verify_key(),
    )
    .expect("verify");
    assert_eq!(
        device_zero.hydrate(&stale),
        Hydrated::NotNewer { floor: Epoch(2) }
    );
}

/// The version survives a restart. A cutter that reset to 1 on reboot would re-emit a version pullers
/// have already applied, and their floor would refuse every later cut: the freeze, reintroduced.
#[tokio::test]
async fn the_store_round_trips_the_membership_version() {
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-ver-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let mut store = ContactsStore::open(path.clone()).await.expect("open");
    store
        .contacts_mut()
        .add(petname("me"), Some(device("desk")), node(1));
    store
        .contacts_mut()
        .add(petname("me"), Some(device("phone")), node(2));
    store.save().await.expect("save");

    let reloaded = ContactsStore::open(path.clone()).await.expect("reopen");
    assert_eq!(
        reloaded.contacts().roster_version().epoch(),
        Some(Epoch(2)),
        "the cutter's version must survive a restart"
    );
    // The two counters persist under two keys and stay independent.
    assert_eq!(reloaded.contacts().roster_floor(), None);

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

/// A book written before membership versioning existed loads as UNVERSIONED, and the operator's next edit
/// lifts it to 1, which is newer than every floor in the field. That is the whole migration: no reset, no
/// verb, no `--force`, nothing an operator has to know.
#[tokio::test]
async fn a_pre_versioning_book_unsticks_itself_on_the_next_edit() {
    let dir = std::env::temp_dir().join(format!("swoosh-contacts-mig-{}", std::process::id()));
    let path = dir.join("contacts.toml");
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await.expect("mkdir");
    // Exactly what an upgrading operator's file looks like: a fleet, a floor pinned at 0 by the one pull
    // that ever applied, and no version key at all.
    tokio::fs::write(
        &path,
        format!("roster_epoch = 0\n\n[me]\ndesk = \"{}\"\n", node(1)),
    )
    .await
    .expect("write the legacy file");

    let mut store = ContactsStore::open(path.clone()).await.expect("open");
    assert_eq!(
        store.contacts().roster_version(),
        RosterVersion::Unversioned
    );
    assert!(
        cut_roster(store.contacts()).expect("cut").is_none(),
        "an unversioned book has nothing a puller may accept, so it cuts nothing"
    );

    store
        .contacts_mut()
        .add(petname("me"), Some(device("phone")), node(2));
    let doc = cut_roster(store.contacts())
        .expect("cut")
        .expect("the edit made it versioned");
    assert_eq!(doc.epoch(), Epoch(1));

    // And the stuck puller, floor 0, applies it.
    let mut stuck = Contacts::default();
    stuck.set_roster_floor(Some(Epoch(0)));
    assert!(matches!(stuck.hydrate(&doc), Hydrated::Applied(_)));

    tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
}

/// The `me/*` member set as a roster doc stamped with the book's version, or `None` for an unversioned
/// book: the cut a signer makes from this book, which these tests pull through `hydrate`.
fn cut_roster(contacts: &Contacts) -> Result<Option<RosterDoc>, FormatError> {
    let Some(epoch) = contacts.roster_version.epoch() else {
        return Ok(None);
    };
    let members: Vec<Member> = contacts
        .people
        .get(&Petname(ME.to_owned()))
        .into_iter()
        .flat_map(|person| person.devices.iter())
        .map(|(label, binding)| {
            crate::testkit::TestRoot::seeded(SIGNET_SEED)
                .member(VerifyKey::new(*binding.node.key()), label.clone())
                .expect("a member")
        })
        .collect();
    RosterDoc::new(epoch, members).map(Some)
}
