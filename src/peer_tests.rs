use std::path::Path;

use bifrost::NodeId;

use super::{Kind, MachineError, Peer};
use crate::contacts::{Contacts, Petname};
use crate::credential::LinkExt as _;
use crate::link::LinkError;

/// A distinct node id for a test, derived from a fixed seed so it is stable and comparable.
fn node(seed: u8) -> NodeId {
    NodeId::from_ed25519_secret(&[seed; 32])
}

/// A real signet-bound `swoosh:` link (work issues it for a foreign fleet), so a test can assert a
/// `Capability` peer self-addresses to the cap ROOT and folds its slip into the credential.
fn signet_link() -> String {
    let slip = crate::testkit::TestNode::seeded(1)
        .fleet_slip(
            &"ssh".parse().expect("valid service"),
            crate::testkit::TestRoot::seeded(2).verify_key(),
            nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
        )
        .expect("mint a signet-bound slip");
    crate::link::Link::from(slip).to_string()
}

/// `me/ci` parses as a `Named` peer (not a raw key, not a link) and resolves through the book to the key
/// saved under it, one of your devices; a raw key parses `Raw` and needs no name; an unknown word is a
/// refusal, never a silent nothing.
#[test]
fn a_petname_peer_resolves_through_contacts_to_the_saved_key() {
    let ci = node(7);
    let mut contacts = Contacts::default();
    contacts.add(
        "me".parse::<Petname>().expect("valid petname"),
        Some("ci".parse().expect("valid device")),
        ci,
    );

    let peer = "me/ci".parse::<Peer>().expect("a petname parses as a Peer");
    assert!(
        matches!(peer, Peer::Named(_)),
        "a saved-contact address parses as a petname to resolve, not a raw key"
    );
    let machine = peer
        .machine(&contacts)
        .expect("a known name resolves to a machine");
    assert_eq!(
        machine.key(),
        ci,
        "the name dials the key it was saved under"
    );
    assert_eq!(machine.kind(), Kind::Yours);

    let raw = node(9);
    let peer = raw.to_string().parse::<Peer>().expect("a raw key parses");
    assert!(
        matches!(peer, Peer::Raw(_)),
        "a raw base32 key is a Raw peer"
    );
    let machine = peer.machine(&contacts).expect("a raw key needs no store");
    assert_eq!(machine.key(), raw);
    assert_eq!(machine.kind(), Kind::Key);
    assert_eq!(machine.name(), None);

    let ghost = "ghost".parse::<Peer>().expect("a name parses as a Peer");
    assert!(
        matches!(ghost.machine(&contacts), Err(MachineError::NotSaved { .. })),
        "an unknown name is a refusal, not a silent nothing"
    );
}

/// A base32 key is `Raw`, never `Named`: petnames are additive, so a literal key always wins the parse
/// order and never needs a store lookup.
#[test]
fn a_raw_key_parses_before_a_petname() {
    let raw = node(11);
    let peer = raw.to_string().parse::<Peer>().expect("a raw key parses");
    assert!(
        matches!(peer, Peer::Raw(_)),
        "a base32 key parses as Raw, never as a petname to resolve"
    );
}

/// A pasted `swoosh:<link>` parses as a `Capability` peer and resolves to the cap root (`dial_node`), a
/// machine of kind `Link` whatever the book calls that key.
#[test]
fn a_pasted_swoosh_link_parses_as_a_peer() {
    let link = signet_link();
    let peer = link.parse::<Peer>().expect("a swoosh: link parses");
    let root = match &peer {
        Peer::Capability { link, .. } => link.dial_node().expect("a link root is a key"),
        _ => panic!("a swoosh: link parses as a Capability peer"),
    };

    let machine = peer
        .machine(&Contacts::default())
        .expect("a link resolves with no store");
    assert_eq!(machine.key(), root, "the link dials its cap root");
    assert_eq!(machine.kind(), Kind::Link);

    let mut contacts = Contacts::default();
    contacts
        .save(&"me/nas".parse().expect("a device name"), root)
        .expect("the name is free");
    let machine = peer.machine(&contacts).expect("a link resolves");
    assert_eq!(
        machine.kind(),
        Kind::Link,
        "a link stays a link even when its machine is one of yours"
    );
    assert_eq!(
        machine.name().map(ToString::to_string).as_deref(),
        Some("me/nas")
    );
}

/// A malformed `swoosh:` link is a `PeerParseError::Capability` at the boundary, not deferred to a
/// petname lookup that would miss: the parse fails fast where the user typed it.
#[test]
fn parse_rejects_a_malformed_link_at_the_boundary() {
    let error = "swoosh:not-a-real-link".parse::<Peer>();
    assert!(
        matches!(
            error,
            Err(super::PeerParseError::Capability(LinkError::Link(_)))
        ),
        "a bad swoosh: link is a Capability parse error, not a petname to resolve: {error:?}"
    );
}

/// A bare link typed where a peer goes (`ed01….x`) is not a name and not a key: it refuses with the
/// line that names the prefix, whatever follows the dot.
#[test]
fn a_bare_link_is_refused_with_the_prefix_hint() {
    let bare = crate::link::parse(&signet_link()).expect("a link");
    for text in [bare.as_str().to_owned(), format!("{}.x", node(3))] {
        let error = text.parse::<Peer>().expect_err("a bare link is refused");
        assert!(
            matches!(error, super::PeerParseError::Capability(LinkError::Prefix)),
            "{text}: {error:?}"
        );
        assert_eq!(
            error.to_string(),
            "this looks like a link; a link starts with `swoosh:`"
        );
    }
}

/// A peer typed as a path reads the link its file holds, one trailing newline trimmed, and keeps the
/// path; a file holding anything else refuses naming the path as typed.
#[test]
fn a_path_peer_reads_its_link_from_the_file() {
    let dir = std::env::temp_dir().join(format!("swoosh-peer-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let link = signet_link();
    let kept = dir.join("nas.link");
    std::fs::write(&kept, format!("{link}\n")).expect("write");
    let typed = kept.to_str().expect("a UTF-8 path");
    let peer = typed.parse::<Peer>().expect("a path holding a link parses");
    assert_eq!(peer.file(), Some(kept.as_path()));
    assert_eq!(
        peer.self_present()
            .map(|held| crate::link::Link::from(held).to_string()),
        Some(link),
    );

    let empty = dir.join("empty");
    std::fs::write(&empty, "alice\n").expect("write");
    let typed = empty.to_str().expect("a UTF-8 path");
    let error = typed
        .parse::<Peer>()
        .expect_err("a file with no link refuses");
    assert_eq!(error.to_string(), format!("{typed} holds no swoosh: link."));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A path that cannot be read refuses with the reason, so a missing file, a directory, and a device
/// each say which they are instead of sharing one line.
#[test]
fn an_unreadable_peer_path_says_why() {
    let dir = std::env::temp_dir().join(format!("swoosh-peer-why-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let missing = dir.join("nope");
    let missing = missing.to_str().expect("a UTF-8 path");
    assert_eq!(
        missing
            .parse::<Peer>()
            .expect_err("a missing file refuses")
            .to_string(),
        format!("could not read {missing}: no such file or directory"),
    );
    let folder = dir.to_str().expect("a UTF-8 path");
    assert_eq!(
        folder
            .parse::<Peer>()
            .expect_err("a directory refuses")
            .to_string(),
        format!("{folder} is not a file; name the file that holds the swoosh: link"),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Only a regular file is read, and only so far: a device refuses before any read (so `/dev/zero`
/// cannot fill memory, nor a FIFO wait on a writer), and a regular file larger than any link refuses
/// without being read whole.
#[test]
fn a_peer_path_reads_only_a_small_regular_file() {
    assert_eq!(
        "/dev/null"
            .parse::<Peer>()
            .expect_err("a device refuses")
            .to_string(),
        "/dev/null is not a file; name the file that holds the swoosh: link",
    );
    let dir = std::env::temp_dir().join(format!("swoosh-peer-big-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let big = dir.join("big.link");
    let padded = format!("{}{}", signet_link(), "a".repeat(128 * 1024));
    std::fs::write(&big, padded).expect("write");
    let typed = big.to_str().expect("a UTF-8 path");
    assert_eq!(
        typed
            .parse::<Peer>()
            .expect_err("a huge file refuses")
            .to_string(),
        format!("{typed} is too large to hold one swoosh: link"),
    );
    // A FIFO with no writer refuses at once: it is opened without waiting, then refused by its type.
    let fifo = dir.join("fifo.link");
    let named = std::ffi::CString::new(fifo.to_str().expect("a UTF-8 path")).expect("no NUL");
    // SAFETY: `named` is a valid NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(named.as_ptr(), 0o600) }, 0, "mkfifo");
    let typed = fifo.to_str().expect("a UTF-8 path");
    assert_eq!(
        typed
            .parse::<Peer>()
            .expect_err("a FIFO refuses")
            .to_string(),
        format!("{typed} is not a file; name the file that holds the swoosh: link"),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file holding a `swoosh:` link that does not parse names the file in its refusal.
#[test]
fn a_bad_link_in_a_file_names_the_file() {
    let dir = std::env::temp_dir().join(format!("swoosh-peer-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let bad = dir.join("bad.link");
    std::fs::write(&bad, "swoosh:notalink\n").expect("write");
    let typed = bad.to_str().expect("a UTF-8 path");
    assert_eq!(
        typed
            .parse::<Peer>()
            .expect_err("a bad link refuses")
            .to_string(),
        format!("{typed}: not a valid link"),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `~/` joins onto `HOME`; an unset or empty `HOME` refuses naming the full path as the fix, rather
/// than an empty one reading `~/x` as `x` in the working directory.
#[test]
fn a_tilde_path_needs_a_non_empty_home() {
    assert_eq!(
        super::expand("~/nas.link", Some("/home/me".into())).expect("expands"),
        Path::new("/home/me/nas.link"),
    );
    for home in [None, Some(std::ffi::OsString::new())] {
        assert_eq!(
            super::expand("~/nas.link", home)
                .expect_err("no home refuses")
                .to_string(),
            "HOME is not set, so ~/ has nowhere to point; type the file's full path",
        );
    }
}

/// A book holding `alice` with the given machines, a root-only `carol`, and your devices `desk` and `nas`.
fn book(alice: &[&str]) -> Contacts {
    let mut contacts = Contacts::default();
    for (seed, name) in (20u8..).zip(alice) {
        contacts
            .save(
                &format!("alice/{name}").parse().expect("a machine name"),
                node(seed),
            )
            .expect("the name is free");
    }
    contacts
        .save(&"carol".parse().expect("a person"), node(40))
        .expect("carol's root is saved");
    for (seed, name) in [(41u8, "desk"), (42, "nas")] {
        contacts
            .save(&format!("me/{name}").parse().expect("a device"), node(seed))
            .expect("the name is free");
    }
    contacts
}

/// Resolve `typed` against `contacts`.
fn resolve(contacts: &Contacts, typed: &str) -> Result<super::Machine, MachineError> {
    typed
        .parse::<Peer>()
        .expect("a peer parses")
        .machine(contacts)
}

/// A bare person with one machine saved is that machine, and says it was picked for them; a machine typed
/// whole is not "picked".
#[test]
fn a_bare_person_with_one_machine_resolves_to_it() {
    let contacts = book(&["laptop"]);
    let machine = resolve(&contacts, "alice").expect("one machine resolves");
    assert_eq!(machine.key(), node(20));
    assert_eq!(machine.kind(), Kind::Contact);
    assert_eq!(machine.picked().map(Petname::as_str), Some("alice"));
    assert_eq!(
        machine.name().map(ToString::to_string).as_deref(),
        Some("alice/laptop")
    );
    let typed = resolve(&contacts, "alice/laptop").expect("a machine resolves");
    assert_eq!(typed.picked(), None, "a machine typed whole was not picked");
}

/// A bare person with several machines is never guessed at: the refusal lists them in name order.
#[test]
fn a_bare_person_with_several_machines_never_resolves() {
    let contacts = book(&["nas", "laptop"]);
    let Err(MachineError::Several { person, machines }) = resolve(&contacts, "alice") else {
        panic!("several machines refuse");
    };
    assert_eq!(person.as_str(), "alice");
    let names: Vec<&str> = machines.iter().map(|label| label.as_str()).collect();
    assert_eq!(names, ["laptop", "nas"]);
}

/// A person saved with no machine, and a word saved as nobody, each refuse with their own kind.
#[test]
fn a_person_with_no_machine_and_an_unknown_word_refuse_apart() {
    let contacts = book(&[]);
    assert!(matches!(
        resolve(&contacts, "carol"),
        Err(MachineError::NoneSaved { person }) if person.as_str() == "carol"
    ));
    assert!(matches!(
        resolve(&contacts, "zed"),
        Err(MachineError::NotSaved { person }) if person.as_str() == "zed"
    ));
    assert!(matches!(
        resolve(&contacts, "zed/box"),
        Err(MachineError::NotSaved { person }) if person.as_str() == "zed"
    ));
}

/// `me` alone names none of your devices in particular, even with one; a bare word that is one of your
/// device names (and no person) names `me/<name>`; a person by that name wins over the device.
#[test]
fn me_alone_and_a_bare_device_name_refuse() {
    let contacts = book(&["laptop"]);
    let Err(MachineError::WhichOfYours { yours }) = resolve(&contacts, "me") else {
        panic!("me alone refuses");
    };
    let yours: Vec<String> = yours.iter().map(ToString::to_string).collect();
    assert_eq!(yours, ["me/desk", "me/nas"]);
    assert!(matches!(
        resolve(&contacts, "nas"),
        Err(MachineError::YourDevice { device }) if device.to_string() == "me/nas"
    ));
    let mut contacts = contacts;
    contacts
        .save(&"nas/box".parse().expect("a machine"), node(50))
        .expect("the name is free");
    assert_eq!(
        resolve(&contacts, "nas").expect("a person named nas").key(),
        node(50)
    );
}

/// The kind is read from the book for the key, never from the form typed: one of your devices typed by
/// its key (as the ssh bridge receives it) and by its name is one kind, and so is a contact's machine.
#[test]
fn the_kind_is_the_books_for_the_key_not_the_form_typed() {
    let contacts = book(&["laptop"]);
    for (typed, key, kind) in [
        ("me/nas", node(42), Kind::Yours),
        ("alice/laptop", node(20), Kind::Contact),
    ] {
        let by_name = resolve(&contacts, typed).expect("a name resolves");
        let by_key = resolve(&contacts, &key.to_string()).expect("a key resolves");
        assert_eq!(by_name.kind(), kind, "{typed}");
        assert_eq!(by_key.kind(), kind, "{typed} by its key");
        assert_eq!(by_key.name(), by_name.name(), "{typed} by its key");
    }
}
