//! The words for a machine argument: the refusals a machine that is not one machine exits 2 with, and
//! the dial refusal, by the kind of machine refused.

use std::ffi::OsString;

use bifrost::NodeId;
use nauthy::Service;
use swoosh::contacts::Contacts;
use swoosh::peer::{Machine, Peer};
use swoosh::reach::Diagnosis;

use super::{refused, usage};

/// The key of `me/nas`.
fn nas() -> NodeId {
    NodeId::from_ed25519_secret(&[0x61; 32])
}

/// The key of `bob/nas`.
fn bobs() -> NodeId {
    NodeId::from_ed25519_secret(&[0x62; 32])
}

/// A book holding your device `me/nas` and bob's machine `bob/nas`.
fn book() -> Contacts {
    let mut contacts = Contacts::default();
    contacts
        .save(&"me/nas".parse().expect("a device"), nas())
        .expect("the name is free");
    contacts
        .save(&"bob/nas".parse().expect("a machine"), bobs())
        .expect("the name is free");
    contacts
}

/// `typed` resolved against `contacts`, as the composition root resolves it.
fn machine(contacts: &Contacts, typed: &str) -> Machine {
    typed
        .parse::<Peer>()
        .expect("a peer parses")
        .machine(contacts)
        .expect("one machine")
}

fn ssh() -> Service {
    "ssh".parse().expect("a service")
}

/// Every line a dial refusal can print, for a test that reads them all.
fn every_refusal() -> Vec<String> {
    let contacts = book();
    let yours = machine(&contacts, "me/nas");
    let mut lines: Vec<String> = [
        Some(Diagnosis::NotListed),
        Some(Diagnosis::Listed),
        Some(Diagnosis::NotYours),
        Some(Diagnosis::Unknown),
    ]
    .into_iter()
    .map(|diagnosis| refused(&yours, &ssh(), diagnosis).to_string())
    .collect();
    for typed in [
        "bob/nas".to_owned(),
        NodeId::from_ed25519_secret(&[0x63; 32]).to_string(),
    ] {
        lines.push(refused(&machine(&contacts, &typed), &ssh(), None).to_string());
    }
    lines
}

// A refusal from one of your own devices says which of the three causes the follow-up found: not served
// (with the `service add` form, built-ins bare and `recv` with its directory), listed (turned off, removed
// or busy, and `swoosh status` on that device), or the device does not count this machine as yours.
#[test]
fn a_dial_refused_by_your_device_names_the_cause() {
    let yours = machine(&book(), "me/nas");
    assert_eq!(
        refused(&yours, &ssh(), Some(Diagnosis::NotListed)).to_string(),
        "me/nas does not serve ssh\n  Only nas can add it; on nas, run:\n    swoosh service add ssh"
    );
    assert_eq!(
        refused(&yours, &ssh(), Some(Diagnosis::Listed)).to_string(),
        "me/nas refused ssh\n  ssh was turned off or removed on nas, or nas is too busy to take it \
         now.\n  On nas, run this to see which:\n    swoosh status"
    );
    assert_eq!(
        refused(&yours, &ssh(), Some(Diagnosis::NotYours)).to_string(),
        "me/nas refused ssh\n  nas does not count this machine as one of your devices."
    );
}

// The add form is the shortest that serves the name: `recv` names the directory files land in, `proxy`
// the site, and any other name a TCP target.
#[test]
fn a_dial_to_a_machine_not_serving_it_names_the_serve_command() {
    let yours = machine(&book(), "me/nas");
    for (service, form) in [
        ("recv", "recv:<dir>"),
        ("proxy", "proxy:<url>"),
        ("ping", "ping"),
        ("db", "db=tcp:<address>:<port>"),
    ] {
        let line = refused(
            &yours,
            &service.parse().expect("a service"),
            Some(Diagnosis::NotListed),
        )
        .to_string();
        assert!(
            line.ends_with(&format!("\n    swoosh service add {form}")),
            "{service}: {line}"
        );
    }
}

// A follow-up that claimed no cause prints the head alone: nothing it cannot prove.
#[test]
fn a_follow_up_that_claims_no_cause_prints_the_head_alone() {
    let yours = machine(&book(), "me/nas");
    assert_eq!(
        refused(&yours, &ssh(), Some(Diagnosis::Unknown)).to_string(),
        "me/nas refused ssh"
    );
}

// A contact's machine and a bare key are never asked why: the line names both causes the wire cannot
// tell apart, and no command, since none the reader can run fixes it.
#[test]
fn a_dial_refused_by_a_contact_names_both_causes() {
    let contacts = book();
    assert_eq!(
        refused(&machine(&contacts, "bob/nas"), &ssh(), None).to_string(),
        "bob/nas refused ssh\n  It does not serve ssh, or its owner has not shared ssh with you."
    );
    let stranger = NodeId::from_ed25519_secret(&[0x63; 32]).to_string();
    assert_eq!(
        refused(&machine(&contacts, &stranger), &ssh(), None).to_string(),
        "that machine refused ssh\n  It does not serve ssh, or its owner has not shared ssh with you."
    );
}

// The wire's word for a refusal is never the reader's: no line says "not admitted".
#[test]
fn a_refused_dial_says_refused_not_admitted() {
    for line in every_refusal() {
        assert!(!line.contains("not admitted"), "{line}");
        assert!(
            line.contains("refused") || line.contains("does not serve"),
            "{line}"
        );
    }
}

// The ssh bridge receives the key of `me/nas` and the typed verb its name; the kind is read from the book
// for the key, so both print the same refusal.
#[test]
fn the_bridge_and_the_typed_verb_agree_on_the_kind() {
    let contacts = book();
    let typed = machine(&contacts, "me/nas");
    let bridged = machine(&contacts, &nas().to_string());
    assert_eq!(typed.kind(), bridged.kind());
    for diagnosis in [Some(Diagnosis::NotListed), Some(Diagnosis::NotYours), None] {
        assert_eq!(
            refused(&typed, &ssh(), diagnosis).to_string(),
            refused(&bridged, &ssh(), diagnosis).to_string(),
        );
    }
}

/// `argv` as the binary receives it.
fn argv(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

/// The usage error `typed` exits with on `verb`, typed as `words`.
fn refusal(contacts: &Contacts, verb: &str, words: &[&str], typed: &str) -> String {
    let error = typed
        .parse::<Peer>()
        .expect("a peer parses")
        .machine(contacts)
        .expect_err("not one machine");
    usage(&error, verb, &argv(words), typed).expect("a usage error")
}

// A bare word that is one of your devices hands back the line as typed, global flags included, with only
// the machine replaced; `send`'s machine is its last argument, so a file named like the machine stays.
#[test]
fn a_bare_device_name_hands_back_the_typed_line() {
    let contacts = book();
    assert_eq!(
        refusal(
            &contacts,
            "ssh",
            &[
                "/opt/swoosh",
                "--home",
                "/tmp/my home",
                "ssh",
                "nas",
                "--",
                "-p",
                "22"
            ],
            "nas"
        ),
        "name the machine:\n  swoosh --home '/tmp/my home' ssh me/nas -- -p 22"
    );
    assert_eq!(
        refusal(&contacts, "send", &["swoosh", "send", "nas", "nas"], "nas"),
        "name the machine:\n  swoosh send nas me/nas"
    );
}

// Several machines, none, and a word saved as nobody: each its own lines, `which machine?` in `stop`'s
// shape, and a fix only the reader can fill.
#[test]
fn a_bare_person_refuses_in_its_own_words() {
    let mut contacts = book();
    contacts
        .save(
            &"bob/laptop".parse().expect("a machine"),
            NodeId::from_ed25519_secret(&[0x64; 32]),
        )
        .expect("the name is free");
    contacts
        .save(
            &"carol".parse().expect("a person"),
            NodeId::from_ed25519_secret(&[0x65; 32]),
        )
        .expect("the name is free");
    assert_eq!(
        refusal(&contacts, "ping", &["swoosh", "ping", "bob"], "bob"),
        "which machine?\n  bob's: bob/laptop, bob/nas."
    );
    assert_eq!(
        refusal(&contacts, "ping", &["swoosh", "ping", "carol"], "carol"),
        "none of carol's machines is saved here\n  To reach carol, save one of carol's machines:\n    \
         swoosh contact add carol/<name> <key>"
    );
    assert_eq!(
        refusal(&contacts, "ping", &["swoosh", "ping", "zed"], "zed"),
        "zed is not saved here\n  To reach zed, save one of zed's machines:\n    swoosh contact add \
         zed/<name> <key>"
    );
    assert_eq!(
        refusal(&contacts, "ssh", &["swoosh", "ssh", "me"], "me"),
        "which machine?\n  Yours: me/nas."
    );
    assert_eq!(
        refusal(&Contacts::default(), "ssh", &["swoosh", "ssh", "me"], "me"),
        "which machine?\n  This machine knows none of your devices."
    );
}

// A machine name that is none of a known person's prints `stop`'s lines: the person's machines, or the
// save that would add this one; yours, or that this machine knows none of them, and never a save, since
// `me/` is your root's to name.
#[test]
fn an_unknown_machine_name_refuses_in_stops_shape() {
    let mut contacts = book();
    contacts
        .save(
            &"bob/laptop".parse().expect("a machine"),
            NodeId::from_ed25519_secret(&[0x64; 32]),
        )
        .expect("the name is free");
    contacts
        .save(
            &"carol".parse().expect("a person"),
            NodeId::from_ed25519_secret(&[0x65; 32]),
        )
        .expect("the name is free");
    assert_eq!(
        refusal(&contacts, "ping", &["swoosh", "ping", "bob/box"], "bob/box"),
        "bob has no machine box\n  bob's: bob/laptop, bob/nas."
    );
    assert_eq!(
        refusal(
            &contacts,
            "ping",
            &["swoosh", "ping", "carol/box"],
            "carol/box"
        ),
        "carol has no machine box\n  To reach carol, save one of carol's machines:\n    swoosh contact add \
         carol/box <key>"
    );
    assert_eq!(
        refusal(&contacts, "ping", &["swoosh", "ping", "me/box"], "me/box"),
        "you have no machine me/box\n  Yours: me/nas."
    );
    assert_eq!(
        refusal(
            &Contacts::default(),
            "ssh",
            &["swoosh", "ssh", "me/nas"],
            "me/nas"
        ),
        "you have no machine me/nas\n  This machine knows none of your devices."
    );
}
