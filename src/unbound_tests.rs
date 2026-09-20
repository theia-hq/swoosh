//! The client half of the default-service pairing: that a failed dial of a defaulted name names the
//! `serve` entry that would bind it, and that it names the SAME one however the dial failed.
//!
//! The serve half (that a bare `swoosh serve` binds exactly `ping`, `speed` and the two `control.*`
//! routes, and none of the names in this table) is proven against the real default set in the
//! binary's `serve` tests, which is where that set lives.

use std::collections::BTreeSet;

use super::Unbound;

/// THE TRIPWIRE. The sentence attaches to every way a dial of the name can fail, and reads the same
/// every time: a uniform refusal, a refusal with a different reason, a timeout that never reached the
/// peer, and a wrapped chain all come back carrying byte-identical text.
///
/// This is what keeps the client from becoming an oracle. The wire refusal is uniform on purpose (an
/// unserved name and an unadmitted caller read alike), and a client that said more about one failure
/// than another would hand back the distinction the wire withholds, the day the wire stops being
/// uniform. So the check is not "the sentence appears" but "the same sentence appears, always".
#[test]
fn the_same_sentence_attaches_to_every_way_a_dial_can_fail() {
    // Four failures with nothing in common but that they happened: the words `refused`, `not
    // admitted`, a plain timeout that never reached the gate at all, and a two-link chain.
    let failures = [
        "refused: not admitted",
        "refused: service unavailable",
        "timed out after 10s with no response",
        "could not reach alice: no route to host",
    ];
    let teaching = Unbound::SSH.teaching();
    for failure in failures {
        let named = Unbound::name_the_entry(eyre::eyre!("{failure}"), Unbound::SSH.name());
        assert_eq!(
            format!("{named:#}"),
            format!("{teaching}: {failure}"),
            "the same sentence, verbatim, whatever came back"
        );
    }
    assert!(
        teaching.contains("swoosh serve ssh=sshd:"),
        "the sentence names the exact serve line that enables the dial: {teaching}"
    );
}

/// A name no verb defaults to is left alone, and so are the two a bare `serve` DOES bind: there is
/// nothing for a client to teach about `ping` or `speed`, and `sshd` is the engine's spelling, never a
/// name any client requests. The report comes back byte-identical, with nothing appended.
#[test]
fn a_name_the_client_did_not_default_to_is_left_alone() {
    for name in [
        "ping",
        "speed",
        "control.stop",
        "control.services",
        "sshd",
        "web",
    ] {
        assert!(
            Unbound::dialed(name).is_none(),
            "`{name}` is not one of the defaults a bare serve leaves unbound"
        );
        let named = Unbound::name_the_entry(eyre::eyre!("refused: not admitted"), name);
        assert_eq!(
            format!("{named:#}"),
            "refused: not admitted",
            "`{name}` gets no sentence, so the report is untouched"
        );
    }
}

/// Every row teaches an entry that binds its OWN name: `<name>=<scheme>:`, the exact shape `serve`
/// parses. A row whose entry bound some other name would send an operator to run a line that leaves
/// the dial failing exactly as before.
#[test]
fn every_row_teaches_an_entry_that_binds_its_own_name() {
    let mut names = BTreeSet::new();
    for unbound in Unbound::all() {
        let (name, entry) = (unbound.name(), unbound.entry());
        assert!(
            entry.starts_with(&format!("{name}=")),
            "`{entry}` must bind `{name}`, the name the client dials"
        );
        let (_, target) = entry
            .split_once('=')
            .expect("the assertion above found the `=`");
        assert!(
            target.contains(':'),
            "`{entry}` must name a target scheme, which is what `serve` parses"
        );
        assert!(
            unbound
                .teaching()
                .contains(&format!("swoosh serve {entry}")),
            "the sentence hands over a whole serve line, not a fragment: {}",
            unbound.teaching()
        );
        assert!(
            names.insert(name),
            "`{name}` appears twice, so a lookup would answer with whichever row came first"
        );
    }
    assert_eq!(
        names.len(),
        4,
        "the four verbs that default outside the bare set: {names:?}"
    );
}
