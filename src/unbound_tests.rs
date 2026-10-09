//! The client half of the default-service pairing: that each defaulted name has a `service add` form that
//! serves that very name.
//!
//! The serve half (that a bare `swoosh serve` binds exactly `ping`, `speed` and the two `control.*`
//! routes, and none of the names in this table) is proven against the real default set in the
//! binary's `serve` tests, which is where that set lives.

use std::collections::BTreeSet;

use super::Unbound;

/// A name no verb defaults to is not in the table, and neither are the ones a bare `serve` DOES bind.
#[test]
fn a_name_the_client_did_not_default_to_is_not_a_row() {
    for name in [
        "ping",
        "speed",
        "control.stop",
        "control.services",
        "roster",
        "sshd",
        "web",
    ] {
        assert!(
            Unbound::dialed(name).is_none(),
            "`{name}` is not one of the defaults a bare serve leaves unbound"
        );
    }
}

/// Every row's `service add` form binds its OWN name, read through the parser `serve` runs: a form that
/// bound some other name would send an operator to run a line that leaves the dial refused exactly as
/// before. Each placeholder is filled with a value first, since the parser reads a proxy's URL.
#[test]
fn every_row_has_an_add_form_that_binds_its_own_name() {
    let mut names = BTreeSet::new();
    for unbound in Unbound::all() {
        let name = unbound.name();
        let entry = crate::serve::entry_for(name);
        let typed = entry
            .replace("<url>", "https://example.com")
            .replace("<dir>", "/srv/inbox");
        let parsed = crate::serve::service_entry(&typed).expect("the form a row teaches parses");
        let (bound, target) = parsed
            .split_once('=')
            .expect("a parsed entry is always `name=target`");
        assert_eq!(
            bound, name,
            "`{entry}` must bind `{name}`, the name the client dials"
        );
        assert!(
            target.contains(':'),
            "`{entry}` must name a target scheme, which is what `serve` parses"
        );
        assert!(
            names.insert(name),
            "`{name}` appears twice, so a lookup would answer with whichever row came first"
        );
    }
    assert_eq!(
        names.len(),
        3,
        "the three verbs that default outside the bare set: {names:?}"
    );
}
