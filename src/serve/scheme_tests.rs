//! The scheme list, the parsed target, and the line a link's recorded target must meet.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{BoundTargets, Scheme, ServedTarget};

/// `ALL`, `as_str` and `parse` come from one list, so each scheme reads back as itself, once.
#[test]
fn every_scheme_reads_back_as_itself() {
    for &scheme in Scheme::ALL {
        let target = format!("{}:rest", scheme.as_str());
        assert_eq!(Scheme::parse(&target), Some((scheme, "rest")), "{target}");
        assert_eq!(
            Scheme::ALL.iter().filter(|&&other| other == scheme).count(),
            1,
            "{scheme:?} is listed once"
        );
    }
    assert_eq!(Scheme::parse("png:"), None, "a scheme no serve binds");
    assert_eq!(Scheme::parse("ping"), None, "no scheme at all");
}

/// A recorded target names a scheme some `serve` binds and holds no control character.
#[test]
fn a_served_target_is_a_known_scheme_on_one_line() {
    let target: ServedTarget = "tcp:localhost:22".parse().unwrap();
    assert_eq!(
        (target.scheme(), target.argument()),
        (Scheme::Tcp, "localhost:22")
    );
    for refused in ["png:", "ssh", "recv:/a\nb", "recv:/a\tb"] {
        assert!(refused.parse::<ServedTarget>().is_err(), "{refused:?}");
    }
}

/// A link reaches only the target it was made for: one made for another target is refused whatever the
/// engine, and one made while the name served nothing is refused by an engine that must never face an open
/// gate, and admitted by one that may. A name this run binds nothing under checks nothing.
#[test]
fn a_link_is_admitted_only_to_the_target_it_was_made_for() {
    let target = |text: &str| text.parse::<ServedTarget>().unwrap();
    let bound = BoundTargets::of(["ssh=sshd:", "db=tcp:localhost:5432", "drop=recv:/srv/drop"]);

    assert!(bound.admits("ssh", Some(&target("sshd:"))));
    assert!(
        !bound.admits("ssh", Some(&target("tcp:localhost:22"))),
        "retargeted to a shell"
    );
    assert!(!bound.admits("ssh", None), "made when ssh served nothing");

    assert!(bound.admits("db", Some(&target("tcp:localhost:5432"))));
    assert!(
        !bound.admits("db", Some(&target("tcp:localhost:2375"))),
        "a forward moved to another port"
    );
    assert!(bound.admits("db", None), "a forward may face anyone");

    assert!(
        !bound.admits("drop", None),
        "receiving files never faces anyone"
    );
    assert!(bound.admits("other", None), "nothing bound under the name");
}

/// A name bound to a scheme [`Scheme`] does not know (one tightbeam might bind after an upgrade) admits no
/// link, whatever it was made for: this gate cannot say what that engine may face, so it fails closed.
#[test]
fn a_name_bound_to_an_unknown_scheme_admits_no_link() {
    let target = |text: &str| text.parse::<ServedTarget>().unwrap();
    let bound = BoundTargets::of(["web=gopher:localhost:70"]);

    assert!(!bound.admits("web", None), "made when web served nothing");
    assert!(
        !bound.admits("web", Some(&target("tcp:localhost:70"))),
        "made for a forward"
    );
}
