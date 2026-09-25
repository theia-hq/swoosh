use bifrost::NodeId;
use data_encoding::BASE32_NOPAD;
use nauthy::Link;

use super::{Invite, InviteError, encode_seed};
use crate::contacts::DeviceLabel;
use crate::testkit::{TestNode, TestRoot};

fn from() -> NodeId {
    TestNode::seeded(0xa0).node_id()
}

fn name() -> DeviceLabel {
    "laptop".parse().expect("a name")
}

/// A real root-signed standing, so a test carries what the product carries.
fn standing() -> Link {
    TestRoot::seeded(0xb0)
        .device_badge(
            TestNode::seeded(0xb1).node_id(),
            nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
        )
        .expect("mint a standing")
}

/// The standing's text rides once, bare, as the last two fields: its key is the root, and there is no
/// second copy of the root and no `swoosh:` mark in the token.
#[test]
fn an_invite_embeds_the_link_once() {
    let standing = standing();
    let root = standing.root().to_string();
    for token in [
        Invite::bound(from(), name(), Link::clone(&standing)).to_string(),
        Invite::keyed([7; 32], from(), name(), Link::clone(&standing)).to_string(),
    ] {
        assert!(
            token.ends_with(&format!(".{}", standing.as_str())),
            "{token}"
        );
        assert_eq!(token.matches(standing.as_str()).count(), 1, "{token}");
        assert_eq!(token.matches(&root).count(), 1, "one root: {token}");
        assert!(!token.contains("swoosh:"), "{token}");
    }
}

/// Four fields are bound and five are keyed; three and six are not an invite.
#[test]
fn an_invite_parses_by_field_count() {
    let standing = standing();
    let bound = Invite::bound(from(), name(), Link::clone(&standing)).to_string();
    let parsed = Invite::parse(&bound).expect("four fields parse");
    assert!(parsed.seed.is_none(), "four fields carry no key");

    let keyed = Invite::keyed([7; 32], from(), name(), Link::clone(&standing)).to_string();
    let parsed = Invite::parse(&keyed).expect("five fields parse");
    assert_eq!(parsed.seed.as_deref(), Some(&[7; 32]));
    assert_eq!(parsed.standing.as_str(), standing.as_str());

    let three = format!("invite:{}.{}", name(), standing.as_str());
    let six = format!("invite:{}.{}", encode_seed(&[7; 32]).as_str(), &keyed[7..]);
    for token in [three, six] {
        let refused = Invite::parse(&token).expect_err("not 4 or 5 fields");
        assert!(matches!(refused, InviteError::NotAnInvite), "{token}");
        assert_eq!(refused.to_string(), "this is not a swoosh invite");
    }
}

/// `<from>` and `<name>` survive the encode and the parse, in both shapes.
#[test]
fn an_invite_round_trips_its_from_and_name() {
    for token in [
        Invite::bound(from(), name(), standing()).to_string(),
        Invite::keyed([7; 32], from(), name(), standing()).to_string(),
    ] {
        let parsed = Invite::parse(&token).expect("parses");
        assert_eq!(parsed.from, from());
        assert_eq!(parsed.name, name());
    }
}

/// The prefix matches in any ASCII case with surrounding whitespace trimmed, and is required.
#[test]
fn the_prefix_is_required_in_any_case() {
    let token = Invite::bound(from(), name(), standing()).to_string();
    let shouted = format!("  INVITE:{}\n", &token["invite:".len()..]);
    assert!(Invite::parse(&shouted).is_ok());
    assert!(matches!(
        Invite::parse(&token["invite:".len()..]),
        Err(InviteError::NotAnInvite)
    ));
}

/// The manual Debug redacts the seed: a device seed IS a key, so no `{:?}` may print it.
#[test]
fn a_keyed_invite_debug_redacts_the_seed() {
    let seed = [7u8; 32];
    let shown = format!("{:?}", Invite::keyed(seed, from(), name(), standing()));
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(!shown.contains("7, 7"), "{shown}");
    assert!(
        !shown.contains(&BASE32_NOPAD.encode(&seed).to_lowercase()),
        "{shown}"
    );
}

/// A seed has one spelling. `ſ` and `ı` uppercase to `S` and `I` under Unicode rules, so standing in
/// for `s` or `i` they would decode to the same seed; they are refused instead.
#[test]
fn a_seed_with_a_unicode_look_alike_is_refused() {
    for (letter, look_alike) in [('s', "\u{17f}"), ('i', "\u{131}")] {
        let seed = (0..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|seed| encode_seed(seed).contains(letter))
            .expect("some seed spells the letter");
        let token = Invite::keyed(seed, from(), name(), standing()).to_string();
        assert!(Invite::parse(&token).is_ok(), "the seed as sent parses");
        let encoded = encode_seed(&seed);
        let spelled = token.replacen(
            encoded.as_str(),
            &encoded.replacen(letter, look_alike, 1),
            1,
        );
        assert!(
            matches!(Invite::parse(&spelled), Err(InviteError::Encoding)),
            "{look_alike} for {letter} is not the same seed"
        );
    }
}

/// Each field refuses as its own type: a short seed, bad base32, a bad key, a bad name, a bad standing.
#[test]
fn each_field_refuses_as_its_own_type() {
    let standing = standing();
    let short = BASE32_NOPAD.encode(&[0u8; 8]).to_lowercase();
    let (f, n, s) = (from(), name(), standing.as_str());
    assert!(matches!(
        Invite::parse(&format!("invite:{short}.{f}.{n}.{s}")),
        Err(InviteError::Length)
    ));
    assert!(matches!(
        Invite::parse(&format!("invite:not-base32.{f}.{n}.{s}")),
        Err(InviteError::Encoding)
    ));
    assert!(matches!(
        Invite::parse(&format!("invite:not-a-key.{n}.{s}")),
        Err(InviteError::From(_))
    ));
    assert!(matches!(
        Invite::parse(&format!("invite:{f}.me.{s}")),
        Err(InviteError::Name(_))
    ));
    assert!(matches!(
        Invite::parse(&format!("invite:{f}.{n}.{f}.x")),
        Err(InviteError::Standing(_))
    ));
}
