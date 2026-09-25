use super::{Link, LinkError, PREFIX, looks_bare, parse};
use crate::testkit::TestRoot;

fn bare() -> nauthy::Link {
    let root = TestRoot::seeded(0x31);
    let until = std::time::SystemTime::now() + core::time::Duration::from_secs(300);
    root.device_badge(crate::testkit::TestNode::seeded(0x32).node_id(), until)
        .expect("mint a link")
}

/// A link prints with the prefix, then nauthy's text, and parses back to the same bare link.
#[test]
fn a_link_prints_the_prefix_and_parses_back() {
    let inner = bare();
    let shown = Link::from(nauthy::Link::clone(&inner)).to_string();
    assert_eq!(shown, format!("{PREFIX}{}", inner.as_str()));
    let back = parse(&shown).expect("the printed form parses");
    assert_eq!(back.as_str(), inner.as_str());
}

/// The prefix matches in any ASCII case, and surrounding whitespace is trimmed.
#[test]
fn the_prefix_is_case_insensitive_and_whitespace_is_trimmed() {
    let inner = bare();
    let typed = format!("  SwOoSh:{}\n", inner.as_str());
    assert_eq!(
        parse(&typed).expect("parses").as_str(),
        inner.as_str(),
        "the bare link, nothing else"
    );
}

/// A bare link is not a link a person typed: the prefix is required, and the refusal names it.
#[test]
fn a_bare_link_refuses_naming_the_prefix() {
    let inner = bare();
    let refused = parse(inner.as_str()).expect_err("a bare link refuses");
    assert!(matches!(refused, LinkError::Prefix));
    assert_eq!(
        refused.to_string(),
        "this looks like a link; a link starts with `swoosh:`"
    );
    assert!(looks_bare(inner.as_str()));
    assert!(!looks_bare("alice"));
}
