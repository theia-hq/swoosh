use bifrost::NodeId;

use super::{PREFIX, RootKey, RootKeyError, is_prefixed};

fn key(seed: u8) -> NodeId {
    NodeId::from_ed25519_secret(&[seed; 32])
}

/// A root prints as `root:` then its whole key, so it never reads as a machine's `ed01…`.
#[test]
fn a_root_prints_as_root_colon_then_its_key() {
    let root = RootKey::from(key(7));
    assert_eq!(root.to_string(), format!("root:{}", key(7)));
    assert!(root.to_string().starts_with(PREFIX));
    assert_eq!(
        root.short(),
        format!("root:{}", swoosh_short(&key(7))),
        "the short form keeps the prefix too"
    );
}

fn swoosh_short(key: &NodeId) -> String {
    crate::credential::short(key)
}

/// Taking the prefix off leaves the library's own key text: the rest parses as a `NodeId`, in any case of
/// the prefix and with whitespace around it, and the inner key is that `NodeId`.
#[test]
fn stripping_root_leaves_the_library_key_text() {
    for typed in [
        format!("root:{}", key(7)),
        format!("ROOT:{}", key(7)),
        format!("  Root:{}\n", key(7)),
    ] {
        let root: RootKey = typed.parse().expect("a root key parses");
        assert_eq!(root.key(), key(7), "{typed:?}");
        assert_eq!(
            root.key().to_string().parse::<NodeId>().expect("a key"),
            key(7)
        );
    }
}

/// A bare key is a machine's: a root needs its prefix. What follows the prefix must be a key.
#[test]
fn a_bare_key_is_no_root_key() {
    assert!(matches!(
        key(7).to_string().parse::<RootKey>(),
        Err(RootKeyError::NoPrefix)
    ));
    assert!(matches!(
        "root:bob".parse::<RootKey>(),
        Err(RootKeyError::NotAKey(_))
    ));
    assert!(is_prefixed(&format!("root:{}", key(7))));
    assert!(is_prefixed("ROOT:anything"));
    assert!(!is_prefixed(&key(7).to_string()));
}

/// The confirmation token is the 8 characters after `ed01`, never the tag itself.
#[test]
fn the_token_is_the_eight_after_the_tag() {
    let root = RootKey::from(key(7));
    let text = key(7).to_string();
    assert!(text.starts_with("ed01"));
    assert_eq!(root.token(), text[4..12]);
    assert_eq!(root.token().len(), 8);
}
