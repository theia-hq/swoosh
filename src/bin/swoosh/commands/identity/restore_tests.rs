//! The line a restore prints about what it did not bring back.

use super::scope_line;

/// A home with no revocation list is told that revoked grants work again; a home with one is not.
#[test]
fn the_scope_line_warns_when_revocations_are_missing() {
    assert!(scope_line(false).contains("grants you revoked work again"));
    assert!(!scope_line(true).contains("revoked work again"));
}
