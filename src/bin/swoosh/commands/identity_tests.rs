//! `swoosh identity`'s local report: an adopted device reads its signet and how long its badge still
//! stands, a machine with no root says so and prints no badge line, and a badge that cannot say when it dies
//! says that rather than nothing.

use core::time::Duration;

use super::*;

/// A day, to write the spans the way an operator reads them.
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The key this machine holds, for the fixture rows below.
fn node() -> NodeId {
    NodeId::from_ed25519_secret(&[7u8; 32])
}

/// An adopted device's full local answer: its own key, where the key lives, the signet it trusts, and
/// when the badge it presents dies. The badge line is the point of the verb's new half, so it is
/// pinned by value, not by a `contains`.
#[test]
fn an_adopted_device_reports_its_signet_and_its_badge_life() {
    let signet = NodeId::from_ed25519_secret(&[8u8; 32]);
    let out = render(
        node(),
        Path::new("/home/me/.config/swoosh/identity.key"),
        Method::Passphrase,
        Some(signet),
        Some(badge::Expiry::Live { left: 34 * DAY }),
    );
    assert_eq!(
        out,
        format!(
            "{}\nkey: /home/me/.config/swoosh/identity.key\nprotection: passphrase\nsignet: \
             {signet}\nbadge: expires in 34d\n",
            node()
        )
    );
}

/// The dead badge, which is the whole reason this line exists: the operator whose dials just started
/// failing reads WHEN it died here, offline, with no peer to ask and no resident to be running.
#[test]
fn a_dead_badge_says_so_and_says_when() {
    let out = render(
        node(),
        Path::new("/k"),
        Method::Plain,
        Some(NodeId::from_ed25519_secret(&[8u8; 32])),
        Some(badge::Expiry::Expired { ago: 6 * DAY }),
    );
    assert!(
        out.contains("badge: expired 6d ago\n"),
        "an expired badge names how long it has been dead, got:\n{out}"
    );
}

/// A machine that trusts no root states it, and prints no badge line: its own key signs no badge for
/// itself.
#[test]
fn a_machine_with_no_root_says_so_and_prints_no_badge() {
    let out = render(node(), Path::new("/k"), Method::Plain, None, None);
    assert!(
        out.contains("signet: none\n"),
        "the absent pin is stated, got:\n{out}"
    );
    assert!(
        !out.contains("badge:"),
        "there is no badge to describe, got:\n{out}"
    );
}

/// A badge minted before badges carried a readable expiry renders as unknown, never as a span and
/// never as fine: the machine genuinely cannot answer, and saying so is the answer.
#[test]
fn an_unreadable_expiry_renders_as_unknown() {
    let out = render(
        node(),
        Path::new("/k"),
        Method::Plain,
        Some(NodeId::from_ed25519_secret(&[8u8; 32])),
        Some(badge::Expiry::Unknown),
    );
    assert!(
        out.contains("badge: expiry unknown"),
        "an unreadable expiry is reported, not hidden, got:\n{out}"
    );
}
