// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The invite WIRING proof: an `invite:` line -> `adopt` -> present, end to end through the REAL `swoosh`
//! binary, so an adopted DEVICE carries the root-signed standing it needs to reach a family-gated service.
//!
//! The invites here are the lines `swoosh invite` prints, built in process from a test root: signing one
//! takes the root's passphrase at a terminal, which a child process has none of, so the root's half is
//! proven in process beside the command (`commands/invite_tests.rs`). This file proves the device's half
//! takes both shapes:
//!
//! - a key-carrying invite (`invite <name> --new-key`) is five fields, `invite:<seed>.<from>.<name>.<root>.
//!   <token>`, whose standing is root-signed and bound to the key the seed makes; `adopt` becomes that key;
//! - a bound invite (`invite <name> <key>`) is four fields, `invite:<from>.<name>.<root>.<token>`, for a key
//!   the device made: no secret travels, `adopt` keeps that identity, and the standing verifies at the root
//!   bound to the device.
//!
//! The device-adopt-then-DIAL end-to-end reach over a live transport lives in `tier1_invites.rs`.

use core::time::Duration;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

use bifrost::NodeId;
use nauthy::{Cap, VerifyKey};
use swoosh::invite::Invite;
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;

/// The `invite:` prefix every invite starts with.
const INVITE_SCHEME: &str = "invite:";

/// The root that signs the invites here.
const ROOT: u8 = 0x21;
/// Another root.
const OTHER_ROOT: u8 = 0x31;
/// The machine where the root is kept, which an invite names as where it came from.
const FROM: u8 = 0x11;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The bound invite `swoosh invite <name> <device>` prints where `root` is kept: a standing for `device`
/// lasting `lasts`.
fn bound_invite(root: u8, device: NodeId, name: &str, lasts: Duration) -> String {
    let standing = TestRoot::seeded(root)
        .device_badge(device, SystemTime::now() + lasts)
        .unwrap();
    Invite::bound(
        TestNode::seeded(FROM).node_id(),
        name.parse().unwrap(),
        standing,
    )
    .to_string()
}

/// The key-carrying invite `swoosh invite <name> --new-key` prints where `root` is kept: `seed`, and a
/// standing for the key it makes.
fn keyed_invite(root: u8, seed: [u8; 32], name: &str) -> String {
    let standing = TestRoot::seeded(root)
        .device_badge(
            NodeId::from_ed25519_secret(&seed),
            SystemTime::now() + 90 * DAY,
        )
        .unwrap();
    Invite::keyed(
        seed,
        TestNode::seeded(FROM).node_id(),
        name.parse().unwrap(),
        standing,
    )
    .to_string()
}

/// Make the key of the machine at `dir`, and print it, as `swoosh status --key` does.
fn device_key(dir: &Path) -> NodeId {
    let identity = swoosh(&["status", "--key", "--home", path_str(dir)]);
    assert!(identity.status.success(), "{}", stderr(&identity));
    String::from_utf8(identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("status --key prints the key alone")
}

/// The key-carrying shape: the invite hands over a key; the device adopts it as its own; the stored
/// standing roots at the root and admits exactly that key.
#[test]
fn a_keyed_invite_adopts_as_its_key_and_verifies_at_the_root() {
    let base = std::env::temp_dir().join(format!("swoosh-keyed-invite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let device_dir = base.join("device");
    std::fs::create_dir_all(&device_dir).unwrap();
    let device_key = device_dir.join("key");

    let seed = [0x77; 32];
    let token = keyed_invite(ROOT, seed, "ci-runner");

    // Five fields (seed . from . name . root . token), where `<root>.<token>` is the bare standing.
    let fields = invite_fields(&token);
    assert_eq!(
        fields.len(),
        5,
        "a key-carrying invite carries five fields: {token}"
    );
    assert_eq!(fields[2], "ci-runner", "the name rides without `me/`");
    let root: NodeId = fields[3].parse().expect("the root field is a key");
    let badge_field = standing_field(&token);

    // The root's secret is never in the invite: only the device seed, public keys and the standing.
    let root_b32 = data_encoding::BASE32_NOPAD
        .encode(&TestRoot::seeded(ROOT).seed())
        .to_lowercase();
    assert!(
        !token.contains(&root_b32),
        "the root's secret never travels"
    );

    // ADOPT: the seed becomes this machine's key; the root and the standing land beside it.
    let adopt = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(adopt.status.success(), "adopt failed: {}", stderr(&adopt));
    // A key-carrying invite IS a secret, so a bare argv token warns (the bound shape below does not).
    assert!(
        stderr(&adopt).contains("leaks it"),
        "a key-carrying invite on argv warns: {}",
        stderr(&adopt)
    );
    let stored_badge = stored_badge(&device_dir);
    assert_eq!(
        stored_badge, badge_field,
        "the stored standing is exactly the one the invite carried"
    );
    let device_seed = std::fs::read(&device_key).unwrap();
    assert_eq!(device_seed, seed, "the invite's seed is this machine's key");
    let device = NodeId::from_ed25519_secret(&seed);

    // VERIFY: the stored standing roots at the root, never the device, admits the device bound to it, and
    // refuses any other key that presents it.
    let cap = Cap::parse(&stored_badge).expect("the stored standing parses as a cap");
    let root_vk: VerifyKey = root.verify_key().expect("a usable key");
    let device_vk: VerifyKey = device.verify_key().expect("a usable key");
    assert_eq!(cap.root(), root_vk, "the standing roots at the root");
    assert_ne!(cap.root(), device_vk, "never at the device's own key");
    let now = SystemTime::now();
    cap.verify_member_at_root_without_revocation(now, device_vk, root_vk)
        .expect("the standing admits the device at the root");
    let stranger = NodeId::from_ed25519_secret(&[0x5a; 32])
        .verify_key()
        .expect("a usable key");
    assert!(
        cap.verify_member_at_root_without_revocation(now, stranger, root_vk)
            .is_err(),
        "the standing admits no other key"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// The bound shape: the DEVICE makes its key and prints it; the root signs for that key; the invite
/// carries no secret; the device adopts it and keeps its identity; the stored standing verifies at the
/// root bound to that device.
#[test]
fn a_bound_invite_keeps_the_devices_key_and_verifies_at_the_root() {
    let base = std::env::temp_dir().join(format!("swoosh-bound-invite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let device_dir = base.join("device");
    std::fs::create_dir_all(&device_dir).unwrap();

    let device = device_key(&device_dir);
    let device_secret_before = std::fs::read(device_dir.join("key")).unwrap();
    let token = bound_invite(ROOT, device, "laptop", 90 * DAY);
    let fields = invite_fields(&token);
    assert_eq!(
        fields.len(),
        4,
        "a bound invite carries four fields: {token}"
    );
    let root: NodeId = fields[2].parse().expect("the root field is a key");
    let badge_field = standing_field(&token);
    let secret_b32 = data_encoding::BASE32_NOPAD
        .encode(&device_secret_before)
        .to_lowercase();
    assert!(
        !token.contains(&secret_b32),
        "a bound invite never carries the device's secret"
    );

    let adopt = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(
        adopt.status.success(),
        "bound adopt failed: {}",
        stderr(&adopt)
    );
    assert!(
        !stderr(&adopt).contains("leaks it"),
        "a bound invite is not a secret, so no argv warning: {}",
        stderr(&adopt)
    );
    let adopt_out = String::from_utf8(adopt.stdout).unwrap();
    assert!(
        adopt_out.contains(&root.to_string()),
        "adopt prints the full root for the out-of-band compare: {adopt_out}"
    );
    assert_eq!(
        std::fs::read(device_dir.join("key")).unwrap(),
        device_secret_before,
        "adopting a bound invite keeps the device's key"
    );
    assert_eq!(
        std::fs::read_to_string(device_dir.join("signet"))
            .unwrap()
            .trim(),
        root.to_string(),
        "the invite's root is pinned"
    );
    let stored = stored_badge(&device_dir);
    assert_eq!(stored, badge_field, "the standing is stored");
    Cap::parse(&stored)
        .expect("the stored standing parses")
        .verify_member_at_root_without_revocation(
            SystemTime::now(),
            device.verify_key().expect("a usable key"),
            root.verify_key().expect("a usable key"),
        )
        .expect("the standing admits the device at the root");

    let _ = std::fs::remove_dir_all(&base);
}

/// A standing signed for a DIFFERENT machine is refused before anything is written.
#[test]
fn adopt_refuses_a_badge_bound_to_another_machine() {
    let base = std::env::temp_dir().join(format!("swoosh-wrong-device-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let intended_dir = base.join("intended");
    let other_dir = base.join("other");
    for dir in [&intended_dir, &other_dir] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let intended = device_key(&intended_dir);
    let token = bound_invite(ROOT, intended, "laptop", 90 * DAY);

    device_key(&other_dir);
    let adopt = swoosh(&["adopt", &token, "--home", path_str(&other_dir)]);
    assert!(
        !adopt.status.success(),
        "a standing bound to another machine must be refused: {}",
        stderr(&adopt)
    );
    let message = stderr(&adopt);
    assert!(
        message.contains("does not bind this machine"),
        "the error names the binding check: {message}"
    );
    assert!(
        !other_dir.join("signet").exists() && !other_dir.join("badge").exists(),
        "nothing is written when the standing does not bind this machine"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Re-rooting takes an explicit acknowledgement: an invite naming a root this machine does not yet trust
/// switches the root, so a differing one refuses without `--force` and lands with it.
#[test]
fn adopt_requires_force_to_switch_the_trusted_signet() {
    let base = std::env::temp_dir().join(format!("swoosh-reroot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let device_dir = base.join("device");
    std::fs::create_dir_all(&device_dir).unwrap();
    let device = device_key(&device_dir);

    let first_token = bound_invite(ROOT, device, "laptop", 90 * DAY);
    let adopt = swoosh(&["adopt", &first_token, "--home", path_str(&device_dir)]);
    assert!(adopt.status.success(), "{}", stderr(&adopt));
    let pinned = || {
        std::fs::read_to_string(device_dir.join("signet"))
            .unwrap()
            .trim()
            .to_owned()
    };
    let first_root = TestRoot::seeded(ROOT).node_id().to_string();
    assert_eq!(pinned(), first_root);

    // Another root signs for the same device. Adopting would switch the gate's root: refused without
    // `--force`, and the pin is untouched by the refusal.
    let second_token = bound_invite(OTHER_ROOT, device, "laptop", 90 * DAY);
    let refused = swoosh(&["adopt", &second_token, "--home", path_str(&device_dir)]);
    assert!(
        !refused.status.success(),
        "re-rooting without --force must refuse: {}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("--force"),
        "the refusal names the acknowledgement: {}",
        stderr(&refused)
    );
    assert_eq!(
        pinned(),
        first_root,
        "the refused switch leaves the root untouched"
    );

    let forced = swoosh(&[
        "adopt",
        &second_token,
        "--force",
        "--home",
        path_str(&device_dir),
    ]);
    assert!(
        forced.status.success(),
        "--force performs the switch: {}",
        stderr(&forced)
    );
    assert_eq!(
        pinned(),
        TestRoot::seeded(OTHER_ROOT).node_id().to_string(),
        "--force wrote the new root"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A same-root re-adopt turns on ONE question: does the incoming standing outlive the stored one? A
/// renewal lands with no flag; an older, shorter standing replayed under the same root is refused, and
/// `--force` keeps its meaning. Re-adopting the same bytes stays silent either way.
#[test]
fn adopt_renews_without_a_flag_and_refuses_a_downgrade() {
    let base = std::env::temp_dir().join(format!("swoosh-badge-swap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let device_dir = base.join("device");
    std::fs::create_dir_all(&device_dir).unwrap();
    let device = device_key(&device_dir);

    let short_token = bound_invite(ROOT, device, "laptop", 30 * DAY);
    let short_badge = standing_field(&short_token);
    let adopt = swoosh(&["adopt", &short_token, "--home", path_str(&device_dir)]);
    assert!(adopt.status.success(), "{}", stderr(&adopt));
    assert_eq!(
        stored_badge(&device_dir),
        short_badge,
        "the first standing lands"
    );

    let same = swoosh(&["adopt", &short_token, "--home", path_str(&device_dir)]);
    assert!(same.status.success(), "{}", stderr(&same));

    let long_token = bound_invite(ROOT, device, "laptop", 90 * DAY);
    let long_badge = standing_field(&long_token);
    assert_ne!(short_badge, long_badge);
    let renewed = swoosh(&["adopt", &long_token, "--home", path_str(&device_dir)]);
    assert!(
        renewed.status.success(),
        "a standing that outlives the stored one is a renewal, not a swap: {}",
        stderr(&renewed)
    );
    assert_eq!(stored_badge(&device_dir), long_badge);

    let replay = swoosh(&["adopt", &short_token, "--home", path_str(&device_dir)]);
    assert!(
        !replay.status.success(),
        "replaying a standing that does not outlive the stored one must refuse: {}",
        stderr(&replay)
    );
    assert!(
        stderr(&replay).contains("--force"),
        "the refusal names the acknowledgement: {}",
        stderr(&replay)
    );
    assert_eq!(
        stored_badge(&device_dir),
        long_badge,
        "the stored standing survives"
    );

    let forced = swoosh(&[
        "adopt",
        &short_token,
        "--force",
        "--home",
        path_str(&device_dir),
    ]);
    assert!(
        forced.status.success(),
        "--force performs the downgrade: {}",
        stderr(&forced)
    );
    assert_eq!(stored_badge(&device_dir), short_badge);

    let _ = std::fs::remove_dir_all(&base);
}

/// A key-carrying invite adopted onto a machine that already has a key is refused, and the key survives
/// byte-identical, with or without `--force`. Moving the key aside lets the same invite land, and
/// re-adopting it after is a no-op.
#[test]
fn adopt_refuses_to_replace_an_identity_this_machine_already_has() {
    let base = std::env::temp_dir().join(format!("swoosh-keep-identity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let device_dir = base.join("device");
    std::fs::create_dir_all(&device_dir).unwrap();
    let device_key_path = device_dir.join("key");

    let held = device_key(&device_dir);
    let held_seed = std::fs::read(&device_key_path).unwrap();
    let token = keyed_invite(ROOT, [0x78; 32], "ci-runner");

    for argv in [
        vec!["adopt", &token, "--home", path_str(&device_dir)],
        vec!["adopt", &token, "--force", "--home", path_str(&device_dir)],
    ] {
        let refused = swoosh(&argv);
        // FIRST, because it is the assertion the guard exists for.
        assert_eq!(
            std::fs::read(&device_key_path).unwrap(),
            held_seed,
            "{argv:?} must leave the key nothing can re-issue exactly as it found it"
        );
        assert!(
            !refused.status.success(),
            "{argv:?} must refuse: {}",
            stderr(&refused)
        );
        let message = stderr(&refused);
        assert!(
            message.contains(&held.to_string()),
            "the refusal names the key this machine already has: {message}"
        );
        assert!(
            !device_dir.join("signet").exists() && !device_dir.join("badge").exists(),
            "the refusal lands before any write"
        );
    }

    std::fs::rename(&device_key_path, device_dir.join("key.bak")).unwrap();
    let adopted = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(adopted.status.success(), "{}", stderr(&adopted));
    assert_ne!(
        std::fs::read(&device_key_path).unwrap(),
        held_seed,
        "the moved-aside machine takes the invite's key"
    );
    let again = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(
        again.status.success(),
        "re-adopting the same invite stays a no-op: {}",
        stderr(&again)
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Run the compiled `swoosh` binary with `args`, capturing its output. `CARGO_BIN_EXE_swoosh` is set by
/// cargo for an integration test of a crate that builds a binary, so this drives the REAL product path.
fn swoosh(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .args(args)
        // Isolate from any real `~/.config/swoosh`: every path this test uses is explicit via `--home`, but
        // pin HOME to the scratch base so nothing can fall back to the operator's store.
        .env("HOME", std::env::temp_dir())
        .output()
        .expect("the swoosh binary runs")
}

/// The `.`-separated fields of an `invite:` token.
fn invite_fields(token: &str) -> Vec<&str> {
    token
        .strip_prefix(INVITE_SCHEME)
        .expect("an invite carries the invite: prefix")
        .split('.')
        .collect()
}

/// The standing an invite carries: its last two fields, `<root>.<token>`, the bare link.
fn standing_field(token: &str) -> String {
    let fields = invite_fields(token);
    fields[fields.len() - 2..].join(".")
}

/// The badge adopt stored in `home`, trimmed of the trailing newline `write_badge` appends.
fn stored_badge(home: &Path) -> String {
    std::fs::read_to_string(home.join("badge"))
        .expect("adopt stores the badge beside the seed")
        .trim()
        .to_owned()
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("the temp path is valid utf-8")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
