// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The device-badge WIRING proof: `mint` -> `adopt` -> present, end to end through the REAL `swoosh`
//! binary, so an adopted DEVICE carries the signet-signed badge it needs to reach a family-gated service.
//!
//! This is the coverage whose absence let the release blocker hide (deliberation 10): the shipped
//! `mint`/`adopt` handed a device only its child seed + the signet's public id, and the device self-signed
//! a badge rooted at its OWN child key -- which a signet-rooted family gate correctly refuses. This test
//! drives the actual `swoosh mint` and `swoosh adopt` verbs (the product path, not a hand-rolled near-copy)
//! and proves the whole chain:
//!
//! - `mint` emits a THREE-field authkey `authkey:<seed>.<signet>.<badge>` (the badge field is new);
//! - the badge is signet-ROOTED (root == the signet, never the device's own key) and BOUND to the device's
//!   derived node id, so it is the exact credential `verify_member_at_root` admits at the signet root;
//! - `adopt` STORES that badge beside the seed (the `badge` file under the device's `--key` dir), which is
//!   what `self_badge` presents on connect instead of self-signing;
//! - the stored badge is NOT the device's self-sign: a device self-sign roots at the device key, which the
//!   gate refuses, so proving root == signet (and root != device) is the whole point of the fix;
//! - the signet SECRET never appears in the authkey (only the child seed, the signet PUBLIC id, and the
//!   already-signed public badge travel).
//!
//! The device-adopt-then-DIAL end-to-end reach (a second device actually reaching a gated service over a
//! live transport) stays the Operator's quirk-run gate, because the badge binds to the device's PROVEN
//! transport id, which over `mem` is synthetic (see `gated_measure.rs`). This wiring test is the real,
//! in-tree coverage that the mint/adopt/present path produces and stores the correct credential.

use std::path::Path;
use std::process::Command;

use bifrost::NodeId;
use nauthy::{Cap, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;

/// The `authkey:` scheme prefix `mint` prints.
const AUTHKEY_SCHEME: &str = "authkey:";

#[test]
fn mint_signs_a_device_bound_badge_adopt_stores_it_and_it_verifies_at_the_signet_root() {
    // A private scratch dir for this test's key stores, kept apart from other tests by the process id.
    let base =
        std::env::temp_dir().join(format!("swoosh-device-badge-wiring-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let signet_dir = base.join("signet-holder");
    let device_dir = base.join("device");
    std::fs::create_dir_all(&signet_dir).unwrap();
    std::fs::create_dir_all(&device_dir).unwrap();

    // The `--key` a verb reads/writes is a FILE path; its parent dir is the identity+trust unit. `mint`
    // reads/creates the signet at the signet holder's key; `adopt` writes the device identity + signet +
    // badge under the device's key.
    let signet_key = signet_dir.join("identity.key");
    let device_key = device_dir.join("identity.key");

    // 1. MINT: run the real `swoosh mint ci-runner` under the signet holder's key. It derives the child,
    //    signs the device badge, and prints the three-field authkey.
    let mint = swoosh(&["mint", "ci-runner", "--key", path_str(&signet_key)]);
    assert!(mint.status.success(), "mint failed: {}", stderr(&mint));
    let authkey = first_authkey(&String::from_utf8(mint.stdout).unwrap())
        .expect("mint prints an authkey: token");

    // The authkey MUST be three fields now (seed . signet . badge), where the badge is a `sheer:` link.
    let fields: Vec<&str> = authkey
        .strip_prefix(AUTHKEY_SCHEME)
        .unwrap()
        .splitn(3, '.')
        .collect();
    assert_eq!(
        fields.len(),
        3,
        "authkey must carry three fields (seed.signet.badge), got {}: {authkey}",
        fields.len()
    );
    let signet: NodeId = fields[1].parse().expect("the signet field is a node id");
    let badge_field = fields[2];
    assert!(
        badge_field.starts_with("sheer:"),
        "the third field is a signed badge (a sheer: link), got: {badge_field}"
    );

    // The signet SECRET must NEVER be in the authkey: only the child seed, the signet PUBLIC id, and the
    // public badge travel. Read the signet secret off disk and prove its base32 form is absent from the
    // token (belt-and-braces alongside the structural argument that mint only ever encodes the child seed).
    let signet_secret = std::fs::read(&signet_key).unwrap();
    assert_eq!(
        signet_secret.len(),
        32,
        "the signet key file is a 32-byte secret"
    );
    let secret_b32 = data_encoding::BASE32_NOPAD
        .encode(&signet_secret)
        .to_lowercase();
    assert!(
        !authkey.contains(&secret_b32),
        "the signet secret must never appear in the authkey"
    );

    // 2. ADOPT: run the real `swoosh adopt <authkey>` under the DEVICE's key. It writes the child seed as
    //    the device identity, records the trusted signet, and STORES the badge beside them.
    let adopt = swoosh(&["adopt", &authkey, "--key", path_str(&device_key)]);
    assert!(adopt.status.success(), "adopt failed: {}", stderr(&adopt));

    // adopt STORED the badge (this is what `self_badge` presents on connect, in place of a self-sign).
    let stored_badge = std::fs::read_to_string(device_dir.join("badge"))
        .expect("adopt stores the badge beside the seed")
        .trim()
        .to_owned();
    assert_eq!(
        stored_badge, badge_field,
        "the stored badge is exactly the signet-signed badge the authkey carried"
    );

    // The device identity adopt wrote is the child seed; its node id is what the badge must bind to.
    let device_seed = std::fs::read(&device_key).unwrap();
    let device =
        NodeId::from_ed25519_secret(&<[u8; 32]>::try_from(device_seed.as_slice()).unwrap());

    // 3. VERIFY the STORED badge is the credential a signet-rooted family gate admits:
    //    (a) it parses as a cap; (b) its root is the SIGNET (never the device's own key); (c) it verifies
    //    as a member when the proven dialer is the DEVICE (bound_device matches); (d) it does NOT verify
    //    when the proven dialer is some other key (the binding holds).
    let cap = Cap::parse(&stored_badge).expect("the stored badge parses as a cap");
    let signet_vk: VerifyKey = signet.verify_key();
    let device_vk: VerifyKey = device.verify_key();

    // (b) signet-ROOTED, never self-rooted.
    assert_eq!(cap.root(), signet_vk, "the badge roots at the SIGNET");
    assert_ne!(
        cap.root(),
        device_vk,
        "the badge does NOT root at the device's own key (a self-sign would, and is refused)"
    );

    // (c) admits for the bound device at the signet root.
    let now = std::time::SystemTime::now();
    cap.verify_member_at_root(now, device_vk, signet_vk)
        .expect("the badge admits the bound device as a member at the signet root");

    // (d) an intercepted badge replayed from ANOTHER key fails the bound_device binding.
    let stranger = NodeId::from_ed25519_secret(&[0x5a; 32]).verify_key();
    assert!(
        cap.verify_member_at_root(now, stranger, signet_vk).is_err(),
        "the badge must NOT admit a different proven dialer (bound_device binds)"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Run the compiled `swoosh` binary with `args`, capturing its output. `CARGO_BIN_EXE_swoosh` is set by
/// cargo for an integration test of a crate that builds a binary, so this drives the REAL product path.
fn swoosh(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .args(args)
        // Isolate from any real `~/.config/swoosh`: every path this test uses is explicit via `--key`, but
        // pin HOME to the scratch base so nothing can fall back to the operator's store.
        .env("HOME", std::env::temp_dir())
        .output()
        .expect("the swoosh binary runs")
}

/// The first `authkey:` token in `text` (mint frames it on its own line).
fn first_authkey(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|word| word.starts_with(AUTHKEY_SCHEME))
        .map(str::to_owned)
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("the temp path is valid utf-8")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
