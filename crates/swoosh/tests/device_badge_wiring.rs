// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The invite WIRING proof: `invite add` -> `adopt` -> present, end to end through the REAL `swoosh`
//! binary, so an adopted DEVICE carries the signet-signed badge it needs to reach a family-gated service.
//!
//! This is the coverage whose absence let the release blocker hide (deliberation 10): the shipped
//! `mint`/`adopt` pair handed a device only its child seed + the signet's public id, and the device
//! self-signed a badge rooted at its OWN child key -- which a signet-rooted family gate correctly refuses.
//! The test drives the actual `swoosh invite add` and `swoosh adopt` verbs (the product path, not a
//! hand-rolled near-copy) and proves both tier-1 cells:
//!
//! - the DERIVED cell (`invite add <label>`) emits a three-field `invite:<seed>.<signet>.<badge>` whose
//!   badge is signet-ROOTED and bound to the derived node id, which the device stores on `adopt`;
//! - the BOUND cell (`invite add <label> --for <key>`) emits a two-field `invite:<signet>.<badge>` for a
//!   key the device made: no secret travels, `adopt` keeps that identity, and the badge still verifies at
//!   the signet root bound to the device;
//! - `invite rm <label>` revokes the recorded badge at its root, so the gate's revocation seam refuses it;
//! - `invite ls` lists the row under its label, and `rm` leaves the ledger row for audit.
//!
//! The device-adopt-then-DIAL end-to-end reach over a live transport lives in `tier1_invites.rs`; this
//! file is the real, in-tree coverage that the invite/adopt/present path produces and stores the correct
//! credential in both shapes.

use std::path::Path;
use std::process::Command;

use bifrost::NodeId;
use nauthy::{Cap, FileDenylist, VerifyKey};
use swoosh::home::Home;
use tightbeam::identity::AsVerifyKey as _;

/// The `invite:` scheme prefix the create verb prints.
const INVITE_SCHEME: &str = "invite:";

#[test]
fn invite_add_derives_signs_adopt_stores_and_it_verifies_at_the_signet_root() {
    // A private scratch dir for this test's key stores, kept apart from other tests by the process id.
    let base =
        std::env::temp_dir().join(format!("swoosh-device-badge-wiring-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let signet_dir = base.join("signet-holder");
    let device_dir = base.join("device");
    std::fs::create_dir_all(&signet_dir).unwrap();
    std::fs::create_dir_all(&device_dir).unwrap();

    // `--home <dir>` names the identity+trust unit; the key lives inside it at `identity.key`. `invite
    // add` reads/creates the signet in the signet holder's home; `adopt` writes the device identity +
    // signet + badge in the device's home. The key file paths are kept for the on-disk assertions below.
    let signet_key = signet_dir.join("identity.key");
    let device_key = device_dir.join("identity.key");

    // 1. CREATE: run the real `swoosh invite add ci-runner` in the signet holder's home. It derives the
    //    child, signs the device badge, and prints the three-field invite.
    let create = swoosh(&[
        "invite",
        "add",
        "ci-runner",
        "--home",
        path_str(&signet_dir),
    ]);
    assert!(
        create.status.success(),
        "invite add failed: {}",
        stderr(&create)
    );
    let token = first_invite(&String::from_utf8(create.stdout).unwrap())
        .expect("invite add prints an invite: token");

    // The invite MUST be three fields (seed . signet . badge), where the badge is a `sheer:` link.
    let fields: Vec<&str> = token
        .strip_prefix(INVITE_SCHEME)
        .unwrap()
        .splitn(3, '.')
        .collect();
    assert_eq!(
        fields.len(),
        3,
        "a derived invite carries three fields (seed.signet.badge), got {}: {token}",
        fields.len()
    );
    let signet: NodeId = fields[1].parse().expect("the signet field is a node id");
    let badge_field = fields[2];
    assert!(
        badge_field.starts_with("sheer:"),
        "the third field is a signed badge (a sheer: link), got: {badge_field}"
    );

    // The signet SECRET must NEVER be in the invite: only the child seed, the signet PUBLIC id, and the
    // public badge travel. Read the signet secret off disk and prove its base32 form is absent from the
    // token (belt-and-braces alongside the structural argument that add only ever encodes the child seed).
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
        !token.contains(&secret_b32),
        "the signet secret must never appear in the invite"
    );

    // 2. ADOPT: run the real `swoosh adopt <invite>` under the DEVICE's key. It writes the child seed as
    //    the device identity, records the trusted signet, and STORES the badge beside them.
    let adopt = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(adopt.status.success(), "adopt failed: {}", stderr(&adopt));

    // adopt STORED the badge (this is what `self_badge` presents on connect, in place of a self-sign).
    let stored_badge = std::fs::read_to_string(device_dir.join("badge"))
        .expect("adopt stores the badge beside the seed")
        .trim()
        .to_owned();
    assert_eq!(
        stored_badge, badge_field,
        "the stored badge is exactly the signet-signed badge the invite carried"
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
    cap.verify_member_at_root_without_revocation(now, device_vk, signet_vk)
        .expect("the badge admits the bound device as a member at the signet root");

    // (d) an intercepted badge replayed from ANOTHER key fails the bound_device binding.
    let stranger = NodeId::from_ed25519_secret(&[0x5a; 32]).verify_key();
    assert!(
        cap.verify_member_at_root_without_revocation(now, stranger, signet_vk)
            .is_err(),
        "the badge must NOT admit a different proven dialer (bound_device binds)"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// The bound cell: the DEVICE makes its key and prints it; the owner signs `--for` that key; the token
/// carries no secret; the device adopts it and keeps its identity; the stored badge still verifies at the
/// signet root bound to that device.
#[tokio::test]
async fn invite_add_for_binds_a_device_made_key_and_adopt_keeps_that_identity() {
    let base = std::env::temp_dir().join(format!("swoosh-bound-invite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let signet_dir = base.join("signet-holder");
    let device_dir = base.join("device");
    std::fs::create_dir_all(&signet_dir).unwrap();
    std::fs::create_dir_all(&device_dir).unwrap();

    // 1. The DEVICE makes its key and prints the public half (public: any channel will carry it back).
    let identity = swoosh(&["identity", "--home", path_str(&device_dir)]);
    assert!(
        identity.status.success(),
        "identity failed: {}",
        stderr(&identity)
    );
    let device_key_text = String::from_utf8(identity.stdout).unwrap();
    let device_line = device_key_text.lines().next().unwrap().to_owned();
    let device: NodeId = device_line
        .parse()
        .expect("identity prints the node id first");
    let device_secret_before = std::fs::read(device_dir.join("identity.key")).unwrap();

    // 2. The OWNER signs for that key. The token is two fields (signet . badge): no seed, no secret.
    let create = swoosh(&[
        "invite",
        "add",
        "laptop",
        "--for",
        &device.to_string(),
        "--home",
        path_str(&signet_dir),
    ]);
    assert!(
        create.status.success(),
        "invite add --for failed: {}",
        stderr(&create)
    );
    let token = first_invite(&String::from_utf8(create.stdout).unwrap())
        .expect("invite add --for prints an invite: token");
    // A bound invite is `<signet>.<badge>`; the badge itself is a `sheer:` link that contains a `.`, so
    // split off the signet field only, exactly as the parser does.
    let (signet_field, badge_field) = token
        .strip_prefix(INVITE_SCHEME)
        .unwrap()
        .split_once('.')
        .expect("a bound invite carries a signet field and a badge");
    let signet: NodeId = signet_field
        .parse()
        .expect("the first field is the signet node id");
    assert!(
        badge_field.starts_with("sheer:"),
        "the second field is the badge"
    );

    // The device secret must never travel: the device's identity key bytes, base32-encoded, are absent.
    let secret_b32 = data_encoding::BASE32_NOPAD
        .encode(&device_secret_before)
        .to_lowercase();
    assert!(
        !token.contains(&secret_b32),
        "the bound invite must never carry the device secret"
    );

    // The issuer's own ledger view names the row by its label, with no token column.
    let ls = swoosh(&["invite", "ls", "--home", path_str(&signet_dir)]);
    assert!(ls.status.success(), "invite ls failed: {}", stderr(&ls));
    let listing = String::from_utf8(ls.stdout).unwrap();
    assert!(
        listing.contains("laptop") && listing.contains(&device.short()),
        "invite ls names the label and the admitted key: {listing}"
    );

    // 3. The DEVICE adopts: its identity stays exactly as it was; the signet and badge land beside it.
    let adopt = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(
        adopt.status.success(),
        "bound adopt failed: {}",
        stderr(&adopt)
    );
    assert_eq!(
        std::fs::read(device_dir.join("identity.key")).unwrap(),
        device_secret_before,
        "adopting a bound invite keeps the device's identity"
    );
    assert_eq!(
        std::fs::read_to_string(device_dir.join("signet"))
            .unwrap()
            .trim(),
        signet.to_string(),
        "the bound invite's signet is written"
    );
    let stored_badge = std::fs::read_to_string(device_dir.join("badge"))
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(stored_badge, badge_field, "the bound badge is stored");

    // 4. VERIFY: the stored badge roots at the signet and admits exactly this device.
    let cap = Cap::parse(&stored_badge).expect("the stored badge parses");
    let signet_vk: VerifyKey = signet.verify_key();
    cap.verify_member_at_root_without_revocation(
        std::time::SystemTime::now(),
        device.verify_key(),
        signet_vk,
    )
    .expect("the bound badge admits the device at the signet root");

    // 5. CANCEL: `invite rm <label>` revokes the badge at its root; the ledger row stays for audit.
    let rm = swoosh(&["invite", "rm", "laptop", "--home", path_str(&signet_dir)]);
    assert!(rm.status.success(), "invite rm failed: {}", stderr(&rm));
    let denylist = FileDenylist::load(Home::resolve(Some(signet_dir.clone())).unwrap().revoked())
        .await
        .unwrap();
    assert!(
        denylist.is_revoked(&cap),
        "after `invite rm`, the gate's revocation seam refuses the badge"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// The derived create-then-cancel proof (the ship-blocker, deliberation 2026-09-07, carried onto the
/// invite surface): `invite add` records the badge in the mint-log ledger, so `invite rm <label>` cuts
/// the device off at the gate. Before the mint-log fix the row was missing and the badge then stood until
/// its TTL, unrevocable.
#[tokio::test]
async fn invite_add_then_invite_rm_refuses_the_device_at_the_gate() {
    let base = std::env::temp_dir().join(format!("swoosh-invite-rm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let signet_dir = base.join("signet-holder");
    std::fs::create_dir_all(&signet_dir).unwrap();
    // `invite add` and `invite rm` both read/write the identity+trust unit in this one home: the signet,
    // the `me/ci-runner` contact, the mint-log ledger, and the denylist all live inside it.
    let signet_home = Home::resolve(Some(signet_dir.clone())).unwrap();

    let create = swoosh(&[
        "invite",
        "add",
        "ci-runner",
        "--home",
        path_str(&signet_dir),
    ]);
    assert!(
        create.status.success(),
        "invite add failed: {}",
        stderr(&create)
    );
    let token = first_invite(&String::from_utf8(create.stdout).unwrap())
        .expect("invite add prints an invite: token");
    // The badge is field three of the derived invite; recover its cap so we can assert the gate refuses it.
    let badge = token
        .strip_prefix(INVITE_SCHEME)
        .unwrap()
        .splitn(3, '.')
        .nth(2)
        .expect("the invite carries the badge field");
    let cap = Cap::parse(badge).expect("the badge parses as a cap");

    // Before cancel: nothing denylists the badge (the gate would admit the device).
    let denylist = FileDenylist::load(signet_home.revoked()).await.unwrap();
    assert!(
        !denylist.is_revoked(&cap),
        "the badge is not revoked before `invite rm`"
    );

    // CANCEL BY LABEL through the real command: `me/ci-runner` resolves through the contact `invite add`
    // recorded, matches the ledger row, and denylists the badge's root.
    let rm = swoosh(&["invite", "rm", "ci-runner", "--home", path_str(&signet_dir)]);
    assert!(rm.status.success(), "invite rm failed: {}", stderr(&rm));

    // After cancel: the gate's revocation check (the seam a live exposer consults on every dial) refuses
    // the very badge `invite add` produced.
    let denylist = FileDenylist::load(signet_home.revoked()).await.unwrap();
    assert!(
        denylist.is_revoked(&cap),
        "once the invite is cancelled, the gate refuses its badge"
    );

    // The ledger row STAYS for audit: cancel is not deletion.
    let ls = swoosh(&["invite", "ls", "--home", path_str(&signet_dir)]);
    assert!(ls.status.success(), "invite ls failed: {}", stderr(&ls));
    assert!(
        String::from_utf8(ls.stdout).unwrap().contains("ci-runner"),
        "the cancelled invite stays in the ledger for audit"
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

/// The first `invite:` token in `text` (the create verb frames it on its own line).
fn first_invite(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|word| word.starts_with(INVITE_SCHEME))
        .map(str::to_owned)
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("the temp path is valid utf-8")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
