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
    // A derived invite IS a secret, so a bare argv token still warns (the bound shape below does not).
    assert!(
        stderr(&adopt).contains("leaks it"),
        "a derived invite on argv warns: {}",
        stderr(&adopt)
    );

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
    let create_out = String::from_utf8(create.stdout).unwrap();
    let token = first_invite(&create_out).expect("invite add --for prints an invite: token");
    assert!(
        create_out.contains(&device.to_string()),
        "the recorded line prints the full admitted key for the out-of-band compare: {create_out}"
    );
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
    // A bound invite carries no secret, so a bare argv token must NOT warn.
    assert!(
        !stderr(&adopt).contains("leaks it"),
        "a bound invite is not a secret, so no argv warning: {}",
        stderr(&adopt)
    );
    // The compare affordance: the FULL signet prints (not a 16-char prefix) with the out-of-band line.
    let adopt_out = String::from_utf8(adopt.stdout).unwrap();
    assert!(
        adopt_out.contains(&signet.to_string()),
        "adopt prints the full signet for the out-of-band compare: {adopt_out}"
    );
    assert!(
        adopt_out.contains("out of band"),
        "adopt says the signet must be compared out of band: {adopt_out}"
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

/// The device-side acceptance check: a badge signed for a DIFFERENT machine must be refused before
/// anything is written. The pre-fix adopt accepted it with a success banner and stored a dead credential.
#[test]
fn adopt_refuses_a_badge_bound_to_another_machine() {
    let base = std::env::temp_dir().join(format!("swoosh-wrong-device-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let owner_dir = base.join("owner");
    let intended_dir = base.join("intended");
    let other_dir = base.join("other");
    for dir in [&owner_dir, &intended_dir, &other_dir] {
        std::fs::create_dir_all(dir).unwrap();
    }

    // The intended machine prints its key; the owner signs a badge for that key only.
    let identity = swoosh(&["identity", "--home", path_str(&intended_dir)]);
    assert!(
        identity.status.success(),
        "identity failed: {}",
        stderr(&identity)
    );
    let intended: NodeId = String::from_utf8(identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("identity prints the node id first");
    let create = swoosh(&[
        "invite",
        "add",
        "laptop",
        "--for",
        &intended.to_string(),
        "--home",
        path_str(&owner_dir),
    ]);
    assert!(
        create.status.success(),
        "invite add --for failed: {}",
        stderr(&create)
    );
    let token = first_invite(&String::from_utf8(create.stdout).unwrap())
        .expect("invite add --for prints an invite: token");

    // A DIFFERENT machine (its own printed key) adopts the same token. The badge binds the intended
    // machine, so the check fails and neither trust file lands.
    let other_identity = swoosh(&["identity", "--home", path_str(&other_dir)]);
    assert!(
        other_identity.status.success(),
        "identity failed: {}",
        stderr(&other_identity)
    );
    let adopt = swoosh(&["adopt", &token, "--home", path_str(&other_dir)]);
    assert!(
        !adopt.status.success(),
        "a badge bound to another machine must be refused: {}",
        stderr(&adopt)
    );
    let message = stderr(&adopt);
    assert!(
        message.contains("does not bind this machine"),
        "the error names the binding check: {message}"
    );
    assert!(
        !other_dir.join("signet").exists() && !other_dir.join("badge").exists(),
        "nothing is written when the badge does not bind this machine"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// `invite add` signs AS the configured signet. On an adopted device the home key is a device, so any
/// badge it signs roots at the device key and is admitted nowhere the signet gates: refused, not minted
/// under a success banner.
#[test]
fn invite_add_refuses_on_a_machine_that_is_not_its_configured_signet() {
    let base = std::env::temp_dir().join(format!("swoosh-foreign-signet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let owner_dir = base.join("owner");
    let device_dir = base.join("device");
    std::fs::create_dir_all(&owner_dir).unwrap();
    std::fs::create_dir_all(&device_dir).unwrap();

    let identity = swoosh(&["identity", "--home", path_str(&device_dir)]);
    assert!(
        identity.status.success(),
        "identity failed: {}",
        stderr(&identity)
    );
    let device: NodeId = String::from_utf8(identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("identity prints the node id first");
    let create = swoosh(&[
        "invite",
        "add",
        "laptop",
        "--for",
        &device.to_string(),
        "--home",
        path_str(&owner_dir),
    ]);
    assert!(
        create.status.success(),
        "invite add --for failed: {}",
        stderr(&create)
    );
    let token = first_invite(&String::from_utf8(create.stdout).unwrap())
        .expect("invite add --for prints an invite: token");
    let adopt = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(adopt.status.success(), "adopt failed: {}", stderr(&adopt));

    let owner_seed: [u8; 32] = std::fs::read(owner_dir.join("identity.key"))
        .unwrap()
        .try_into()
        .expect("the owner key is 32 bytes");
    let owner = NodeId::from_ed25519_secret(&owner_seed);

    // Now the device holds the owner's signet. `invite add` here must refuse: the key that would sign is
    // the device's, not the configured signet.
    let attempt = swoosh(&["invite", "add", "tablet", "--home", path_str(&device_dir)]);
    assert!(
        !attempt.status.success(),
        "invite add on an adopted device must refuse: {}",
        stderr(&attempt)
    );
    let message = stderr(&attempt);
    assert!(
        message.contains(&owner.to_string()) && message.contains("invite add"),
        "the error names the configured signet and the fix: {message}"
    );
    let contacts = std::fs::read_to_string(device_dir.join("contacts.toml")).unwrap_or_default();
    assert!(
        !contacts.contains("tablet"),
        "no contact is recorded on the refuse path: {contacts}"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A label already bound to a DIFFERENT key is refused: `invite rm <label>` resolves through the CURRENT
/// binding, so shadowing it would leave the displaced badge live with no label that cancels it. The
/// original binding and its revocation path must survive the refusal.
#[tokio::test]
async fn invite_add_refuses_to_reuse_a_label_for_a_different_key() {
    let base = std::env::temp_dir().join(format!("swoosh-label-collision-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let owner_dir = base.join("owner");
    let first_dir = base.join("first");
    let second_dir = base.join("second");
    for dir in [&owner_dir, &first_dir, &second_dir] {
        std::fs::create_dir_all(dir).unwrap();
    }

    let first_identity = swoosh(&["identity", "--home", path_str(&first_dir)]);
    assert!(
        first_identity.status.success(),
        "{}",
        stderr(&first_identity)
    );
    let first: NodeId = String::from_utf8(first_identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("identity prints the node id first");
    let create = swoosh(&[
        "invite",
        "add",
        "desk",
        "--for",
        &first.to_string(),
        "--home",
        path_str(&owner_dir),
    ]);
    assert!(create.status.success(), "{}", stderr(&create));
    let token = first_invite(&String::from_utf8(create.stdout).unwrap()).expect("token");
    let badge = token
        .strip_prefix(INVITE_SCHEME)
        .unwrap()
        .split_once('.')
        .expect("a bound invite carries a signet field and a badge")
        .1;
    let cap = Cap::parse(badge).expect("the badge parses as a cap");

    // A second device with its own key asks for the SAME label: refused, with the two-step fix named.
    let second_identity = swoosh(&["identity", "--home", path_str(&second_dir)]);
    assert!(
        second_identity.status.success(),
        "{}",
        stderr(&second_identity)
    );
    let second: NodeId = String::from_utf8(second_identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("identity prints the node id first");
    let second_attempt = swoosh(&[
        "invite",
        "add",
        "desk",
        "--for",
        &second.to_string(),
        "--home",
        path_str(&owner_dir),
    ]);
    assert!(
        !second_attempt.status.success(),
        "re-using a label for a different key must refuse: {}",
        stderr(&second_attempt)
    );
    let message = stderr(&second_attempt);
    assert!(
        message.contains("invite rm desk") && message.contains("contact rm me/desk"),
        "the error names how to cut the old badge and free the name: {message}"
    );

    // The original row is intact and still revocable by its label.
    let ls = swoosh(&["invite", "ls", "--home", path_str(&owner_dir)]);
    assert!(ls.status.success(), "{}", stderr(&ls));
    let listing = String::from_utf8(ls.stdout).unwrap();
    assert!(
        listing.contains("desk") && listing.contains(&first.short()),
        "the original binding still stands: {listing}"
    );
    let rm = swoosh(&["invite", "rm", "desk", "--home", path_str(&owner_dir)]);
    assert!(rm.status.success(), "{}", stderr(&rm));
    let denylist = FileDenylist::load(Home::resolve(Some(owner_dir.clone())).unwrap().revoked())
        .await
        .unwrap();
    assert!(
        denylist.is_revoked(&cap),
        "the displaced badge is still cut by its label after the refusal"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A refused fleet invite leaves no state: the run-time deferral lands BEFORE the identity resolves, so
/// a fresh home gets no key from a command that never ran.
#[test]
fn a_refused_fleet_invite_leaves_no_identity_behind() {
    let base = std::env::temp_dir().join(format!("swoosh-fleet-refusal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let home_dir = base.join("empty");
    std::fs::create_dir_all(&home_dir).unwrap();

    let attempt = swoosh(&[
        "invite",
        "add",
        "desk",
        "--for",
        "fleet:alice",
        "--home",
        path_str(&home_dir),
    ]);
    assert!(
        !attempt.status.success(),
        "the fleet arm is refused at run time: {}",
        stderr(&attempt)
    );
    let message = stderr(&attempt);
    assert!(
        message.contains("enrollment door"),
        "the error names the missing door: {message}"
    );
    assert!(
        !home_dir.join("identity.key").exists(),
        "the refusal lands before the identity is created"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Re-rooting takes an explicit acknowledgement: an invite naming a signet this machine does not yet
/// trust switches the root, so a differing one refuses without `--force` and lands with it.
#[test]
fn adopt_requires_force_to_switch_the_trusted_signet() {
    let base = std::env::temp_dir().join(format!("swoosh-reroot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let first_dir = base.join("first-owner");
    let second_dir = base.join("second-owner");
    let device_dir = base.join("device");
    for dir in [&first_dir, &second_dir, &device_dir] {
        std::fs::create_dir_all(dir).unwrap();
    }

    let identity = swoosh(&["identity", "--home", path_str(&device_dir)]);
    assert!(identity.status.success(), "{}", stderr(&identity));
    let device: NodeId = String::from_utf8(identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("identity prints the node id first");

    let first = swoosh(&[
        "invite",
        "add",
        "laptop",
        "--for",
        &device.to_string(),
        "--home",
        path_str(&first_dir),
    ]);
    assert!(first.status.success(), "{}", stderr(&first));
    let first_token = first_invite(&String::from_utf8(first.stdout).unwrap()).expect("token");
    let adopt = swoosh(&["adopt", &first_token, "--home", path_str(&device_dir)]);
    assert!(adopt.status.success(), "{}", stderr(&adopt));
    let first_seed: [u8; 32] = std::fs::read(first_dir.join("identity.key"))
        .unwrap()
        .try_into()
        .expect("the first owner key is 32 bytes");
    let first_signet = NodeId::from_ed25519_secret(&first_seed);
    assert_eq!(
        std::fs::read_to_string(device_dir.join("signet"))
            .unwrap()
            .trim(),
        first_signet.to_string()
    );

    // A second owner signs for the same device. Adopting would switch the gate's root: refused without
    // `--force`, and the stored signet is untouched by the refusal.
    let second = swoosh(&[
        "invite",
        "add",
        "laptop",
        "--for",
        &device.to_string(),
        "--home",
        path_str(&second_dir),
    ]);
    assert!(second.status.success(), "{}", stderr(&second));
    let second_token = first_invite(&String::from_utf8(second.stdout).unwrap()).expect("token");
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
        std::fs::read_to_string(device_dir.join("signet"))
            .unwrap()
            .trim(),
        first_signet.to_string(),
        "the refused switch leaves the trusted root untouched"
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
    let second_seed: [u8; 32] = std::fs::read(second_dir.join("identity.key"))
        .unwrap()
        .try_into()
        .expect("the second owner key is 32 bytes");
    assert_eq!(
        std::fs::read_to_string(device_dir.join("signet"))
            .unwrap()
            .trim(),
        NodeId::from_ed25519_secret(&second_seed).to_string(),
        "--force wrote the new signet"
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
