use super::*;
use crate::contacts::Contacts;
use crate::peer::Peer;
use crate::testkit::{HostilePeer, Script, ScriptedPeer};

/// A bind over the named backend with n0's two reach services: what every outcome test about the
/// TRANSPORT remedy is bound as, so no reach line joins its message.
fn bound(transport: transport::Transport, local: bool) -> transport::Bound {
    transport::Bound {
        transport,
        local,
        reach: transport::Reach::default(),
    }
}

// A refused probe is a REFUSAL, never dressed as an addressing problem: the node was reached, so the
// error says so and carries NO quirk `--peer`/discovery hint (the bug: a refused stranger over quirk
// used to print `reached, but refused` and THEN `could not reach`, with the `--peer` remedy).
#[test]
fn a_reached_but_refused_probe_is_a_refusal_without_the_reach_hint() {
    let err = Outcome::Refused
        .into_result(&"alice", &bound(transport::Transport::Quirk, false))
        .expect_err("a refusal is non-zero");
    let msg = format!("{err:#}");
    assert!(msg.contains("reached, but refused"), "{msg}");
    assert!(!msg.contains("could not reach"), "{msg}");
    assert!(!msg.contains("--peer"), "{msg}");
}

// An unreachable probe DOES carry the transport's reach hint: over quirk, the `--peer` remedy, under the
// fact it explains. Each spelling of quirk carries the same lines.
#[test]
fn an_all_unreachable_probe_carries_the_quirk_reach_hint() {
    for transport in [
        transport::Transport::Quirk,
        transport::Transport::QuirkNoise,
    ] {
        let err = Outcome::Unreachable
            .into_result(&"alice", &bound(transport, false))
            .expect_err("all-unreachable is non-zero");
        assert_eq!(
            format!("{err:#}"),
            "could not reach alice\n  quirk finds no machine by itself.\n  Give its address with --peer \
             <key>=<address>, or add --transport iroh."
        );
    }
}

// Under `--local` the remedy names the setting as the cause, both its spellings, since only the variable
// may be set: the internet fallback is what it removed, so "add --transport iroh" would be false advice.
#[test]
fn an_all_unreachable_local_probe_names_the_flag_as_the_cause() {
    for transport in [transport::Transport::Iroh, transport::Transport::QuirkNoise] {
        let err = Outcome::Unreachable
            .into_result(&"alice", &bound(transport, true))
            .expect_err("all-unreachable is non-zero");
        assert_eq!(
            format!("{err:#}"),
            "could not reach alice\n  With --local or SWOOSH_LOCAL, swoosh looks on this network only.\n  \
             Give its address with --peer <key>=<address>, or drop --local and unset SWOOSH_LOCAL."
        );
    }
}

// An iroh dial that reached nobody names the RESOLVER it asked, because iroh's own error does not:
// without that line an empty or unreachable resolver reads as "the peer is offline". It never names
// this node's own relay: a dial runs through whatever relay the PEER's record names, so that URL
// would point at the wrong server.
#[test]
fn an_all_unreachable_iroh_probe_names_the_resolver_it_asked() {
    let over_own = transport::Bound {
        transport: transport::Transport::Iroh,
        local: false,
        reach: transport::Reach {
            relay: transport::RelayHome::Custom(
                "https://relay.example".parse().expect("a valid relay url"),
            ),
            resolver: transport::Resolver::Custom(
                "https://dns.example/pkarr"
                    .parse()
                    .expect("a valid resolver url"),
            ),
        },
    };
    let err = Outcome::Unreachable
        .into_result(&"alice", &over_own)
        .expect_err("all-unreachable is non-zero");
    let msg = format!("{err:#}");
    assert_eq!(
        msg,
        "could not reach alice\n  resolver asked: https://dns.example/pkarr"
    );
}

// An iroh dial over n0's own resolver says nothing extra: n0 is the documented default, so a line
// naming it would be noise on every failed dial anyone ever sees.
#[test]
fn an_all_unreachable_n0_probe_names_no_reach_service() {
    let err = Outcome::Unreachable
        .into_result(&"alice", &bound(transport::Transport::Iroh, false))
        .expect_err("all-unreachable is non-zero");
    assert_eq!(format!("{err:#}"), "could not reach alice");
}

// A probe that failed mid-protocol is its OWN non-zero outcome: the node was reached, so the error
// says the probe failed rather than claiming the peer could not be reached, and it carries no reach
// hint (reach was not the problem). Without this a mid-protocol failure exited green.
#[test]
fn a_failed_probe_probe_is_non_zero_and_says_the_probe_failed() {
    let err = Outcome::Failed
        .into_result(&"alice", &bound(transport::Transport::Quirk, false))
        .expect_err("a failed probe is non-zero");
    let msg = format!("{err:#}");
    assert!(msg.contains("reached, but the probe failed"), "{msg}");
    assert!(!msg.contains("could not reach"), "{msg}");
    assert!(!msg.contains("--peer"), "{msg}");
}

// Only a probe that answered exits green: every other outcome is an error.
#[test]
fn only_a_healthy_probe_exits_green() {
    let quirk = bound(transport::Transport::Quirk, false);
    assert!(Outcome::Healthy.into_result(&"alice", &quirk).is_ok());
    for outcome in [Outcome::Unreachable, Outcome::Refused, Outcome::Failed] {
        assert!(
            outcome.into_result(&"alice", &quirk).is_err(),
            "{outcome:?} must not exit green"
        );
    }
}

/// The reason a peer gives for closing the dial, holding a carriage return, an ESC CSI sequence and a
/// bidi override.
const HOSTILE: &str = "closed by peer: no\r\u{1b}[2Kalice: 900 MiB/s\u{202e}";

/// A node whose every dial fails with [`HOSTILE`] as the cause, the raw key it is asked to reach, and the
/// machine that key resolves to.
fn unreachable() -> (Node<HostilePeer, bifrost::NoDiscovery>, Peer, Machine) {
    let node = Node::new(HostilePeer::Unreachable(HOSTILE), bifrost::NoDiscovery);
    let target = HostilePeer::node_id()
        .to_string()
        .parse::<Peer>()
        .expect("a raw key parses as a Peer");
    let machine = target
        .machine(&Contacts::default())
        .expect("a key is one machine");
    (node, target, machine)
}

/// The line a target the dial did not reach prints: the connect's cause chain, the peer's reason escaped,
/// on one line, with the words as they were.
fn escaped_unreached(target: &Peer) -> String {
    format!(
        r"could not reach {target}: connect to peer: closed by peer: no\r\u{{1b}}[2Kalice: 900 MiB/s\u{{202e}}"
    )
}

// `dial`, the raw reach `proxy` takes: a target the dial did not reach prints the connect's cause chain,
// and a cause can be the peer's own text.
#[tokio::test]
async fn a_hostile_connect_failure_prints_escaped() {
    let (node, target, machine) = unreachable();
    let bound = bound(transport::Transport::Iroh, false);
    let Err(error) = dial(&node, &machine, &target, &bound).await else {
        panic!("a dial the peer closed is an error");
    };
    assert_eq!(format!("{error:#}"), escaped_unreached(&target));
}

// `dial_service`, the gated reach `speed` takes: the same chain, through its own failure path.
#[tokio::test]
async fn a_hostile_service_connect_failure_prints_escaped() {
    let (node, target, machine) = unreachable();
    let bound = bound(transport::Transport::Iroh, false);
    let service = PING_SERVICE
        .parse::<Service>()
        .expect("ping is a service name");
    let Err(error) = dial_service(&node, &machine, &target, &service, None, None, &bound).await
    else {
        panic!("a dial the peer closed is an error");
    };
    assert_eq!(format!("{error:#}"), escaped_unreached(&target));
}

/// The key of `me/nas` in [`yours`].
fn nas() -> bifrost::NodeId {
    bifrost::NodeId::from_ed25519_secret(&[0x51; 32])
}

/// `me/nas`, one of your devices, resolved as a verb resolves it.
fn yours() -> Machine {
    let mut contacts = Contacts::default();
    contacts
        .save(&"me/nas".parse().expect("a device"), nas())
        .expect("the name is free");
    "me/nas"
        .parse::<Peer>()
        .expect("a name")
        .machine(&contacts)
        .expect("one machine")
}

/// A link shown as a person would paste it, for the follow-up's slots.
fn badge(seed: u8) -> Link {
    crate::testkit::TestRoot::seeded(seed)
        .device_badge(
            crate::testkit::TestNode::seeded(0x52).node_id(),
            nauthy::Request::expires_in(Duration::from_secs(3600)),
        )
        .expect("mint a badge")
}

/// Diagnose a refused `ssh` dial to [`yours`] against a gate that answers `script`, presenting `slots`.
async fn diagnosed_with(
    script: Vec<Script>,
    slots: (Option<Link>, Option<Link>),
) -> (Option<Diagnosis>, ScriptedPeer) {
    let peer = ScriptedPeer::new(nas(), script);
    let ssh = "ssh".parse::<Service>().expect("a service");
    let found = diagnose(&peer, &yours(), &ssh, slots.0, slots.1).await;
    (found, peer)
}

/// [`diagnosed_with`] presenting a badge in each slot.
async fn diagnosed(script: Vec<Script>) -> (Option<Diagnosis>, ScriptedPeer) {
    diagnosed_with(script, (Some(badge(1)), Some(badge(2)))).await
}

// The follow-up to a refused dial asks `control.services` presenting the refused dial's own slots, both of
// them: the route is member-only, so a call that presented nothing would always be refused and the line
// would wrongly say the device does not count this machine as one of yours.
#[tokio::test]
async fn the_follow_up_presents_the_refused_dials_credential() {
    let (present, membership) = (badge(1), badge(2));
    let (found, peer) = diagnosed_with(
        vec![Script::Lists(vec!["ping"])],
        (Some(present.clone()), Some(membership.clone())),
    )
    .await;
    assert_eq!(found, Some(Diagnosis::NotListed));
    let [request] = peer.requests().try_into().expect("one call");
    assert_eq!(request.service, CONTROL_SERVICES_SERVICE);
    assert_eq!(
        request.capability,
        Some(present.to_string()),
        "slot 1 is the refused dial's"
    );
    assert_eq!(
        request.membership,
        Some(membership.to_string()),
        "slot 2 is the refused dial's"
    );
}

// The three answers the follow-up can read: not listed, listed, and the call itself refused.
#[tokio::test]
async fn the_follow_up_reads_its_three_causes() {
    for (script, cause) in [
        (Script::Lists(vec!["ping", "speed"]), Diagnosis::NotListed),
        (Script::Lists(vec!["ping", "ssh"]), Diagnosis::Listed),
        (
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Diagnosis::NotYours,
        ),
    ] {
        let (found, _) = diagnosed(vec![script]).await;
        assert_eq!(found, Some(cause));
    }
}

// A follow-up the device admits and never answers ends at its own deadline, under the dial's, and claims
// no cause; so does one refused any way other than `NotAdmitted`, which says nothing about this machine.
#[tokio::test(start_paused = true)]
async fn a_follow_up_that_times_out_claims_no_cause() {
    let started = tokio::time::Instant::now();
    let (found, _) = diagnosed(vec![Script::Silent]).await;
    assert_eq!(found, Some(Diagnosis::Unknown));
    assert!(started.elapsed() >= FOLLOW_UP_TIMEOUT);
    assert!(FOLLOW_UP_TIMEOUT < DIAL_TIMEOUT);

    let busy = bifrost::Refusal::Unavailable {
        detail: bifrost::RefusalDetail::bounded("busy"),
    };
    let (found, _) = diagnosed(vec![Script::Refuse(busy)]).await;
    assert_eq!(found, Some(Diagnosis::Unknown));
}

// Only one of your devices is asked: a link, a contact's machine and a bare key are never sent the call,
// so a refusal from anyone else costs nothing and reveals nothing.
#[tokio::test]
async fn only_your_devices_are_asked_why() {
    let ssh = "ssh".parse::<Service>().expect("a service");
    let key = nas()
        .to_string()
        .parse::<Peer>()
        .expect("a key")
        .machine(&Contacts::default())
        .expect("one machine");
    assert_eq!(key.kind(), crate::peer::Kind::Key);
    let peer = ScriptedPeer::new(nas(), [Script::Lists(vec![])]);
    assert_eq!(diagnose(&peer, &key, &ssh, None, None).await, None);
    let node = Node::new(peer.clone(), bifrost::NoDiscovery);
    assert_eq!(diagnose_over(&node, &key, &ssh, None, None).await, None);
    assert!(peer.requests().is_empty(), "nothing was asked");
    assert_eq!(peer.dials(), 0, "nothing was dialed");
}
