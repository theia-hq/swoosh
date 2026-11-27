use super::*;
use crate::contacts::Contacts;
use crate::peer::Peer;
use crate::testkit::{HostilePeer, Script, ScriptedPeer};

/// The cause a list that is not one gives, as [`ListFailed::UnknownReply`] words it.
const UNKNOWN_LIST_REPLY: &str = "it sent an unknown reply to the list request";

/// The cause a list request that got no answer at all gives, as [`ListFailed::Ended`] words it.
const LIST_ENDED: &str = "it ended the list request without an answer";

/// A bind in the given mode with n0's two reach services: what every outcome test about the bind's
/// remedy is bound as, so no reach line joins its message.
fn bound(local: bool) -> transport::Bound {
    transport::Bound {
        local,
        reach: transport::Reach::default(),
    }
}

// A refused probe is a REFUSAL, never dressed as an addressing problem: the node was reached, so the
// error says so and carries NO `--peer` hint (the bug: a refused stranger used to print `reached, but
// refused` and THEN `could not reach`, with the `--peer` remedy). Bound `--local`, the one bind whose
// reach hint names `--peer`, so the assertion can see the hint leak.
#[test]
fn a_reached_but_refused_probe_is_a_refusal_without_the_reach_hint() {
    let err = Outcome::Refused
        .into_result(&alice(), &bound(true))
        .expect_err("a refusal is non-zero");
    let msg = format!("{err:#}");
    assert!(msg.contains("reached, but refused"), "{msg}");
    assert!(!msg.contains("could not reach"), "{msg}");
    assert!(!msg.contains("--peer"), "{msg}");
}

/// `alice/laptop`, a contact's machine, resolved as a verb resolves it.
fn alice() -> Machine {
    let mut contacts = Contacts::default();
    contacts
        .save(&"alice/laptop".parse().expect("a contact"), laptop())
        .expect("the name is free");
    "alice/laptop"
        .parse::<Peer>()
        .expect("a name")
        .machine(&contacts)
        .expect("one machine")
}

/// The key of `alice/laptop` in [`alice`].
fn laptop() -> bifrost::NodeId {
    bifrost::NodeId::from_ed25519_secret(&[0x1a; 32])
}

// A `--local` dial that reached nothing names both spellings of the setting as the cause, since only the
// variable may be set, then where the machine lists its addresses and the `--peer` form with its whole key.
// Named, the title and the pointer name the machine; unnamed, the title holds the short key and the
// pointer says `that machine`. The dial's cause chain is not shown: it says how the dial failed, which the
// person cannot act on.
#[tokio::test]
async fn a_local_miss_names_status_and_the_peer_form() {
    let named = alice();
    let err = Outcome::Unreachable
        .into_result(&named, &bound(true))
        .expect_err("all-unreachable is non-zero");
    assert_eq!(
        format!("{err:#}"),
        format!(
            "could not reach alice/laptop on this network\n  \
             With --local or SWOOSH_LOCAL, swoosh looks for it on this network,\n  \
             or at an address you give.\n  \
             On alice/laptop, swoosh status lists its addresses under reach.\n  \
             Add one of those addresses to your command:\n    \
             --peer {}=<address>",
            laptop()
        )
    );

    let (node, unnamed) = unreachable();
    let peers = crate::peers::Peers::new(&node);
    let Err(error) = peers
        .isolated(unnamed.key(), crate::peers::Hints::NONE)
        .await
    else {
        panic!("a dial the peer closed is an error");
    };
    let shown = format!("{:#}", open_failed(&unnamed, error, &bound(true)));
    assert_eq!(
        shown,
        format!(
            "could not reach {} on this network\n  \
             With --local or SWOOSH_LOCAL, swoosh looks for it on this network,\n  \
             or at an address you give.\n  \
             On that machine, swoosh status lists its addresses under reach.\n  \
             Add one of those addresses to your command:\n    \
             --peer {}=<address>",
            crate::credential::short(&HostilePeer::node_id()),
            HostilePeer::node_id()
        )
    );
    assert!(!shown.contains("closed by peer"), "{shown}");
}

// Outside `--local` a miss keeps its own line, byte for byte: the chain the dial gave, escaped, and the
// resolver it asked when it is not n0's. None of the `--local` words reach a default bind.
#[tokio::test]
async fn a_default_miss_is_unchanged() {
    let (node, machine) = unreachable();
    let over_own = transport::Bound {
        local: false,
        reach: transport::Reach {
            relay: transport::RelayHome::N0,
            resolver: transport::Resolver::Custom(
                "https://dns.example/pkarr"
                    .parse()
                    .expect("a valid resolver url"),
            ),
        },
    };
    for (bound, expected) in [
        (
            bound(false),
            // The peer's text is cut to the room its `error:` line leaves.
            r"could not reach ed012txmdbu7…: connect to peer: closed by peer: no\r…",
        ),
        (
            over_own,
            "could not reach ed012txmdbu7…: connect to peer: closed by peer: no\\r…\n  \
             resolver asked: https://dns.example/pkarr",
        ),
    ] {
        let peers = crate::peers::Peers::new(&node);
        let Err(error) = peers
            .isolated(machine.key(), crate::peers::Hints::NONE)
            .await
        else {
            panic!("a dial the peer closed is an error");
        };
        assert_eq!(
            format!("{:#}", open_failed(&machine, error, &bound)),
            expected
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
        .into_result(&alice(), &over_own)
        .expect_err("all-unreachable is non-zero");
    let msg = format!("{err:#}");
    assert_eq!(
        msg,
        "could not reach alice/laptop\n  resolver asked: https://dns.example/pkarr"
    );
}

// An iroh dial over n0's own resolver says nothing extra: n0 is the documented default, so a line
// naming it would be noise on every failed dial anyone ever sees.
#[test]
fn an_all_unreachable_n0_probe_names_no_reach_service() {
    let err = Outcome::Unreachable
        .into_result(&alice(), &bound(false))
        .expect_err("all-unreachable is non-zero");
    assert_eq!(format!("{err:#}"), "could not reach alice/laptop");
}

// A probe that failed mid-protocol is its OWN non-zero outcome: the node was reached, so the error
// says the probe failed rather than claiming the peer could not be reached, and it carries no reach
// hint (reach was not the problem). Without this a mid-protocol failure exited green. Bound `--local`, so
// a leaked hint would carry `--peer`.
#[test]
fn a_failed_probe_probe_is_non_zero_and_says_the_probe_failed() {
    let err = Outcome::Failed
        .into_result(&alice(), &bound(true))
        .expect_err("a failed probe is non-zero");
    let msg = format!("{err:#}");
    assert!(msg.contains("reached, but the probe failed"), "{msg}");
    assert!(!msg.contains("could not reach"), "{msg}");
    assert!(!msg.contains("--peer"), "{msg}");
}

// Only a probe that answered exits green: every other outcome is an error.
#[test]
fn only_a_healthy_probe_exits_green() {
    let local = bound(true);
    assert!(Outcome::Healthy.into_result(&alice(), &local).is_ok());
    for outcome in [Outcome::Unreachable, Outcome::Refused, Outcome::Failed] {
        assert!(
            outcome.into_result(&alice(), &local).is_err(),
            "{outcome:?} must not exit green"
        );
    }
}

/// The reason a peer gives for closing the dial, holding a carriage return, an ESC CSI sequence and a
/// bidi override.
const HOSTILE: &str = "closed by peer: no\r\u{1b}[2Kalice: 900 MiB/s\u{202e}";

/// A node whose every dial fails with [`HOSTILE`] as the cause, and the machine it is asked to reach: a
/// raw key no name here holds.
fn unreachable() -> (bifrost::Node<HostilePeer, bifrost::NoDiscovery>, Machine) {
    let node = bifrost::Node::new(HostilePeer::Unreachable(HOSTILE), bifrost::NoDiscovery);
    let machine = HostilePeer::node_id()
        .to_string()
        .parse::<Peer>()
        .expect("a raw key parses as a Peer")
        .machine(&Contacts::default())
        .expect("a key is one machine");
    (node, machine)
}

/// The line a target the dial did not reach prints: the connect's cause chain, the peer's reason escaped,
/// on one line, with the words as they were.
fn escaped_unreached(target: &Machine) -> String {
    format!(
        // Cut to the room its `error:` line leaves; an escape is cut whole.
        r"could not reach {}: connect to peer: closed by peer: no\r…",
        target.label()
    )
}

// A target an open's dial did not reach prints the connect's cause chain, and a cause can be the peer's
// own text.
#[tokio::test]
async fn a_hostile_connect_failure_prints_escaped() {
    let (node, machine) = unreachable();
    let bound = bound(false);
    let peers = crate::peers::Peers::new(&node);
    let Err(error) = peers
        .isolated(machine.key(), crate::peers::Hints::NONE)
        .await
    else {
        panic!("a dial the peer closed is an error");
    };
    assert_eq!(
        format!("{:#}", open_failed(&machine, error, &bound)),
        escaped_unreached(&machine)
    );
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

/// The follow-up to a refused `ssh` stream to [`yours`] by own bind, against a gate that answers
/// `script`, presenting the standing a home under `tag` holds: what it found, the gate, and the badge
/// the home presents.
async fn diagnosed(tag: &str, script: Vec<Script>) -> (Option<Diagnosis>, ScriptedPeer, Link) {
    let peer = ScriptedPeer::new(nas(), script);
    let ssh = "ssh".parse::<Service>().expect("a service");
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    let peers = crate::peers::Peers::new(&node);
    let dir = std::env::temp_dir().join(format!("swoosh-reach-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    crate::config::create_store_dir(&dir).expect("a store dir");
    let home = crate::home::Home::resolve(Some(dir.clone())).expect("a home");
    let root = crate::testkit::TestRoot::seeded(0x70);
    crate::config::write_signet(&crate::testkit::lock(), &home, root.node_id()).expect("a signet");
    let badge = root
        .device_badge(
            node.node_id(),
            std::time::SystemTime::now() + Duration::from_secs(3600),
        )
        .expect("mint a badge");
    crate::config::write_badge(&crate::testkit::lock(), &home, &badge).expect("a badge");
    let credential = crate::credential::Credential::Family { present: None };
    let own = crate::streams::OwnBind::new(&peers, &home, node.node_id(), &credential);
    let found = diagnose_through(&own, &yours(), &ssh, None).await;
    let _ = std::fs::remove_dir_all(dir);
    (found, peer, badge)
}

// The follow-up to a refused stream asks `control.serve` for its list, presenting what the refused
// stream presented, the home's standing: the route is member-only, so a call that presented nothing would
// always be refused and the line would wrongly say the device does not count this machine as one of
// yours. The scripted device answers only a list request, so a diagnosis is the list's.
#[tokio::test]
async fn the_follow_up_asks_list() {
    let (found, peer, badge) = diagnosed("slots", vec![Script::Lists(vec!["ping"])]).await;
    assert_eq!(found, Some(Diagnosis::NotListed));
    let [request] = peer.requests().try_into().expect("one call");
    assert_eq!(request.service, CONTROL_SERVE_SERVICE);
    assert_eq!(
        request.capability,
        Some(badge.to_string()),
        "slot 1 is the refused stream's"
    );
}

// The three answers the follow-up can read: not listed, listed, and the call itself refused.
#[tokio::test]
async fn the_follow_up_reads_its_three_causes() {
    for (tag, script, cause) in [
        (
            "unlisted",
            Script::Lists(vec!["ping", "speed"]),
            Diagnosis::NotListed,
        ),
        (
            "listed",
            Script::Lists(vec!["ping", "ssh"]),
            Diagnosis::Listed,
        ),
        (
            "not-yours",
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Diagnosis::NotYours,
        ),
    ] {
        let (found, _, _) = diagnosed(tag, vec![script]).await;
        assert_eq!(found, Some(cause), "{tag}");
    }
}

// A follow-up the device admits and never answers ends at its own deadline, under the dial's, and claims
// no cause; so does one refused any way other than `NotAdmitted`, which says nothing about this machine.
#[tokio::test(start_paused = true)]
async fn a_follow_up_that_times_out_claims_no_cause() {
    let started = tokio::time::Instant::now();
    // Admitted, then silent: a stream that never opens meets the open's own, shorter deadline first.
    let (found, _, _) = diagnosed("silent", vec![Script::Holds]).await;
    assert_eq!(found, Some(Diagnosis::Unknown));
    assert!(started.elapsed() >= FOLLOW_UP_TIMEOUT);
    assert!(FOLLOW_UP_TIMEOUT < crate::peers::DIAL_TIMEOUT);

    let busy = bifrost::Refusal::Unavailable {
        detail: bifrost::RefusalDetail::bounded("busy"),
    };
    let (found, _, _) = diagnosed("busy", vec![Script::Refuse(busy)]).await;
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
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    let peers = crate::peers::Peers::new(&node);
    let home = crate::home::Home::resolve(Some(std::env::temp_dir().join("swoosh-reach-unasked")))
        .expect("a home");
    let credential = crate::credential::Credential::Family { present: None };
    let own = crate::streams::OwnBind::new(&peers, &home, node.node_id(), &credential);
    assert_eq!(diagnose_through(&own, &key, &ssh, None).await, None);
    assert!(peer.requests().is_empty(), "nothing was asked");
    assert_eq!(peer.dials(), 0, "nothing was dialed");
}

// The list request is the wire byte `1` and this side's end, then the answer: anything but `Done`, or a list
// that does not decode, is the one unknown reply, and an end before any answer is its own cause; the
// follow-up reads either as no cause. The writer is lent, not moved, so only `ask_list`'s own shutdown can
// end the request: a dropped writer would end it too, and prove nothing.
#[tokio::test]
async fn a_list_is_asked_and_only_done_answers_it() {
    use tokio::io::AsyncReadExt as _;

    use crate::serve::control::Answer;

    let asked = |answer: Vec<u8>| async move {
        let (mut write, mut node_reads) = tokio::io::duplex(64);
        let (mut node_writes, read) = tokio::io::duplex(64);
        node_writes
            .write_all(&answer)
            .await
            .expect("the answer fits");
        drop(node_writes);
        let listed = ask_list(&mut write, read).await;
        let mut request = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), node_reads.read_to_end(&mut request))
            .await
            .expect("the request was ended while its writer still lives")
            .expect("the request reads");
        drop(write);
        (listed, request)
    };
    let mut done = vec![Answer::Done.encode()];
    done.extend_from_slice(&0u32.to_be_bytes());
    let (listed, request) = asked(done).await;
    // The literal wire byte: W1a numbers `List` 1 and `Stop` 2, so a swap of the codes fails here.
    assert_eq!(request, [1u8], "one list request, then the end");
    assert_eq!(listed.expect("Done and a list").entries().count(), 0);
    for (answer, cause) in [
        (vec![Answer::BadRequest.encode()], UNKNOWN_LIST_REPLY),
        (vec![Answer::NotYet.encode()], UNKNOWN_LIST_REPLY),
        (vec![0x7f], UNKNOWN_LIST_REPLY),
        (
            vec![Answer::BadRequest.encode(), 0, 0, 0, 0],
            UNKNOWN_LIST_REPLY,
        ),
        (vec![Answer::Done.encode(), 0, 0, 0, 9], UNKNOWN_LIST_REPLY),
        (Vec::new(), LIST_ENDED),
    ] {
        let (listed, _) = asked(answer.clone()).await;
        let error = listed.expect_err("no list");
        assert_eq!(format!("{error:#}"), cause, "{answer:?}");
    }
}

/// A request half that fails: at the request's write, or at its end once the request is written.
struct FailingRequest {
    at_write: bool,
}

impl tokio::io::AsyncWrite for FailingRequest {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        core::task::Poll::Ready(if self.at_write {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::BrokenPipe,
                "the write broke",
            ))
        } else {
            Ok(buf.len())
        })
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Err(tokio::io::Error::new(
            tokio::io::ErrorKind::BrokenPipe,
            "the end broke",
        )))
    }
}

// A list request whose write or end fails is no list: the transport's own cause, never a claim about the
// machine's answer, and nothing is read after it.
#[tokio::test]
async fn a_list_request_that_fails_to_go_keeps_its_cause() {
    for (at_write, cause) in [(true, "the write broke"), (false, "the end broke")] {
        let mut done = vec![crate::serve::control::Answer::Done.encode()];
        done.extend_from_slice(&0u32.to_be_bytes());
        let error = ask_list(FailingRequest { at_write }, done.as_slice())
            .await
            .expect_err("no list");
        assert_eq!(format!("{error:#}"), cause);
    }
}
