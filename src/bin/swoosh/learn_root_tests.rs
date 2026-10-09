// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Asking a machine which root vouches for it, through the path a dialing verb takes in the composition
//! root: a real `ping`, clap-parsed, run on an in-process node against a machine whose `lookup.root` is a
//! stand-in that counts every stream it is asked on, and answers, or never does.
//!
//! Over `mem` a machine's key is the transport's own, so each home here saves the machine under the key the
//! transport gave it, and its standing is bound to that key.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bifrost::{NoDiscovery, Node, NodeId};
use bifrost_mem::MemTransport;
use clap::Parser as _;
use keystore::{KeyFile, Protection};
use nauthy::{Denylist, Link};
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;
use swoosh::roster::{Epoch, RosterDoc};
use swoosh::sync::Answer;
use swoosh::testkit::{Answering, Counting, TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::open_policy::ProvenOnly;
use tightbeam::tunnel::{
    self, BoxRead, BoxWrite, CancellationToken, Handler, Router, ServeError, Served,
};
use tokio::io::AsyncWriteExt as _;

use crate::commands::learning::Asking;
use crate::{Cli, Outward, Verb, run_verb};

/// Alice's root, which vouches for the machine dialed.
const ALICE_ROOT: u8 = 0x81;
/// This machine.
const DESK: u8 = 0x82;
/// The root this machine is a device of, in the case the machine dialed is one of yours.
const YOUR_ROOT: u8 = 0x83;

/// What the stand-in `lookup.root` does with a stream.
#[derive(Clone, Copy)]
enum Answers {
    /// Hands over the machine's standing.
    Standing,
    /// Never answers, holding the stream open.
    Never,
}

/// The stand-in root route: it counts every stream it is asked on.
struct Lookup {
    asked: Arc<AtomicU32>,
    answers: Answers,
    standing: Link,
}

impl Handler for Lookup {
    type Exposure = ProvenOnly;

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        match self.answers {
            Answers::Standing => {
                // The route's hit: the status byte, the length, the standing.
                let text = self.standing.as_str().as_bytes();
                let mut bytes = vec![0x01];
                bytes.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
                bytes.extend_from_slice(text);
                let _ = writer.write_all(&bytes).await;
                let _ = writer.shutdown().await;
            }
            Answers::Never => core::future::pending::<()>().await,
        }
        Ok(())
    }
}

/// A machine serving `ping` to anyone and the stand-in root route, under alice's root, until `cancel`:
/// its key, and the count of root questions.
fn machine(answers: Answers, cancel: CancellationToken) -> (NodeId, Arc<AtomicU32>) {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let key = host.node_id();
    let standing = TestRoot::seeded(ALICE_ROOT)
        .device_badge(key, SystemTime::now() + Duration::from_secs(3600))
        .unwrap();
    let asked = Arc::new(AtomicU32::new(0));
    let lookup = Lookup {
        asked: Arc::clone(&asked),
        answers,
        standing,
    };
    let ping: nauthy::Service = "ping".parse().unwrap();
    tokio::task::spawn_local(async move {
        let denylist = Denylist::load(std::env::temp_dir().join(format!(
            "swoosh-learn-root-deny-{}-{key}",
            std::process::id()
        )))
        .unwrap();
        let gate =
            tunnel::resolve_gate(Some(TestRoot::seeded(ALICE_ROOT).node_id()), denylist).unwrap();
        Router::new(gate)
            .service(ping.clone(), measure::server::MeteredPing::new())
            .unwrap()
            .public([ping])
            .proven_service(
                swoosh::serve::LOOKUP_ROOT_SERVICE.parse().unwrap(),
                lookup,
                |_| true,
            )
            .unwrap()
            .expose()
            .unwrap()
            .run(&host, cancel)
            .await
            .unwrap();
    });
    (key, asked)
}

/// A fresh home holding this machine's key.
fn desk(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-learn-root-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    swoosh::identity::make_machine_dir(&home).unwrap();
    let mut seed = TestNode::seeded(DESK).seed();
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .unwrap();
    home
}

/// Save `key` in `home`'s book as alice's laptop.
async fn alice_laptop(home: &Home, key: NodeId) {
    let mut store = ContactsStore::open(home).await.unwrap();
    store.contacts_mut().add(
        "alice".parse().unwrap(),
        Some("laptop".parse().unwrap()),
        key,
    );
    store.save(&swoosh::testkit::lock()).unwrap();
}

/// Make `home` a device of your root whose list holds `key` as `me/nas`, its last exchange just now.
async fn your_nas(home: &Home, key: NodeId) {
    let root = TestRoot::seeded(YOUR_ROOT);
    swoosh::config::write_signet(&swoosh::testkit::lock(), home, root.node_id()).unwrap();
    let until = SystemTime::now() + Duration::from_secs(3600);
    let badge = root
        .device_badge(TestNode::seeded(DESK).node_id(), until)
        .unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), home, &badge).unwrap();
    let members = vec![
        root.member(TestNode::seeded(DESK).verify_key(), "desk".parse().unwrap())
            .unwrap(),
        root.member(key.verify_key().unwrap(), "nas".parse().unwrap())
            .unwrap(),
    ];
    let update = root.sign_update(&RosterDoc::new(Epoch(1), members).unwrap());
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(home).await.unwrap(),
        home,
        &update,
    )
    .await
    .unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(home.synced(), format!("{now}\n")).unwrap();
}

/// What one `swoosh ping -c 1 <peer>` did: how long it ran, and what it said about roots.
struct Pinged {
    took: Duration,
    told: String,
}

/// Run `swoosh ping -c 1 <peer>` as the composition root runs it, from `home`, with nobody at a terminal.
async fn ping(home: &Home, peer: &str) -> Pinged {
    let Some(command) = Cli::try_parse_from(["swoosh", "ping", "-c", "1", peer])
        .unwrap()
        .command
    else {
        panic!("ping parses");
    };
    let Verb::Outward(outward @ Outward::Ping(_)) = command.split() else {
        panic!("ping is a reaching verb");
    };
    let contacts = ContactsStore::open(home).await.unwrap().contacts().clone();
    let machine = swoosh::reaching::Reaching::dialed(&outward)
        .unwrap()
        .machine(&contacts)
        .unwrap();
    let bound = swoosh::transport::Bound {
        transport: swoosh::transport::Transport::Iroh,
        local: false,
        reach: swoosh::transport::Reach::default(),
    };
    let ctx = swoosh::reaching::ReachCtx {
        contacts: &contacts,
        machine: Some(&machine),
        bound: &bound,
        present: None,
        membership: None,
        home,
        admitted: swoosh::learn::Admitted::unheard(),
    };
    let node = Node::new(MemTransport::bind(), NoDiscovery);
    let mut told = Vec::new();
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        run_verb(
            outward,
            &node,
            ctx,
            &Answering::with(Answer::Same),
            Asking::NoTerminal,
            &mut Counting::refusing(),
            &mut told,
        ),
    )
    .await
    .expect("the verb ends");
    let took = started.elapsed();
    node.close().await;
    result.expect("the machine answers the ping");
    Pinged {
        took,
        told: String::from_utf8(told).unwrap(),
    }
}

/// Drive `body` on a thread with room to spare, on one local set: a verb's future on an unoptimized build
/// outgrows a test thread's default stack, and the machine's routes run as local tasks.
fn on_a_big_stack<F: core::future::Future<Output = ()> + 'static>(body: fn() -> F) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            tokio::task::LocalSet::new().block_on(&runtime, body());
        })
        .unwrap()
        .join()
        .unwrap();
}

/// A dial of a person's saved machine asks it once which root vouches for it, and, with nobody to ask, says
/// on stderr how to save that root.
#[test]
fn a_dial_of_a_saved_machine_asks_its_root_once() {
    on_a_big_stack(|| async {
        let cancel = CancellationToken::new();
        let (key, asked) = machine(Answers::Standing, cancel.clone());
        let home = desk("asks");
        alice_laptop(&home, key).await;
        let pinged = ping(&home, "alice/laptop").await;
        assert_eq!(asked.load(Ordering::SeqCst), 1, "one question");
        let root = TestRoot::seeded(ALICE_ROOT).node_id();
        assert_eq!(
            pinged.told,
            format!(
                "alice/laptop is vouched for by a root not saved here.\nTo share with all of alice's \
                 machines, save it as alice's root:\n  swoosh contact add alice root:{root}\n"
            )
        );
        // Said once: the same root from the same machine is not said again.
        let again = ping(&home, "alice/laptop").await;
        assert_eq!(asked.load(Ordering::SeqCst), 2, "asked on every dial");
        assert_eq!(again.told, "", "said once per new root");
        cancel.cancel();
    });
}

/// One of your own devices, and a key no name here holds, are never asked: the root route sees no stream.
#[test]
fn no_root_lookup_for_me_or_an_unsaved_key() {
    on_a_big_stack(|| async {
        let cancel = CancellationToken::new();
        let (key, asked) = machine(Answers::Standing, cancel.clone());

        let yours = desk("me");
        your_nas(&yours, key).await;
        let pinged = ping(&yours, "me/nas").await;
        assert_eq!(pinged.told, "");

        let bare = desk("bare");
        let pinged = ping(&bare, &key.to_string()).await;
        assert_eq!(pinged.told, "");

        assert_eq!(asked.load(Ordering::SeqCst), 0, "no root question");
        cancel.cancel();
    });
}

/// A machine that admits the question and never answers holds the run no longer than the question's own
/// deadline from when it was asked, and nothing is said.
#[test]
fn a_slow_root_lookup_never_holds_the_verb() {
    on_a_big_stack(|| async {
        let cancel = CancellationToken::new();
        let (key, asked) = machine(Answers::Never, cancel.clone());
        let home = desk("slow");
        alice_laptop(&home, key).await;
        let pinged = ping(&home, "alice/laptop").await;
        assert_eq!(asked.load(Ordering::SeqCst), 1, "it was asked");
        // The question's deadline is 2 s from its start, well under the asked machine's own 5 s: the run,
        // a one-probe ping, ends inside 3 s.
        assert!(
            pinged.took < Duration::from_secs(3),
            "the run ends within 2 s of the question: {:?}",
            pinged.took
        );
        assert_eq!(pinged.told, "", "dropped silently");
        cancel.cancel();
    });
}

/// The verb a command line splits to, when it reaches outward.
fn outward(argv: &[&str]) -> Outward {
    let Some(command) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("{argv:?} parses");
    };
    match command.split() {
        Verb::Outward(outward) => outward,
        _ => panic!("{argv:?} reaches outward"),
    }
}

/// The ssh bridge (`forward <key> ssh -`, ssh's ProxyCommand) never asks about roots: ssh owns its stderr
/// and ends it with the session, so nothing could be told. `proxy` neither; `ping`, `speed`, `status
/// <machine>` and `send` do.
#[test]
fn the_ssh_bridge_asks_no_root() {
    let key = TestNode::seeded(DESK).node_id().to_string();
    assert!(!outward(&["swoosh", "forward", &key, "ssh", "-"]).teaches_root());
    assert!(!outward(&["swoosh", "proxy", &key, "https://example.com"]).teaches_root());
    for argv in [
        vec!["swoosh", "ping", key.as_str()],
        vec!["swoosh", "speed", key.as_str()],
        vec!["swoosh", "status", key.as_str()],
        vec!["swoosh", "send", "/etc/hosts", key.as_str()],
    ] {
        assert!(outward(&argv).teaches_root(), "{argv:?}");
    }
}

/// `swoosh ssh` is a launcher that execs ssh, so it has no after in which to ask, and never does: it never
/// reaches the verbs that ask, and its bridge asks nothing.
#[test]
fn ssh_never_asks_to_learn_a_root() {
    let Some(command) = Cli::try_parse_from(["swoosh", "ssh", "alice/laptop"])
        .unwrap()
        .command
    else {
        panic!("ssh parses");
    };
    assert!(matches!(command.split(), Verb::Ssh(_)), "a launcher");
    let key = TestNode::seeded(DESK).node_id().to_string();
    assert!(!outward(&["swoosh", "forward", &key, "ssh", "-"]).teaches_root());
}

/// The root route is `lookup.root`: every `serve`'s catalog names it, and it is dotted, so no typed service
/// name is it; `lookup` and `control` are reserved names, so no person or machine is one.
#[tokio::test]
async fn the_root_route_is_lookup_root() {
    assert_eq!(swoosh::serve::LOOKUP_ROOT_SERVICE, "lookup.root");
    let home = desk("route-name");
    let (gate, _cut) = swoosh::gate::anchored(
        &home,
        TestNode::seeded(DESK).node_id(),
        swoosh::serve::BoundTargets::default(),
    )
    .await
    .unwrap();
    let (router, _devices) = swoosh::serve::bind_lookup(Router::new(gate), &home)
        .await
        .unwrap();
    assert!(
        router
            .catalog(None)
            .entries()
            .any(|entry| entry.name == swoosh::serve::LOOKUP_ROOT_SERVICE),
        "the catalog names the route"
    );
    let root = format!("root:{}", TestRoot::seeded(ALICE_ROOT).node_id());
    let machine = TestNode::seeded(DESK).node_id().to_string();
    for argv in [
        vec!["swoosh", "serve", "lookup.root=tcp:localhost:1"],
        vec!["swoosh", "serve", "--public", "lookup.root"],
        vec!["swoosh", "share", "lookup.root", "anyone"],
        vec!["swoosh", "contact", "add", "lookup", root.as_str()],
        vec!["swoosh", "contact", "add", "control", root.as_str()],
        vec!["swoosh", "contact", "add", "bob/lookup", machine.as_str()],
    ] {
        let error = Cli::try_parse_from(&argv).expect_err("never typed");
        assert_eq!(error.exit_code(), 2, "{argv:?} is a usage error");
    }
    let _ = std::fs::remove_dir_all(home.dir());
}
