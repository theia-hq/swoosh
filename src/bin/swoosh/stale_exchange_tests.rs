// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The stale-list exchange, through the path a dialing verb takes in the composition root: a real verb,
//! clap-parsed, run on a bound node with the exchange's dial seamed.

use core::time::Duration;
use std::time::SystemTime;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use clap::Parser as _;
use keystore::{KeyFile, Protection};
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;
use swoosh::roster::{Epoch, RosterDoc};
use swoosh::sync::Answer;
use swoosh::testkit::{Answering, STANDING_UNTIL, TestNode, TestRoot};

use crate::{Cli, Outward, Verb, run_verb};

/// The root both devices belong to.
const ROOT: u8 = 0x51;
/// This machine.
const DESK: u8 = 0x52;
/// The device the verb dials.
const NAS: u8 = 0x53;

/// A device of `ROOT` holding an update that lists `NAS` as `me/nas`, its last exchange `hours` ago.
async fn device(tag: &str, hours: u64) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-stale-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut seed = TestNode::seeded(DESK).seed();
    KeyFile::device(home.identity_key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .unwrap();
    let root = TestRoot::seeded(ROOT);
    swoosh::config::write_signet(&home, root.node_id())
        .await
        .unwrap();
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root
        .device_badge(TestNode::seeded(DESK).node_id(), until)
        .unwrap();
    swoosh::config::write_badge(&home, &badge).await.unwrap();
    let members = [(DESK, "desk"), (NAS, "nas")]
        .into_iter()
        .map(|(seed, label)| {
            root.member(TestNode::seeded(seed).verify_key(), label.parse().unwrap())
                .unwrap()
        })
        .collect();
    let update = root.sign_update(&RosterDoc::new(Epoch(1), members).unwrap());
    swoosh::roster::fold(&home, &update).await.unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(home.roster_synced(), format!("{}\n", now - hours * 3600)).unwrap();
    home
}

/// Run `swoosh ping me/nas` as the composition root runs it, from `home`, with the exchange dialed
/// through `dial`. Nothing answers at me/nas, so the verb itself fails.
async fn ping_nas(home: &Home, dial: &Answering) -> eyre::Result<()> {
    let Some(command) = Cli::try_parse_from(["swoosh", "ping", "me/nas"])
        .unwrap()
        .command
    else {
        panic!("ping parses");
    };
    let Verb::Outward(outward @ Outward::Ping(_)) = command.split() else {
        panic!("ping is a reaching verb");
    };
    let contacts = ContactsStore::open(home.contacts())
        .await
        .unwrap()
        .contacts()
        .clone();
    let bound = swoosh::transport::Bound {
        transport: swoosh::transport::Transport::Iroh,
        local: false,
        reach: swoosh::transport::Reach::default(),
    };
    let ctx = swoosh::reaching::ReachCtx {
        contacts: &contacts,
        bound: &bound,
        present: None,
        membership: None,
        home,
    };
    let node = Node::new(MemTransport::bind(), NoDiscovery);
    let result = tokio::time::timeout(Duration::from_secs(30), run_verb(outward, &node, ctx, dial))
        .await
        .expect("the verb ends");
    node.close().await;
    result
}

/// On its own thread with room to spare: a verb's future on an unoptimized build outgrows a test
/// thread's default stack.
#[test]
fn a_dialing_verb_pulls_when_stale() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(stale_then_fresh());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn stale_then_fresh() {
    let stale = device("stale", 2).await;
    let dial = Answering::with(Answer::Same);
    let result = ping_nas(&stale, &dial).await;
    assert!(result.is_err(), "nothing answers the ping itself");
    assert_eq!(
        dial.calls(),
        1,
        "one exchange on a dial past an hour, whatever the verb's outcome"
    );

    let fresh = device("fresh", 0).await;
    let dial = Answering::with(Answer::Same);
    let _ = ping_nas(&fresh, &dial).await;
    assert_eq!(dial.calls(), 0, "none on a fresh one");
}
