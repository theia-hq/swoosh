// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The device-list exchanges on the stream source: by own bind, over the run's sessions, presenting this
//! home's standing as it reads at each open; through a running `serve`, one Open per exchange.

use core::time::Duration;
use std::rc::Rc;

use bifrost::{NoDiscovery, Node, NodeId};
use clap::Parser as _;
use keystore::{KeyFile, Protection};
use swoosh::credential::Credential;
use swoosh::home::Home;
use swoosh::node_client::UidSocket;
use swoosh::peers::Peers;
use swoosh::serve::control_codec::OpenRefusal;
use swoosh::streams::{OwnBind, Resident, StreamSource};
use swoosh::sync::{Dial as _, SourceDial};
use swoosh::testkit::{Script, ScriptedPeer, TestNode, TestRoot};

use crate::commands::invite::invite_tests::{
    NAS, OWN, PASS, PHONE, ROOT, Row, copy, device_of, lapsed, live, node, records, root_key_at,
    scratch,
};
use crate::commands::through_serve::tests::{Answer, Heard, ROW_BOUND, Rig, Served, scripted};
use crate::{Cli, Outward, Verb};

/// What every exchange presents: this home's standing, never a slip.
const FAMILY: Credential = Credential::Family { present: None };

/// A pick-up that finds no renewal anywhere.
struct NoRenewal;

impl swoosh::renewal::Fetch for NoRenewal {
    async fn fetch(
        &self,
        _peer: NodeId,
    ) -> Result<Option<nauthy::Link>, swoosh::renewal::FetchError> {
        Ok(None)
    }
}

/// Make `home` a device of `ROOT` holding the list of [`siblings`] whose own standing ended five days
/// ago.
async fn a_lapsed_device(home: &Home) {
    a_device(home, false).await;
    device_of(home, &lapsed(OWN, "desk")).await;
}

/// `sync`'s body over `dial` and `source`, with no renewal anywhere: what it printed.
async fn synced(home: &Home, dial: &impl swoosh::sync::Dial, source: &impl StreamSource) -> String {
    let Outward::Sync(cmd) = outward(&["sync"]) else {
        unreachable!("sync parses as sync")
    };
    let mut out = Vec::new();
    cmd.exchange(home, dial, &NoRenewal, source, &mut out)
        .await
        .unwrap();
    String::from_utf8(out).unwrap()
}

/// The line `sync` prints when its pick-up found no renewal.
const MISSED: &str = "none of your devices had a renewal for this machine.";

/// A badge past its date is refused before it is sent, by own bind, and by the resident through
/// `serve`: on both paths the exchange reads it as not admitted, so `sync` reaches its pick-up and
/// prints its line.
#[tokio::test]
async fn a_dead_standing_still_reaches_the_pick_up() {
    // By own bind: no stream to `control.sync` carries the dead badge.
    let home = bare("dead-own");
    a_lapsed_device(&home).await;
    let wire = ScriptedPeer::new(node(NAS), [Script::Lists(Vec::new())]);
    let node_here = Node::new(wire.clone(), NoDiscovery);
    let peers = Peers::new(&node_here);
    let own = OwnBind::new(&peers, &home, node(OWN), &FAMILY);
    let dial = SourceDial::new(&own, &home);
    assert!(matches!(
        dial.exchange(node(NAS)).await,
        Err(swoosh::sync::ExchangeError::NotAdmitted)
    ));
    let printed = synced(&home, &dial, &own).await;
    assert!(printed.starts_with(MISSED), "{printed}");
    assert_eq!(wire.dials(), 0, "the dead badge reached no session");
    let _ = std::fs::remove_dir_all(home.dir());

    // Through `serve`: the resident's own refusal of the ended standing.
    let mut served = Served::new("dead-serve").await;
    a_lapsed_device(&served.home).await;
    let rig = Rig::default();
    let refused = (0..2)
        .map(|_| Answer::Refuse(OpenRefusal::StandingEnded))
        .collect();
    let resident = scripted(&mut served, refused, &rig);
    let source = Resident::new(Rc::new(UidSocket::resolve(&served.home).unwrap()));
    let printed = synced(
        &served.home,
        &SourceDial::new(&source, &served.home),
        &source,
    )
    .await;
    assert!(printed.starts_with(MISSED), "{printed}");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(heard.len(), 2, "one Open per device, each refused");
    all_exchanges(&heard);
}

/// By own bind, the exchange presents the badge the home stores, read at the open: after a join, after a
/// join that switched roots, and after a restore. A damaged home presents nothing.
#[tokio::test]
async fn an_own_bind_exchange_presents_the_badge_it_stored() {
    let presented = async |home: &Home| {
        let wire = ScriptedPeer::new(node(NAS), [Script::Lists(Vec::new())]);
        let node_here = Node::new(wire.clone(), NoDiscovery);
        let peers = Peers::new(&node_here);
        let own = OwnBind::new(&peers, home, node(OWN), &FAMILY);
        // The scripted peer speaks no exchange, so the body fails once the stream is admitted.
        let _ = SourceDial::new(&own, home).exchange(node(NAS)).await;
        let requests = wire.requests();
        assert_eq!(requests.len(), 1, "one stream");
        assert_eq!(requests[0].service, swoosh::serve::SYNC_SERVICE);
        requests[0].capability.clone()
    };

    // After a join: the pin and the standing it stored.
    let joined = scratch("stored-join");
    let desk = live(OWN, "desk");
    device_of(&joined, &desk).await;
    assert_eq!(
        presented(&joined).await.as_deref(),
        Some(desk.standing.as_str())
    );

    // After a join that moved this machine to another root: the new root's standing.
    let other = TestRoot::seeded(ROOT.wrapping_add(1));
    let moved = other
        .device_badge(
            node(OWN),
            std::time::SystemTime::now() + Duration::from_secs(80 * 24 * 60 * 60),
        )
        .unwrap();
    swoosh::config::write_signet(&swoosh::testkit::lock(), &joined, other.node_id()).unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &joined, &moved).unwrap();
    assert_eq!(presented(&joined).await.as_deref(), Some(moved.as_str()));

    // After a restore, as `root restore` writes the home: the root kept here, beside the standing.
    let restored = bare("stored-restore");
    let _ = restoring(&restored, &mut Asked::default()).await;
    let stored = swoosh::config::load_badge(&restored).await.unwrap();
    assert!(stored.is_some(), "the restore stored a standing");
    assert_eq!(
        presented(&restored).await.as_deref(),
        stored.as_ref().map(nauthy::Link::as_str)
    );

    // A damaged home, pinned at its own key: nothing.
    swoosh::config::write_signet(&swoosh::testkit::lock(), &joined, node(OWN)).unwrap();
    assert_eq!(presented(&joined).await, None);

    let _ = std::fs::remove_dir_all(restored.dir().with_extension("copy"));
    for home in [joined, restored] {
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A prompt that answers every passphrase and counts each by the key it opens.
#[derive(Default)]
struct Asked {
    root: usize,
    machine: usize,
}

impl swoosh::passphrase::Prompt for Asked {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(
        &mut self,
        asked: swoosh::passphrase::Asked<'_>,
    ) -> eyre::Result<keystore::Passphrase> {
        match asked {
            swoosh::passphrase::Asked::MachineKey => self.machine += 1,
            swoosh::passphrase::Asked::Root | swoosh::passphrase::Asked::Copy(_) => self.root += 1,
        }
        Ok(keystore::Passphrase::try_from(zeroize::Zeroizing::new(PASS.to_owned())).unwrap())
    }

    fn choose(
        &mut self,
        _asked: swoosh::passphrase::Asked<'_>,
    ) -> eyre::Result<swoosh::passphrase::Choice> {
        eyre::bail!("no passphrase is chosen here")
    }

    fn say(&mut self, _line: &str) {}
}

/// This machine's key, `OWN`, sealed under [`PASS`], so a read that opened it would ask. Sealed once
/// per process: the seal is slow by design.
fn sealed_machine_key(home: &Home) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    static SEALED: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bytes = SEALED.get_or_init(|| {
        let scratch = bare("sealed-machine-key");
        swoosh::identity::make_machine_dir(&scratch).unwrap();
        let passphrase =
            keystore::Passphrase::try_from(zeroize::Zeroizing::new(PASS.to_owned())).unwrap();
        let mut seed = TestNode::seeded(OWN).seed();
        KeyFile::new(scratch.key())
            .write(
                &keystore::Secret::take(&mut seed),
                Protection::Passphrase(&passphrase),
            )
            .unwrap();
        let bytes = std::fs::read(scratch.key()).unwrap();
        let _ = std::fs::remove_dir_all(scratch.dir());
        bytes
    });
    swoosh::identity::make_machine_dir(home).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(home.key())
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// An empty home, holding nothing yet.
fn bare(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-exchange-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    Home::resolve(Some(dir)).unwrap()
}

/// The devices this machine's root lists beside it, `me/nas` and `me/phone`.
fn siblings() -> Vec<Row> {
    vec![live(OWN, "desk"), live(NAS, "nas"), live(PHONE, "phone")]
}

/// Make `home` `OWN`, its key sealed, a device of `ROOT` holding the list of [`siblings`], folded so
/// `me` names them; with the root kept here when `root` says so.
async fn a_device(home: &Home, root: bool) {
    a_device_of(home, root, &siblings()).await;
}

/// [`a_device`], holding the list of `rows`, this machine's own first.
async fn a_device_of(home: &Home, root: bool, rows: &[Row]) {
    sealed_machine_key(home);
    device_of(home, &rows[0]).await;
    if root {
        root_key_at(&home.root_key());
    }
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(home).await.unwrap(),
        home,
        &TestRoot::seeded(ROOT).sign_update(&records(1, rows, Vec::new())),
    )
    .await
    .unwrap();
}

/// `argv` as the composition root splits it.
fn verb(argv: &[&str]) -> Verb {
    Cli::try_parse_from(core::iter::once("swoosh").chain(argv.iter().copied()))
        .unwrap()
        .command
        .unwrap()
        .split()
}

/// `argv`, a reaching verb, as the composition root dispatches it.
fn outward(argv: &[&str]) -> Outward {
    match verb(argv) {
        Verb::Outward(outward) => outward,
        _ => panic!("{argv:?} is no reaching verb"),
    }
}

/// `root restore` of a copy of `ROOT` listing [`siblings`] onto `home`, a machine that is none of its
/// devices yet, its local part run first: the exchange that brings the restored root up to date.
async fn restoring(home: &Home, asked: &mut Asked) -> Outward {
    sealed_machine_key(home);
    let dir = home.dir().with_extension("copy");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, &records(1, &siblings()[1..], Vec::new()));
    let Verb::RootRestore(cmd) = verb(&["root", "restore", dir.to_str().unwrap()]) else {
        panic!("root restore parses");
    };
    let restored = cmd.restore(home, asked).await.unwrap();
    Outward::RootRestore(Box::new(restored))
}

/// Every Open heard is one exchange: `control.sync`, on Main, with no slip.
fn all_exchanges(heard: &[Heard]) {
    for open in heard {
        assert_eq!(open.service, swoosh::serve::SYNC_SERVICE);
        assert_eq!(open.lane, swoosh::serve::control_codec::OpenLane::Main);
        assert_eq!(open.slip, None, "an exchange carries no slip");
    }
}
