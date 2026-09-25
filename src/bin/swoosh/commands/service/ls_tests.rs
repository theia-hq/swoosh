//! S4 tests: the bare `service ls` read renders the live menu table with disabled markers and
//! teaches when no resident is addressable under the home.

use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser as _;
use swoosh::home::Home;
use swoosh::serve::control_codec::DisabledList;
use tightbeam::tunnel::{MAX_CATALOG_BLOB, ServiceCatalog};
use tokio::io;

use super::{ServiceLsCmd, disabled_warning, read_catalog, render_catalog};

/// Serializes scratch names within this test process; the pid keeps two concurrent runs apart.
static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A unique 0700 scratch base under the temp dir.
fn scratch(tag: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sw4-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("0700 scratch");
    dir
}

/// A node home under `base`, created so `Home::resolve` sees a directory.
fn home_in(base: &Path) -> Home {
    let dir = base.join("home");
    std::fs::create_dir_all(&dir).expect("scratch home");
    Home::resolve(Some(dir)).expect("the scratch home resolves")
}

/// A catalog built from `(name, posture tag)` pairs: the test encodes the production wire form
/// (0 gated, 1 open) and decodes it through [`ServiceCatalog`], so only service content is local.
fn catalog(entries: &[(&str, u8)]) -> ServiceCatalog {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (name, posture) in entries {
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(*posture);
    }
    ServiceCatalog::decode(&bytes).expect("the test catalog decodes")
}

/// The table row whose first cell is `name`, so an assertion binds to one service, never the whole
/// table (a marker word could appear elsewhere in it).
fn row(table: &str, name: &str) -> String {
    table
        .lines()
        .find(|line| line.starts_with(name))
        .unwrap_or_else(|| panic!("no {name} row in the table: {table}"))
        .to_owned()
}

/// The bare read renders the live table: a `STATE` column marking the live disabled list, with the
/// listed service `off` and every other service `on`.
#[test]
fn bare_ls_prints_the_live_table() {
    let menu = catalog(&[("ping", 0), ("speed", 0), ("logs", 1)]);
    let table = render_catalog(&menu, Some(&DisabledList::Known(vec!["speed".to_owned()])));

    assert!(
        table.contains("SERVICE") && table.contains("GATE") && table.contains("STATE"),
        "the self read carries the live-state column: {table}"
    );
    assert!(row(&table, "ping").contains("on"), "{table}");
    assert!(
        row(&table, "speed").contains("off"),
        "a listed name is marked off: {table}"
    );
    assert!(
        row(&table, "logs").contains("open") && row(&table, "logs").contains("on"),
        "an unlisted open service stays on: {table}"
    );
}

/// An explicit unknown disabled list must never render a false `on`: every state is `?` on stdout,
/// and the reason is a separate stderr diagnostic (never a table row), so the clean result and its
/// warning cannot be confused.
#[test]
fn an_unknown_disabled_list_renders_fail_closed() {
    let menu = catalog(&[("ping", 0)]);
    let disabled = DisabledList::Unknown("the file could not be read".to_owned());
    let table = render_catalog(&menu, Some(&disabled));

    assert!(
        row(&table, "ping").contains('?'),
        "the state is honestly unknown: {table}"
    );
    assert!(
        !table.contains("could not be read"),
        "the warning rides stderr, never the stdout table: {table}"
    );
    assert!(
        !table.contains(" on\n") && !table.contains(" off\n"),
        "neither on nor off may be claimed: {table}"
    );
    assert_eq!(
        disabled_warning(&disabled).as_deref(),
        Some(
            "warning: the disabled list could not be read (the file could not be read); states unknown\n"
        ),
        "the warning names the reason on the diagnostic stream"
    );
    assert_eq!(
        disabled_warning(&DisabledList::Known(vec!["ping".to_owned()])),
        None,
        "a known list has nothing to warn about"
    );
}

/// The remote `--at` read has no live disabled list and keeps the two-column `SERVICE  GATE` table.
#[test]
fn the_remote_read_keeps_the_two_column_table() {
    let menu = catalog(&[("ping", 0), ("logs", 1)]);
    let table = render_catalog(&menu, None);

    assert!(
        !table.contains("STATE"),
        "a peer's disabled list is its own business: {table}"
    );
    assert!(row(&table, "ping").contains("gated"), "{table}");
    assert!(row(&table, "logs").contains("open"), "{table}");
}

/// A bare `service ls` with no addressable resident is the same teaching error as bare `stop`,
/// non-zero at the root: never a silent empty table that reads as "this node serves nothing".
#[tokio::test]
async fn bare_ls_without_resident_is_teaching() {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        ls: ServiceLsCmd,
    }

    let base = scratch("teach");
    let home = home_in(&base);
    let ls = Wrap::try_parse_from(["x"])
        .expect("bare service ls parses")
        .ls;

    let error = ls
        .run_local(&home)
        .await
        .expect_err("no resident must refuse, never an empty table");
    let message = format!("{error:#}");
    assert!(
        message.contains("start one with `swoosh serve --resident`"),
        "the error names the fix: {message}"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A bare `service ls` reaches no peer, so the reach trio (`--transport`/`--local`/`--peer`) has nothing
/// to bind or find: each is refused by name, never silently ignored (I.3, B4).
#[tokio::test]
async fn bare_ls_rejects_the_reach_flags() {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        ls: ServiceLsCmd,
    }

    let base = scratch("reach");
    let home = home_in(&base);
    let hint = format!(
        "{}=127.0.0.1:9000",
        bifrost::NodeId::from_ed25519_secret(&[5u8; 32])
    );
    let cases: [(&[&str], &str); 3] = [
        (&["x", "--transport", "quirk"], "--transport"),
        (&["x", "--local"], "--local"),
        (&["x", "--peer", &hint], "--peer"),
    ];
    for (argv, flag) in cases {
        let ls = Wrap::try_parse_from(argv)
            .expect("the reach flag parses")
            .ls;
        let error = ls
            .run_local(&home)
            .await
            .expect_err("no peer, no effect: the flag must refuse, never be ignored");
        assert_eq!(
            format!("{error:#}"),
            format!("{flag} only applies when reaching a peer; drop it or name one")
        );
    }

    let _ = std::fs::remove_dir_all(&base);
}

/// A bare `service ls` reaches no peer, so `--present` has nothing to select: it is refused with the
/// exact teaching line, never silently dropped (I.3, MAJOR-1).
#[tokio::test]
async fn bare_ls_rejects_present() {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        ls: ServiceLsCmd,
    }

    let base = scratch("present");
    let home = home_in(&base);
    let link = swoosh::link::Link::from(
        swoosh::testkit::TestRoot::seeded(0xb0)
            .device_badge(
                swoosh::testkit::TestNode::seeded(0xb1).node_id(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
            )
            .expect("mint a stand-in slip"),
    )
    .to_string();
    let ls = Wrap::try_parse_from(["x", "--present", &link])
        .expect("bare service ls --present parses")
        .ls;

    let error = ls
        .run_local(&home)
        .await
        .expect_err("--present without --at must refuse, never be ignored");
    assert_eq!(
        format!("{error:#}"),
        "--present only applies when reaching a peer; drop it or name one"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// How many times the wire's own cap the flooding fixture offers. Comfortably past the cap so a bounded
/// read is visibly bounded, and finite so that REMOVING the cap fails the assertions below instead of
/// hanging the suite on an endless peer, which reports nothing.
const FLOOD_MULTIPLE: u64 = 4;

/// The byte the flood is made of: any non-zero value, so a capless read decodes as a wildly over-count
/// catalog rather than as the empty one a zero count would spell.
const FLOOD_BYTE: u8 = 0xAA;

/// A hostile peer on the serving end of `control.services`: it answers the read with `remaining` bytes of
/// noise and counts what it actually handed over.
///
/// What the counter proves and does not prove. It CANNOT see allocations: this workspace denies `unsafe`,
/// so a test cannot install an allocator probe and assert a `Vec`'s capacity from outside. What it can see
/// is how many bytes the peer got to deliver, and `read_to_end` cannot buffer bytes it was never given, so
/// a delivery bounded at the cap is a buffer bounded at the cap. That is the property the guard exists for,
/// measured at the only seam a safe test can observe it from.
struct FloodingPeer {
    /// Bytes still on offer; the fixture reports EOF once it reaches zero.
    remaining: u64,
    /// Bytes actually handed to the reader, shared so the test can read it after the refusal.
    delivered: Arc<AtomicU64>,
}

impl io::AsyncRead for FloodingPeer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let want = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.remaining());
        // Filling nothing is how this fixture spells EOF: the peer has streamed all it offered.
        if want > 0 {
            buf.initialize_unfilled_to(want).fill(FLOOD_BYTE);
            buf.advance(want);
            self.remaining -= want as u64;
            self.delivered.fetch_add(want as u64, Ordering::Relaxed);
        }
        Poll::Ready(Ok(()))
    }
}

/// An honest peer's menu still reads: the bound admits everything a real catalog is, so the guard costs
/// the normal path nothing (zero, one, many).
#[tokio::test]
async fn a_peer_under_the_cap_reads_its_menu() {
    let dial = bifrost::NodeId::from_ed25519_secret(&[4u8; 32]);
    for entries in [&[][..], &[("ping", 0)][..], &[("ping", 0), ("logs", 1)][..]] {
        let menu = catalog(entries);
        let blob = menu.encode().expect("a real menu is under the wire bound");
        let read = read_catalog(&blob[..], dial)
            .await
            .expect("an honest peer's menu reads");
        assert_eq!(read, menu, "the menu survives the bounded read");
    }
}

/// `service ls --at <peer>` reads bytes a REMOTE node chooses, so the peer is the attacker here: without a
/// bound on the READ it can grow this client's buffer for as long as it cares to stream, and the decoder's
/// own caps cannot help because the buffer is already full by the time decode is called.
///
/// The fixture offers FLOOD_MULTIPLE times the wire's cap and the client must refuse, having accepted no
/// more than the cap plus the one byte that tells at-the-ceiling from over-it. See [`FloodingPeer`] for
/// what the byte counter does and does not prove.
#[tokio::test]
async fn a_flooding_peer_is_refused_before_it_fills_the_buffer() {
    let delivered = Arc::new(AtomicU64::new(0));
    let peer = FloodingPeer {
        remaining: MAX_CATALOG_BLOB * FLOOD_MULTIPLE,
        delivered: Arc::clone(&delivered),
    };
    let dial = bifrost::NodeId::from_ed25519_secret(&[9u8; 32]);

    let Err(error) = read_catalog(peer, dial).await else {
        panic!("a peer streaming past the cap must be refused, never buffered");
    };
    // The negative assertion FIRST, and on the TEXT rather than merely on the error: with the cap removed
    // this read still fails, in the DECODER, on a blob four times the size. A test that asked only for an
    // error would stay green with the guard gone and report the protection as covered.
    let message = format!("{error:#}");
    assert!(
        message.contains("sent more than a service menu can be"),
        "the refusal says the peer overran the read, not that its menu is malformed: {message}"
    );
    assert!(
        message.contains(&dial.to_string()),
        "the refusal names which peer did it: {message}"
    );
    assert!(
        delivered.load(Ordering::Relaxed) <= MAX_CATALOG_BLOB + 1,
        "the client took {} bytes of the {} the peer offered; the read is not bounded",
        delivered.load(Ordering::Relaxed),
        MAX_CATALOG_BLOB * FLOOD_MULTIPLE
    );
}
