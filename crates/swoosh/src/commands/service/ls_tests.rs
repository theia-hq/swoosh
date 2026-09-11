//! S4 tests: the bare `service ls` read renders the live menu table with disabled markers and
//! teaches when no resident is addressable under the home.

use core::sync::atomic::{AtomicU32, Ordering};
use std::path::{Path, PathBuf};

use clap::Parser as _;
use tightbeam::tunnel::ServiceCatalog;

use super::{ServiceLsCmd, render_catalog};
use crate::commands::serve::control_codec::DisabledList;
use crate::home::Home;

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

/// An explicit unknown disabled list must never render a false `on`: every state is `?` and one
/// warning line names the reason (the gate may still refuse what the read could not list).
#[test]
fn an_unknown_disabled_list_renders_fail_closed() {
    let menu = catalog(&[("ping", 0)]);
    let table = render_catalog(
        &menu,
        Some(&DisabledList::Unknown(
            "the file could not be read".to_owned(),
        )),
    );

    assert!(
        row(&table, "ping").contains('?'),
        "the state is honestly unknown: {table}"
    );
    assert!(
        table.contains("could not be read"),
        "the warning names the reason: {table}"
    );
    assert!(
        !table.contains(" on\n") && !table.contains(" off\n"),
        "neither on nor off may be claimed: {table}"
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
