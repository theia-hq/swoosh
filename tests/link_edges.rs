// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A link carries `swoosh:` only where a person reads it: the real binary prints it on an issued link,
//! and the files it writes hold the bare form.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use swoosh::home::Home;

/// A scratch directory for this test, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("swoosh-link-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn home(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the binary on `home` with `args`, and return its stdout, failing on a refusal.
fn swoosh(home: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    assert!(
        output.status.success(),
        "`swoosh {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// `grant issue` prints the link a person hands on: `swoosh:`, then the key, a dot, and the token.
#[test]
fn share_prints_the_swoosh_prefix() {
    let scratch = Scratch::new("share");
    let home = scratch.home("owner");
    let printed = swoosh(&home, &["grant", "issue", "ping"]);
    let printed = printed.trim();
    let link = swoosh::link::parse(printed).expect("the printed link parses");
    assert_eq!(
        printed,
        format!("swoosh:{}", link.as_str()),
        "the issued link prints `swoosh:` then nauthy's text"
    );
    assert!(
        printed.starts_with(&format!("swoosh:{}.", link.root())),
        "`swoosh:<key>.<token>`, the key an `ed01` key: {printed}"
    );
    assert!(printed.starts_with("swoosh:ed01"), "{printed}");
}

/// The files a verb writes hold links bare: the badge `adopt` stores and the ledger `invite add` and
/// `grant issue` append carry no `swoosh:`.
#[test]
fn a_stored_link_carries_no_prefix() {
    let scratch = Scratch::new("stored");
    let owner = scratch.home("owner");
    let device = scratch.home("device");
    let created = swoosh(&owner, &["invite", "add", "laptop"]);
    let invite = created
        .split_whitespace()
        .find(|word| word.starts_with("invite:"))
        .expect("invite add prints an invite");
    swoosh(&device, &["adopt", invite]);
    swoosh(&owner, &["grant", "issue", "ping"]);

    let badge = std::fs::read_to_string(Home::resolve(Some(device)).unwrap().badge())
        .expect("adopt stores the badge");
    let ledger = std::fs::read_to_string(Home::resolve(Some(owner)).unwrap().links())
        .expect("the ledger is written");
    for (file, text) in [("badge", &badge), ("ledger", &ledger)] {
        assert!(!text.is_empty(), "{file} holds something");
        assert!(
            !text.contains("swoosh:"),
            "{file} holds a prefixed link: {text}"
        );
    }
    badge
        .trim()
        .parse::<nauthy::Link>()
        .expect("the stored badge is nauthy's bare link");
}

/// A fresh home's first key is `<home>/key` and its first link row is in `<home>/links`; no file under an
/// older name is written.
#[test]
fn a_fresh_home_writes_key_and_links() {
    let scratch = Scratch::new("fresh");
    let home = scratch.home("owner");
    swoosh(&home, &["grant", "issue", "ping"]);

    assert!(home.join("key").is_file(), "the key is <home>/key");
    let rows = std::fs::read_to_string(home.join("links")).expect("the row is in <home>/links");
    assert_eq!(rows.lines().count(), 1, "one link, one row: {rows}");
    for old in ["identity.key", "grants"] {
        assert!(!home.join(old).exists(), "nothing is written at {old}");
    }
}
