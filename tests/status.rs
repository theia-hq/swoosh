// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Bare `swoosh status` through the real binary: it runs with nothing serving and nothing to dial, makes
//! no key on a home that has none, keeps its report on stdout and its notices on stderr, and never asks for
//! a passphrase, even where a sealed root is kept.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;

use bifrost::NodeId;
use swoosh::config;
use swoosh::home::Home;
use swoosh::root::{Minted, Root};
use swoosh::testkit::{Counting, STANDING_UNTIL, TestNode, TestRoot};

static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A scratch base whose `home` does not exist yet. Drop removes the base.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "swoosh-status-bin-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `swoosh --home <home> <args>` with no terminal: the child leaves the test's session, so a
/// passphrase prompt has nowhere to open and fails the run.
fn swoosh(home: &PathBuf, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null());
    // SAFETY: `setsid` is async-signal-safe and touches only the child's own session.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Make `home` with this machine's key in it, plain, as the first verb that needs a key leaves it.
fn keyed(home: &Path) -> NodeId {
    let home = Home::resolve(Some(home.to_path_buf())).unwrap();
    config::create_store_dir(home.dir()).unwrap();
    swoosh::identity::make_machine_dir(&home).unwrap();
    let mut seed = TestNode::seeded(0x11).seed();
    keystore::KeyFile::device(home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            keystore::Protection::Plain,
        )
        .unwrap();
    TestNode::seeded(0x11).node_id()
}

/// Bare `status` succeeds with no `serve` running and nobody to dial.
#[test]
fn status_never_dials_and_runs_with_no_node() {
    let scratch = Scratch::new("no-node");
    keyed(&scratch.home());
    let out = swoosh(&scratch.home(), &["status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("this machine: not one of your devices yet"),
        "{}",
        text(&out.stdout)
    );
}

/// On a home with no key, `status` prints `key: none yet` and makes no key: no `machine/` appears.
#[test]
fn status_on_a_home_with_no_key_makes_none() {
    let scratch = Scratch::new("no-key");
    let out = swoosh(&scratch.home(), &["status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout).lines().next(),
        Some("key: none yet"),
        "{}",
        text(&out.stdout)
    );
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert!(
        !scratch.home().join("machine").exists(),
        "status made no key"
    );
}

/// On a home with no key, `status --key` exits 1, names `join`, and makes no key.
#[test]
fn status_key_with_no_key_exits_1_and_names_join() {
    let scratch = Scratch::new("key-empty");
    let out = swoosh(&scratch.home(), &["status", "--key"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert_eq!(
        text(&out.stderr),
        "error: this machine has no key yet; to make one and print it: swoosh join\n"
    );
    assert!(
        !scratch.home().join("machine").exists(),
        "status made no key"
    );
}

/// stdout is the key and a newline, nothing else, and nothing goes to stderr.
#[test]
fn status_key_stdout_is_the_key_alone() {
    let scratch = Scratch::new("key-alone");
    let key = keyed(&scratch.home());
    let out = swoosh(&scratch.home(), &["status", "--key"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("{key}\n"));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
}

/// Line 1 is exactly `key: <key>`, line 2 `key lock: none` on a plain key, and line 3 `home: <dir>`.
#[test]
fn status_prints_key_lock_then_home() {
    let scratch = Scratch::new("line-one");
    let key = keyed(&scratch.home());
    let out = swoosh(&scratch.home(), &["status"]);
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some(format!("key: {key}").as_str()));
    assert_eq!(lines.next(), Some("key lock: none"));
    assert_eq!(
        lines.next(),
        Some(format!("home: {}", scratch.home().display()).as_str())
    );
}

/// The report is on stdout, whole, and stderr holds nothing when there is nothing to note.
#[test]
fn status_report_is_on_stdout_and_its_notices_on_stderr() {
    let scratch = Scratch::new("streams");
    keyed(&scratch.home());
    let out = swoosh(&scratch.home(), &["status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(stdout.starts_with("key: "), "{stdout}");
    assert!(
        stdout.contains("to join yours, paste its invite into: swoosh join"),
        "{stdout}"
    );
    assert!(stderr.is_empty(), "{stderr}");
}

/// Where a sealed root is kept, and on a device of a root kept elsewhere, `status` reads the root and asks for no
/// passphrase: the run has no terminal, so any prompt would have failed it.
#[test]
fn status_with_a_root_copy_never_prompts() {
    let keeps = Scratch::new("sealed-root");
    let home = Home::resolve(Some(keeps.home())).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut prompt = Counting::new(["a passphrase for the root"]);
    let minted = runtime.block_on(Root::mint(&home, &mut prompt));
    assert!(matches!(minted, Ok(Minted::Made(_))), "{minted:?}");
    drop(minted);
    let out = swoosh(&keeps.home(), &["status"]);
    assert!(
        out.status.success(),
        "status reads a sealed root without asking for it: {}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stdout).contains("on this machine, locked with a passphrase."),
        "{}",
        text(&out.stdout)
    );

    let moved = Scratch::new("root-elsewhere");
    let home = Home::resolve(Some(moved.home())).unwrap();
    config::create_store_dir(home.dir()).unwrap();
    let mut seed = TestNode::seeded(0x11).seed();
    swoosh::identity::make_machine_dir(&home).unwrap();
    keystore::KeyFile::device(home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            keystore::Protection::Plain,
        )
        .unwrap();
    let root = TestRoot::seeded(0x21);
    runtime.block_on(async {
        config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).unwrap();
        let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
        let standing = root
            .device_badge(TestNode::seeded(0x11).node_id(), until)
            .unwrap();
        config::write_badge(&swoosh::testkit::lock(), &home, &standing).unwrap();
    });
    let out = swoosh(&moved.home(), &["status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains(&format!("root:{} not on this machine.", root.node_id())),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(
        prompt.events(),
        1,
        "the one prompt is the mint's, before either status ran"
    );
}

/// A trust file group or other can write is refused before any verb reads it: exit 1, one line naming
/// the file and the fix, and its contents never printed.
#[test]
fn a_group_writable_trust_file_is_refused_at_load() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("loose");
    let home = scratch.home();
    keyed(&home);
    let links = Home::resolve(Some(home.clone())).unwrap().links();
    std::fs::write(&links, "a-secret-row\n").unwrap();
    std::fs::set_permissions(&links, std::fs::Permissions::from_mode(0o660)).unwrap();

    let out = swoosh(&home, &["status"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    let path = links.display();
    assert_eq!(
        text(&out.stderr),
        format!("error: {path} can be written by others: chmod 600 {path}\n")
    );
}
