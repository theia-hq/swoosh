// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Bare `swoosh status` through the real binary: it runs with nothing serving and nothing to dial, makes
//! this machine's key on a first run, keeps its report on stdout and its notices on stderr, and never asks
//! for a passphrase, even where a sealed root is kept.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;

use bifrost::NodeId;
use swoosh::config;
use swoosh::home::Home;
use swoosh::root::{Date, Minted, Moved, Root};
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
        .env_remove("SWOOSH_KEY")
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

/// Bare `status` succeeds with no `serve` running and nobody to dial.
#[test]
fn status_never_dials_and_runs_with_no_node() {
    let scratch = Scratch::new("no-node");
    let out = swoosh(&scratch.home(), &["status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("serving: nothing (swoosh serve is not running)"),
        "{}",
        text(&out.stdout)
    );
}

/// On an empty home, `status --key` makes a key and prints it.
#[test]
fn status_key_on_an_empty_home_makes_and_prints_a_key() {
    let scratch = Scratch::new("key-empty");
    let out = swoosh(&scratch.home(), &["status", "--key"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let key: NodeId = text(&out.stdout).trim().parse().expect("a key prints");
    assert!(scratch.home().join("key").exists(), "the key is kept");
    let again = swoosh(&scratch.home(), &["status", "--key"]);
    assert_eq!(
        text(&again.stdout).trim(),
        key.to_string(),
        "the same key, the second time"
    );
    assert!(
        !text(&again.stderr).contains("made this machine's key"),
        "made once: {}",
        text(&again.stderr)
    );
}

/// On a first run, stdout is the key and a newline, nothing else; the "made" notice is on stderr.
#[test]
fn status_key_stdout_is_the_key_alone_on_first_run() {
    let scratch = Scratch::new("key-alone");
    let out = swoosh(&scratch.home(), &["status", "--key"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let key: NodeId = stdout.trim().parse().expect("the key");
    assert_eq!(stdout, format!("{key}\n"));
    assert_eq!(
        text(&out.stderr),
        format!(
            "made this machine's key (first run): {}\n",
            scratch.home().join("key").display()
        )
    );
}

/// Line 1 is exactly `key: <key>`, and line 2 exactly `lock: none` on a plain key.
#[test]
fn status_line_one_is_key_colon_space() {
    let scratch = Scratch::new("line-one");
    let key = text(&swoosh(&scratch.home(), &["status", "--key"]).stdout);
    let out = swoosh(&scratch.home(), &["status"]);
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some(format!("key: {}", key.trim()).as_str()));
    assert_eq!(lines.next(), Some("lock: none"));
}

/// The report is on stdout, whole; the first run's notice is on stderr and nowhere in the report.
#[test]
fn status_report_is_on_stdout_and_its_notices_on_stderr() {
    let scratch = Scratch::new("streams");
    let out = swoosh(&scratch.home(), &["status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(stdout.starts_with("key: "), "{stdout}");
    assert!(stdout.contains("root: none yet."), "{stdout}");
    assert!(stdout.contains("serving: "), "{stdout}");
    assert!(!stdout.contains("made this machine's key"), "{stdout}");
    assert!(
        stderr.starts_with("made this machine's key (first run): "),
        "{stderr}"
    );
    assert!(!stderr.contains("key: "), "{stderr}");
}

/// Where a sealed root is kept, and where it was moved away from, `status` reads the root and asks for no
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
        text(&out.stdout).contains("kept on this machine, locked with a passphrase."),
        "{}",
        text(&out.stdout)
    );

    let moved = Scratch::new("moved-root");
    let home = Home::resolve(Some(moved.home())).unwrap();
    config::create_store_dir(home.dir()).unwrap();
    let mut seed = TestNode::seeded(0x11).seed();
    keystore::KeyFile::device(home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            keystore::Protection::Plain,
        )
        .unwrap();
    let root = TestRoot::seeded(0x21);
    runtime.block_on(async {
        config::write_signet(&home, root.node_id()).await.unwrap();
        let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
        let standing = root
            .device_badge(TestNode::seeded(0x11).node_id(), until)
            .unwrap();
        config::write_badge(&home, &standing).await.unwrap();
        Moved {
            to: PathBuf::from("/media/usb/root"),
            on: Date(1_790_000_000),
        }
        .write(&home)
        .await
        .unwrap();
    });
    let out = swoosh(&moved.home(), &["status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains(&format!(
            "root: root:{}, not on this machine (you moved it to /media/usb/root on 2026-09-21).",
            root.node_id()
        )),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(
        prompt.events(),
        1,
        "the one prompt is the mint's, before either status ran"
    );
}
