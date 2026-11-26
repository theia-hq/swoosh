// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A reserved word in a service slot through the real binary: every slot, on the command line or in
//! `serve.toml`, refuses each of the five with the one line, under the usage of the verb it was typed to,
//! exit 2, before anything is bound or written.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use swoosh::home::Home;
use swoosh::names::Name;

/// Serializes scratch names within this test process; the pid keeps two concurrent runs apart.
static SEQ: AtomicU32 = AtomicU32::new(0);

/// How long one run may take before the test calls it a start: a refusal returns at once.
const BOUND: Duration = Duration::from_secs(20);

/// A scratch home, removed on drop.
struct Scratch {
    home: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let home = std::env::temp_dir().join(format!(
            "swoosh-reserved-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        swoosh::config::create_store_dir(&home).unwrap();
        Self { home }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// Run the binary on `home` with `args`, and kill the one child it spawned should it outlive [`BOUND`]: a
/// slot that let a reserved word through would start a `serve`.
fn swoosh(args: &[&str], home: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .args(args)
        .env("SWOOSH_HOME", home)
        .env_remove("SWOOSH_RELAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > BOUND {
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

/// Every file under `dir` with its length, sorted: what a refusal must leave as it was.
fn tree(dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                pending.push(entry.path());
            } else {
                found.push((entry.path(), meta.len()));
            }
        }
    }
    found.sort();
    found
}

/// The one line a reserved word gets.
fn line(word: &str) -> String {
    format!("error: {word} is reserved; no service can have that name\n")
}

/// Each of the five words, in each service slot a person types one into, refuses with its own line under
/// the usage of the verb it was typed to, exit 2, and writes nothing.
#[test]
fn a_reserved_service_name_has_its_own_line() {
    for word in Name::RESERVED {
        let definition = format!("{word}=ping:");
        let lines: [(&str, Vec<&str>); 15] = [
            ("serve", vec!["serve", word]),
            ("serve", vec!["serve", &definition]),
            ("serve", vec!["serve", "--public", word]),
            ("serve", vec!["serve", "--public-unsafe", word]),
            ("serve", vec!["serve", "--with", &definition]),
            ("serve", vec!["serve", "--without", word]),
            ("service add", vec!["service", "add", &definition]),
            ("service rm", vec!["service", "rm", word]),
            ("service on", vec!["service", "on", word]),
            ("service off", vec!["service", "off", word]),
            ("share", vec!["share", word]),
            ("forward", vec!["forward", "me/nas", word, "8080"]),
            (
                "proxy",
                vec!["proxy", "me/nas", "https://example.com", "--service", word],
            ),
            ("ssh", vec!["ssh", "me/nas", "--service", word]),
            (
                "send",
                vec!["send", "notes.txt", "me/nas", "--service", word],
            ),
        ];
        for (verb, args) in lines {
            let scratch = Scratch::new("typed");
            let before = tree(&scratch.home);
            let out = swoosh(&args, &scratch.home);
            let err = String::from_utf8(out.stderr).unwrap();
            assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
            assert!(err.starts_with(&line(word)), "{args:?}: {err}");
            assert!(
                err.contains(&format!("Usage: swoosh {verb}")),
                "{args:?}: {err}"
            );
            assert_eq!(tree(&scratch.home), before, "{args:?} wrote to the home");
        }
    }
}

/// A `serve.toml` that names a service with a reserved word, saved or turned off, is refused when a bare
/// `serve` loads it: the same line, then the file it is in, exit 2. The refusal comes before the home's
/// lock is taken: no lock file is made and the file is left as it was.
#[test]
fn a_reserved_name_in_serve_toml_is_refused_at_load() {
    for word in Name::RESERVED {
        for text in [
            format!("services = [\"ping=ping:\", \"{word}=ping:\"]\n"),
            format!("services = [\"ping=ping:\"]\noff = [\"{word}\"]\n"),
        ] {
            let scratch = Scratch::new("saved");
            let home = Home::resolve(Some(scratch.home.clone())).unwrap();
            write_private(&home.serve_toml(), &text);
            let before = tree(&scratch.home);

            let out = swoosh(&["serve"], &scratch.home);
            let err = String::from_utf8(out.stderr).unwrap();
            assert_eq!(out.status.code(), Some(2), "{text}: {err}");
            let head = format!(
                "{}  It is in {}. Remove it there.\n",
                line(word),
                home.serve_toml().display()
            );
            assert!(err.starts_with(&head), "{text}: {err}");
            assert!(err.contains("Usage: swoosh serve"), "{err}");
            for lock in ["home.lock", "serve.lock"] {
                assert!(!scratch.home.join(lock).exists(), "{text}: {lock} was made");
            }
            assert_eq!(tree(&scratch.home), before, "{text}: the home changed");
        }
    }
}

/// Write `text` to `path`, readable by its owner only, as swoosh writes its trust files.
fn write_private(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
