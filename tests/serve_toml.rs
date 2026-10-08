// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `<home>/serve.toml` end to end, through the compiled binary: a `serve` saves its relay only once its
//! routes bind, a relay the file keeps is read when the file is, by every verb that reads it, and a service
//! added while `serve` runs is named and starts on the next one. Only the exact spawned pid is ever
//! signalled.

use core::time::Duration;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A scratch home removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let home = std::env::temp_dir().join(format!("sw-serve-toml-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("scratch home");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).expect("0700");
        Self(home)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `swoosh --home <home> <args>`, run to its end with nothing to read.
fn swoosh(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("swoosh runs")
}

/// A `serve --relay` that refuses after its bind, before its routes bind, saves nothing: the next verb
/// under the home is not pointed at a relay no `serve` ever ran with.
#[test]
fn a_serve_that_did_not_start_saves_no_relay() {
    let scratch = Scratch::new("no-start");
    let out = swoosh(
        &scratch.0,
        &[
            "serve",
            "--relay",
            "https://relay.example/",
            "--public",
            "web",
            "web=proxy:",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let kept = std::fs::read_to_string(scratch.0.join("serve.toml")).unwrap_or_default();
    assert!(!kept.contains("relay"), "nothing saved: {kept}");
}

/// A relay `serve.toml` keeps that is not a usable one is damage the file is read with: `service disable`
/// refuses on it, naming the key, before it writes anything.
#[test]
fn a_bad_relay_in_serve_toml_is_refused_where_the_file_is_read() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let scratch = Scratch::new("bad-relay");
    let path = scratch.0.join("serve.toml");
    let text = "relay = \"http://relay.example\"\n";
    std::io::Write::write_all(
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap(),
        text.as_bytes(),
    )
    .unwrap();
    let out = swoosh(&scratch.0, &["service", "disable", "speed"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!(
            "error: the relay in {} is not a usable relay, and swoosh will not fall back to the default one\n",
            path.display()
        )
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "unchanged");
}

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `swoosh --home <home> <args>` with its runtime directory at `run`, run to its end.
fn swoosh_in(home: &Path, run: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env("XDG_RUNTIME_DIR", run)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("swoosh runs")
}

/// Start `swoosh serve <args>` on `home` over sealed quirk, which reaches no server, and wait for its
/// banner. Returns the child, the banner, and its stderr lines as they come.
fn serve(
    home: &Path,
    run: &Path,
    args: &[&str],
) -> (KillOnDrop, String, std::sync::mpsc::Receiver<String>) {
    use std::io::{BufRead as _, Read as _};

    let mut serve = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(home)
            .args(["serve", "--transport", "quirk+noise"])
            .args(args)
            .env("XDG_RUNTIME_DIR", run)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("serve spawns"),
    );
    let stderr = serve.0.stderr.take().expect("piped stderr");
    let (lines, said) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut stdout = serve.0.stdout.take().expect("piped stdout");
    let mut seen = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut byte = [0u8; 1];
    while !String::from_utf8_lossy(&seen).contains("ctrl-c to stop") {
        assert!(
            std::time::Instant::now() < deadline,
            "serve never became ready"
        );
        if stdout.read(&mut byte).expect("read serve's banner") == 0 {
            panic!("serve exited before it was ready");
        }
        seen.push(byte[0]);
    }
    (serve, String::from_utf8_lossy(&seen).into_owned(), said)
}

/// A service added to `serve.toml` while `serve` runs is not served live: the run says, once, that it
/// starts on the next `serve`, and `status` still lists only what the run started. The next `serve` serves
/// it.
#[test]
fn a_service_added_to_serve_toml_starts_on_the_next_serve() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("added");
    let home = scratch.0.join("home");
    let run = scratch.0.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();

    let (first, banner, said) = serve(&home, &run, &["ping"]);
    assert!(
        banner.contains("serving: ping (your devices)\n"),
        "{banner}"
    );
    let path = home.join("serve.toml");
    let kept = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        kept, "services = [\"ping=ping:\"]\n",
        "the run saved its list"
    );
    std::fs::write(&path, "services = [\"ping=ping:\", \"speed=speed:\"]\n").unwrap();

    let line = said
        .recv_timeout(Duration::from_secs(10))
        .expect("the run names what waits");
    assert_eq!(
        line,
        "warning: the added service speed in serve.toml takes effect the next time serve starts"
    );
    let status = swoosh_in(&home, &run, &["status"]);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("serving: ping\n"),
        "the route stays absent: {}",
        String::from_utf8_lossy(&status.stdout)
    );
    assert!(
        said.recv_timeout(Duration::from_secs(3)).is_err(),
        "the line is said once"
    );
    drop(first);

    let (_next, banner, _) = serve(&home, &run, &[]);
    assert!(
        banner.contains("serving: ping (your devices), speed (your devices) (as last time)\n"),
        "{banner}"
    );
}
