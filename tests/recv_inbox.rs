// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Where `serve`'s `recv:` saves, driven through the compiled binary: a `recv:` with no directory saves
//! into the inbox in this user's data directory, never the directory `serve` started in; and an output
//! directory that is `$HOME`, the swoosh home, or a directory holding the swoosh home is refused, whether
//! named on the command line or resumed from the home's saved list, before anything starts.
//!
//! A push names its own path under the output directory, so a `serve` saving into `$HOME` would let any
//! sender replace the home's files, the pin the gate reads among them.

use core::net::SocketAddr;
use core::time::Duration;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Instant;

use bifrost::{Node, NodeId, Session as _};
use bifrost_iroh::Endpoint;
use swoosh::credential::Credential;
use swoosh::reaching::BindRole;
use swoosh::transport::PeerHint;
use tightbeam::tunnel::Connector;
use transfer::wire::{Blob, Transfer};

/// The role the pushing node binds under: it browses the LAN and advertises nothing.
const DIALING: BindRole = BindRole::Dialing(Credential::Family { present: None });

/// One test's directories, removed on drop: `user` stands in for `$HOME`, `home` is the swoosh home (kept
/// out of `user`, so each refusal is reached by its own rule, unless the test uses the default home), and
/// `work` is where `serve` is started.
struct Scratch {
    base: PathBuf,
    user: PathBuf,
    home: PathBuf,
    work: PathBuf,
    /// Whether `home` is named with `--home`, or is the platform default under `user`.
    named: bool,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("sw-inbox-{tag}-{}", std::process::id()));
        Self::made(base.join("home"), base, true)
    }

    /// A scratch whose swoosh home is the platform default under `user`, named by nothing.
    fn at_default(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("sw-inbox-{tag}-{}", std::process::id()));
        #[cfg(target_os = "macos")]
        let home = base
            .join("user")
            .join("Library")
            .join("Application Support")
            .join("swoosh");
        #[cfg(not(target_os = "macos"))]
        let home = base
            .join("user")
            .join(".local")
            .join("state")
            .join("swoosh");
        Self::made(home, base, false)
    }

    fn made(home: PathBuf, base: PathBuf, named: bool) -> Self {
        let _ = std::fs::remove_dir_all(&base);
        let scratch = Self {
            user: base.join("user"),
            work: base.join("work"),
            home,
            base,
            named,
        };
        for dir in [&scratch.user, &scratch.work] {
            std::fs::create_dir_all(dir).unwrap();
        }
        if named {
            std::fs::create_dir_all(&scratch.home).unwrap();
        }
        scratch
    }

    /// The inbox `serve` resolves when `HOME` is `user` and `XDG_DATA_HOME` is unset: beside the default
    /// home on macOS, never in it.
    fn inbox(&self) -> PathBuf {
        #[cfg(target_os = "macos")]
        let inbox = self
            .user
            .join("Library")
            .join("Application Support")
            .join("swoosh-inbox");
        #[cfg(not(target_os = "macos"))]
        let inbox = self
            .user
            .join(".local")
            .join("share")
            .join("swoosh")
            .join("inbox");
        inbox
    }

    /// `swoosh [--home <home>] <args>`, with `HOME` set to `user` and nothing else choosing a directory.
    fn swoosh(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
        if self.named {
            command.arg("--home").arg(&self.home);
        }
        command
            .args(args)
            .env("HOME", &self.user)
            .env("XDG_RUNTIME_DIR", self.base.join("run"))
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null());
        command
    }

    /// `swoosh [--home <home>] serve --local <args>`, with `HOME` set to `user` and started
    /// in `cwd`.
    fn serve(&self, cwd: &Path, args: &[&str]) -> Command {
        use std::os::unix::fs::PermissionsExt as _;

        let run = self.base.join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = self.swoosh(&[&["serve", "--local"][..], args].concat());
        command.current_dir(cwd).env("XDG_RUNTIME_DIR", &run);
        command
    }

    /// Run a `serve` that should refuse: its output, or `None` when it was still running after the
    /// deadline (it started instead of refusing), in which case it is killed.
    fn refused(&self, cwd: &Path, args: &[&str]) -> Option<Output> {
        let mut child = self
            .serve(cwd, args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("serve spawns");
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Some(child.wait_with_output().unwrap())
    }

    /// Assert `serve <args>`, started in `cwd`, refuses with exit 1 and the line naming `dir` and `why`,
    /// and that nothing started: no key made, no list saved.
    fn assert_refused(&self, cwd: &Path, args: &[&str], dir: &str, why: &str) {
        let Some(output) = self.refused(cwd, args) else {
            panic!("serve {args:?} started; it must refuse to save into {dir}");
        };
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "serve {args:?}: {stderr}");
        assert_eq!(
            stderr,
            format!("error: inbox cannot save into {dir}: {why}\n"),
            "serve {args:?} names the directory and why"
        );
        assert!(
            !self.home.join("machine").join("key").exists(),
            "serve {args:?} made no key"
        );
        assert!(output.stdout.is_empty(), "serve {args:?} printed no banner");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// A running `swoosh serve`, killed and reaped on drop.
struct Served {
    _child: KillOnDrop,
    key: NodeId,
    addr: SocketAddr,
}

/// Only this test's owned child is killed and reaped, including readiness failures.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The overall deadline bounds channel receives even when the child's pipe stays open and silent.
fn read_banner(
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
    deadline: Instant,
) -> (String, String) {
    let (mut key, mut addr) = (None, None);
    while key.is_none() || addr.is_none() {
        assert!(Instant::now() < deadline, "serve never printed its banner");
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("serve never printed its banner before the deadline")
            .expect("read the banner");
        if key.is_none()
            && let Some(parsed) = line.strip_prefix("  key  ")
        {
            key = Some(parsed.trim().to_owned());
        }
        if let Some(found) = line.trim().strip_suffix("(this machine)") {
            addr = Some(found.trim().to_owned());
        }
    }
    (key.unwrap(), addr.unwrap())
}

#[test]
fn readiness_uses_the_key_fact_row_and_keeps_the_loopback_address() {
    let (sender, lines) = std::sync::mpsc::channel();
    for line in [
        "swoosh is serving",
        "  key            ed01exampleid",
        "  127.0.0.1:1234 (this machine)",
    ] {
        sender.send(Ok(line.to_owned())).unwrap();
    }
    assert_eq!(
        read_banner(lines, Instant::now() + Duration::from_secs(1)),
        ("ed01exampleid".to_owned(), "127.0.0.1:1234".to_owned())
    );
}

#[test]
fn a_service_named_key_does_not_replace_the_first_key_fact() {
    let key = bifrost::NodeId::from_ed25519_secret(&[0x11; 32]).to_string();
    let (sender, lines) = std::sync::mpsc::channel();
    for line in [
        format!("  key            {key}"),
        "  key  your devices  echo:".to_owned(),
        "  127.0.0.1:1234 (this machine)".to_owned(),
    ] {
        sender.send(Ok(line)).unwrap();
    }
    assert_eq!(
        read_banner(lines, Instant::now() + Duration::from_secs(1)),
        (key, "127.0.0.1:1234".to_owned())
    );
}

#[test]
fn readiness_rejects_colon_records_and_a_silent_open_pipe_is_bounded() {
    let (sender, lines) = std::sync::mpsc::channel();
    sender.send(Ok("key: ed01exampleid".to_owned())).unwrap();
    sender
        .send(Ok("127.0.0.1:1234 (this machine)".to_owned()))
        .unwrap();
    drop(sender);
    assert!(
        std::panic::catch_unwind(|| read_banner(lines, Instant::now() + Duration::from_secs(1)))
            .is_err()
    );
    let (_sender, lines) = std::sync::mpsc::channel();
    assert!(
        std::panic::catch_unwind(|| read_banner(lines, Instant::now() + Duration::from_millis(10)))
            .is_err()
    );
}

/// Start `serve <args>` in `cwd` and wait for its banner: the key it answers at and its loopback address.
fn serve(scratch: &Scratch, cwd: &Path, args: &[&str]) -> Served {
    let child = scratch
        .serve(cwd, &[&["--verbose"][..], args].concat())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve spawns");
    let mut child = KillOnDrop(child);
    let stdout = child.0.stdout.take().expect("piped stdout");
    // Bound both the wait and queued output; the pipe reader may block, never the deadline owner.
    let (sender, lines) = std::sync::mpsc::sync_channel(16);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            // Keep draining after readiness, without closing the child's output pipe early.
            let _ = sender.send(line);
        }
    });
    let (key, addr) = read_banner(lines, Instant::now() + Duration::from_secs(60));
    Served {
        _child: child,
        key: key.parse().expect("the banner's key"),
        addr: addr.parse().expect("a loopback address"),
    }
}

/// The link `share <service> anyone` prints on the scratch's home, once a running `serve` can have seen its
/// ledger row.
fn issue(scratch: &Scratch, service: &str) -> nauthy::Link {
    let output = scratch
        .swoosh(&["share", service, "anyone", "--once"])
        .output()
        .expect("the binary runs");
    assert!(
        output.status.success(),
        "share failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let link = swoosh::link::parse(&String::from_utf8(output.stdout).unwrap()).expect("a link");
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(100));
    link
}

/// Push `payload` as `name` to `service` on `served`, presenting `link`, the way `swoosh send` does.
async fn push(served: &Served, service: &str, link: nauthy::Link, name: &[u8], payload: &[u8]) {
    let transport = Endpoint::bind_local_with_secret(&[0x51; 32])
        .await
        .expect("bind iroh on loopback");
    let hint: PeerHint = format!("{}={}", served.key, served.addr).parse().unwrap();
    let discovery = PeerHint::discovery(&transport, [hint], &DIALING).discovery;
    let node = Node::new(transport, discovery);
    let session = Connector::to_node(served.key, service.parse().unwrap(), Some(link))
        .open_service(&node)
        .await
        .expect("connect");
    let (send, recv) = tokio::time::timeout(Duration::from_secs(15), session.open_bi())
        .await
        .expect("the stream answers within the deadline")
        .expect("the gate admits a link this machine signed");
    let mut to_hash = payload;
    let blob = Blob::hash(&mut to_hash).await.unwrap();
    let mut to_send = payload;
    Transfer::new(send, recv)
        .send(name, &blob, &mut to_send)
        .await
        .expect("the push is accepted and acknowledged");
}

/// `inbox=recv:` saves a push into the inbox, created owner-only, and nothing into the directory `serve`
/// was started in; invocation selection leaves the saved list absent and the next bare start at defaults.
#[tokio::test]
async fn a_dirless_recv_saves_into_the_inbox() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("dirless");
    let served = serve(&scratch, &scratch.work, &["inbox=recv:"]);
    let link = issue(&scratch, "inbox");
    push(&served, "inbox", link, b"notes.txt", b"hello").await;

    let landed = scratch.inbox().join("notes.txt");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !landed.exists() {
        assert!(
            Instant::now() < deadline,
            "the push never landed at {}",
            landed.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read(&landed).unwrap(), b"hello");
    let mode = std::fs::metadata(scratch.inbox())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "the inbox is owner-only");
    assert_eq!(
        std::fs::read_dir(&scratch.work).unwrap().count(),
        0,
        "nothing lands in the directory serve was started in"
    );
    let home = swoosh::home::Home::resolve(Some(scratch.home.clone())).unwrap();
    let saved = swoosh::serve_toml::ServeToml::read(&home).unwrap();
    assert_eq!(saved.services, None, "the invocation inbox is not saved");
    assert!(saved.off.is_empty(), "launch does not change off policy");
    assert!(
        matches!(
            swoosh::serve::Started::bare(&saved).unwrap(),
            swoosh::serve::Started::Default
        ),
        "the next bare start uses defaults, not the invocation inbox"
    );
}

/// With the home in its platform default place, named by nothing, a dirless `recv:` still saves: the inbox
/// is outside that home (on macOS both sit under `Application Support`), so the rule that refuses a
/// directory inside the home never meets it.
#[tokio::test]
async fn a_dirless_recv_beside_the_default_home_saves_into_the_inbox() {
    let scratch = Scratch::at_default("default-home");
    let served = serve(&scratch, &scratch.work, &["inbox=recv:"]);
    assert!(
        scratch.home.join("machine").join("key").is_file(),
        "serve runs in the default home"
    );
    assert!(
        !scratch.inbox().starts_with(&scratch.home),
        "the inbox is not inside the home"
    );
    let link = issue(&scratch, "inbox");
    push(&served, "inbox", link, b"notes.txt", b"hello").await;

    let landed = scratch.inbox().join("notes.txt");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !landed.exists() {
        assert!(
            Instant::now() < deadline,
            "the push never landed at {}",
            landed.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read(&landed).unwrap(), b"hello");
}

/// A `recv:` into `$HOME`, the swoosh home, a directory holding it, or a directory inside it is refused at
/// start with the line naming the directory, and nothing starts. `.` in `$HOME` is the case the rule is for
/// (the start directory is read canonical, so the line names it that way, `.` dropped); a symlink into the
/// swoosh home is caught because the check compares canonical paths, and on macOS another spelling of the
/// same directory through the `/System/Volumes/Data` firmlink because it compares device and inode too.
#[test]
fn a_recv_into_home_is_refused() {
    let scratch = Scratch::new("named");
    let home = scratch.home.display().to_string();
    let base = scratch.base.display().to_string();
    let link = scratch.work.join("link");
    std::os::unix::fs::symlink(&scratch.home, &link).unwrap();
    let link = link.display().to_string();
    let inside = scratch.home.join("root");
    std::fs::create_dir_all(&inside).unwrap();
    let inside = inside.display().to_string();

    scratch.assert_refused(
        &scratch.user,
        &["inbox=recv:."],
        &std::fs::canonicalize(&scratch.user)
            .unwrap()
            .display()
            .to_string(),
        "it is your home directory",
    );
    scratch.assert_refused(
        &scratch.work,
        &[&format!("inbox=recv:{home}")],
        &home,
        "it is the swoosh home",
    );
    scratch.assert_refused(
        &scratch.work,
        &[&format!("inbox=recv:{link}")],
        &link,
        "it is the swoosh home",
    );
    scratch.assert_refused(
        &scratch.work,
        &[&format!("inbox=recv:{base}")],
        &base,
        "it holds the swoosh home",
    );
    scratch.assert_refused(
        &scratch.work,
        &[&format!("inbox=recv:{inside}")],
        &inside,
        "it is inside the swoosh home",
    );
    #[cfg(target_os = "macos")]
    for (dir, why) in [
        (&scratch.user, "it is your home directory"),
        (&scratch.base, "it holds the swoosh home"),
        (&scratch.home.join("root"), "it is inside the swoosh home"),
    ] {
        // `realpath` keeps this spelling: the firmlink is not a symlink, so only the identity matches.
        let other = Path::new("/System/Volumes/Data")
            .join(
                std::fs::canonicalize(dir)
                    .unwrap()
                    .strip_prefix("/")
                    .unwrap(),
            )
            .display()
            .to_string();
        scratch.assert_refused(
            &scratch.work,
            &[&format!("inbox=recv:{other}")],
            &other,
            why,
        );
    }
    assert!(
        !scratch.home.join("serve.toml").exists(),
        "a refused start saves no list"
    );
}

/// An inbox that cannot be made stops `serve` before anything is written to the home, the machine key
/// among them.
#[test]
fn an_inbox_that_cannot_be_made_stops_before_the_key() {
    let scratch = Scratch::new("unmade");
    let data_root = scratch
        .inbox()
        .ancestors()
        .find(|above| above.parent() == Some(scratch.user.as_path()))
        .unwrap()
        .to_owned();
    std::fs::write(&data_root, b"not a directory").unwrap();

    let Some(output) = scratch.refused(&scratch.work, &["inbox=recv:"]) else {
        panic!("serve started with an inbox it could not make");
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.starts_with("error: could not create "), "{stderr}");
    assert!(
        !scratch.home.join("machine").join("key").exists(),
        "serve made no key"
    );
}

/// A saved list that names such a directory is refused at resume the same way, and nothing starts.
#[test]
fn a_saved_recv_into_the_home_is_refused_at_resume() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let scratch = Scratch::new("resume");
    for (dir, why) in [
        (&scratch.home, "it is the swoosh home"),
        (&scratch.user, "it is your home directory"),
    ] {
        let dir = dir.display().to_string();
        let saved = scratch.home.join("serve.toml");
        let _ = std::fs::remove_file(&saved);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&saved)
            .unwrap();
        let entry = format!("inbox=recv:{dir}");
        std::io::Write::write_all(&mut file, format!("services = [{entry:?}]\n").as_bytes())
            .unwrap();
        drop(file);

        scratch.assert_refused(&scratch.work, &[], &dir, why);
    }
}
