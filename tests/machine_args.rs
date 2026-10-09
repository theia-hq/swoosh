// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A verb's machine argument through the real binary: a bare person is never guessed at, every machine
//! that is not one machine exits 2 before the key is read or anything binds, an unanswered dial teaches no
//! service, and the hidden flags are read from their variables.

use core::sync::atomic::{AtomicU32, Ordering};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use bifrost::NodeId;
use swoosh::contacts::DeviceLabel;
use swoosh::home::{Home, HomeWrite};
use swoosh::roster::{Epoch, RosterDoc, fold};
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;

/// Serializes scratch names within this test process; the pid keeps two concurrent runs apart.
static SEQ: AtomicU32 = AtomicU32::new(0);

/// A scratch home, removed on drop.
struct Scratch {
    base: PathBuf,
    home: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("swoosh-machine-{tag}-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        swoosh::config::create_store_dir(&home).unwrap();
        Self { base, home }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// A key for a machine, by seed.
fn key(seed: u8) -> String {
    NodeId::from_ed25519_secret(&[seed; 32]).to_string()
}

/// `swoosh --home <home> <args>`, with `env` set and every other `SWOOSH_*` variable unset.
fn swoosh_with(scratch: &Scratch, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command.arg("--home").arg(&scratch.home).args(args);
    for variable in [
        "SWOOSH_HOME",
        "SWOOSH_TRANSPORT",
        "SWOOSH_LOCAL",
        "SWOOSH_PEER",
        "SWOOSH_RELAY",
        "SWOOSH_RESOLVER",
        "SWOOSH_QUIET",
        "SWOOSH_SERVICE",
    ] {
        command.env_remove(variable);
    }
    command.envs(env.iter().copied());
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A session of its own, so `/dev/tty` opens for nothing: a passphrase can never be asked.
    // SAFETY: `setsid` is async-signal-safe and touches only the child's own session.
    unsafe {
        use std::os::unix::process::CommandExt as _;
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command.output().unwrap()
}

fn swoosh(scratch: &Scratch, args: &[&str]) -> Output {
    swoosh_with(scratch, args, &[])
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Save `name` as `key` through `contact add`.
fn save(scratch: &Scratch, name: &str, key: &str) {
    let out = swoosh(scratch, &["contact", "add", name, key]);
    assert!(out.status.success(), "{}", text(&out.stderr));
}

/// Give the home a list of your devices, `desk` and `nas`, signed by a root it pins.
fn yours(scratch: &Scratch) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let home = Home::resolve(Some(scratch.home.clone())).unwrap();
        let root = TestRoot::seeded(0x71);
        // This machine is `desk`: its key, the pin, and the standing the root signed for it.
        swoosh::identity::make_machine_dir(&home).unwrap();
        let mut seed = TestNode::seeded(0x72).seed();
        keystore::KeyFile::new(home.key())
            .write(
                &keystore::Secret::take(&mut seed),
                keystore::Protection::Plain,
            )
            .unwrap();
        swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).unwrap();
        let badge = root
            .device_badge(
                TestNode::seeded(0x72).node_id(),
                std::time::SystemTime::UNIX_EPOCH
                    + core::time::Duration::from_secs(swoosh::testkit::STANDING_UNTIL),
            )
            .unwrap();
        swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
        let members = [(0x72u8, "desk"), (0x73, "nas")]
            .into_iter()
            .map(|(seed, label)| {
                root.member(
                    TestNode::seeded(seed).node_id().verify_key().unwrap(),
                    label.parse::<DeviceLabel>().unwrap(),
                )
                .unwrap()
            })
            .collect();
        let doc = RosterDoc::with_revocations(Epoch(1), members, vec![], Vec::new()).unwrap();
        fold(
            &HomeWrite::take(&home).await.unwrap(),
            &home,
            &root.sign_update(&doc),
        )
        .await
        .unwrap();
    });
}

/// A bare person with one machine saved is that machine: the verb says which, once, on stderr, and dials
/// it (here it finds nothing at the key, and says so).
#[test]
fn a_bare_person_with_one_machine_dials_it_and_says_so() {
    let scratch = Scratch::new("one");
    save(&scratch, "alice/laptop", &key(1));
    let out = swoosh(&scratch, &["ping", "alice", "--transport", "quirk"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.starts_with("alice is alice/laptop.\n"), "{stderr}");
    assert_eq!(
        stderr.matches("alice is alice/laptop.").count(),
        1,
        "{stderr}"
    );
    assert_eq!(
        text(&out.stdout),
        "alice/laptop via quirk: unreachable\n",
        "it dialed the one machine"
    );
}

/// Several machines saved: `stop`'s `which machine?`, the machines in name order, exit 2, nothing dialed.
#[test]
fn a_bare_person_with_several_machines_refuses_and_lists_them() {
    let scratch = Scratch::new("several");
    save(&scratch, "alice/nas", &key(2));
    save(&scratch, "alice/laptop", &key(1));
    for verb in ["ping", "speed", "ssh", "proxy"] {
        let mut args = vec![verb, "alice"];
        if verb == "proxy" {
            args.push("https://example.com");
        }
        let out = swoosh(&scratch, &args);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{verb}: {stderr}");
        assert!(
            stderr.starts_with("error: which machine?\n  alice's: alice/laptop, alice/nas.\n"),
            "{verb}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("Usage: swoosh {verb}")),
            "{verb}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{verb}: nothing dialed");
    }
}

/// A person saved by their root alone, and a word saved as nobody: exit 2, the fix that saves a machine.
#[test]
fn a_bare_person_with_no_machines_refuses_and_names_contact_add() {
    let scratch = Scratch::new("none");
    save(&scratch, "alice", &key(3));
    let out = swoosh(&scratch, &["send", "/etc/hosts", "alice"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.starts_with(
            "error: none of alice's machines is saved here\n  To reach alice, save one of alice's \
             machines:\n    swoosh contact add alice/<name> <key>\n"
        ),
        "{stderr}"
    );
    let out = swoosh(&scratch, &["forward", "zed", "db", "-"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.starts_with(
            "error: zed is not saved here\n  To reach zed, save one of zed's machines:\n    swoosh \
             contact add zed/<name> <key>\n"
        ),
        "{stderr}"
    );
}

/// No verb fans out over a person's machines any more: `ping` and `status` of a person with two refuse,
/// and print no line for either machine.
#[test]
fn a_bare_person_never_fans_out() {
    let scratch = Scratch::new("fan");
    save(&scratch, "alice/laptop", &key(1));
    save(&scratch, "alice/nas", &key(2));
    for verb in ["ping", "status"] {
        let out = swoosh(&scratch, &[verb, "alice", "--transport", "quirk"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{verb}: {stderr}");
        assert!(out.stdout.is_empty(), "{verb}: {}", text(&out.stdout));
        assert!(!stderr.contains("via"), "{verb}: {stderr}");
    }
}

/// `me` alone is `stop`'s two lines, always: your devices, or that this machine knows none.
#[test]
fn me_alone_prints_stops_lines() {
    let scratch = Scratch::new("me");
    let out = swoosh(&scratch, &["ssh", "me"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr)
            .starts_with("error: which machine?\n  This machine knows none of your devices.\n"),
        "{}",
        text(&out.stderr)
    );
    yours(&scratch);
    let out = swoosh(&scratch, &["ssh", "me"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).starts_with("error: which machine?\n  Yours: me/desk, me/nas.\n"),
        "{}",
        text(&out.stderr)
    );
}

/// A machine name that is none of a known person's, yours included, is `stop`'s two lines and exit 2: with
/// no list of your devices here, `ssh me/nas` and `ping me/nas` say this machine knows none, and never
/// name `contact add`, which refuses `me/`.
#[test]
fn an_unknown_machine_name_prints_stops_lines() {
    let scratch = Scratch::new("unknown");
    for verb in ["ssh", "ping"] {
        let out = swoosh(&scratch, &[verb, "me/nas"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{verb}: {stderr}");
        assert!(
            stderr.starts_with(
                "error: you have no machine me/nas\n  This machine knows none of your devices.\n"
            ),
            "{verb}: {stderr}"
        );
        assert!(!stderr.contains("contact add"), "{verb}: {stderr}");
    }
    yours(&scratch);
    save(&scratch, "alice/laptop", &key(1));
    let out = swoosh(&scratch, &["ping", "me/box"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr)
            .starts_with("error: you have no machine me/box\n  Yours: me/desk, me/nas.\n"),
        "{}",
        text(&out.stderr)
    );
    let out = swoosh(&scratch, &["ping", "alice/box"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr)
            .starts_with("error: alice has no machine box\n  alice's: alice/laptop.\n"),
        "{}",
        text(&out.stderr)
    );
}

/// A bare word that is no contact but one of your device names hands back the line typed, with only the
/// machine replaced by `me/<name>`.
#[test]
fn a_bare_device_name_names_me_slash() {
    let scratch = Scratch::new("device");
    yours(&scratch);
    let out = swoosh(&scratch, &["ssh", "nas"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.starts_with(&format!(
            "error: name the machine:\n  swoosh --home {} ssh me/nas\n",
            scratch.home.display()
        )),
        "{stderr}"
    );
}

/// The machine resolves before anything is bound: with this home's `serve.toml` unreadable, which a
/// dialing verb reads to compose its bind, a person with several machines still refuses with exit 2,
/// while one machine goes on to the bind and meets the file.
#[test]
fn a_bare_person_refuses_before_any_bind() {
    let scratch = Scratch::new("bind");
    save(&scratch, "alice/laptop", &key(1));
    save(&scratch, "bob/laptop", &key(4));
    save(&scratch, "bob/nas", &key(5));
    std::fs::create_dir_all(scratch.home.join("serve.toml")).unwrap();
    let refused = swoosh(&scratch, &["ping", "bob"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).starts_with("error: which machine?\n"));
    let bound = swoosh(&scratch, &["ping", "alice"]);
    assert_eq!(bound.status.code(), Some(1), "{}", text(&bound.stderr));
    assert!(
        text(&bound.stderr).contains("serve.toml"),
        "one machine reaches the bind: {}",
        text(&bound.stderr)
    );
}

/// The machine resolves before the key is read: under a sealed key with no terminal to ask on, a person
/// with several machines refuses with exit 2, asking nothing, while one machine goes on to the key and
/// cannot unlock it.
#[test]
fn a_bare_person_refuses_before_the_key_is_read() {
    let scratch = Scratch::new("sealed");
    save(&scratch, "alice/laptop", &key(1));
    save(&scratch, "bob/laptop", &key(4));
    save(&scratch, "bob/nas", &key(5));
    let home = Home::resolve(Some(scratch.home.clone())).unwrap();
    swoosh::identity::make_machine_dir(&home).unwrap();
    let passphrase = keystore::Passphrase::try_from(zeroize::Zeroizing::new(
        "a passphrase long enough".to_owned(),
    ))
    .unwrap();
    let mut seed = [9u8; 32];
    keystore::KeyFile::new(home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            keystore::Protection::Passphrase(&passphrase),
        )
        .unwrap();

    let refused = swoosh(&scratch, &["ping", "bob"]);
    let stderr = text(&refused.stderr);
    assert_eq!(refused.status.code(), Some(2), "{stderr}");
    assert!(stderr.starts_with("error: which machine?\n"), "{stderr}");
    assert!(
        !stderr.contains("passphrase"),
        "nothing was asked: {stderr}"
    );

    let read = swoosh(&scratch, &["ping", "alice"]);
    assert_ne!(read.status.code(), Some(0));
    assert_ne!(read.status.code(), Some(2), "{}", text(&read.stderr));
    assert!(
        text(&read.stderr).contains("passphrase"),
        "one machine goes on to the key: {}",
        text(&read.stderr)
    );
}

/// A dial nothing answered was never refused, so it teaches no service: the reach line, and no
/// `service add` form or claim about what the machine serves.
#[test]
fn an_unanswered_dial_teaches_no_service() {
    let scratch = Scratch::new("unanswered");
    for verb in ["ping", "speed"] {
        let out = swoosh(&scratch, &[verb, &key(6), "--transport", "quirk"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{verb}: {stderr}");
        assert!(stderr.contains("could not reach"), "{verb}: {stderr}");
        assert!(!stderr.contains("service add"), "{verb}: {stderr}");
        assert!(!stderr.contains("does not serve"), "{verb}: {stderr}");
        assert!(!stderr.contains("does not bind"), "{verb}: {stderr}");
    }
}

/// The hidden reach flags are read from their variables, and a refusal about one names both spellings:
/// `SWOOSH_TRANSPORT` and `SWOOSH_RELAY` together, `SWOOSH_LOCAL` and `SWOOSH_RESOLVER` together, exit 2.
#[test]
fn hidden_reach_flags_are_read_from_their_variables() {
    let scratch = Scratch::new("variables");
    let target = key(7);
    let out = swoosh_with(
        &scratch,
        &["ping", &target],
        &[
            ("SWOOSH_TRANSPORT", "quirk"),
            ("SWOOSH_RELAY", "https://relay.example"),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).starts_with(
            "error: --relay or SWOOSH_RELAY has no effect over quirk\n  quirk uses no relay.\n"
        ),
        "{}",
        text(&out.stderr)
    );
    let out = swoosh_with(
        &scratch,
        &["ping", &target],
        &[
            ("SWOOSH_LOCAL", "1"),
            ("SWOOSH_RESOLVER", "https://dns.example/pkarr"),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).starts_with(
            "error: --resolver or SWOOSH_RESOLVER has no effect with --local or SWOOSH_LOCAL\n  swoosh \
             publishes no record when it runs on this network only.\n"
        ),
        "{}",
        text(&out.stderr)
    );
}

/// A stand-in `ssh` on `PATH` that prints the argv `swoosh ssh` hands it, one word per line.
fn fake_ssh(scratch: &Scratch) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let bin = scratch.base.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let ssh = bin.join("ssh");
    std::fs::write(&ssh, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// The `ProxyCommand` `swoosh ssh` hands the system ssh, with `env` set.
fn proxy_command(scratch: &Scratch, bin: &Path, target: &str, env: &[(&str, &str)]) -> String {
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let mut env: Vec<(&str, &str)> = env.to_vec();
    env.push(("PATH", &path));
    let out = swoosh_with(scratch, &["ssh", target], &env);
    assert!(out.status.success(), "{}", text(&out.stderr));
    text(&out.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("ProxyCommand="))
        .expect("a ProxyCommand")
        .to_owned()
}

/// `--service` has no variable: a `SWOOSH_SERVICE` in the environment does not retarget `ssh`, which
/// still dials its own default.
#[test]
fn service_has_no_env_variable() {
    let scratch = Scratch::new("service");
    let bin = fake_ssh(&scratch);
    let target = key(8);
    let line = proxy_command(&scratch, &bin, &target, &[("SWOOSH_SERVICE", "x")]);
    assert!(line.contains(&format!(" forward {target} ssh -")), "{line}");
}

/// `SWOOSH_PEER` holds several hints, comma-separated, and each reaches the bridge.
#[test]
fn swoosh_peer_takes_several_hints() {
    let scratch = Scratch::new("hints");
    let bin = fake_ssh(&scratch);
    let (one, two) = (key(10), key(11));
    let hints = format!("{one}=127.0.0.1:1001,{two}=127.0.0.1:1002");
    let line = proxy_command(&scratch, &bin, &key(9), &[("SWOOSH_PEER", &hints)]);
    for hint in [
        format!("{one}=127.0.0.1:1001"),
        format!("{two}=127.0.0.1:1002"),
    ] {
        assert!(line.contains(&format!("--peer '{hint}'")), "{hint}: {line}");
    }
}
