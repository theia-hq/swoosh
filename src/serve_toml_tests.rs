//! `serve.toml`: what each writer lands, and what a running `serve` reads of it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::path::{Path, PathBuf};

use nauthy::{STAT_DEBOUNCE, Service};
use tightbeam::enabled::EnabledServices as _;

use super::{LiveServeToml, ServeToml};
use crate::home::Home;
use crate::serve::Started;

#[test]
fn complete_invalid_off_clearing_update_retains_accepted_data_and_recovers_without_retargeting() {
    let path = PathBuf::from("/unused/serve.toml");
    let accepted = ServeToml {
        services: Some(vec![
            "api=file:./old".into(),
            "raw=stdin:".into(),
            "drop=recv:".into(),
        ]),
        off: ["api".into()].into(),
        ..ServeToml::default()
    };
    let watcher = LiveServeToml::from_read(
        path.clone(),
        Some((accepted.clone(), None)),
        Path::new("/captured/./cwd"),
    )
    .unwrap();
    let started = Started::positional(&["api=echo:".into()], Path::new("/captured/./cwd")).unwrap();
    // Set bound state directly to isolate policy acceptance from filesystem polling or preparation.
    let mut held = watcher.lock();
    held.serving = Some(super::Serving {
        bound: super::targets(&started),
        selection: super::Selection::Invocation,
        relay: None,
        resolver: None,
    });
    for invalid in [
        "bad=ping:80",
        "bad=file:",
        "bad=proxy:https://user:secret@example.test/",
    ] {
        let changed = ServeToml {
            services: Some(vec!["api=echo:".into(), invalid.into()]),
            ..ServeToml::default()
        };
        held.take(&path, Ok(Some((changed, None))), None);
        assert_eq!(held.file, accepted);
        assert!(held.policy == super::LivePolicy::Failed);
        assert!(held.refuses("api"));
        assert!(!held.refuses("control.stop"));
        assert_eq!(held.serving.as_ref().unwrap().bound["api"], "echo:");
    }
    let recovered = ServeToml {
        services: Some(vec![
            "api=file:./next".into(),
            "drop=recv:".into(),
            "raw=stdin:".into(),
        ]),
        ..ServeToml::default()
    };
    held.take(&path, Ok(Some((recovered.clone(), None))), None);
    assert!(held.policy == super::LivePolicy::Accepted);
    assert!(!held.refuses("api"));
    assert_eq!(held.file, recovered, "accepted text is not rewritten");
    assert_eq!(
        held.running.as_ref().unwrap()["api"],
        "file:/captured/./cwd/./next"
    );
    assert_eq!(held.serving.as_ref().unwrap().bound["api"], "echo:");
}

#[test]
fn initial_complete_invalid_grammar_never_establishes_policy_health() {
    for invalid in [
        "bad=ping:80",
        "bad=stdin:tail",
        "bad=proxy:https://u:secret@host.test",
    ] {
        let file = ServeToml {
            services: Some(vec![invalid.into()]),
            ..ServeToml::default()
        };
        let result = LiveServeToml::from_read(
            "/unused/serve.toml".into(),
            Some((file, None)),
            Path::new("/work"),
        );
        assert!(matches!(result, Err(super::ServeTomlError::Definition(_))));
    }
}

/// A scratch home, removed on drop.
struct Scratch {
    dir: PathBuf,
    home: Home,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "swoosh-serve-toml-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch home");
        let home = Home::resolve(Some(dir.clone())).expect("an explicit home");
        Self { dir, home }
    }

    /// Turn `name` off alone, through the writer `service off` uses.
    fn only_off(&self, name: &str) {
        ServeToml::update(&crate::testkit::lock(), &self.home, |file| {
            file.off.clear();
            file.off.insert(name.to_owned());
        })
        .expect("write serve.toml");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn service(name: &str) -> Service {
    name.parse().expect("a service")
}

fn past_the_debounce() {
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));
}

/// Two toggles that leave `serve.toml` the same length, the second renamed in with the first's mtime, as
/// two writes inside one tick of a coarse clock leave it: the watcher the gate asks still sees the second,
/// because its stamp holds the inode and ctime, not only the mtime and length.
#[test]
fn the_disabled_watcher_sees_a_same_length_rename() {
    let scratch = Scratch::new("same-length");
    let off = LiveServeToml::load(&scratch.home).expect("load");
    scratch.only_off("ping");
    past_the_debounce();
    assert!(!off.is_enabled(&service("ping")), "ping is off");
    let path = scratch.home.serve_toml();
    let first = std::fs::metadata(&path).unwrap();

    scratch.only_off("pong");
    let second = std::fs::metadata(&path).unwrap();
    assert_eq!(second.len(), first.len(), "the two writes are one length");
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(first.modified().unwrap())
        .unwrap();
    past_the_debounce();
    assert!(off.is_enabled(&service("ping")), "ping is back on");
    assert!(!off.is_enabled(&service("pong")), "pong is off");
}

/// A `serve.toml` deleted, or turned to something that is not one, keeps the set read last: deleting the
/// file never turns a service back on.
#[test]
fn a_missing_or_damaged_serve_toml_keeps_the_set_read_last() {
    let scratch = Scratch::new("kept");
    scratch.only_off("ping");
    let off = LiveServeToml::load(&scratch.home).expect("load");
    assert_eq!(off.off(), ["ping"]);

    std::fs::remove_file(scratch.home.serve_toml()).unwrap();
    past_the_debounce();
    assert!(!off.is_enabled(&service("ping")), "still off once deleted");

    std::fs::write(scratch.home.serve_toml(), "off = 3\n").unwrap();
    past_the_debounce();
    assert_eq!(off.off(), ["ping"], "still off once damaged");
}

/// A file swoosh did not write is damaged: a key it does not know, a field of the wrong type, or a service
/// turned off that is not a name as swoosh stores one (capitals never match the folded name served).
#[test]
fn a_serve_toml_swoosh_did_not_write_is_damaged() {
    let scratch = Scratch::new("damaged");
    for text in [
        "colour = \"blue\"\n",
        "off = \"ping\"\n",
        "off = [\"not a name\"]\n",
        "off = [\"SSH\"]\n",
        "off = [\"a.b\"]\n",
        "relay = 3\n",
        "not toml\n",
    ] {
        std::fs::write(scratch.home.serve_toml(), text).unwrap();
        let read = ServeToml::read(&scratch.home);
        assert!(
            matches!(read, Err(super::ServeTomlError::Damaged { .. })),
            "{text:?} is damaged"
        );
        assert_eq!(
            read.unwrap_err().to_string(),
            format!(
                "{} was changed outside swoosh: refusing to use it",
                scratch.home.serve_toml().display()
            )
        );
    }
}

/// A file removed between the watcher's stat and its read reads as absent: what was held stays, so the
/// race never turns a service back on.
#[test]
fn a_file_removed_between_stat_and_read_keeps_what_was_held() {
    for initially_absent in [true, false] {
        let scratch = Scratch::new("removed-mid-read");
        if !initially_absent {
            scratch.only_off("ping");
        }
        let watcher = LiveServeToml::load(&scratch.home).expect("load");
        watcher.serving(&bare(&scratch));
        let accepted = watcher.held();
        let path = scratch.home.serve_toml();
        scratch.only_off("ping");
        let statted = nauthy::FileStamp::of(&std::fs::metadata(&path).unwrap());
        std::fs::remove_file(&path).unwrap();
        {
            let mut state = watcher.lock();
            state.take(&path, super::read_stamped(&path), statted);
            state.last_stat = Some(std::time::Instant::now());
        }
        assert_eq!(watcher.held(), accepted, "the raced read changes no data");
        assert_bound_decisions(
            &watcher,
            &[("ping", "ping:", true), ("speed", "speed:", true)],
            &["ping", "speed"],
        );
        watcher.lock().last_stat = None;
        assert!(
            !watcher.is_enabled(&service("speed")),
            "continued absence cannot recover a failed observed read"
        );
    }
}

/// A damaged file is read once and then held as read until it changes, so a running `serve` does not
/// re-read and re-parse it at every stat.
#[test]
fn a_damaged_serve_toml_is_read_once_until_it_changes() {
    let scratch = Scratch::new("damaged-once");
    scratch.only_off("ping");
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    let path = scratch.home.serve_toml();
    std::fs::write(&path, "off = 3\n").unwrap();
    past_the_debounce();
    assert_eq!(watcher.off(), ["ping"], "still off once damaged");
    let damaged = nauthy::FileStamp::of(&std::fs::metadata(&path).unwrap());
    assert!(damaged.is_some(), "the damaged file has a stamp");
    assert_eq!(
        watcher.shared.state.lock().unwrap().stamp,
        damaged,
        "the damaged file is marked as read"
    );
}

/// What a run starts with and binds over is the watcher's first read, even once the file changed and the
/// watcher re-read it: a slow start never binds over a later read than the one its services came from.
#[test]
fn the_first_read_stays_what_load_read() {
    let scratch = Scratch::new("first-read");
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        file.relay = Some("https://relay.example".parse().expect("a valid relay url"));
    })
    .expect("write serve.toml");
    past_the_debounce();
    assert!(
        watcher.held().relay.is_some(),
        "the watcher read the change"
    );
    assert_eq!(watcher.first_read().relay, None, "the first read is kept");
}

#[test]
fn local_detail_preserves_startup_targets_across_saved_refresh() {
    let scratch = Scratch::new("detail-provenance");
    list(&scratch, &["api=tcp:old:1", "gone=ping:", "off=ping:"]);
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    list(&scratch, &["api=tcp:next:2", "off=ping:", "added=ping:"]);
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        file.off.extend(["off".to_owned(), "unbound".to_owned()]);
    })
    .unwrap();
    watcher.lock().last_stat = None;
    let snapshot = watcher.local_service_snapshot().unwrap();
    assert_eq!(snapshot.len(), 3);
    assert_eq!(snapshot.get("api").unwrap().target().as_str(), "tcp:old:1");
    assert!(!snapshot.get("api").unwrap().refused());
    assert!(snapshot.get("gone").unwrap().refused());
    assert!(snapshot.get("off").unwrap().refused());
    assert!(!snapshot.contains("unbound") && !snapshot.contains("added"));
    assert_eq!(
        ServeToml::read(&scratch.home).unwrap().services.unwrap()[0],
        "api=tcp:next:2"
    );
    let replacement = LiveServeToml::load(&scratch.home).unwrap();
    replacement.serving(&bare(&scratch));
    let next = replacement.local_service_snapshot().unwrap();
    assert_eq!(next.get("api").unwrap().target().as_str(), "tcp:next:2");
    assert!(!next.contains("gone"));
    assert_eq!(snapshot.get("api").unwrap().target().as_str(), "tcp:old:1");
}

#[test]
fn local_detail_distinguishes_missing_empty_and_inconsistent_startup() {
    use crate::serve::control_codec::LocalDetailError;
    let scratch = Scratch::new("detail-state");
    list(&scratch, &[]);
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    assert!(matches!(
        watcher.local_service_snapshot(),
        Err(LocalDetailError::MissingStartup)
    ));
    watcher.serving(&bare(&scratch));
    assert!(watcher.local_service_snapshot().unwrap().is_empty());
    watcher.lock().running = None;
    assert!(matches!(
        watcher.local_service_snapshot(),
        Err(LocalDetailError::InconsistentState)
    ));
}

#[test]
fn local_detail_limits_do_not_change_valid_saved_configuration() {
    use crate::serve::control_codec::{LocalDetailError, LocalDetailLimit};
    let scratch = Scratch::new("detail-large");
    let entries: Vec<_> = (0..257).map(|n| format!("s{n:03}=ping:")).collect();
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        file.services = Some(Vec::clone(&entries))
    })
    .unwrap();
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    assert!(matches!(
        watcher.local_service_snapshot(),
        Err(LocalDetailError::LimitExceeded(
            LocalDetailLimit::BoundCount
        ))
    ));
    assert_eq!(
        ServeToml::read(&scratch.home).unwrap().services.unwrap(),
        entries
    );
    assert!(watcher.is_enabled(&service("s000")));
}

#[test]
fn local_detail_waits_for_one_atomic_watcher_update() {
    use std::sync::{Arc, Barrier, mpsc};
    let scratch = Scratch::new("detail-atomic");
    list(&scratch, &["a=ping:", "b=ping:"]);
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    let mut held = watcher.lock();
    let ready = Arc::new(Barrier::new(2));
    let (send, recv) = mpsc::channel();
    let reader = std::thread::spawn({
        let watcher = LiveServeToml::clone(&watcher);
        let ready = Arc::clone(&ready);
        move || {
            ready.wait();
            send.send(watcher.local_service_snapshot()).unwrap();
        }
    });
    ready.wait();
    assert!(recv.try_recv().is_err());
    held.file.off.insert("a".to_owned());
    held.running.as_mut().unwrap().remove("b");
    drop(held);
    let snapshot = recv.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    reader.join().unwrap();
    assert!(snapshot.get("a").unwrap().refused());
    assert!(snapshot.get("b").unwrap().refused());
}

/// Assert decisions through the real gate and both observation APIs, including original bound targets.
fn assert_bound_decisions(watcher: &LiveServeToml, bound: &[(&str, &str, bool)], refused: &[&str]) {
    let snapshot = watcher.local_service_snapshot().unwrap();
    assert_eq!(snapshot.len(), bound.len(), "refresh constructs no routes");
    assert_eq!(watcher.refused(), refused, "the refused set matches policy");
    for &(name, target, denied) in bound {
        assert_eq!(
            watcher.is_enabled(&service(name)),
            !denied,
            "the admission guard must distinguish failure for {name}"
        );
        let entry = snapshot
            .get(name)
            .expect("the bound service remains visible");
        assert_eq!(entry.target().as_str(), target, "no target substitution");
        assert_eq!(
            entry.refused(),
            denied,
            "detail agrees with the gate for {name}"
        );
    }
}

#[test]
fn initial_absence_is_not_later_deletion() {
    let scratch = Scratch::new("initial-absence");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[("ping", "ping:", false), ("speed", "speed:", false)],
        &[],
    );
    scratch.only_off("ping");
    watcher.lock().last_stat = None;
    assert!(!watcher.is_enabled(&service("ping")));
    assert!(watcher.is_enabled(&service("speed")));
    let accepted = watcher.held();
    std::fs::remove_file(scratch.home.serve_toml()).unwrap();
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[("ping", "ping:", true), ("speed", "speed:", true)],
        &["ping", "speed"],
    );
    assert_eq!(watcher.held(), accepted);
    assert_eq!(watcher.off(), ["ping"], "failure invents no off mark");
    assert!(
        !scratch.home.serve_toml().exists(),
        "the reader writes nothing"
    );
}

#[test]
fn an_unstamped_initial_read_is_not_absence() {
    let scratch = Scratch::new("unstamped-initial");
    list(&scratch, &["api=tcp:old:1", "off=ping:"]);
    scratch.only_off("off");
    let path = scratch.home.serve_toml();
    let accepted = ServeToml::read(&scratch.home).unwrap();
    let started = bare(&scratch);
    let watcher = LiveServeToml::from_read(
        path.clone(),
        Some((accepted.clone(), None)),
        Path::new("/work"),
    )
    .unwrap();
    assert!(matches!(watcher.lock().policy, super::LivePolicy::Accepted));
    assert!(watcher.lock().stamp.is_none());
    assert_eq!(watcher.first_read(), &accepted);
    assert!(watcher.is_enabled(&service("api")));
    assert!(!watcher.is_enabled(&service("off")));

    std::fs::remove_file(&path).unwrap();
    watcher.serving(&started);
    assert_bound_decisions(
        &watcher,
        &[("api", "tcp:old:1", true), ("off", "ping:", true)],
        &["api", "off"],
    );
    assert_eq!(watcher.held(), accepted);
    assert_eq!(watcher.off(), ["off"]);
}

#[test]
fn an_unstamped_valid_read_recovers_policy() {
    let scratch = Scratch::new("unstamped-recovery");
    list(&scratch, &["api=tcp:old:1", "gone=ping:", "off=ping:"]);
    scratch.only_off("off");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    let path = scratch.home.serve_toml();
    std::fs::write(&path, "off = 3\n").unwrap();
    watcher.lock().last_stat = None;
    assert!(!watcher.is_enabled(&service("api")), "reach failed policy");

    std::fs::write(
        &path,
        "services = ['api=tcp:next:2', 'off=ping:', 'added=ping:']\noff = ['api']\n",
    )
    .unwrap();
    let (accepted, _) = super::read_stamped(&path)
        .unwrap()
        .expect("existing policy");
    {
        let mut state = watcher.lock();
        state.take(&path, Ok(Some((accepted.clone(), None))), None);
        state.last_stat = Some(std::time::Instant::now());
        assert!(matches!(state.policy, super::LivePolicy::Accepted));
        assert!(
            state.stamp.is_none(),
            "no stamp means retry, not read failure"
        );
    }
    assert_bound_decisions(
        &watcher,
        &[
            ("api", "tcp:old:1", true),
            ("gone", "ping:", true),
            ("off", "ping:", false),
        ],
        &["api", "gone"],
    );
    assert_eq!(watcher.held(), accepted);
    assert_eq!(watcher.off(), ["api"]);
    assert_eq!(watcher.waiting().added, ["added"]);
    assert_eq!(watcher.waiting().changed, ["api"]);
    assert!(!watcher.local_service_snapshot().unwrap().contains("added"));

    scratch.only_off("off");
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[
            ("api", "tcp:old:1", false),
            ("gone", "ping:", true),
            ("off", "ping:", true),
        ],
        &["gone", "off"],
    );
}

#[test]
fn stat_failure_requires_a_valid_read_to_recover() {
    let scratch = Scratch::new("stat-failure");
    list(&scratch, &["api=tcp:old:1", "off=ping:"]);
    scratch.only_off("off");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    let accepted = watcher.held();
    let running = watcher.lock().running.clone();
    let stamp = watcher.lock().stamp;
    // A non-directory parent deterministically fails stat without relying on effective UID permissions.
    let parked = scratch.dir.with_extension("parked");
    std::fs::rename(&scratch.dir, &parked).unwrap();
    std::fs::write(&scratch.dir, b"not a directory").unwrap();
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[("api", "tcp:old:1", true), ("off", "ping:", true)],
        &["api", "off"],
    );
    assert_eq!(watcher.held(), accepted);
    assert_eq!(watcher.lock().running, running);
    assert_eq!(watcher.off(), ["off"]);
    assert!(
        watcher.lock().stamp.is_none(),
        "stat failure must retry a read"
    );
    std::fs::remove_file(&scratch.dir).unwrap();
    std::fs::rename(&parked, &scratch.dir).unwrap();
    assert_eq!(
        nauthy::FileStamp::of(&std::fs::metadata(scratch.home.serve_toml()).unwrap()),
        stamp,
        "stat recovery need not change the file stamp"
    );
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[("api", "tcp:old:1", false), ("off", "ping:", true)],
        &["off"],
    );
}

/// Only a file that is absent serves the defaults with no file: a stat that fails for any other reason,
/// with no file ever read, refuses every service the run serves, as a failed read of a file does.
#[test]
fn a_failed_stat_after_initial_absence_refuses_what_the_run_serves() {
    let scratch = Scratch::new("absent-stat-failure");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    watcher.lock().last_stat = None;
    assert!(
        watcher.is_enabled(&service("ping")),
        "absence serves the defaults"
    );
    // A non-directory parent deterministically fails stat without relying on effective UID permissions.
    let parked = scratch.dir.with_extension("parked");
    std::fs::rename(&scratch.dir, &parked).unwrap();
    std::fs::write(&scratch.dir, b"not a directory").unwrap();
    watcher.lock().last_stat = None;
    let ping = watcher.is_enabled(&service("ping"));
    let speed = watcher.is_enabled(&service("speed"));
    let control = watcher.is_enabled(&service("control.stop"));
    std::fs::remove_file(&scratch.dir).unwrap();
    std::fs::rename(&parked, &scratch.dir).unwrap();
    assert!(!ping, "a failed stat is not absence");
    assert!(!speed, "every service the run serves is refused");
    assert!(control, "the node's own routes stay open");
}

/// A writer the log is captured into, so a test can count the lines a run logs.
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A read that keeps failing is logged once, when it starts to fail, and once when the file reads again:
/// a failure retried at every stat never logs at every stat.
#[test]
fn a_failing_read_is_logged_once_and_its_recovery_once() {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = std::sync::Arc::clone(&log);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || LogCapture(std::sync::Arc::clone(&writer)))
        .finish();
    let _capturing = tracing::subscriber::set_default(subscriber);

    let scratch = Scratch::new("logged-once");
    list(&scratch, &["api=tcp:old:1"]);
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    let parked = scratch.dir.with_extension("parked");
    std::fs::rename(&scratch.dir, &parked).unwrap();
    std::fs::write(&scratch.dir, b"not a directory").unwrap();
    for _ in 0..3 {
        watcher.lock().last_stat = None;
        assert!(!watcher.is_enabled(&service("api")), "each stat fails");
    }
    std::fs::remove_file(&scratch.dir).unwrap();
    std::fs::rename(&parked, &scratch.dir).unwrap();
    watcher.lock().last_stat = None;
    assert!(watcher.is_enabled(&service("api")), "a good read recovers");

    let log = String::from_utf8(log.lock().unwrap().clone()).unwrap();
    let count = |what: &str| log.lines().filter(|line| line.contains(what)).count();
    assert_eq!(count("serve.toml cannot be read"), 1, "{log}");
    assert_eq!(count("serve.toml can be read again"), 1, "{log}");
}

// `core::io::ErrorKind` is still unstable, as in `read_stamped`.
#[allow(clippy::std_instead_of_core)]
#[test]
fn read_failure_retains_data_and_retries_the_same_stamp() {
    let scratch = Scratch::new("read-failure");
    list(&scratch, &["api=tcp:old:1", "off=ping:"]);
    scratch.only_off("off");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    let accepted = watcher.held();
    let path = scratch.home.serve_toml();
    {
        let mut state = watcher.lock();
        let stamp = state.stamp;
        state.take(
            &path,
            Err(super::ServeTomlError::Io {
                path: path.clone(),
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            }),
            stamp,
        );
        state.last_stat = Some(std::time::Instant::now());
        assert!(
            state.stamp.is_none(),
            "I/O failure must not cache the attempted stamp"
        );
    }
    assert_bound_decisions(
        &watcher,
        &[("api", "tcp:old:1", true), ("off", "ping:", true)],
        &["api", "off"],
    );
    assert_eq!(watcher.held(), accepted);
    assert_eq!(ServeToml::read(&scratch.home).unwrap(), accepted);
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[("api", "tcp:old:1", false), ("off", "ping:", true)],
        &["off"],
    );
}

#[test]
fn invalid_policy_is_not_empty_or_default_policy() {
    let scratch = Scratch::new("invalid-policy");
    list(&scratch, &["api=tcp:old:1", "off=ping:"]);
    scratch.only_off("off");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    let accepted = watcher.held();
    let running = watcher.lock().running.clone();
    for text in [
        "not toml\n",
        "off = 3\n",
        "relay = 'not a url'\n",
        "services = ['--public']\n",
        "services = ['api=tcp:next:2', 'bad=ping:80']\noff = []\n",
        "services = ['api=tcp:next:2', 'bad=proxy:https://user:secret@host.test']\noff = []\n",
    ] {
        std::fs::write(scratch.home.serve_toml(), text).unwrap();
        watcher.lock().last_stat = None;
        assert_bound_decisions(
            &watcher,
            &[("api", "tcp:old:1", true), ("off", "ping:", true)],
            &["api", "off"],
        );
        assert_eq!(watcher.held(), accepted);
        assert_eq!(watcher.lock().running, running);
        assert_eq!(watcher.off(), ["off"]);
        let stamp = nauthy::FileStamp::of(&std::fs::metadata(scratch.home.serve_toml()).unwrap());
        assert_eq!(
            watcher.lock().stamp,
            stamp,
            "rejected contents are marked read"
        );
        watcher.lock().last_stat = None;
        assert!(
            !watcher.is_enabled(&service("api")),
            "unchanged damage remains denied"
        );
        assert_eq!(
            std::fs::read_to_string(scratch.home.serve_toml()).unwrap(),
            text
        );
    }
}

#[test]
fn failed_policy_preserves_saved_and_bound_targets_separately() {
    let scratch = Scratch::new("failed-targets");
    list(&scratch, &["api=tcp:old:1", "off=ping:"]);
    scratch.only_off("off");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    list(&scratch, &["api=tcp:next:2", "off=ping:", "added=ping:"]);
    watcher.lock().last_stat = None;
    let accepted = watcher.held();
    let waiting = watcher.waiting();
    assert_eq!(waiting.added, ["added"]);
    assert_eq!(waiting.changed, ["api"]);
    std::fs::write(scratch.home.serve_toml(), "off = 3\n").unwrap();
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[("api", "tcp:old:1", true), ("off", "ping:", true)],
        &["api", "off"],
    );
    assert_eq!(
        watcher.held(),
        accepted,
        "saved targets remain independently inspectable"
    );
    assert_eq!(watcher.waiting(), waiting);
    assert_eq!(watcher.off(), ["off"], "refusal is not a saved off edit");
}

#[test]
fn valid_policy_recovers_off_and_removal_without_constructing_routes() {
    let scratch = Scratch::new("valid-recovery");
    list(&scratch, &["api=tcp:old:1", "gone=ping:", "off=ping:"]);
    scratch.only_off("off");
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    watcher.serving(&bare(&scratch));
    std::fs::write(scratch.home.serve_toml(), "off = 3\n").unwrap();
    watcher.lock().last_stat = None;
    assert!(
        !watcher.is_enabled(&service("api")),
        "reach the failed-policy guard first"
    );
    std::fs::write(
        scratch.home.serve_toml(),
        "services = ['api=tcp:next:2', 'off=ping:', 'added=ping:']\noff = ['api']\n",
    )
    .unwrap();
    watcher.lock().last_stat = None;
    assert_bound_decisions(
        &watcher,
        &[
            ("api", "tcp:old:1", true),
            ("gone", "ping:", true),
            ("off", "ping:", false),
        ],
        &["api", "gone"],
    );
    assert_eq!(watcher.off(), ["api"]);
    assert_eq!(watcher.waiting().added, ["added"]);
    assert_eq!(watcher.waiting().changed, ["api"]);
    assert!(!watcher.local_service_snapshot().unwrap().contains("added"));
    assert_eq!(watcher.held(), ServeToml::read(&scratch.home).unwrap());
}

#[test]
fn failed_user_policy_leaves_internal_routes_enabled() {
    for entries in [&[][..], &["a=ping:"][..], &["a=ping:", "b=ping:"][..]] {
        let scratch = Scratch::new("internal-exemption");
        list(&scratch, entries);
        let watcher = LiveServeToml::load(&scratch.home).unwrap();
        watcher.serving(&bare(&scratch));
        std::fs::write(scratch.home.serve_toml(), "off = 3\n").unwrap();
        watcher.lock().last_stat = None;
        assert_eq!(watcher.refused().len(), entries.len());
        for name in [
            "control.stop",
            "control.services",
            "control.reach",
            "control.pickup",
        ] {
            assert!(
                watcher.is_enabled(&service(name)),
                "internal route {name} remains enabled"
            );
        }
        let snapshot = watcher.local_service_snapshot().unwrap();
        assert_eq!(snapshot.len(), entries.len());
        for entry in entries {
            let (name, _) = entry.split_once('=').unwrap();
            assert!(
                !watcher.is_enabled(&service(name)),
                "only bound user routes are denied"
            );
            assert!(snapshot.get(name).unwrap().refused());
        }
    }
}

/// Write `services` as the file's list, through the writer `serve` uses, keeping every other field.
fn list(scratch: &Scratch, services: &[&str]) {
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        file.services = Some(services.iter().map(|&entry| entry.to_owned()).collect());
    })
    .expect("write serve.toml");
}

/// What a bare `serve` of `scratch`'s home starts with now.
fn bare(scratch: &Scratch) -> crate::serve::Started {
    let file = ServeToml::read(&scratch.home).expect("read serve.toml");
    crate::serve::Started::bare(&file).expect("the list starts")
}

/// A service dropped from `services` while `serve` runs is refused on its next stream, as one turned off
/// is, and the status reports it with the services off; put back, it is served again. A route no entry
/// bound (the node's own) is never refused for being absent from the list.
#[test]
fn a_service_removed_from_serve_toml_refuses_new_streams() {
    let scratch = Scratch::new("removed");
    list(&scratch, &["files=recv:", "ping=ping:"]);
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));
    assert!(watcher.is_enabled(&service("files")), "served at the start");

    list(&scratch, &["ping=ping:"]);
    past_the_debounce();
    assert!(
        !watcher.is_enabled(&service("files")),
        "refused once removed"
    );
    assert!(
        watcher.is_enabled(&service("ping")),
        "the rest still served"
    );
    assert!(
        watcher.is_enabled(&service("control.stop")),
        "the node's own route is no entry's"
    );
    assert_eq!(watcher.refused(), ["files"], "the status reports it");
    assert!(watcher.waiting().is_empty(), "a removal waits for nothing");

    list(&scratch, &["files=recv:", "ping=ping:"]);
    past_the_debounce();
    assert!(
        watcher.is_enabled(&service("files")),
        "served once put back"
    );
}

/// An emptied `services` runs nothing, never the default: `service rm` of the last entry refuses every
/// service the run bound, at once, and `ping` and `speed` do not come back on their own.
#[test]
fn an_emptied_services_refuses_every_service_it_served() {
    let scratch = Scratch::new("emptied");
    list(&scratch, &["ping=ping:", "speed=speed:"]);
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));

    list(&scratch, &[]);
    past_the_debounce();
    assert!(!watcher.is_enabled(&service("ping")), "ping is refused");
    assert!(!watcher.is_enabled(&service("speed")), "speed is refused");
    assert_eq!(watcher.refused(), ["ping", "speed"]);
}

/// A `services` that lists a service that is not one is a failed read, as a damaged file is: the list held
/// is kept rather than read as every service removed, and the services the run serves are refused until a
/// read succeeds.
#[test]
fn a_services_entry_that_is_not_a_service_refuses_what_the_run_serves() {
    let scratch = Scratch::new("not-a-service");
    list(&scratch, &["files=recv:"]);
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));

    list(&scratch, &["--public"]);
    past_the_debounce();
    assert!(
        !watcher.is_enabled(&service("files")),
        "invalid policy denies new admissions despite retaining the list"
    );
    assert_eq!(
        watcher.held().services.as_deref(),
        Some(&["files=recv:".to_owned()][..]),
        "the list held is kept"
    );
}

#[test]
fn invocation_selection_is_admitted_without_replacing_saved_services() {
    let scratch = Scratch::new("no-launch-write");
    list(&scratch, &["ping=ping:"]);
    let before = std::fs::read(scratch.home.serve_toml()).unwrap();
    let watcher = LiveServeToml::load(&scratch.home).unwrap();
    let started = crate::serve::Started::Named(vec!["files=recv:".to_owned()]);
    watcher.serving(&started);
    assert_bound_decisions(&watcher, &[("files", "recv:", false)], &[]);
    assert_eq!(watcher.waiting().added, ["ping"]);
    assert_eq!(std::fs::read(scratch.home.serve_toml()).unwrap(), before);
    assert_eq!(bare(&scratch).entries(), ["ping=ping:"]);
}

#[test]
fn captured_selection_controls_membership_but_never_off_or_failed_policy() {
    use crate::serve::Started;
    for started in [
        Started::Named(vec!["api=tcp:old:1".to_owned(), "gone=ping:".to_owned()]),
        Started::Resumed(vec!["api=tcp:old:1".to_owned(), "gone=ping:".to_owned()]),
        Started::Default,
    ] {
        let scratch = Scratch::new("selection-policy-matrix");
        let original = started.entries();
        let refs: Vec<_> = original.iter().map(String::as_str).collect();
        list(&scratch, &refs);
        let before = std::fs::read(scratch.home.serve_toml()).unwrap();
        let watcher = LiveServeToml::load(&scratch.home).unwrap();
        watcher.serving(&started);
        let invocation = matches!(started, Started::Named(_));
        let path = scratch.home.serve_toml();
        let first = started.names()[0].clone();
        let changed = ServeToml {
            services: Some(vec![format!("{first}=echo:"), "added=ping:".to_owned()]),
            ..ServeToml::default()
        };
        {
            let mut held = watcher.lock();
            held.take(&path, Ok(Some((changed.clone(), None))), None);
            held.last_stat = Some(std::time::Instant::now());
        }
        let snapshot = watcher.local_service_snapshot().unwrap();
        assert_eq!(snapshot.len(), original.len());
        assert!(!snapshot.contains("added"));
        for entry in &original {
            let (name, target) = entry.split_once('=').unwrap();
            let denied = !invocation && name != first;
            assert_eq!(watcher.is_enabled(&service(name)), !denied);
            assert_eq!(snapshot.get(name).unwrap().target().as_str(), target);
            assert_eq!(snapshot.get(name).unwrap().refused(), denied);
        }
        {
            let mut held = watcher.lock();
            let mut off = changed.clone();
            off.off.insert(first.clone());
            held.take(&path, Ok(Some((off, None))), None);
        }
        assert!(!watcher.is_enabled(&service(&first)));
        {
            let mut held = watcher.lock();
            held.take(
                &path,
                Err(super::ServeTomlError::Damaged { path: path.clone() }),
                None,
            );
        }
        assert!(watcher.saved_services().is_none());
        for name in started.names() {
            assert!(!watcher.is_enabled(&service(&name)));
        }
        assert!(watcher.is_enabled(&service("control.stop")));
        {
            let mut held = watcher.lock();
            held.take(
                &path,
                Ok(Some((
                    ServeToml {
                        services: Some(vec![]),
                        ..ServeToml::default()
                    },
                    None,
                ))),
                None,
            );
        }
        for name in started.names() {
            assert_eq!(watcher.is_enabled(&service(&name)), invocation);
        }
        assert!(watcher.saved_services().is_some());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn malformed_initial_saved_services_are_not_repaired_by_explicit_startup() {
    use crate::serve::Started;
    for entries in [&["db"][..], &["ping", "ping"][..]] {
        let scratch = Scratch::new("malformed-explicit-startup");
        list(&scratch, entries);
        let before = std::fs::read(scratch.home.serve_toml()).unwrap();
        assert!(Started::positional(&["api=tcp:bound:1".into()], Path::new("/work")).is_ok());
        assert!(matches!(
            LiveServeToml::load(&scratch.home),
            Err(super::ServeTomlError::Definition(_))
        ));
        assert_eq!(std::fs::read(scratch.home.serve_toml()).unwrap(), before);
    }
}

#[test]
fn malformed_live_membership_retains_accepted_policy_until_valid_recovery() {
    for entries in [&["db"][..], &["ping", "ping"][..]] {
        let scratch = Scratch::new("malformed-live-membership");
        list(&scratch, &["api=tcp:saved:1", "off=ping:"]);
        scratch.only_off("off");
        let watcher = LiveServeToml::load(&scratch.home).unwrap();
        assert!(matches!(watcher.lock().policy, super::LivePolicy::Accepted));
        watcher.serving(&Started::Named(vec![
            "api=tcp:bound:1".into(),
            "off=ping:".into(),
        ]));
        let accepted = watcher.held();
        let running = watcher.lock().running.clone();
        assert_bound_decisions(
            &watcher,
            &[("api", "tcp:bound:1", false), ("off", "ping:", true)],
            &["off"],
        );
        // A rejected update must not clear the accepted off policy.
        std::fs::write(
            scratch.home.serve_toml(),
            format!("services = {entries:?}\noff = []\n"),
        )
        .unwrap();
        let rejected = std::fs::read(scratch.home.serve_toml()).unwrap();
        watcher.lock().last_stat = None;
        assert_bound_decisions(
            &watcher,
            &[("api", "tcp:bound:1", true), ("off", "ping:", true)],
            &["api", "off"],
        );
        assert!(matches!(watcher.lock().policy, super::LivePolicy::Failed));
        assert_eq!(watcher.held(), accepted);
        assert_eq!(watcher.lock().running, running);
        assert_eq!(watcher.off(), ["off"]);
        assert!(watcher.saved_services().is_none());
        assert!(watcher.is_enabled(&service("control.stop")));
        assert_eq!(std::fs::read(scratch.home.serve_toml()).unwrap(), rejected);

        std::fs::write(
            scratch.home.serve_toml(),
            "services = ['api=tcp:next:2', 'other=ping:']\noff = []\n",
        )
        .unwrap();
        let recovered = std::fs::read(scratch.home.serve_toml()).unwrap();
        watcher.lock().last_stat = None;
        assert_bound_decisions(
            &watcher,
            &[("api", "tcp:bound:1", false), ("off", "ping:", false)],
            &[],
        );
        assert!(matches!(watcher.lock().policy, super::LivePolicy::Accepted));
        assert!(watcher.off().is_empty());
        assert_eq!(
            watcher.saved_services().unwrap().entries(),
            ["api=tcp:next:2", "other=ping:"]
        );
        assert_eq!(watcher.waiting().added, ["other"]);
        assert_eq!(watcher.waiting().changed, ["api"]);
        assert!(watcher.is_enabled(&service("control.stop")));
        assert_eq!(std::fs::read(scratch.home.serve_toml()).unwrap(), recovered);
    }
}

#[cfg(not(feature = "ssh"))]
#[test]
fn unsupported_ssh_cannot_establish_or_replace_accepted_policy() {
    for entry in ["ssh", "ssh=sshd:"] {
        let path = PathBuf::from("/unused/serve.toml");
        let unsupported = ServeToml {
            services: Some(vec![entry.into()]),
            ..ServeToml::default()
        };
        assert!(matches!(
            LiveServeToml::from_read(
                PathBuf::clone(&path),
                Some((ServeToml::clone(&unsupported), None)),
                Path::new("/work"),
            ),
            Err(super::ServeTomlError::Definition(_))
        ));
        let accepted = ServeToml {
            services: Some(vec!["api=echo:".into()]),
            off: ["api".into()].into(),
            ..ServeToml::default()
        };
        let watcher = LiveServeToml::from_read(
            PathBuf::clone(&path),
            Some((ServeToml::clone(&accepted), None)),
            Path::new("/work"),
        )
        .unwrap();
        let mut held = watcher.lock();
        held.take(&path, Ok(Some((unsupported, None))), None);
        assert!(matches!(held.policy, super::LivePolicy::Failed));
        assert_eq!(held.file, accepted);
        assert_eq!(held.running.as_ref().unwrap()["api"], "echo:");
    }
}

/// A service added to `services`, and a relay or a resolver changed, wait for the next `serve`: the
/// watcher names each, and the line says so. A relay given at the start is held as the one bound, so it
/// never reads as a change.
#[test]
fn what_a_running_serve_cannot_apply_is_named() {
    let scratch = Scratch::new("waiting");
    list(&scratch, &["ping=ping:"]);
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        file.relay = Some("https://relay.example".parse().expect("a relay"));
    })
    .expect("write serve.toml");
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));
    assert!(
        watcher.waiting().is_empty(),
        "the bound relay waits for nothing"
    );

    list(&scratch, &["ping=ping:", "speed=speed:", "files=recv:"]);
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        file.relay = Some("https://other.example".parse().expect("a relay"));
    })
    .expect("write serve.toml");
    past_the_debounce();
    let waiting = watcher.waiting();
    assert_eq!(
        waiting,
        super::Waiting {
            relay: true,
            resolver: false,
            added: vec!["files".to_owned(), "speed".to_owned()],
            changed: Vec::new(),
        }
    );
    assert!(watcher.is_enabled(&service("ping")), "ping still served");
    assert_eq!(
        waiting.to_string(),
        "the changed relay in serve.toml takes effect at the next start\nsaved service files applies to the next bare serve\nsaved service speed applies to the next bare serve"
    );
    assert_eq!(
        super::Waiting {
            resolver: true,
            ..super::Waiting::default()
        }
        .to_string(),
        "the changed resolver in serve.toml takes effect at the next start"
    );
}

/// A shell added to `serve.toml` under a name whose live links were made for another target is not bound
/// while `serve` runs (nothing added is), and the warning that start will print is what the run prints.
#[cfg(feature = "ssh")]
#[test]
fn a_live_add_of_sshd_over_other_links_keeps_the_running_set() {
    use crate::grants::{Delegation, GrantKind, GrantRecord, Grants, LinksForAnother};

    let scratch = Scratch::new("live-shell");
    list(&scratch, &["ping=ping:"]);
    let holder = crate::testkit::TestNode::seeded(0x61).node_id().to_string();
    Grants::at(scratch.home.links())
        .append(
            &crate::testkit::lock(),
            &GrantRecord {
                target: service("ssh"),
                serves: Some("tcp:localhost:22".parse().expect("a target")),
                kind: GrantKind::Device,
                delegation: Delegation::Sealed,
                holder: holder.clone(),
                root_id: nauthy::RevocationId::from_bytes(vec![0x61]),
                expiry: std::time::SystemTime::now() + Duration::from_secs(3600),
            },
        )
        .expect("record a link for ssh as a forward");
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));

    list(&scratch, &["ping=ping:", "ssh"]);
    past_the_debounce();
    let waiting = watcher.waiting();
    assert_eq!(waiting.added, ["ssh"], "ssh waits for the next start");
    assert!(watcher.is_enabled(&service("ping")), "ping is still served");
    let links = LinksForAnother::among_changed(&scratch.home, &watcher.held(), &waiting.added)
        .expect("the ledger reads")
        .expect("that start would warn of the shell");
    assert_eq!(
        links.to_string(),
        "ssh has live links made when it served tcp:localhost:22, and they are refused while it serves \
         something else (swoosh status lists them under links you shared)"
    );
    assert!(
        !links.to_string().contains(&holder),
        "no holder's key is printed"
    );
}

/// A running name retargeted in `serve.toml` waits for the next start like an added one: the watcher names
/// it, and when that start would warn of links made for the old target, the run prints that too.
#[cfg(feature = "ssh")]
#[test]
fn a_retarget_of_a_running_name_is_named_and_checked() {
    use crate::grants::{Delegation, GrantKind, GrantRecord, Grants, LinksForAnother};

    let scratch = Scratch::new("retarget");
    list(&scratch, &["ping=ping:", "ssh=tcp:localhost:22"]);
    Grants::at(scratch.home.links())
        .append(
            &crate::testkit::lock(),
            &GrantRecord {
                target: service("ssh"),
                serves: Some("tcp:localhost:22".parse().expect("a target")),
                kind: GrantKind::Bearer,
                delegation: Delegation::Delegable,
                holder: crate::grants::ANYONE.to_owned(),
                root_id: nauthy::RevocationId::from_bytes(vec![0x62]),
                expiry: std::time::SystemTime::now() + Duration::from_secs(3600),
            },
        )
        .expect("record a link for ssh as a forward");
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));

    list(&scratch, &["ping=ping:", "ssh=sshd:"]);
    past_the_debounce();
    let waiting = watcher.waiting();
    assert_eq!(
        (waiting.added.as_slice(), waiting.changed.as_slice()),
        (&[][..], &["ssh".to_owned()][..]),
        "ssh's new target waits for the next start"
    );
    assert_eq!(
        waiting.to_string(),
        "saved service ssh applies to the next bare serve"
    );
    let links = LinksForAnother::among_changed(&scratch.home, &watcher.held(), &waiting.changed)
        .expect("the ledger reads");
    assert!(links.is_some(), "that start would warn of the shell");
}
