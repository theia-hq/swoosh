//! `serve.toml`: what each writer lands, and what a running `serve` reads of it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::path::PathBuf;

use nauthy::{STAT_DEBOUNCE, Service};
use tightbeam::enabled::EnabledServices as _;

use super::{LiveServeToml, ServeToml};
use crate::home::Home;

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
    let scratch = Scratch::new("removed-mid-read");
    scratch.only_off("ping");
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    let path = scratch.home.serve_toml();
    let statted = nauthy::FileStamp::of(&std::fs::metadata(&path).unwrap());
    std::fs::remove_file(&path).unwrap();
    {
        let mut state = watcher.shared.state.lock().unwrap();
        state.take(&path, super::read_stamped(&path), statted);
    }
    assert_eq!(watcher.held().off, ["ping".to_owned()].into(), "still off");
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

/// Write `services` as the file's list, through the writer `serve` uses, keeping every other field.
fn list(scratch: &Scratch, services: &[&str]) {
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        file.services = services.iter().map(|&entry| entry.to_owned()).collect();
    })
    .expect("write serve.toml");
}

/// What a bare `serve` of `scratch`'s home starts with now.
fn bare(scratch: &Scratch) -> crate::serve::Started {
    let file = ServeToml::read(&scratch.home).expect("read serve.toml");
    crate::serve::Started::bare(&file, &scratch.home.serve_toml()).expect("the list starts")
}

/// A service dropped from `services` while `serve` runs is refused on its next stream, as one turned off
/// is, and the status reports it with the services off; put back, it is served again. A route no entry
/// bound (the node's own) is never refused for being absent from the list.
#[test]
fn a_service_removed_from_serve_toml_refuses_new_streams() {
    let scratch = Scratch::new("removed");
    list(&scratch, &["files=fetch:", "ping=ping:"]);
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

    list(&scratch, &["files=fetch:", "ping=ping:"]);
    past_the_debounce();
    assert!(
        watcher.is_enabled(&service("files")),
        "served once put back"
    );
}

/// Guard: an emptied `services` is the default set a bare `serve` starts with, never nothing, so a hand
/// edit that empties the list does not refuse `ping` and `speed`.
#[test]
fn an_emptied_services_keeps_the_default_set() {
    let scratch = Scratch::new("emptied");
    list(&scratch, &["ping=ping:", "speed=speed:"]);
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));

    list(&scratch, &[]);
    past_the_debounce();
    assert!(watcher.is_enabled(&service("ping")), "ping still served");
    assert!(watcher.is_enabled(&service("speed")), "speed still served");
    assert!(watcher.refused().is_empty());
}

/// A `services` that lists a service that is not one is a read that keeps what was held, as a damaged file
/// is: it never reads as every service removed.
#[test]
fn a_services_entry_that_is_not_a_service_keeps_what_was_held() {
    let scratch = Scratch::new("not-a-service");
    list(&scratch, &["files=fetch:"]);
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    watcher.serving(&bare(&scratch));

    list(&scratch, &["--public"]);
    past_the_debounce();
    assert!(watcher.is_enabled(&service("files")), "still served");
    assert_eq!(
        watcher.held().services,
        ["files=fetch:"],
        "the list held is kept"
    );
}

/// The run's own write of what it was told is held at once, not at the next stat: a `serve` that names
/// its services never refuses them for the list the file held before it wrote, however soon a stream
/// comes.
#[test]
fn the_runs_own_write_is_held_at_once() {
    let scratch = Scratch::new("own-write");
    list(&scratch, &["ping=ping:"]);
    let watcher = LiveServeToml::load(&scratch.home).expect("load");
    past_the_debounce();
    assert!(
        watcher.held().services == ["ping=ping:"],
        "the stat is fresh"
    );

    // `serve files=fetch:`: what it names, recorded once its routes bound, read straight after.
    let started = crate::serve::Started::Named(vec!["files=fetch:".to_owned()]);
    ServeToml::update(&crate::testkit::lock(), &scratch.home, |file| {
        started.record(file);
    })
    .expect("write serve.toml");
    watcher.serving(&started);
    assert!(watcher.is_enabled(&service("files")), "served at once");
    assert!(watcher.waiting().is_empty(), "nothing waits");
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

    list(&scratch, &["ping=ping:", "speed=speed:", "files=fetch:"]);
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
        "the changed relay and the added services files and speed in serve.toml take effect the \
         next time serve starts"
    );
    assert_eq!(
        super::Waiting {
            resolver: true,
            ..super::Waiting::default()
        }
        .to_string(),
        "the changed resolver in serve.toml takes effect the next time serve starts"
    );
}

/// A shell added to `serve.toml` under a name whose live links were made for another target is not bound
/// while `serve` runs (nothing added is), and the warning that start will print is what the run prints.
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
        "ssh has live links made when it served tcp:localhost:22, and they would open a shell: serve the \
         shell under another name, or revoke them first (swoosh status lists them under links you shared)"
    );
    assert!(
        !links.to_string().contains(&holder),
        "no holder's key is printed"
    );
}

/// A running name retargeted in `serve.toml` waits for the next start like an added one: the watcher names
/// it, and when that start would warn of links made for the old target, the run prints that too.
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
        "the changed service ssh in serve.toml takes effect the next time serve starts"
    );
    let links = LinksForAnother::among_changed(&scratch.home, &watcher.held(), &waiting.changed)
        .expect("the ledger reads");
    assert!(links.is_some(), "that start would warn of the shell");
}
