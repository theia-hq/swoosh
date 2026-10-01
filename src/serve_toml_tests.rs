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
