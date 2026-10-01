//! What a `serve` starts with: the named list, the recorded one, or the default, and how the record is
//! read and written.

use std::path::{Path, PathBuf};

use super::{ServingError, Started};
use crate::home::Home;

/// A scratch home, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sw-serving-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch home");
        Self(dir)
    }

    fn home(&self) -> Home {
        Home::resolve(Some(self.0.clone())).expect("the scratch home resolves")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn named(entries: &[&str]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| super::service_entry(entry).expect("a service form"))
        .collect()
}

/// A home that never named services serves `ping` and `speed`, and records nothing.
#[test]
fn first_bare_serve_serves_the_default() {
    let scratch = Scratch::new("default");
    let home = scratch.home();
    let started = Started::of(&[], &home, Path::new("/")).expect("a fresh home starts");
    assert_eq!(started, Started::Default);
    assert_eq!(started.entries(), ["ping=ping:", "speed=speed:"]);
    assert!(!started.is_resumed(), "the default is not a resume");
    started
        .record(&crate::testkit::lock(), &home)
        .expect("recording the default is a no-op");
    assert!(
        !home.serving().exists(),
        "a default start writes no list for the next one"
    );
}

/// A named start is recorded, and the next bare start serves exactly that list, marked as a resume.
#[test]
fn a_named_list_is_what_the_next_bare_serve_resumes() {
    let scratch = Scratch::new("resume");
    let home = scratch.home();
    let started = Started::of(&named(&["ssh", "ping"]), &home, Path::new("/")).expect("named");
    started
        .record(&crate::testkit::lock(), &home)
        .expect("recorded");

    let resumed = Started::of(&[], &home, Path::new("/")).expect("resumed");
    assert_eq!(resumed.entries(), ["ssh=sshd:", "ping=ping:"]);
    assert!(
        resumed.is_resumed(),
        "a bare start after a named one resumes it"
    );
}

/// Every line of the record goes through the service-entry parser, never the flag parser: a line that
/// starts with `-` is refused with the file and the line named, and nothing is served from it.
#[test]
fn resumed_list_is_parsed_as_services_never_flags() {
    let scratch = Scratch::new("flags");
    let home = scratch.home();
    for line in ["--public=ssh", "-q", "not a service"] {
        std::fs::write(home.serving(), format!("ssh=sshd:\n{line}\n")).expect("a planted list");
        let refused = Started::of(&[], &home, Path::new("/"));
        let Err(error @ ServingError::NotAService { .. }) = refused else {
            panic!("a `{line}` line must refuse, not serve: {refused:?}");
        };
        assert_eq!(
            error.to_string(),
            format!(
                "{} has a line that is not a service: {line}. Name the services: swoosh serve ssh ping …",
                home.serving().display()
            )
        );
    }
}

/// A path target is recorded absolute, so a service manager started in another directory serves the
/// same files; a `~/…` path is relative like any other (nothing expands it), and a dirless `recv:` (it
/// saves into the inbox), raw `stdin:` and non-path targets are kept as typed.
#[test]
fn resumed_paths_are_absolute() {
    let scratch = Scratch::new("paths");
    let home = scratch.home();
    let cwd = Path::new("/work/here");
    let started = Started::of(
        &named(&[
            "inbox=recv:",
            "drop=recv:.",
            "db=unix:db.sock",
            "logs=file:app.log",
            "live=fifo:pipe+lossy",
            "abs=file:/etc/motd",
            "home=file:~/notes",
            "raw=stdin:",
            "web=tcp:127.0.0.1:8080",
        ]),
        &home,
        cwd,
    )
    .expect("named");
    started
        .record(&crate::testkit::lock(), &home)
        .expect("recorded");
    let recorded = std::fs::read_to_string(home.serving()).expect("the record");
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        [
            "inbox=recv:",
            "drop=recv:/work/here/.",
            "db=unix:/work/here/db.sock",
            "logs=file:/work/here/app.log",
            "live=fifo:/work/here/pipe+lossy",
            "abs=file:/etc/motd",
            "home=file:/work/here/~/notes",
            "raw=stdin:",
            "web=tcp:127.0.0.1:8080",
        ]
    );
}

/// A service one line of the record cannot hold is refused, and nothing is saved: a line break in the
/// cwd or the typed path would read back as more services, and a space at either end would be trimmed.
#[test]
fn a_path_with_a_newline_is_refused_not_recorded() {
    let scratch = Scratch::new("newline");
    let home = scratch.home();
    for (typed, cwd) in [
        ("inbox=recv:.", "/work/dl\nssh=sshd:"),
        ("inbox=recv:dl\nssh=sshd:", "/work"),
        ("logs=file:app.log ", "/work"),
    ] {
        let refused = Started::of(&[typed.to_owned()], &home, Path::new(cwd));
        let Err(error @ ServingError::CannotSave { .. }) = refused else {
            panic!("{typed:?} under {cwd:?} must refuse, not be saved: {refused:?}");
        };
        assert!(
            error.to_string().starts_with("inbox=recv:") || error.to_string().starts_with("logs="),
            "the refusal names the service: {error}"
        );
        assert!(!home.serving().exists(), "nothing is saved");
    }
}

/// A path that is not UTF-8 cannot be saved as the path it names, so it is refused.
#[test]
fn a_cwd_that_is_not_utf8_is_refused_not_recorded() {
    use std::os::unix::ffi::OsStrExt as _;

    let scratch = Scratch::new("utf8");
    let home = scratch.home();
    let cwd = Path::new(std::ffi::OsStr::from_bytes(b"/work/\xff"));
    let refused = Started::of(&["inbox=recv:.".to_owned()], &home, cwd);
    assert!(
        matches!(refused, Err(ServingError::CannotSave { .. })),
        "{refused:?}"
    );
}

/// The record is owner-only: it says what this machine serves.
#[test]
fn the_record_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("mode");
    let home = scratch.home();
    Started::of(&named(&["ping"]), &home, Path::new("/"))
        .expect("named")
        .record(&crate::testkit::lock(), &home)
        .expect("recorded");
    let mode = std::fs::metadata(home.serving())
        .expect("the record")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
