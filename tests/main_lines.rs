// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The lines the binary's entry point prints itself, through the real binary: a refusal's prefix, a bare
//! `swoosh`, and help that names `SWOOSH_HOME` without printing its value.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Run `swoosh <args>` with `SWOOSH_HOME` set to `home`, or unset when `None`.
fn swoosh(args: &[&str], home: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command
        .args(args)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null());
    if let Some(home) = home {
        command.env("SWOOSH_HOME", home);
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A path under the temp dir unique to this test and process. Nothing is created there.
fn scratch(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("swoosh-main-lines-{tag}-{}", std::process::id()))
}

/// A refusal that exits 1 starts with `error: `, the prefix clap prints for a usage error (exit 2).
#[test]
fn a_refusal_starts_with_error_colon() {
    let file = scratch("file");
    std::fs::write(&file, "").unwrap();
    let out = swoosh(&["--home", file.to_str().unwrap(), "status"], None);
    let _ = std::fs::remove_file(&file);

    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).starts_with("error: "),
        "{}",
        text(&out.stderr)
    );
}

/// A refusal still exits 1 when its line cannot be written: here stdout and stderr are one socket
/// whose writing has ended, as `forward -` leaves it after it ends its stdout.
#[test]
fn a_refusal_exits_1_when_stderr_cannot_be_written() {
    use std::os::unix::net::UnixStream;

    let file = scratch("ended-stderr");
    std::fs::write(&file, "").unwrap();
    let (_reader, ended) = UnixStream::pair().unwrap();
    ended.shutdown(std::net::Shutdown::Write).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .args(["--home", file.to_str().unwrap(), "status"])
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(std::os::fd::OwnedFd::from(ended.try_clone().unwrap()))
        .stderr(std::os::fd::OwnedFd::from(ended))
        .status()
        .unwrap();
    let _ = std::fs::remove_file(&file);

    assert_eq!(status.code(), Some(1));
}

/// Colour follows the stream: a refusal's `error:` is styled only where the stream asks for it, never in a
/// pipe, and `NO_COLOR` beats `CLICOLOR_FORCE`. How a terminal's `TERM` counts is `anstream`'s, and a test
/// with no terminal cannot see it.
#[test]
fn colour_follows_the_stream() {
    use clap::builder::styling::{AnsiColor, Style};

    let file = scratch("colour");
    std::fs::write(&file, "").unwrap();
    let refusal = |env: &[(&str, &str)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
        command
            .args(["--home", file.to_str().unwrap(), "status"])
            .env_remove("SWOOSH_HOME")
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR")
            .env_remove("CLICOLOR_FORCE")
            .envs(env.iter().copied())
            .stdin(Stdio::null());
        let out = command.output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        text(&out.stderr)
    };
    let piped = refusal(&[]);
    let forced = refusal(&[("CLICOLOR_FORCE", "1")]);
    let refused = refusal(&[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")]);
    let _ = std::fs::remove_file(&file);

    for plain in [&piped, &refused] {
        assert!(plain.starts_with("error: "), "{plain:?}");
        assert!(!plain.contains('\u{1b}'), "{plain:?}");
    }
    let error = Style::new().bold().fg_color(Some(AnsiColor::Red.into()));
    assert_eq!(
        forced,
        format!(
            "{error}error:{error:#}{}",
            piped.strip_prefix("error:").unwrap()
        )
    );
}

/// A bare `swoosh` is a mistake: its help goes to stderr, stdout stays empty, and it exits 2, with or
/// without `SWOOSH_HOME` set.
#[test]
fn bare_swoosh_prints_help_on_stderr_and_exits_2() {
    let home = scratch("bare");
    for env in [None, Some(home.to_str().unwrap())] {
        let out = swoosh(&[], env);
        assert_eq!(out.status.code(), Some(2), "SWOOSH_HOME {env:?}");
        assert!(
            out.stdout.is_empty(),
            "SWOOSH_HOME {env:?}: {}",
            text(&out.stdout)
        );
        assert!(
            text(&out.stderr).contains("Usage: swoosh"),
            "SWOOSH_HOME {env:?}: {}",
            text(&out.stderr)
        );
    }
}

/// The verbs listed under a help page's `Commands:` heading, `help` left out.
fn listed_verbs(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|line| line.trim_end() != "Commands:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .filter(|verb| *verb != "help")
        .map(str::to_owned)
        .collect()
}

/// With `SWOOSH_HOME=/tmp/x`, no `-h` or `--help` of any listed command prints `/tmp/x`; the root help
/// still names the variable.
#[test]
fn help_never_shows_the_home_value() {
    const HOME: &str = "/tmp/x";

    let mut pending: Vec<Vec<String>> = vec![Vec::new()];
    let mut seen = 0_usize;
    while let Some(path) = pending.pop() {
        for flag in ["-h", "--help"] {
            let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
            args.push(flag);
            let out = swoosh(&args, Some(HOME));
            assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
            let shown = format!("{}{}", text(&out.stdout), text(&out.stderr));
            assert!(!shown.contains(HOME), "{args:?} prints the home:\n{shown}");
            if flag == "--help" {
                for verb in listed_verbs(&text(&out.stdout)) {
                    let mut child = path.clone();
                    child.push(verb);
                    pending.push(child);
                }
            }
        }
        seen += 1;
    }
    assert!(seen > 10, "the walk reached only {seen} commands");

    let root = swoosh(&["--help"], Some(HOME));
    assert!(
        text(&root.stdout).contains("[env: SWOOSH_HOME]"),
        "{}",
        text(&root.stdout)
    );
}

/// Which of the run's two streams is a terminal; the other is a pipe.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum OnTerminal {
    Stdout,
    Stderr,
}

/// One of a run's two output streams.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum Stream {
    Stdout,
    Stderr,
}

/// `swoosh <args>` on `home`, running with one stream on a pseudo-terminal and the other on a pipe, with
/// `NO_COLOR` and `CLICOLOR*` unset and `TERM=xterm`, so only the handle decides. Both streams are read as
/// they come, each on a thread, so a full buffer never holds the child.
#[cfg(unix)]
struct Watched {
    child: std::process::Child,
    /// The terminal's end the child writes to, held here until the reading is done: some systems drop
    /// what a terminal holds once its last writer closes.
    end: std::fs::File,
    run: PathBuf,
    came: [std::sync::mpsc::Receiver<Vec<u8>>; 2],
    seen: [Vec<u8>; 2],
}

#[cfg(unix)]
impl Watched {
    fn spawn(args: &[&str], home: &std::path::Path, on: OnTerminal) -> Self {
        let (terminal, end) = pty();
        let (pipe, pipe_writer) = std::io::pipe().unwrap();
        let (stdout, stderr) = match on {
            OnTerminal::Stdout => (
                Stdio::from(end.try_clone().unwrap()),
                Stdio::from(pipe_writer),
            ),
            OnTerminal::Stderr => (
                Stdio::from(pipe_writer),
                Stdio::from(end.try_clone().unwrap()),
            ),
        };
        let run = scratch(&format!("pty-run-{on:?}"));
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(home)
            .args(args)
            .env_remove("SWOOSH_HOME")
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("RUST_LOG")
            .env("TERM", "xterm")
            .env("XDG_RUNTIME_DIR", &run)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap();
        let (terminal, pipe) = (read_as_it_comes(terminal), read_as_it_comes(pipe));
        let came = match on {
            OnTerminal::Stdout => [terminal, pipe],
            OnTerminal::Stderr => [pipe, terminal],
        };
        Self {
            child,
            end,
            run,
            came,
            seen: [Vec::new(), Vec::new()],
        }
    }

    /// Read `stream` until its text so far holds `wanted`.
    fn until(&mut self, stream: Stream, wanted: &str) {
        let at = stream as usize;
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(60);
        while !text(&self.seen[at]).contains(wanted) {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let Ok(chunk) = self.came[at].recv_timeout(left) else {
                panic!(
                    "{stream:?} never said {wanted:?}: {:?}",
                    text(&self.seen[at])
                );
            };
            self.seen[at].extend(chunk);
        }
    }

    /// Stop the run, then read what it wrote, as [`finish`](Self::finish) does.
    fn stop(mut self) -> (String, String) {
        let _ = self.child.kill();
        self.finish()
    }

    /// Wait for the run to end, stopping it at the deadline, then read both streams until they go quiet:
    /// what it wrote to stdout, and to stderr.
    fn finish(mut self) -> (String, String) {
        use core::time::Duration;

        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("the run did not end");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        for (came, seen) in self.came.iter().zip(&mut self.seen) {
            while let Ok(chunk) = came.recv_timeout(Duration::from_millis(500)) {
                seen.extend(chunk);
            }
        }
        drop(self.end);
        let _ = std::fs::remove_dir_all(&self.run);
        (text(&self.seen[0]), text(&self.seen[1]))
    }
}

/// What `swoosh <args>` on `home` wrote to stdout and stderr, one of them a terminal as `on` says, once
/// the run has ended on its own.
#[cfg(unix)]
fn on_a_terminal(args: &[&str], home: &std::path::Path, on: OnTerminal) -> (String, String) {
    Watched::spawn(args, home, on).finish()
}

/// `reader`'s bytes as they come, on a thread, until it ends or fails: a terminal fails once its writers
/// close, and some systems never end it at all while a writer is held, so a reader waits for quiet instead.
#[cfg(unix)]
fn read_as_it_comes(
    mut reader: impl std::io::Read + Send + 'static,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (chunks, came) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(read @ 1..) = reader.read(&mut chunk) {
            if chunks.send(chunk[..read].to_vec()).is_err() {
                break;
            }
        }
    });
    came
}

/// A new pseudo-terminal: the end this process reads, and the end a child is given as a stream.
#[cfg(unix)]
fn pty() -> (std::fs::File, std::fs::File) {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt as _;

    // `ptsname` writes a buffer every thread shares, and tests run on threads: one terminal at a time.
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let held = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: each call is checked before its result is used; the descriptor `posix_openpt` returns is
    // owned by the `OwnedFd` alone, and `ptsname`'s buffer is copied out while `held` keeps every other
    // caller here out.
    let (reader, path) = unsafe {
        let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(fd >= 0, "posix_openpt: {}", std::io::Error::last_os_error());
        let reader = OwnedFd::from_raw_fd(fd);
        assert_eq!(libc::grantpt(fd), 0, "{}", std::io::Error::last_os_error());
        assert_eq!(libc::unlockpt(fd), 0, "{}", std::io::Error::last_os_error());
        let name = libc::ptsname(fd);
        assert!(!name.is_null(), "{}", std::io::Error::last_os_error());
        let path = core::ffi::CStr::from_ptr(name).to_str().unwrap().to_owned();
        (reader, path)
    };
    drop(held);
    let end = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(path)
        .unwrap();
    (std::fs::File::from(reader), end)
}

/// Colour is decided for each stream from its own handle: with stderr a terminal and stdout a pipe, the
/// refusal on stderr is styled; swapped, it is plain. The same holds the other way for serve's title on
/// stdout. A stream that followed the other's handle, or the two decisions swapped, prints the wrong one.
#[cfg(unix)]
#[test]
fn colour_is_decided_per_stream() {
    use clap::builder::styling::{AnsiColor, Style};

    let error = Style::new().bold().fg_color(Some(AnsiColor::Red.into()));
    let title = Style::new().bold();

    let file = scratch("pty-file");
    std::fs::write(&file, "").unwrap();
    let (_, styled) = on_a_terminal(&["status"], &file, OnTerminal::Stderr);
    let (_, plain) = on_a_terminal(&["status"], &file, OnTerminal::Stdout);
    let _ = std::fs::remove_file(&file);
    assert!(
        styled.starts_with(&format!("{error}error:{error:#} ")),
        "{styled:?}"
    );
    assert!(plain.starts_with("error: "), "{plain:?}");
    assert!(!plain.contains('\u{1b}'), "{plain:?}");

    let home = scratch("pty-serve");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let serve = ["serve", "--local", "--expires", "1s"];
    let (styled, _) = on_a_terminal(&serve, &home, OnTerminal::Stdout);
    let (plain, _) = on_a_terminal(&serve, &home, OnTerminal::Stderr);
    let _ = std::fs::remove_dir_all(&home);
    assert!(
        styled.starts_with(&format!(
            "{title}swoosh is serving, on this network only{title:#}"
        )),
        "{styled:?}"
    );
    assert!(
        plain.starts_with("swoosh is serving, on this network only\n"),
        "{plain:?}"
    );
    assert!(!plain.contains('\u{1b}'), "{plain:?}");
}

/// One run that styles on both streams keeps them apart: serve's title on stdout, then a `warning:` on
/// stderr for a service saved while it runs. With stdout the terminal, the title is styled and the warning
/// plain; swapped, the reverse. One decision shared by both streams styles both lines alike, whichever
/// stream asked first.
#[cfg(unix)]
#[test]
fn one_run_styles_each_stream_by_its_own_handle() {
    use clap::builder::styling::{AnsiColor, Style};

    const TITLE: &str = "swoosh is serving, on this network only";
    const WAITING: &str = "saved service speed applies to the next bare";
    let title = Style::new().bold();
    let warning = Style::new().bold().fg_color(Some(AnsiColor::Yellow.into()));

    let mut shown = Vec::new();
    for on in [OnTerminal::Stdout, OnTerminal::Stderr] {
        let home = scratch(&format!("pty-both-{on:?}"));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let saved = home.join("serve.toml");
        std::fs::write(&saved, "services = []\n").unwrap();
        let mut run = Watched::spawn(&["serve", "--local", "--expires", "1d", "ping"], &home, on);
        run.until(Stream::Stdout, "Serving until ");
        std::fs::write(&saved, "services = [\"ping=ping:\", \"speed=speed:\"]\n").unwrap();
        run.until(Stream::Stderr, WAITING);
        shown.push(run.stop());
        let _ = std::fs::remove_dir_all(&home);
    }
    let [(styled_out, plain_err), (plain_out, styled_err)] = <[_; 2]>::try_from(shown).unwrap();

    assert!(
        styled_out.starts_with(&format!("{title}{TITLE}{title:#}")),
        "{styled_out:?}"
    );
    assert!(
        plain_err.contains(&format!("warning: {WAITING}")),
        "{plain_err:?}"
    );
    assert!(!plain_err.contains('\u{1b}'), "{plain_err:?}");

    assert!(
        plain_out.starts_with(&format!("{TITLE}\n")),
        "{plain_out:?}"
    );
    assert!(!plain_out.contains('\u{1b}'), "{plain_out:?}");
    assert!(
        styled_err.contains(&format!("{warning}warning:{warning:#} {WAITING}")),
        "{styled_err:?}"
    );
}

/// Bare `swoosh lock` through the real binary is a read: on a home never made it exits 0, prints the no-key
/// screen on stdout and nothing on stderr, and leaves the home unmade, so it took no `home.lock` and made no
/// key. Red when it prompts, writes, or exits non-zero.
#[test]
fn bare_lock_on_an_empty_home_is_a_read() {
    let home = scratch("bare-lock");
    let _ = std::fs::remove_dir_all(&home);
    let out = swoosh(&["--home", home.to_str().unwrap(), "lock"], None);
    let made = home.exists();
    let _ = std::fs::remove_dir_all(&home);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "");
    #[cfg(target_os = "macos")]
    let screen = "This machine has no key yet.\n\n\
                  locks\n  \
                  touch-id     a touch on this Mac's sensor; opens on this Mac only\n  \
                  passphrase   typed at each use; a copy opens on any machine\n\n\
                  To make the key with one of them:\n  swoosh lock touch-id\n  swoosh lock passphrase\n";
    #[cfg(not(target_os = "macos"))]
    let screen = "This machine has no key yet.\n\n\
                  locks\n  \
                  passphrase   typed at each use; a copy opens on any machine\n\n\
                  To make the key with a passphrase:\n  swoosh lock passphrase\n";
    assert_eq!(text(&out.stdout), screen);
    assert!(!made, "the home was made");
}
