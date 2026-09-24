//! Asking a person for a passphrase: on the controlling terminal, and nowhere else.
//!
//! A sealed identity opens only under a passphrase someone types, and there is exactly one place it may
//! be typed: `/dev/tty`, with echo off. Never argv (it lands in `ps` and shell history), never the
//! environment (it is inherited by every child and read by anything that dumps one), never stdin (a pipe
//! lets whatever composed the pipeline supply it, and a stdin prompt hangs a script rather than failing
//! it). A process with no terminal gets a refusal that says so, not a hang and never a fallback key.
//!
//! [`Prompt`] is the seam between the verbs that need a passphrase and where it comes from: the product
//! path is [`Terminal`], and a test supplies its passphrases through the same trait.

use std::path::Path;

use keystore::Passphrase;
use zeroize::Zeroizing;

/// The longest passphrase line read, in bytes. A cap, so a stuck key or a pasted file cannot grow the
/// buffer, and growing it is what would leave a copy of the passphrase behind in freed memory.
const MAX_LINE: usize = 1024;

/// Where a verb gets a passphrase from.
pub trait Prompt {
    /// The passphrase the sealed key file at `path` opens under.
    fn unlock(&mut self, path: &Path) -> eyre::Result<Passphrase>;

    /// A new passphrase to seal the key file at `path` under, typed twice, so a typo cannot seal a key
    /// under a passphrase nobody knows.
    fn choose(&mut self, path: &Path) -> eyre::Result<Passphrase>;
}

/// The controlling terminal: the only place a person types a passphrase for swoosh.
#[derive(Debug, Default)]
pub struct Terminal;

impl Prompt for Terminal {
    fn unlock(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        let text = Tty::open()?.ask(&format!("passphrase for {}: ", path.display()))?;
        passphrase(text)
    }

    fn choose(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        let tty = Tty::open()?;
        let first = tty.ask(&format!("new passphrase for {}: ", path.display()))?;
        let second = tty.ask("repeat the new passphrase: ")?;
        if first != second {
            eyre::bail!("the two passphrases did not match; nothing was changed");
        }
        passphrase(first)
    }
}

/// Typed text as a passphrase: put in the one byte form every sealed file uses, and never empty.
pub(crate) fn passphrase(text: Zeroizing<String>) -> eyre::Result<Passphrase> {
    Passphrase::try_from(text).map_err(|_| eyre::eyre!("the passphrase cannot be empty"))
}

/// The open controlling terminal.
struct Tty(std::fs::File);

impl Tty {
    /// Open `/dev/tty` for reading and writing. The prompt is written there too, so it reaches the
    /// person even when stdout and stderr are redirected.
    fn open() -> eyre::Result<Self> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map(Self)
            .map_err(|_| {
                eyre::eyre!(
                    "no terminal to ask for the passphrase on; a sealed identity is unlocked by typing \
                     its passphrase at a terminal, so a node that starts with nobody at the keyboard \
                     needs a plain key (`swoosh identity protect plain`)"
                )
            })
    }

    /// Write `prompt`, then read one line with echo off.
    fn ask(&self, prompt: &str) -> eyre::Result<Zeroizing<String>> {
        use std::io::Write as _;

        (&self.0).write_all(prompt.as_bytes())?;
        let line = {
            let _quiet = Echo::off(&self.0)?;
            self.read_line()
        };
        // The Enter the person typed was not echoed, so end the prompt's line for them.
        (&self.0).write_all(b"\n")?;
        let line = line?;
        let text = core::str::from_utf8(&line)
            .map_err(|_| eyre::eyre!("the passphrase is not valid UTF-8"))?;
        // Sized exactly, so the copy never reallocates; both buffers wipe themselves on drop.
        let mut owned = Zeroizing::new(String::with_capacity(text.len()));
        owned.push_str(text);
        Ok(owned)
    }

    /// One line from the terminal, without its line ending, in a buffer that never grows.
    fn read_line(&self) -> eyre::Result<Zeroizing<Vec<u8>>> {
        use std::io::Read as _;

        let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
        // One byte at a time, so nothing past the line is consumed; the byte wipes itself too.
        let mut byte = Zeroizing::new([0u8; 1]);
        loop {
            if (&self.0).read(&mut *byte)? == 0 || byte[0] == b'\n' {
                break;
            }
            if line.len() == MAX_LINE {
                eyre::bail!("the passphrase is longer than {MAX_LINE} bytes");
            }
            line.push(byte[0]);
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }
}

/// Echo turned off on a terminal, and back on when this drops, on every path out of the read: a return,
/// an error, or a panic unwinding through it. A signal that ends the process skips every `Drop`, so while
/// echo is off the signals that end a process from the keyboard or the session (`SIGINT`, `SIGQUIT`,
/// `SIGHUP`, `SIGTERM`) are caught, the terminal is put back, and the signal is raised again to end the
/// process exactly as it would have. Without that, a Ctrl-C at the prompt leaves the shell typing blind.
struct Echo<'a> {
    tty: &'a std::fs::File,
    #[cfg(unix)]
    saved: libc::termios,
    /// The handlers the process had before the prompt, put back when it ends.
    #[cfg(unix)]
    previous: [libc::sigaction; ENDING.len()],
}

/// The signals that end a process while a prompt waits.
#[cfg(unix)]
const ENDING: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGTERM];

/// What a signal handler must put back: the terminal and the setting it had. A signal handler can reach
/// only static state, so the guard parks it here for as long as echo is off.
#[cfg(unix)]
struct Pending {
    fd: libc::c_int,
    saved: libc::termios,
}

/// The setting to restore if a signal ends the process, or null while no prompt is open.
#[cfg(unix)]
static PENDING: core::sync::atomic::AtomicPtr<Pending> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Put the terminal back and end the process with the signal that arrived. Only async-signal-safe calls:
/// `tcsetattr`, `signal`, `raise`. The parked setting is not freed, because freeing is not safe here and
/// the process is ending.
#[cfg(unix)]
extern "C" fn restore_and_reraise(signal: libc::c_int) {
    let pending = PENDING.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::SeqCst);
    // SAFETY: a non-null `PENDING` is a live box the guard parked and has not yet taken back (taking it
    // back swaps it out first), and its `fd` is the open terminal the guard borrows.
    unsafe {
        if !pending.is_null() {
            libc::tcsetattr((*pending).fd, libc::TCSANOW, &(*pending).saved);
        }
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

impl<'a> Echo<'a> {
    #[cfg(unix)]
    fn off(tty: &'a std::fs::File) -> eyre::Result<Self> {
        use std::os::fd::AsRawFd as _;

        let fd = tty.as_raw_fd();
        // SAFETY: `termios` is a plain C struct for which all-zero bytes are a valid value, and
        // `tcgetattr` fully overwrites it before it is read.
        let mut saved: libc::termios = unsafe { core::mem::zeroed() };
        // SAFETY: `fd` is the open terminal `tty` borrows for this guard's whole life, and `saved` is a
        // live, writable `termios`.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Parked and caught BEFORE echo goes off, so there is no instant with echo off and no way back.
        let parked = Box::into_raw(Box::new(Pending { fd, saved }));
        PENDING.store(parked, core::sync::atomic::Ordering::SeqCst);
        let guard = Self {
            tty,
            saved,
            previous: catch_ending(),
        };
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: as above; `quiet` is a valid `termios` derived from the one the terminal returned.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(guard)
    }

    /// No terminal control here: a passphrase could only be read with echo on, so none is read.
    #[cfg(not(unix))]
    fn off(_tty: &'a std::fs::File) -> eyre::Result<Self> {
        eyre::bail!("reading a passphrase without echo is not supported on this platform")
    }
}

/// Install [`restore_and_reraise`] for every [`ENDING`] signal, and return the handlers it displaced.
#[cfg(unix)]
fn catch_ending() -> [libc::sigaction; ENDING.len()] {
    // SAFETY: `sigaction` is a plain C struct for which all-zero bytes are a valid value (no handler, no
    // flags, an empty mask), and every call gets live, writable structs.
    unsafe {
        let mut previous: [libc::sigaction; ENDING.len()] = core::mem::zeroed();
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction =
            restore_and_reraise as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        for (signal, previous) in ENDING.iter().zip(previous.iter_mut()) {
            libc::sigaction(*signal, &action, previous);
        }
        previous
    }
}

impl Drop for Echo<'_> {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;

            // SAFETY: the terminal is still open (this guard borrows it), and `saved` is the setting
            // `tcgetattr` returned for it. Best effort: there is nothing left to do if restoring fails.
            let _ = unsafe { libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSANOW, &self.saved) };
            // Echo is back, so a signal from here on has nothing to restore: take the parked setting
            // back first, then hand the signals back to whoever had them.
            let parked = PENDING.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::SeqCst);
            if !parked.is_null() {
                // SAFETY: `parked` came from `Box::into_raw` in `off`, and the swap above made this the
                // only owner: a handler that runs now finds null.
                drop(unsafe { Box::from_raw(parked) });
            }
            for (signal, previous) in ENDING.iter().zip(self.previous.iter()) {
                // SAFETY: `previous` is the handler `sigaction` returned for this signal in `off`.
                unsafe { libc::sigaction(*signal, previous, core::ptr::null_mut()) };
            }
        }
        #[cfg(not(unix))]
        let _ = self.tty;
    }
}

/// A prompt that answers from a script, for tests: every question, `unlock` or `choose`, takes the next
/// answer in order, and a question with none left refuses the way a missing terminal does. So a test
/// that scripts nothing also proves nothing was asked.
#[cfg(test)]
pub(crate) struct Scripted(std::collections::VecDeque<&'static str>);

#[cfg(test)]
impl Scripted {
    pub(crate) fn new(answers: impl IntoIterator<Item = &'static str>) -> Self {
        Self(answers.into_iter().collect())
    }

    fn next(&mut self) -> eyre::Result<Passphrase> {
        let answer = self
            .0
            .pop_front()
            .ok_or_else(|| eyre::eyre!("no scripted answer left"))?;
        passphrase(Zeroizing::new(answer.to_owned()))
    }
}

#[cfg(test)]
impl Prompt for Scripted {
    fn unlock(&mut self, _path: &Path) -> eyre::Result<Passphrase> {
        self.next()
    }

    fn choose(&mut self, _path: &Path) -> eyre::Result<Passphrase> {
        self.next()
    }
}
