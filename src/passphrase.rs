//! Asking a person for a passphrase: on the controlling terminal, and nowhere else.
//!
//! A sealed key opens only under a passphrase someone types, and there is exactly one place it may be typed:
//! `/dev/tty`, with echo off. Never argv (it lands in `ps` and shell history), never the environment (it is
//! inherited by every child and read by anything that dumps one), never stdin (a pipe lets whatever composed
//! the pipeline supply it, and a stdin prompt hangs a script rather than failing it). A process with no
//! terminal gets a refusal that says so, not a hang and never a fallback key.
//!
//! [`Prompt`] is the seam between the verbs that need a passphrase and where it comes from: the product path
//! is [`Terminal`], and a test supplies its passphrases through the same trait. A prompt asks one round; the
//! retries live here, in [`unlock`] and [`choose`], so every verb asks three times at most and says why
//! between tries.
//!
//! A prompt names the key it asks for ([`Asked`]), never its file: the person knows their root and this
//! machine's key, not where swoosh keeps them.

use std::path::Path;

use keystore::Passphrase;
use rand::Rng as _;
use zeroize::Zeroizing;

use crate::escape::EscapedPath;

/// The longest passphrase line read, in bytes. A cap, so a stuck key or a pasted file cannot grow the
/// buffer, and growing it is what would leave a copy of the passphrase behind in freed memory.
const MAX_LINE: usize = 1024;

/// How many times a passphrase is asked for, unlocking or choosing, before the command gives up.
pub const TRIES: usize = 3;

/// The fewest characters a chosen passphrase has. Characters, not bytes, of the text as typed: nothing is
/// trimmed and nothing else is checked. A floor against the shortest guesses only; the passphrase swoosh
/// makes is the one that holds against a rig guessing a stolen copy offline.
pub const MINIMUM: usize = 15;

/// How many words a made passphrase has: five from 7,776, about 64 bits.
const WORDS: usize = 5;

/// The EFF large wordlist, one word per line: 7,776 words, CC BY 3.0 US, from
/// <https://www.eff.org/dice>. A made passphrase's strength is this list's length, which a test pins.
const WORD_LIST: &str = include_str!("passphrase/eff_large_wordlist.txt");

/// The line before the first prompt of a passphrase to choose.
const CHOOSE_HINT: &str =
    "Type one of at least 15 characters, or press Enter and swoosh makes one.";

/// The refusal of a chosen passphrase under [`MINIMUM`].
pub const TOO_SHORT: &str = "a passphrase needs at least 15 characters; nothing was changed. Press Enter at the prompt and swoosh makes one.";

/// The refusal when this machine's key is locked and nobody is at a terminal to type its passphrase.
pub const NO_TERMINAL_FOR_KEY: &str = "no terminal to ask for the passphrase on; a sealed identity is unlocked by typing \
     its passphrase at a terminal, so a node that starts with nobody at the keyboard needs a plain key: swoosh lock \
     --remove";

/// The refusal of two entries that differ.
pub const MISMATCH: &str = "the two did not match.";

/// What a prompt asks for: the key a passphrase opens or seals, named the way a person knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked<'a> {
    /// Your root, kept on this machine.
    Root,
    /// The copy of your root in this directory.
    Copy(&'a Path),
    /// This machine's own key.
    MachineKey,
}

impl Asked<'_> {
    /// The line after a passphrase that does not open the key, and the refusal after the last try.
    fn wrong(self) -> String {
        match self {
            Self::Root => "that passphrase does not open your root.".to_owned(),
            Self::Copy(dir) => format!(
                "that passphrase does not open the copy in {}.",
                EscapedPath(dir)
            ),
            Self::MachineKey => "that passphrase does not open this machine's key.".to_owned(),
        }
    }
}

/// One round of choosing: a passphrase, or why the round refused it. A refused round changed nothing.
#[derive(Debug)]
pub enum Choice {
    /// Typed or made, and typed again to match.
    Chosen(Passphrase),
    /// Under [`MINIMUM`].
    Short,
    /// The second entry differed from the first.
    Mismatch,
}

/// Where a verb gets a passphrase from: one round at a time. [`unlock`] and [`choose`] own the retries.
pub trait Prompt {
    /// Whether a person can be asked at all. A check that runs before anything is printed or written, so a
    /// command that must ask refuses up front rather than half way.
    fn terminal(&self) -> bool;

    /// One passphrase for `asked`, as typed: whether it opens the key is the caller's to find out.
    fn unlock(&mut self, asked: Asked<'_>) -> eyre::Result<Passphrase>;

    /// One round of choosing a new passphrase for `asked`: the first entry, held to [`MINIMUM`] (through
    /// [`chosen`]) before it is asked again, or made when it is empty; then the second, which must match.
    fn choose(&mut self, asked: Asked<'_>) -> eyre::Result<Choice>;

    /// Tell the person, where they type, why the last round did not take.
    fn say(&mut self, line: &str);
}

/// A passphrase that did not open its key after the last try: the refusal, in the words of what was asked.
#[derive(Debug, thiserror::Error)]
#[error("{line}")]
pub struct Wrong {
    line: String,
}

/// Ask for `asked` and try it with `open` up to [`TRIES`] times: after each wrong one, say so and ask again.
/// Returns what `open` returned, and the passphrase that opened it. A failure of `open` other than a wrong
/// passphrase ends at once.
///
/// # Errors
///
/// The third wrong passphrase ([`Wrong`]), the prompt's own failure, or `open`'s.
pub fn unlock<T>(
    prompt: &mut impl Prompt,
    asked: Asked<'_>,
    mut open: impl FnMut(&Passphrase) -> Result<T, keystore::Error>,
) -> eyre::Result<(T, Passphrase)> {
    for tried in 1..=TRIES {
        let passphrase = prompt.unlock(asked)?;
        match open(&passphrase) {
            Ok(opened) => return Ok((opened, passphrase)),
            Err(keystore::Error::Unlock { .. }) if tried < TRIES => prompt.say(&asked.wrong()),
            Err(keystore::Error::Unlock { .. }) => {
                return Err(Wrong {
                    line: asked.wrong(),
                }
                .into());
            }
            Err(other) => return Err(other.into()),
        }
    }
    Err(Wrong {
        line: asked.wrong(),
    }
    .into())
}

/// Choose a new passphrase for `asked` in up to [`TRIES`] rounds, saying why each refused round did not take.
///
/// # Errors
///
/// The reason the third round refused, or the prompt's own failure.
pub fn choose(prompt: &mut impl Prompt, asked: Asked<'_>) -> eyre::Result<Passphrase> {
    let mut last = MISMATCH;
    for tried in 1..=TRIES {
        last = match prompt.choose(asked)? {
            Choice::Chosen(passphrase) => return Ok(passphrase),
            Choice::Short => TOO_SHORT,
            Choice::Mismatch => MISMATCH,
        };
        if tried < TRIES {
            prompt.say(last);
        }
    }
    eyre::bail!("{last}")
}

/// The first entry of a passphrase being chosen, held to [`MINIMUM`]: a passphrase, or [`Choice::Short`]. The
/// one place the floor lives; an unlock never applies it, so a key sealed under anything still opens.
///
/// # Errors
///
/// The text is empty (a made passphrase replaces an empty entry before this is asked).
pub fn chosen(text: Zeroizing<String>) -> eyre::Result<Choice> {
    if text.chars().count() < MINIMUM {
        return Ok(Choice::Short);
    }
    passphrase(text).map(Choice::Chosen)
}

/// A new passphrase of [`WORDS`] words drawn from the EFF large wordlist by the operating system's random
/// source, one uniform draw per word (never a modulo, which would favour the first words), joined by spaces.
/// Words may repeat.
pub fn made() -> Zeroizing<String> {
    let words: Vec<&str> = WORD_LIST.lines().collect();
    let mut phrase = Zeroizing::new(String::with_capacity(WORDS * 10));
    for word in 0..WORDS {
        if word > 0 {
            phrase.push(' ');
        }
        phrase.push_str(words[rand::rngs::OsRng.gen_range(0..words.len())]);
    }
    phrase
}

/// The controlling terminal: the only place a person types a passphrase for swoosh.
#[derive(Debug, Default)]
pub struct Terminal;

impl Prompt for Terminal {
    fn terminal(&self) -> bool {
        Tty::open(Asked::MachineKey).is_ok()
    }

    fn unlock(&mut self, asked: Asked<'_>) -> eyre::Result<Passphrase> {
        let question = match asked {
            Asked::Root => "root passphrase: ".to_owned(),
            Asked::Copy(dir) => format!("passphrase for the copy in {}: ", EscapedPath(dir)),
            Asked::MachineKey => "passphrase for this machine's key: ".to_owned(),
        };
        passphrase(Tty::open(asked)?.ask(&question)?)
    }

    fn choose(&mut self, asked: Asked<'_>) -> eyre::Result<Choice> {
        let question = match asked {
            Asked::Root | Asked::Copy(_) => "root passphrase: ",
            Asked::MachineKey => "new passphrase for this machine's key: ",
        };
        let tty = Tty::open(asked)?;
        tty.say(CHOOSE_HINT)?;
        let mut first = tty.ask(question)?;
        if first.is_empty() {
            first = made();
            // Shown on the terminal only, never on stdout or stderr, so a pipe, a log or a CI capture never
            // holds it. Typed back once, because a root sealed under a phrase nobody wrote down is lost.
            tty.say(&format!("your passphrase: {}", first.as_str()))?;
            tty.say("Keep it where you keep your passwords, then type it once more.")?;
        } else if let Choice::Short = chosen(Zeroizing::new(first.as_str().to_owned()))? {
            return Ok(Choice::Short);
        }
        let second = tty.ask("again: ")?;
        if first != second {
            return Ok(Choice::Mismatch);
        }
        chosen(first)
    }

    fn say(&mut self, line: &str) {
        if let Ok(tty) = Tty::open(Asked::MachineKey) {
            let _ = tty.say(line);
        }
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
    /// person even when stdout and stderr are redirected. With no terminal, the refusal says what needs one.
    fn open(asked: Asked<'_>) -> eyre::Result<Self> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map(Self)
            .map_err(|_| match asked {
                Asked::Root | Asked::Copy(_) => eyre::eyre!(crate::root::UNLOCK_NEEDS_TERMINAL),
                Asked::MachineKey => eyre::eyre!(NO_TERMINAL_FOR_KEY),
            })
    }

    /// Write `line` and end it.
    fn say(&self, line: &str) -> eyre::Result<()> {
        use std::io::Write as _;

        (&self.0).write_all(format!("{line}\n").as_bytes())?;
        Ok(())
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
/// answer in order, and a question with none left refuses the way a missing terminal does. So a test that
/// scripts nothing also proves nothing was asked. A `choose` answer is held to the minimum like a typed one.
#[cfg(test)]
pub(crate) struct Scripted(std::collections::VecDeque<&'static str>);

#[cfg(test)]
impl Scripted {
    pub(crate) fn new(answers: impl IntoIterator<Item = &'static str>) -> Self {
        Self(answers.into_iter().collect())
    }

    fn next(&mut self) -> eyre::Result<Zeroizing<String>> {
        let answer = self
            .0
            .pop_front()
            .ok_or_else(|| eyre::eyre!("no scripted answer left"))?;
        Ok(Zeroizing::new(answer.to_owned()))
    }
}

#[cfg(test)]
impl Prompt for Scripted {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _asked: Asked<'_>) -> eyre::Result<Passphrase> {
        passphrase(self.next()?)
    }

    fn choose(&mut self, _asked: Asked<'_>) -> eyre::Result<Choice> {
        chosen(self.next()?)
    }

    fn say(&mut self, _line: &str) {}
}

#[cfg(test)]
#[path = "passphrase_tests.rs"]
mod passphrase_tests;
