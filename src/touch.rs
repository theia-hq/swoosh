//! `touch-id`: opening a key file with a finger on this Mac's sensor.
//!
//! A key file with a `touch-id` lock opens with a touch where one may be asked for, and otherwise with its
//! passphrase. Whether one may be asked is decided before any dialog, in this order: a terminal (a service
//! manager and a pipe have none), then no ssh session, then the enclave's own answer read with no dialog
//! ([`Health`]). Only a lock that reads live is touched, so a lock that does not open here shows no dialog.
//!
//! What follows a touch that is not asked, or does not open, turns on one fact, read from the file's own lock
//! list: whether it holds a passphrase lock. A file that does opens with it; a file that does not is refused,
//! with the line that says why. A touch is never asked twice for one key. A timeout never falls to the
//! passphrase: the dialog may still be up, and nobody touched it for a minute.
//!
//! The touch runs on a thread of its own, which owns everything it uses, and the caller waits for it
//! [`TOUCH_WAIT`]: every act shows one dialog. On a timeout the command ends and the thread is left behind:
//! the process exiting is what ends it, and a touch on a dialog left up hands its secret to nobody. That is
//! why the thread is a plain one and never the runtime's: dropping a runtime waits for its blocking tasks,
//! which would hold the process open until the dialog closed.

use core::time::Duration;
use std::ffi::OsString;

use keystore::{Health, KeyFile, Locked, Method, NewLock, Passphrase, Protection, Stored, Unlock};

use crate::escape::EscapedPath;
use crate::identity::Whose;
use crate::passphrase::{Asked, Prompt};

/// How long a touch is waited for: long enough to read the dialog and reach a keyboard's sensor, short
/// enough that a parked command lets go of what it holds.
pub const TOUCH_WAIT: Duration = Duration::from_secs(60);

/// The reason a dialog shows to open this machine's key: `<program> is trying to <reason>`.
pub const USE_MACHINE_KEY: &str = "use this machine's key";

/// The reason a dialog shows to prove a new `touch-id` lock on this machine's key.
pub const CHECK_MACHINE_KEY: &str = "check touch-id opens this machine's key";

/// The reason a dialog shows to open this machine's key for a change to its locks.
pub const CHANGE_MACHINE_KEY: &str = "change the locks on this machine's key";

/// The reason a dialog shows to open your root.
pub const USE_ROOT: &str = "use your root";

/// The reason a dialog shows to prove a new `touch-id` lock on your root.
pub const CHECK_ROOT: &str = "check touch-id opens your root";

/// Said before `lock touch-id` asks or writes anything, where no root is kept: what a new fingerprint does to
/// a key with one lock.
pub const ONE_LOCK: &str = "touch-id will be this machine's key's one lock. Adding a fingerprint in Touch ID & \
     Password stops it opening the key until that fingerprint is removed.";

/// Said before `lock touch-id` asks or writes anything, where a root is kept: the passphrase stays.
pub const BESIDE_PASSPHRASE: &str = "touch-id goes beside this machine's key's passphrase. Adding a fingerprint \
     in Touch ID & Password stops touch-id opening the key until that fingerprint is removed; the passphrase \
     still opens it.";

/// Said before `root lock touch-id` asks or writes anything.
pub const ROOT_BESIDE_PASSPHRASE: &str = "Adding a fingerprint in Touch ID & Password stops touch-id opening your \
     root until that fingerprint is removed; its passphrase still opens it.";

/// Said when your root and this machine's key come to open with `touch-id` both.
pub const SHARED_FINGER: &str = "your root and this machine's key both open with touch-id on this Mac, and a \
     Touch ID dialog cannot show which of the two it opens.";

/// The refusal of a change by touch on a key file with no `touch-id` lock left to open it: it changed since
/// it was read.
pub const TOUCH_ID_GONE: &str =
    "the key file changed while this ran, and has no touch-id lock now; run it again";

/// The refusal when a touch opens a key other than the one the file's header named when it was checked: the
/// file was replaced between the read and the touch's own load, so the key in hand is not the one vetted.
pub const KEY_CHANGED: &str = "the key file changed while this ran; run it again";

/// The refusal of setting `touch-id` anywhere but at this Mac's own screen, naming `command` to run there.
pub fn set_elsewhere(here: TouchHere, command: &str) -> String {
    match here {
        TouchHere::OverSsh(variable) => format!(
            "touch-id is set at this Mac's own screen, not over ssh ({variable} is set); run it there: {command}"
        ),
        TouchHere::Here | TouchHere::NoEnclave | TouchHere::NoTerminal => {
            format!("touch-id is set at this Mac's own screen, unlocked; run it there: {command}")
        }
    }
}

/// A change a touch was asked for, as its end: done, or the refusal. A cancel or a lock that does not open
/// changed nothing, since every act fails at its first touch before it writes. A write that fails after the
/// new lock went on says the file holds both, never that the touch did not open.
///
/// # Errors
///
/// Anything but [`Touched::Opened`].
pub(crate) fn changed(touched: Touched, lines: &Lines<'_>) -> eyre::Result<()> {
    match touched {
        Touched::Opened(_) => Ok(()),
        Touched::Declined | Touched::NotHere => {
            eyre::bail!("touch-id did not open {}; nothing changed", lines.key())
        }
        Touched::Failed(why) => Err(why.wrap_err(format!("touch-id did not open {}", lines.key()))),
        Touched::HalfDone(why) => eyre::bail!(
            "{} has its new lock, but the old one did not come off: {why:#}; swoosh status says what is \
             there",
            lines.key()
        ),
        Touched::TimedOut => eyre::bail!("{TIMED_OUT}"),
    }
}

/// The variables an ssh session sets, read in this order. Present and not empty, any of them means no touch.
/// Trusted one way only: present means an ssh session (or a terminal multiplexer started in one), absent
/// proves nothing, and unsetting them gains nobody anything, since code running as you can ask the enclave
/// itself.
pub const SSH_VARIABLES: [&str; 3] = ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"];

/// Whether a touch may be asked for here, as [`Prompt::touch_here`] reads it, before any dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchHere {
    /// A person at this Mac's own terminal: a touch may be asked.
    Here,
    /// This build has no Secure Enclave to ask: it is not a macOS build.
    NoEnclave,
    /// No controlling terminal: a service manager, or a pipe.
    NoTerminal,
    /// An ssh session, named by the variable that said so, so a person at the Mac whose shell carries a
    /// stale one can see why the touch was skipped.
    OverSsh(&'static str),
}

/// The first of [`SSH_VARIABLES`] that `variable` finds set and not empty. Pure over the lookup, so the
/// environment is the caller's.
pub fn over_ssh(variable: impl Fn(&str) -> Option<OsString>) -> Option<&'static str> {
    SSH_VARIABLES
        .into_iter()
        .find(|name| variable(name).is_some_and(|value| !value.is_empty()))
}

/// One touch to ask for: the act it opens the way to, on `file`, with `reason` in the dialog. Owned whole,
/// so the thread that waits on the enclave needs nothing of the caller's.
#[derive(Debug)]
pub struct Touch {
    /// The key file the act is on.
    pub file: KeyFile,
    /// Why the touch is asked, shown in the dialog as `<program> is trying to <reason>`.
    pub reason: &'static str,
    /// What the touch is for.
    pub act: TouchAct,
}

/// What a touch is asked for. Each is one call into the key store, or two where a lock is replaced, and
/// each shows one dialog.
#[derive(Debug)]
pub enum TouchAct {
    /// Open the file through its `touch-id` lock.
    Open,
    /// Write a new file holding this key, under one `touch-id` lock.
    Write(keystore::Secret),
    /// Put a `touch-id` lock on a plain file.
    SealPlain,
    /// Put a `touch-id` lock on the file, opened with its passphrase; then keep the passphrase lock, or
    /// take it off.
    BesidePassphrase {
        /// The passphrase that opens the file now.
        current: Passphrase,
        /// What becomes of the passphrase lock.
        then: Then,
    },
    /// Put a passphrase lock on the file, opened with its `touch-id` lock; then keep the `touch-id` lock, or
    /// take it off.
    AddPassphrase {
        /// The new passphrase.
        new: Passphrase,
        /// What becomes of the `touch-id` lock.
        then: Then,
    },
    /// Take the file's `touch-id` lock off, opened with itself.
    RemoveTouchId,
}

/// What becomes of the lock that opened the file, once the new one is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Then {
    /// It stays beside the new one.
    Keep,
    /// It comes off, so the new lock is the file's one lock.
    Drop,
}

/// How a touch ended.
#[derive(Debug)]
pub enum Touched {
    /// It opened the file, and the act is done: the key, when the act was [`TouchAct::Open`].
    Opened(Option<keystore::Secret>),
    /// The person cancelled, or the touch did not match.
    Declined,
    /// The lock does not open on this Mac now, as the enclave said after the dialog.
    NotHere,
    /// Anything else: the enclave failed, the unwrap refused (a lock someone else made with this Mac's
    /// enclave reads live and fails here), or the act's own write.
    Failed(eyre::Report),
    /// The touch opened and the new lock is on, then taking the old lock off failed: the file holds both.
    HalfDone(eyre::Report),
    /// Nobody touched in time. The dialog may still be up.
    TimedOut,
}

/// Where an act stopped: at the call that asks the touch, or at the write after it.
#[derive(Debug)]
pub enum Stopped {
    /// The call that asks the touch refused, and nothing was written.
    Touch(keystore::Error),
    /// The new lock is on; taking the old one off refused.
    After(keystore::Error),
}

impl From<keystore::Error> for Stopped {
    fn from(error: keystore::Error) -> Self {
        Self::Touch(error)
    }
}

impl Touch {
    /// Run the act against the key store. Blocks for as long as the dialog is up.
    ///
    /// # Errors
    ///
    /// The key store's refusal, the touch's own included, and where the act stopped.
    pub fn run(self) -> Result<Option<keystore::Secret>, Stopped> {
        let Self { file, reason, act } = self;
        let touch = Unlock::TouchId { reason };
        let new = NewLock::TouchId { reason };
        match act {
            // The file is read again here, on this thread: its unlock proves its own header, so the key it
            // returns is the one this file holds now, which `open` checks against the header the caller read.
            TouchAct::Open => match file.load()? {
                Some(Stored::Locked(locked)) => {
                    locked.unlock(touch).map(Some).map_err(Stopped::Touch)
                }
                Some(Stored::Plain(_)) | None => Err(Stopped::Touch(keystore::Error::NoLock {
                    path: file.path().to_path_buf(),
                    method: Method::TouchId,
                })),
            },
            TouchAct::Write(secret) => file
                .write(&secret, Protection::TouchId { reason })
                .map(|()| None)
                .map_err(Stopped::Touch),
            TouchAct::SealPlain => file
                .add_lock(None, new)
                .map(|()| None)
                .map_err(Stopped::Touch),
            TouchAct::BesidePassphrase { current, then } => {
                let with = Unlock::Passphrase(&current);
                file.add_lock(Some(with), new)?;
                if then == Then::Drop {
                    file.remove_lock(with, Method::Passphrase)
                        .map_err(Stopped::After)?;
                }
                Ok(None)
            }
            TouchAct::AddPassphrase { new, then } => {
                file.add_lock(Some(touch), NewLock::Passphrase(&new))?;
                if then == Then::Drop {
                    file.remove_lock(Unlock::Passphrase(&new), Method::TouchId)
                        .map_err(Stopped::After)?;
                }
                Ok(None)
            }
            TouchAct::RemoveTouchId => file
                .remove_lock(touch, Method::TouchId)
                .map(|()| None)
                .map_err(Stopped::Touch),
        }
    }
}

/// The key store's answer, as a touch's end. Only the refusals a person can tell apart are named; the rest is
/// a failure, carried whole, and a write that failed after the new lock went on says so.
impl From<Result<Option<keystore::Secret>, Stopped>> for Touched {
    fn from(answer: Result<Option<keystore::Secret>, Stopped>) -> Self {
        match answer {
            Ok(opened) => Self::Opened(opened),
            Err(Stopped::After(error)) => Self::HalfDone(eyre::Report::new(error)),
            Err(Stopped::Touch(keystore::Error::TouchId { source, .. })) => match source {
                keystore::TouchIdError::Declined(_) => Self::Declined,
                keystore::TouchIdError::NotHere(_) | keystore::TouchIdError::Unavailable => {
                    Self::NotHere
                }
                other => Self::Failed(eyre::Report::new(other)),
            },
            Err(Stopped::Touch(other)) => Self::Failed(eyre::Report::new(other)),
        }
    }
}

/// Ask for `touch` on a thread of its own and wait [`TOUCH_WAIT`] for it: the product's touch.
pub(crate) fn ask(touch: Touch) -> Touched {
    match bounded(TOUCH_WAIT, move || touch.run()) {
        Ok(answer) => Touched::from(answer),
        Err(Unfinished::TimedOut) => Touched::TimedOut,
        Err(Unfinished::Thread(why)) => Touched::Failed(why),
    }
}

/// Why [`bounded`] has no answer.
#[derive(Debug)]
pub(crate) enum Unfinished {
    /// The bound passed first. The job runs on, and ends with the process.
    TimedOut,
    /// The thread could not start, or ended without an answer.
    Thread(eyre::Report),
}

/// Run `job` on a thread of its own and wait for its answer up to `bound`. On a timeout the thread is left to
/// run and its answer is dropped: nothing here can stop a call that blocks in the operating system, so the
/// caller ends instead.
pub(crate) fn bounded<T: Send + 'static>(
    bound: Duration,
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Unfinished> {
    // A channel and not a join: a join cannot be given a deadline, and the receiver dropped on a timeout
    // makes the thread's late send fail quietly.
    let (answer, answered) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("touch-id".to_owned())
        .spawn(move || {
            let _ = answer.send(job());
        })
        .map_err(|why| Unfinished::Thread(eyre::eyre!("could not wait for touch-id: {why}")))?;
    answered.recv_timeout(bound).map_err(|why| match why {
        std::sync::mpsc::RecvTimeoutError::Timeout => Unfinished::TimedOut,
        std::sync::mpsc::RecvTimeoutError::Disconnected => {
            Unfinished::Thread(eyre::eyre!("touch-id ended without an answer"))
        }
    })
}

/// How a key file opens for one act, decided before any dialog.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// Ask for a touch.
    Touch,
    /// Ask for the passphrase, after this line where there is one.
    Passphrase(Option<Aside>),
    /// Refuse, with this line: the file has no passphrase lock to fall to.
    Refuse(String),
}

/// A line said on the way to the passphrase: one that goes with the ask, or a warning, which rides stderr
/// ([`Prompt::warn`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Aside {
    /// Why the passphrase is asked rather than a touch.
    Say(String),
    /// A lock that does not open on this Mac now.
    Warn(String),
}

impl Aside {
    /// Tell it to the person, on its own channel.
    pub(crate) fn tell(&self, prompt: &mut impl Prompt) {
        match self {
            Self::Say(line) => prompt.say(line),
            Self::Warn(line) => prompt.warn(line),
        }
    }

    /// The line, for a refusal that ends the command instead.
    pub(crate) fn into_line(self) -> String {
        match self {
            Self::Say(line) | Self::Warn(line) => line,
        }
    }
}

/// How `locked`, read from `file`, opens for `asked`: [`Route::Touch`] only for a `touch-id` lock a touch may
/// be asked for and that reads live; the passphrase where the file holds one; else a refusal.
pub(crate) fn route(
    prompt: &impl Prompt,
    file: &KeyFile,
    locked: &Locked,
    asked: Asked<'_>,
) -> Route {
    if !locked.methods().any(|method| method == Method::TouchId) {
        return Route::Passphrase(None);
    }
    let passphrase = holds_passphrase(locked);
    let lines = Lines::of(asked, file, passphrase);
    // The line said on the way to the passphrase, or the refusal where there is none to go to.
    let skip = |line: Option<Aside>, refusal: String| {
        if passphrase {
            Route::Passphrase(line)
        } else {
            Route::Refuse(refusal)
        }
    };
    match prompt.touch_here() {
        // No enclave and no terminal say nothing on the way to the passphrase: the prompt that follows
        // refuses on its own when there is no terminal, and a build with no enclave names no `touch-id`.
        TouchHere::NoEnclave => skip(None, lines.no_enclave()),
        TouchHere::NoTerminal => skip(None, lines.no_terminal()),
        TouchHere::OverSsh(variable) => skip(
            Some(Aside::Say(lines.over_ssh(variable))),
            lines.over_ssh(variable),
        ),
        TouchHere::Here => match prompt.health(locked) {
            Some(Health::Live) => Route::Touch,
            Some(Health::Dead) => skip(Some(Aside::Warn(lines.warning())), lines.dead()),
            Some(Health::Unchecked) | None => {
                skip(Some(Aside::Say(lines.unchecked())), lines.unchecked())
            }
        },
    }
}

/// Open `locked`, read from `file`, for `asked`: by one touch where [`route`] says so, else by its passphrase,
/// up to [`TRIES`](crate::passphrase::TRIES) times. A touch that is declined, does not open, or fails falls
/// to the passphrase once, never to a second touch; a touch that times out ends the command.
///
/// The touch loads the file again on its own thread, so the key it opens is checked against the one
/// `locked`'s header names, which is the one the caller checked: a file replaced between the two reads is
/// refused, never signed with.
///
/// # Errors
///
/// The refusal [`route`] gave, a key other than the one checked, the touch's end on a file with no
/// passphrase lock, a timeout, or the passphrase's.
pub fn open(
    prompt: &mut impl Prompt,
    file: &KeyFile,
    locked: &Locked,
    asked: Asked<'_>,
    reason: &'static str,
) -> eyre::Result<keystore::Secret> {
    let lines = Lines::of(asked, file, holds_passphrase(locked));
    match route(prompt, file, locked, asked) {
        Route::Refuse(line) => eyre::bail!("{line}"),
        Route::Passphrase(aside) => {
            if let Some(aside) = aside {
                aside.tell(prompt);
            }
        }
        Route::Touch => {
            prompt.say(&lines.waiting());
            let touch = Touch {
                file: file.clone(),
                reason,
                act: TouchAct::Open,
            };
            let fallen = match prompt.touch(touch) {
                Touched::Opened(Some(secret)) if secret.public_key() == locked.public_key() => {
                    return Ok(secret);
                }
                Touched::Opened(Some(_)) => eyre::bail!("{KEY_CHANGED}"),
                Touched::Opened(None) => Some(Aside::Say(
                    lines.failed(&eyre::eyre!("the touch opened no key")),
                )),
                Touched::TimedOut => eyre::bail!("{TIMED_OUT}"),
                // A cancel is its own answer: the prompt that follows says the rest.
                Touched::Declined => None,
                Touched::NotHere => Some(Aside::Warn(lines.warning())),
                Touched::Failed(why) | Touched::HalfDone(why) => {
                    Some(Aside::Say(lines.failed(&why)))
                }
            };
            if !lines.passphrase {
                eyre::bail!(
                    "{}",
                    fallen.map_or_else(|| lines.declined(), Aside::into_line)
                );
            }
            if let Some(aside) = fallen {
                aside.tell(prompt);
            }
        }
    }
    let (secret, _) = crate::passphrase::unlock(prompt, asked, |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase))
    })?;
    Ok(secret)
}

/// Whether `locked` holds a passphrase lock: the one fact every fall from a touch turns on.
pub fn holds_passphrase(locked: &Locked) -> bool {
    locked.methods().any(|method| method == Method::Passphrase)
}

/// The refusal when a touch is not answered in time: every act shows one dialog, waited [`TOUCH_WAIT`]. It
/// never says nothing changed: a lock change the touch was for may have finished in the last instant, and
/// `status` says what is there.
pub const TIMED_OUT: &str = "touch-id waited 60 seconds and no touch came";

/// The lines a touch on one key file says, in the words of whose key it is.
#[derive(Debug, Clone, Copy)]
pub struct Lines<'a> {
    asked: Asked<'a>,
    whose: Whose,
    /// Whether the file holds a passphrase lock.
    passphrase: bool,
}

impl<'a> Lines<'a> {
    pub fn of(asked: Asked<'a>, file: &KeyFile, passphrase: bool) -> Self {
        Self {
            asked,
            whose: Whose::of(file),
            passphrase,
        }
    }

    /// The key, as a person knows it.
    const fn key(&self) -> &'static str {
        match self.asked {
            Asked::Root | Asked::Copy(_) => "your root",
            Asked::MachineKey => "this machine's key",
        }
    }

    /// The command that sets the `touch-id` lock again on this key.
    fn again(&self) -> String {
        match self.asked {
            Asked::Root => "swoosh root lock touch-id".to_owned(),
            Asked::Copy(dir) => format!("swoosh root lock touch-id {}", EscapedPath(dir)),
            Asked::MachineKey => "swoosh lock touch-id".to_owned(),
        }
    }

    /// Said before the dialog, which may come up on another screen.
    pub(crate) fn waiting(&self) -> String {
        format!("waiting for touch-id to use {}…", self.key())
    }

    /// Said before the dialog that proves a new lock.
    pub(crate) fn checking(&self) -> String {
        format!("waiting for touch-id to check it opens {}…", self.key())
    }

    /// The lock does not open on this Mac now. A file with a passphrase leads with setting it again, which
    /// loses nothing whatever the cause, after the one check that a finger nobody added is not the cause. A
    /// machine key with no other lock cannot be set again: removing an added finger is the step that loses
    /// nothing, then a new key, which `leave` gives only where no root is kept.
    pub fn dead(&self) -> String {
        if self.passphrase {
            return format!(
                "touch-id does not open {} on this Mac now; if you did not add a fingerprint, check Touch ID \
                 & Password before setting it again: {}",
                self.key(),
                self.again()
            );
        }
        match self.whose {
            Whose::Machine => "touch-id does not open this machine's key on this Mac now. If you added a \
                 fingerprint, remove it and run this again; otherwise give this machine a new key and join \
                 again: swoosh leave --new-key"
                .to_owned(),
            Whose::MachineKeepingRoot | Whose::Root => format!(
                "touch-id does not open {} on this Mac now. If you added a fingerprint, remove it and run \
                 this again",
                self.key()
            ),
        }
    }

    /// [`dead`](Self::dead), warned of at use on the way to the passphrase, and before a lock that does not
    /// open is set again.
    pub fn warning(&self) -> String {
        format!("warning: {}", self.dead())
    }

    /// The enclave could not say, with no dialog, whether the lock opens: a locked screen, a closed lid, a
    /// lockout. Never read as dead.
    pub(crate) fn unchecked(&self) -> String {
        if self.passphrase {
            return "touch-id cannot be checked now (the screen may be locked, or Touch ID locked out)."
                .to_owned();
        }
        format!(
            "touch-id cannot be checked now (the screen may be locked, or Touch ID locked out), and {} has \
             no other lock; unlock this Mac and run this again",
            self.key()
        )
    }

    fn over_ssh(&self, variable: &str) -> String {
        if self.passphrase {
            return format!("touch-id is not asked over ssh ({variable} is set).");
        }
        format!(
            "{} opens only with touch-id, which is not asked over ssh ({variable} is set); run this at the \
             Mac's own screen",
            self.key()
        )
    }

    fn no_terminal(&self) -> String {
        format!(
            "{} opens with touch-id, which needs a person at a terminal on this Mac; start this from a \
             terminal there",
            self.key()
        )
    }

    fn no_enclave(&self) -> String {
        format!(
            "{} opens only with touch-id, on the Mac that set it",
            self.key()
        )
    }

    /// The touch was cancelled, on a file with no passphrase to fall to.
    fn declined(&self) -> String {
        format!("touch-id was cancelled; {} was not opened", self.key())
    }

    fn failed(&self, why: &eyre::Report) -> String {
        format!("touch-id did not open {}: {why:#}", self.key())
    }
}

#[cfg(test)]
#[path = "touch_tests.rs"]
mod touch_tests;
