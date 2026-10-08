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
//! passphrase: nobody touched the dialog for a minute, so nobody is there to type one.
//!
//! The touch runs on the caller's thread, which waits for the key store to answer. Every act shows one
//! dialog, and the key store closes it itself after [`TOUCH_WAIT`] and answers that no touch came. No clock
//! runs here: one started before the work that comes ahead of the dialog (a passphrase's KDF, the file's
//! load and write) would fire first, and the command would end with the dialog still up. So a timeout means
//! the dialog is closed and nothing was written, a touch in the last instant is acted on, and `home.lock`
//! holds until the call ends.

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
pub const CHECK_MACHINE_KEY: &str = "add Touch ID to this machine's key";

/// The reason a dialog shows to open this machine's key, under `touch-id` alone, to put a passphrase on it.
/// One reason per act, so the dialog names the change the person asked for.
pub const SET_PASSPHRASE_ON_MACHINE_KEY: &str = "set a passphrase on this machine's key";

/// The reason a dialog shows to open this machine's key, under `touch-id` alone, to take that lock off.
pub const REMOVE_TOUCH_ID_FROM_MACHINE_KEY: &str = "remove Touch ID from this machine's key";

/// The reason a dialog shows to open your root.
pub const USE_ROOT: &str = "use your root";

/// The reason a dialog shows to prove a new `touch-id` lock on your root.
pub const CHECK_ROOT: &str = "add Touch ID to your root";

/// The second line of each notice before a `touch-id` lock is set: what a new fingerprint does to it. A
/// macro, so `concat!` can join it into each notice as one constant.
macro_rules! finger_added_later {
    () => {
        "a fingerprint added later in Touch ID & Password stops touch-id opening it until that fingerprint is \
         removed."
    };
}

/// Said before `lock touch-id` asks or writes anything, where no root is kept: the key will have one lock.
/// Two lines, said as one warning.
pub const ONE_LOCK: &str = concat!(
    "this machine's key will open with touch-id only.\n",
    finger_added_later!()
);

/// Said before `lock touch-id` asks or writes anything, where a root is kept: a passphrase stays beside it.
pub const BESIDE_PASSPHRASE: &str = concat!(
    "this machine's key will open with touch-id or a passphrase, since your root is on this machine.\n",
    finger_added_later!()
);

/// Said before `root lock touch-id` asks or writes anything.
pub const ROOT_BESIDE_PASSPHRASE: &str = concat!(
    "your root will open with touch-id or its passphrase.\n",
    finger_added_later!()
);

/// Said when your root and this machine's key come to open with `touch-id` both: a dialog shows whatever
/// words its asker gives, so it cannot tell the two apart for the person.
pub const SHARED_FINGER: &str = "your root and this machine's key will both open with touch-id on this Mac.\n\
     any program running as you can ask for a touch with any words in the dialog, so touch it only for a \
     command you just ran.";

/// The refusal of a change by touch on a key file with no `touch-id` lock left to open it: it changed since
/// it was read.
pub const TOUCH_ID_GONE: &str =
    "this machine's key lost its touch-id lock while this ran; run this again.";

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
        // Only this machine's key drops a lock after adding one: a root keeps its passphrase.
        Touched::HalfDone {
            left: Method::Passphrase,
            why,
        } => eyre::bail!(
            "this machine's key has its new touch-id lock, but its passphrase did not come off: {why:#}\n\
             to take it off: swoosh lock --remove"
        ),
        Touched::HalfDone {
            left: Method::TouchId,
            why,
        } => eyre::bail!(
            "this machine's key has its new passphrase, but its touch-id lock did not come off: {why:#}\n\
             to take it off: swoosh lock touch-id --remove"
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
    /// The touch opened and the new lock is on, then taking the old lock, `left`, off failed: the file holds
    /// both.
    HalfDone {
        /// The lock that stayed on.
        left: Method,
        /// Why it stayed.
        why: eyre::Report,
    },
    /// Nobody touched in time: the key store closed the dialog, and nothing was written.
    TimedOut,
}

/// Where an act stopped: at the call that asks the touch, or at the write after it.
#[derive(Debug)]
pub(crate) enum Stopped {
    /// The call that asks the touch refused, and nothing was written.
    Touch(keystore::Error),
    /// The new lock is on; taking the old one, of this method, off refused.
    After(Method, keystore::Error),
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
    pub(crate) fn run(self) -> Result<Option<keystore::Secret>, Stopped> {
        let Self { file, reason, act } = self;
        let touch = Unlock::TouchId {
            reason,
            wait: TOUCH_WAIT,
        };
        let new = NewLock::TouchId {
            reason,
            wait: TOUCH_WAIT,
        };
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
                .write(
                    &secret,
                    Protection::TouchId {
                        reason,
                        wait: TOUCH_WAIT,
                    },
                )
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
                        .map_err(|error| Stopped::After(Method::Passphrase, error))?;
                }
                Ok(None)
            }
            TouchAct::AddPassphrase { new, then } => {
                file.add_lock(Some(touch), NewLock::Passphrase(&new))?;
                if then == Then::Drop {
                    file.remove_lock(Unlock::Passphrase(&new), Method::TouchId)
                        .map_err(|error| Stopped::After(Method::TouchId, error))?;
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
/// a failure, carried whole, and a write that failed after the new lock went on says so. A timeout is named
/// so it never reads as a failure, which falls to the passphrase: nobody touched for a minute, so nobody is
/// there to type one.
impl From<Result<Option<keystore::Secret>, Stopped>> for Touched {
    fn from(answer: Result<Option<keystore::Secret>, Stopped>) -> Self {
        match answer {
            Ok(opened) => Self::Opened(opened),
            Err(Stopped::After(left, error)) => Self::HalfDone {
                left,
                why: eyre::Report::new(error),
            },
            Err(Stopped::Touch(keystore::Error::TouchId { source, .. })) => match source {
                keystore::TouchIdError::Declined(_) => Self::Declined,
                keystore::TouchIdError::TimedOut(_) => Self::TimedOut,
                keystore::TouchIdError::NotHere(_) | keystore::TouchIdError::Unavailable => {
                    Self::NotHere
                }
                other => Self::Failed(eyre::Report::new(other)),
            },
            Err(Stopped::Touch(other)) => Self::Failed(eyre::Report::new(other)),
        }
    }
}

/// Ask for `touch` and wait for the key store's answer: the product's touch. The key store bounds the dialog
/// at [`TOUCH_WAIT`], so this blocks no longer than the act's own work and one wait.
pub(crate) fn ask(touch: Touch) -> Touched {
    Touched::from(touch.run())
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
                Touched::Opened(Some(_)) => eyre::bail!("{}", lines.replaced()),
                Touched::Opened(None) => Some(Aside::Say(
                    lines.failed(&eyre::eyre!("the touch opened no key")),
                )),
                Touched::TimedOut => eyre::bail!("{TIMED_OUT}"),
                // A cancel is its own answer: the prompt that follows says the rest.
                Touched::Declined => None,
                Touched::NotHere => Some(Aside::Warn(lines.warning())),
                Touched::Failed(why) | Touched::HalfDone { why, .. } => {
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
    ///
    /// Several lines, one message: a caller that prefixes it (`warning: `, or `error: ` from `main`) prefixes
    /// the first line only.
    pub fn dead(&self) -> String {
        let key = self.key();
        if self.passphrase {
            return format!(
                "touch-id does not open {key} on this Mac now.\n\
                 check Touch ID & Password for a fingerprint you did not add, then set touch-id again: {}",
                self.again()
            );
        }
        match self.whose {
            Whose::Machine => "touch-id does not open this machine's key on this Mac now.\n\
                 if you added a fingerprint, removing it lets touch-id open the key again.\n\
                 otherwise, give this machine a new key and join again: swoosh leave --new-key"
                .to_owned(),
            Whose::MachineKeepingRoot | Whose::Root => format!(
                "touch-id does not open {key} on this Mac now.\n\
                 if you added a fingerprint, removing it lets touch-id open the key again."
            ),
        }
    }

    /// [`dead`](Self::dead), warned of at use on the way to the passphrase, where naming the command that sets
    /// it again is the fix.
    pub fn warning(&self) -> String {
        format!("warning: {}", self.dead())
    }

    /// Warned of before a lock that does not open here is set again, by the command already running: so it
    /// names no command, and says what the new lock will open with while there is still time to stop.
    pub fn before_set_again(&self) -> String {
        format!(
            "warning: touch-id does not open {} on this Mac now.\n\
             the new lock will open with every fingerprint now in Touch ID & Password; if one is not yours, \
             press ctrl-c and remove it first.",
            self.key()
        )
    }

    /// The refusal when a touch opens a key other than the one the file's header named when it was checked:
    /// the file was replaced between the read and the touch's own load, so the key in hand is not the one
    /// vetted.
    pub(crate) fn replaced(&self) -> String {
        format!(
            "the file holding {} was replaced while this ran; run this again.",
            self.key()
        )
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
