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

use core::fmt;
use core::time::Duration;
use std::ffi::OsString;
use std::sync::OnceLock;

use keystore::{Health, KeyFile, Locked, Method, NewLock, Passphrase, Protection, Stored, Unlock};

use crate::escape::EscapedPath;
use crate::identity::Whose;
use crate::passphrase::{Asked, Prompt};

/// How long a touch is waited for: long enough to read the dialog and reach a keyboard's sensor, short
/// enough that a parked command lets go of what it holds.
pub const TOUCH_WAIT: Duration = Duration::from_secs(60);

/// The reason a dialog shows to open this machine's key: `<program> is trying to <reason>`, followed by the
/// command that asked where one is named ([`Reason::Use`]).
pub const USE_MACHINE_KEY: &str = "use this machine's key";

/// The reason a dialog shows to prove a new `touch-id` lock on this machine's key.
pub const CHECK_MACHINE_KEY: &str = "add Touch ID to this machine's key";

/// The reason a dialog shows to open this machine's key, under `touch-id` alone, to put a passphrase on it.
/// One reason per act, so the dialog names the change the person asked for.
pub const ADD_PASSPHRASE_TO_MACHINE_KEY: &str = "add a passphrase to this machine's key";

/// The reason a dialog shows to open this machine's key, under `touch-id` alone, to take that lock off.
pub const REMOVE_TOUCH_ID_FROM_MACHINE_KEY: &str = "remove Touch ID from this machine's key";

/// The reason a dialog shows to write this machine's first key under `touch-id`: its own, so the dialog does
/// not say `add` while the terminal says `make`.
pub const MAKE_MACHINE_KEY: &str = "make this machine's key";

/// The reason a dialog shows to open your root, followed by the command that asked where one is named.
pub const USE_ROOT: &str = "use your root";

/// The reason a dialog shows to prove a new `touch-id` lock on your root.
pub const CHECK_ROOT: &str = "add Touch ID to your root";

/// What a new fingerprint does to a `touch-id` lock, said only where that lock will be the key's only one:
/// beside a passphrase a lock that stops opening costs a prompt, alone it costs the key. A macro, so
/// `concat!` can join it into each notice as one constant.
macro_rules! finger_added_later {
    () => {
        "A fingerprint added later stops Touch ID opening this key until it is removed."
    };
}

/// Who may open a `touch-id` lock: every finger enrolled when it is made, someone else's included, so it is
/// said before an act puts one on this machine's key or changes it. A macro, so `concat!` can join it into a
/// notice as one constant.
macro_rules! every_fingerprint {
    () => {
        "Every fingerprint in Touch ID & Password opens it."
    };
}

/// Why a key beside a kept root keeps a passphrase, and what that costs: the two lines every add that puts
/// one there says. A macro, so `concat!` can join it into each notice as one constant.
macro_rules! root_keeps_passphrase {
    () => {
        "Your root is on this machine, so the key keeps a passphrase.\n\
         A copy of the key file opens with the passphrase on any machine.\n"
    };
}

/// Said before `lock passphrase` on a home with no key asks for anything.
pub const MAKES_UNDER_PASSPHRASE: &str = "This machine has no key yet.\n\
     This makes one that opens with a passphrase.";

/// Said before `lock touch-id` on a home with no key, where no root is kept, asks for anything: the key will
/// have one lock.
pub const MAKES_UNDER_TOUCH_ID: &str = concat!(
    "This machine has no key yet.\n",
    "This makes one that only Touch ID on this Mac opens.\n",
    every_fingerprint!(),
    "\n",
    finger_added_later!()
);

/// Said before `lock touch-id` on a home with no key, where a root is kept, asks for anything: a passphrase
/// goes beside Touch ID, and a copy of the file opens with it anywhere.
pub const MAKES_BESIDE_ROOT: &str = concat!(
    "This machine has no key yet.\n",
    "This makes one that opens with Touch ID or a passphrase.\n",
    root_keeps_passphrase!(),
    every_fingerprint!()
);

/// Said before `lock passphrase` on a plain key asks for anything.
pub const SEALS_UNDER_PASSPHRASE: &str = "This machine's key has no lock.\n\
     This adds a passphrase.";

/// Said before `lock touch-id` on a plain key, where no root is kept, asks for anything: Touch ID will be its
/// only lock.
pub const SEALS_UNDER_TOUCH_ID: &str = concat!(
    "This machine's key has no lock.\n",
    "This adds Touch ID, so only Touch ID on this Mac opens it.\n",
    every_fingerprint!(),
    "\n",
    finger_added_later!()
);

/// Said before `lock touch-id` on a plain key, where a root is kept, asks for anything: a passphrase goes
/// beside Touch ID, and a copy of the file opens with it anywhere.
pub const SEALS_BESIDE_ROOT: &str = concat!(
    "This machine's key has no lock.\n",
    "This adds Touch ID and a passphrase.\n",
    root_keeps_passphrase!(),
    every_fingerprint!()
);

/// Said before `lock passphrase` on a key under `touch-id` alone asks for anything: the passphrase goes
/// beside the lock it has, and a copy of the file then opens with it anywhere.
pub const BESIDE_TOUCH_ID: &str = "This adds a passphrase beside Touch ID; either will open this machine's key.\n\
     A copy of the key file would then open with the passphrase on any machine.";

/// Said before `lock touch-id` on a key under a passphrase alone asks for anything: the passphrase stays, so
/// a copy of the file still opens with it anywhere.
pub const TOUCH_ID_BESIDE: &str = concat!(
    "This adds Touch ID beside the passphrase; either will open this machine's key.\n",
    "A copy of the key file still opens with the passphrase on any machine.\n",
    every_fingerprint!()
);

/// Said before `lock touch-id` on a key under both locks asks for anything: the new `touch-id` lock replaces
/// the old one, and the passphrase stays beside it. Followed by [`EVERY_FINGERPRINT`], unless the old lock does
/// not open here, whose warning says who opens the new one.
pub const CHANGES_TOUCH_ID: &str = "This changes Touch ID on this machine's key.\n\
     Once changed, either lock will open it.\n\
     A copy of the key file still opens with the passphrase on any machine.";

/// Who may open the new `touch-id` lock, said on its own after [`CHANGES_TOUCH_ID`].
pub const EVERY_FINGERPRINT: &str = every_fingerprint!();

/// Said before `lock --remove` takes the passphrase off a key that keeps Touch ID: Touch ID will be its only
/// lock.
pub const TAKES_PASSPHRASE_OFF: &str = concat!(
    "This takes the passphrase off.\n",
    "Only Touch ID on this Mac will then open this machine's key.\n",
    finger_added_later!()
);

/// Said before `lock touch-id --remove` takes Touch ID off a key that keeps its passphrase.
pub const TAKES_TOUCH_ID_OFF: &str = "This takes Touch ID off.\n\
     Only the passphrase will then open this machine's key.";

/// Said before a removal takes off the one lock the key has: a copy of its file then acts as this machine.
pub const TAKES_LAST_LOCK_OFF: &str = "This takes the last lock off this machine's key.\n\
     Anyone with a copy of its key file could then act as this machine.";

/// The refusal of taking the passphrase off a key that keeps Touch ID, on a build with no enclave: no lock but
/// the passphrase opens it here.
pub const PASSPHRASE_STAYS_OFF_THE_MAC: &str =
    "the passphrase stays: Touch ID opens this key only on the Mac that set it";

/// Said before `root lock touch-id` asks or writes anything: who may open the new lock. The root always keeps
/// its passphrase, so a new fingerprint never costs it, and that line is not said.
pub const ROOT_BESIDE_PASSPHRASE: &str = concat!(
    "Your root will open with Touch ID or its passphrase.\n",
    every_fingerprint!()
);

/// Said when your root and this machine's key come to open with `touch-id` both: a dialog shows whatever
/// words its asker gives, so it cannot tell the two apart for the person.
pub const SHARED_FINGER: &str = "Your root and this machine's key will both open with Touch ID on this Mac.\n\
     Any program running as you can ask for a touch with any words in the dialog,\n  \
     so touch it only for a command you just ran.";

/// The refusal of a change by touch on a key file with no `touch-id` lock left to open it: it changed since
/// it was read.
pub const TOUCH_ID_GONE: &str =
    "this machine's key lost its Touch ID lock while this ran; run this again.";

/// The refusal of setting `touch-id` anywhere but at this Mac's own screen, naming `command` to run there.
pub fn set_elsewhere(here: TouchHere, command: &str) -> String {
    match here {
        TouchHere::OverSsh(variable) => format!(
            "Touch ID is set at this Mac's own screen, not over ssh ({variable} is set); run it there: {command}"
        ),
        TouchHere::Here | TouchHere::NoEnclave | TouchHere::NoTerminal => {
            format!("Touch ID is set at this Mac's own screen, unlocked; run it there: {command}")
        }
    }
}

/// A change a touch was asked for, as its end: done, or the refusal. A cancel or a lock that does not open
/// changed nothing, since every act is one call into the key store, which fails at its touch before it
/// writes.
///
/// # Errors
///
/// Anything but [`Touched::Opened`].
pub(crate) fn changed(touched: Touched, lines: &Lines<'_>) -> eyre::Result<()> {
    match touched {
        Touched::Opened(_) => Ok(()),
        Touched::Declined | Touched::NotHere => {
            eyre::bail!("Touch ID did not open {}; nothing changed", lines.key())
        }
        Touched::Failed(why) => Err(why.wrap_err(format!("Touch ID did not open {}", lines.key()))),
        Touched::TimedOut => eyre::bail!("{TIMED_OUT}"),
    }
}

/// [`changed`], but for an act whose write is in place though the key store answered a failure after it
/// (its directory not synced): that is a written result, its failure's chain handed back to be said beside it.
///
/// # Errors
///
/// As [`changed`], for every other end.
pub(crate) fn landed(touched: Touched, lines: &Lines<'_>) -> eyre::Result<Option<String>> {
    match touched {
        Touched::Failed(why) if unsynced(&why) => Ok(Some(format!("{why:#}"))),
        other => changed(other, lines).map(|()| None),
    }
}

/// Whether `why` is the key store's answer that a write is in place but its directory was not synced.
pub(crate) fn unsynced(why: &eyre::Report) -> bool {
    matches!(
        why.downcast_ref::<keystore::Error>(),
        Some(keystore::Error::Unsynced { .. })
    )
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

/// The command this process runs, by its path in swoosh's own command table (`serve`, `root restore`). A
/// static set once rather than a field threaded to each open: the key is opened from three sites that build
/// their own prompt, and only the binary, after its parse, knows the command.
static COMMAND: OnceLock<&'static str> = OnceLock::new();

/// Name the command this process runs, so a dialog that opens a key to use it says which command asked:
/// `use your root for swoosh invite`. The name is a label, not a check: any program running as you can show
/// a dialog with any words. It takes only `&'static` words, the binary's own command table, so nothing typed
/// after the command and no peer's text can reach a dialog. The first call stands.
pub fn for_command(path: &'static str) {
    // A second call is ignored: one process runs one command, and its first name is that command's.
    let _ = COMMAND.set(path);
}

/// What a dialog says a touch is for, shown as `<program> is trying to <reason>`. Only opening a key to use it
/// names the command that asked; a change names itself (`add Touch ID to your root`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// A change to a key's locks, said alone.
    Change(&'static str),
    /// A key opened to use it, `act` naming the key, for `command` where one is named.
    Use {
        /// The act on the key: [`USE_MACHINE_KEY`] or [`USE_ROOT`].
        act: &'static str,
        /// The command's path, as [`for_command`] named it.
        command: Option<&'static str>,
    },
}

impl Reason {
    /// A key opened to use it, for the command this process runs where one is named.
    pub fn to_use(act: &'static str) -> Self {
        Self::Use {
            act,
            command: COMMAND.get().copied(),
        }
    }
}

/// The words the key store shows: the bare act, or `<act> for swoosh <path>`.
impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Change(act) | Self::Use { act, command: None } => f.write_str(act),
            Self::Use {
                act,
                command: Some(command),
            } => write!(f, "{act} for swoosh {command}"),
        }
    }
}

/// One touch to ask for: the act it opens the way to, on `file`, with `reason` in the dialog. Owned whole,
/// so the thread that waits on the enclave needs nothing of the caller's.
#[derive(Debug)]
pub struct Touch {
    /// The key file the act is on.
    pub file: KeyFile,
    /// Why the touch is asked, shown in the dialog as `<program> is trying to <reason>`.
    pub reason: Reason,
    /// What the touch is for.
    pub act: TouchAct,
}

/// What a touch is asked for. Each is one call into the key store, and each shows one dialog. None takes a
/// lock off but [`RemoveTouchId`](Self::RemoveTouchId): a lock comes off a key only where a person asked
/// for that.
#[derive(Debug)]
pub enum TouchAct {
    /// Open the file through its `touch-id` lock.
    Open,
    /// Write a new file holding this key, under one `touch-id` lock.
    Write(keystore::Secret),
    /// Put a `touch-id` lock on a plain file.
    SealPlain,
    /// Put a `touch-id` lock on the file beside its passphrase, opened with that passphrase. A `touch-id`
    /// lock the file already has is replaced by the new one.
    BesidePassphrase {
        /// The passphrase that opens the file now.
        current: Passphrase,
    },
    /// Put a passphrase lock on the file beside its `touch-id` lock, opened with that lock.
    AddPassphrase {
        /// The new passphrase.
        new: Passphrase,
    },
    /// Take the file's `touch-id` lock off, opened with itself.
    RemoveTouchId,
}

/// What a dialog asks the touch for, as the person reads it twice: in the dialog's reason and on the line
/// that waits for it. Both come from one act, so the two never name different changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    /// Open the key, to use it.
    Use,
    /// Write this machine's first key.
    Make,
    /// Put a new `touch-id` lock on the key.
    Add,
    /// Put a passphrase beside the key's `touch-id` lock.
    AddPassphrase,
    /// Take the key's `touch-id` lock off.
    Remove,
}

impl Act {
    /// The dialog's reason for this act on this machine's key.
    pub fn machine_key_reason(self) -> Reason {
        match self {
            Self::Use => Reason::to_use(USE_MACHINE_KEY),
            Self::Make => Reason::Change(MAKE_MACHINE_KEY),
            Self::Add => Reason::Change(CHECK_MACHINE_KEY),
            Self::AddPassphrase => Reason::Change(ADD_PASSPHRASE_TO_MACHINE_KEY),
            Self::Remove => Reason::Change(REMOVE_TOUCH_ID_FROM_MACHINE_KEY),
        }
    }
}

impl TouchAct {
    /// What the dialog for this act asks the touch for.
    pub const fn act(&self) -> Act {
        match self {
            Self::Open => Act::Use,
            Self::Write(_) => Act::Make,
            Self::SealPlain | Self::BesidePassphrase { .. } => Act::Add,
            Self::AddPassphrase { .. } => Act::AddPassphrase,
            Self::RemoveTouchId => Act::Remove,
        }
    }
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
    /// Nobody touched in time: the key store closed the dialog, and the act wrote nothing.
    TimedOut,
}

impl Touch {
    /// A touch for `act` on this machine's key `file`, its dialog's reason the act's own.
    pub fn on_machine_key(file: KeyFile, act: TouchAct) -> Self {
        Self {
            file,
            reason: act.act().machine_key_reason(),
            act,
        }
    }

    /// Run the act against the key store. Blocks for as long as the dialog is up.
    ///
    /// # Errors
    ///
    /// The key store's refusal, the touch's own included.
    pub(crate) fn run(self) -> Result<Option<keystore::Secret>, keystore::Error> {
        let Self { file, reason, act } = self;
        // Rendered here, once, to the words the key store takes.
        let reason = reason.to_string();
        let reason = reason.as_str();
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
                Some(Stored::Locked(locked)) => locked.unlock(touch).map(Some),
                Some(Stored::Plain(_)) | None => Err(keystore::Error::NoLock {
                    path: file.path().to_path_buf(),
                    method: Method::TouchId,
                }),
            },
            TouchAct::Write(secret) => file
                .write(
                    &secret,
                    Protection::TouchId {
                        reason,
                        wait: TOUCH_WAIT,
                    },
                )
                .map(|()| None),
            TouchAct::SealPlain => file.add_lock(None, new).map(|()| None),
            TouchAct::BesidePassphrase { current } => file
                .add_lock(Some(Unlock::Passphrase(&current)), new)
                .map(|()| None),
            TouchAct::AddPassphrase { new } => file
                .add_lock(Some(touch), NewLock::Passphrase(&new))
                .map(|()| None),
            TouchAct::RemoveTouchId => file.remove_lock(touch, Method::TouchId).map(|()| None),
        }
    }
}

/// The key store's answer, as a touch's end. Only the refusals a person can tell apart are named; the rest is
/// a failure, carried whole. A timeout is named so it never reads as a failure, which falls to the
/// passphrase: nobody touched for a minute, so nobody is there to type one.
impl From<Result<Option<keystore::Secret>, keystore::Error>> for Touched {
    fn from(answer: Result<Option<keystore::Secret>, keystore::Error>) -> Self {
        match answer {
            Ok(opened) => Self::Opened(opened),
            Err(keystore::Error::TouchId { source, .. }) => match source {
                keystore::TouchIdError::Declined(_) => Self::Declined,
                keystore::TouchIdError::TimedOut(_) => Self::TimedOut,
                keystore::TouchIdError::NotHere(_) | keystore::TouchIdError::Unavailable => {
                    Self::NotHere
                }
                other => Self::Failed(eyre::Report::new(other)),
            },
            Err(other) => Self::Failed(eyre::Report::new(other)),
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
    reason: Reason,
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
            prompt.say(&lines.waiting(Act::Use));
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
                Touched::Failed(why) => Some(Aside::Say(lines.failed(&why))),
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

/// The refusal when a touch is not answered in time: every act shows one dialog, waited [`TOUCH_WAIT`]. The
/// key store closes the dialog itself and answers this only when no touch came, a touch in the last instant
/// answering as one, so the act the touch was for wrote nothing. It still never says nothing changed: a lock
/// change may have been written before the touch (a key sealed under a chosen passphrase first), which stands,
/// so the caller says what is left.
pub const TIMED_OUT: &str = "Touch ID waited 60 seconds and no touch came";

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

    /// Said before the dialog for `act`, which may come up on another screen: what to do, and the change the
    /// dialog names.
    pub fn waiting(&self, act: Act) -> String {
        let what = match act {
            Act::Use => return format!("Touch the sensor to use {}…", self.key()),
            Act::Make => "make this machine's key",
            Act::Add => "add Touch ID",
            Act::AddPassphrase => "add the passphrase",
            Act::Remove => "remove Touch ID",
        };
        format!("Touch the sensor to {what}…")
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
                "Touch ID does not open {key} on this Mac now.\n\
                 check Touch ID & Password for a fingerprint you did not add, then set Touch ID again: {}",
                self.again()
            );
        }
        match self.whose {
            Whose::Machine => "Touch ID does not open this machine's key on this Mac now.\n\
                 if you added a fingerprint, removing it lets Touch ID open the key again.\n\
                 otherwise, give this machine a new key and join again: swoosh leave --new-key"
                .to_owned(),
            Whose::MachineKeepingRoot | Whose::Root => format!(
                "Touch ID does not open {key} on this Mac now.\n\
                 if you added a fingerprint, removing it lets Touch ID open the key again."
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
            "warning: Touch ID does not open {} on this Mac now.\n\
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
            return "Touch ID cannot be checked now (the screen may be locked, or Touch ID locked out)."
                .to_owned();
        }
        format!(
            "Touch ID cannot be checked now (the screen may be locked, or Touch ID locked out), and {} has \
             no other lock; unlock this Mac and run this again",
            self.key()
        )
    }

    fn over_ssh(&self, variable: &str) -> String {
        if self.passphrase {
            return format!("Touch ID is not asked over ssh ({variable} is set).");
        }
        format!(
            "{} opens only with Touch ID, which is not asked over ssh ({variable} is set); run this at the \
             Mac's own screen",
            self.key()
        )
    }

    fn no_terminal(&self) -> String {
        format!(
            "{} opens with Touch ID, which needs a person at a terminal on this Mac; start this from a \
             terminal there",
            self.key()
        )
    }

    fn no_enclave(&self) -> String {
        format!(
            "{} opens only with Touch ID, on the Mac that set it",
            self.key()
        )
    }

    /// The touch was cancelled, on a file with no passphrase to fall to.
    fn declined(&self) -> String {
        format!("Touch ID was cancelled; {} was not opened", self.key())
    }

    fn failed(&self, why: &eyre::Report) -> String {
        format!("Touch ID did not open {}: {why:#}", self.key())
    }
}

#[cfg(test)]
#[path = "touch_tests.rs"]
mod touch_tests;
