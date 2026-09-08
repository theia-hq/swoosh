//! `swoosh service enable <svc>` / `swoosh service disable <svc>`: turn one of YOUR node's services off or
//! back on, live, without stopping it.
//!
//! Both are LOCAL FILE WRITES on `<home>/disabled` (a newline list of disabled service names), never a
//! socket call and never a remote op: you toggle your OWN node, so there is no `--at`. A running `serve`
//! honors the edit within the mtime-watch window (the [`FileDisabledList`](tightbeam::enabled::FileDisabledList)
//! oracle its gate consults per stream), so a `disable` refuses the service on the next stream and an `enable`
//! restores it, both with NO restart. A `disable` PERSISTS (fail-closed): a restart keeps a turned-off service
//! off, so a node never silently re-exposes something the operator disabled. An `enable` only REMOVES a name
//! from the list, so it can only return a declared service to its declared baseline, never open a new one or
//! raise posture (validation is serve-side; a name this node does not serve is simply a no-op there).
//!
//! Two racing toggles cannot lose an edit: the read-modify-write runs under an exclusive advisory
//! [`flock`](libc::flock) on `<home>/disabled.lock`, and the rewrite is atomic (write a temp sibling, rename
//! over), the same durability the revocation denylist uses, so a crash mid-write can never leave a torn list.

use std::collections::BTreeSet;
use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd as _;
use std::path::Path;

use clap::Args;

use crate::home::Home;

/// Turn a service off (`disable`) or back on (`enable`); the leaf carries only the service name, the verb
/// (which way to toggle) is the subcommand.
#[derive(Debug, Args)]
pub struct ServiceToggleCmd {
    /// the service to toggle (a name this node serves, e.g. `speed`)
    #[arg(value_name = "service")]
    pub service: String,
}

impl ServiceToggleCmd {
    /// `service disable <svc>`: add the name to `<home>/disabled` so a running `serve` refuses it live and a
    /// restart keeps it off. Idempotent: disabling an already-disabled service just reports the state.
    pub fn run_disable(self, home: &Home) -> eyre::Result<()> {
        edit(home, |disabled| {
            disabled.insert(self.service.clone());
        })?;
        // CLI-Architect ratified voice (delib-47 round-2, "Output shapes"): one terse line naming that the
        // effect persists. FLAG(CLI-Architect): exact wording is yours.
        println!("{}: disabled (persisted)", self.service);
        Ok(())
    }

    /// `service enable <svc>`: remove the name from `<home>/disabled` so a running `serve` serves it again
    /// live. Idempotent: enabling a service that was not disabled just reports the state. Only ever removes a
    /// name, so it returns a declared service to its baseline and never opens a new one.
    pub fn run_enable(self, home: &Home) -> eyre::Result<()> {
        edit(home, |disabled| {
            disabled.remove(&self.service);
        })?;
        // CLI-Architect ratified voice (delib-47 round-2, "Output shapes"). FLAG(CLI-Architect): wording yours.
        println!("{}: enabled", self.service);
        Ok(())
    }
}

/// Read `<home>/disabled`, apply `mutate`, and write it back atomically, all under an exclusive flock so two
/// concurrent toggles serialize (neither loses the other's edit). The disabled set is a [`BTreeSet`] so the
/// rewritten file is name-sorted and stable (a clean diff, and the same shape the denylist writes).
fn edit(home: &Home, mutate: impl FnOnce(&mut BTreeSet<String>)) -> eyre::Result<()> {
    // The home may not exist yet (a toggle before the first `serve`/`adopt`); create it owner-only
    // (`0700`), mirroring how the contacts store provisions its parent on first save, so the disabled
    // list and its lock file never sit in a group/world-traversable dir. An already-provisioned dir is
    // left as set, never chmod'd.
    crate::config::create_store_dir(home.dir()).map_err(|error| {
        eyre::eyre!("cannot create store dir {}: {error}", home.dir().display())
    })?;
    // Hold the lock across the WHOLE read-modify-write. Dropped at function end (and released for free on the
    // fd close), so a crash never strands the lock.
    let _lock = FileLock::acquire(&home.disabled_lock())?;

    let mut disabled = read(&home.disabled())?;
    mutate(&mut disabled);
    write_atomic(&home.disabled(), &disabled)?;
    Ok(())
}

/// Parse `<home>/disabled` into its set of names: one trimmed, non-empty name per line. An absent file is an
/// empty set (nothing disabled), the first-run case, not an error.
fn read(path: &Path) -> eyre::Result<BTreeSet<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(error) => Err(error.into()),
    }
}

/// Rewrite `<home>/disabled` atomically: write the sorted names to a temp sibling, then rename over the
/// target. The rename is all-or-nothing, so a reader (the running `serve`'s oracle) sees the old file or the
/// new one, never a torn one. `rename` keeps its portable replace semantics: on unix it atomically
/// replaces the target, and the temp's `0600` mode rides along onto it. An EMPTY set still writes an
/// (empty) file rather than deleting it, so the oracle
/// reads "nothing disabled" from a present file and the mtime-watch tracks the change cleanly.
fn write_atomic(path: &Path, disabled: &BTreeSet<String>) -> eyre::Result<()> {
    let mut body = disabled.iter().cloned().collect::<Vec<_>>().join("\n");
    body.push('\n');
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    // Tighten the temp to `0600` before the rename carries that mode onto the target: the disabled set
    // leaks which services this node runs, so it stays owner-only, the same posture as the contacts
    // store and the revocation denylist. The `0700` dir already keeps the transient temp unreadable to
    // other local users in the meantime.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// An exclusive advisory lock held for the lifetime of a read-modify-write of `<home>/disabled`.
///
/// Unix-only for now: the lock rides `flock`, and neither std's file locking (MSRV 1.89, this workspace
/// targets 1.85) nor a portable helper is available yet. A non-unix build fails LOUD here naming the seam
/// and the fix (a portable helper over `LockFileEx` on Windows, or std locking once the MSRV allows it),
/// rather than silently shipping an unlocked read-modify-write.
///
/// The lock sits on a SEPARATE `<home>/disabled.lock` file, not on `disabled` itself, because the atomic
/// rewrite replaces `disabled`'s inode each time; a lock on that moving inode would not serialize the racing
/// writers. The lock file's inode is stable, so two `swoosh service disable` invocations contend on the SAME
/// lock and run their edits one after another.
#[cfg(unix)]
struct FileLock {
    file: std::fs::File,
}

#[cfg(not(unix))]
compile_error!(
    "service toggle locking needs a portable helper on this platform: flock (below) is unix-only. \
     Add a LockFileEx-backed lock on Windows (or std file locking once the MSRV passes 1.89)."
);

#[cfg(unix)]
impl FileLock {
    /// Take the exclusive lock, creating the lock file if absent. Blocks (`LOCK_EX`, no `LOCK_NB`) until any
    /// other in-flight toggle releases, so a concurrent toggle waits rather than failing.
    fn acquire(path: &Path) -> eyre::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        // SAFETY: `file` owns a valid fd for the duration of the call, and `flock` only associates an advisory
        // lock with it. A nonzero return is an OS error surfaced through `last_os_error`.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if locked != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        // Best-effort explicit unlock; closing the fd (right after) releases the flock regardless, so a
        // failure here cannot strand the lock.
        // SAFETY: `self.file` still owns a valid fd here; `LOCK_UN` only drops this fd's advisory lock.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
#[path = "toggle_tests.rs"]
mod toggle_tests;
