//! Taking a secret value without forcing it onto argv.
//!
//! A secret handed on the command line leaks: argv is visible to any process that can read `ps` or
//! `/proc/<pid>/cmdline`, so a device secret must never be REQUIRED there. This is the one convention every
//! secret slot in swoosh reuses to take its value from somewhere private instead. A slot accepts, in
//! precedence order:
//!   - a literal on argv: still works, the caller's own choice, but leaky;
//!   - `-`: read the value from standard input (the honest close: nothing on argv, nothing left on disk);
//!   - `@<path>`: read the value from that file. `@<path>` is the form reached for BELIEVING it is safe, so
//!     on unix it REFUSES a group- or world-accessible file (mirroring ssh's "Permissions 0644 for 'id_rsa'
//!     are too open"): silently reading a secret others can read would defeat the point. The mode guard is
//!     unix-only; other platforms have no portable equivalent and read the file as given;
//!   - an environment variable: read the value from the environment. A PARTIAL close ONLY: the value is
//!     owner-readable in `/proc/<pid>/environ`, but the environment is INHERITED by every child the process
//!     spawns (and `swoosh ssh` spawns `ssh`), so a secret placed there reaches those children. It is a
//!     convenience, not a way to close the argv leak.
//!
//! Exactly one source resolves. An argv value (in any form) wins over the environment, matching how an
//! explicit flag beats its env fallback everywhere else. The argv form is parsed at the CLI boundary
//! (`FromStr`), so a command field is an already-decided `Option<SecretSource>`, and the environment
//! fallback plus the "exactly one source" rule live in [`SecretSource::resolve`], which any secret slot
//! reuses regardless of the variable that names it.

use core::convert::Infallible;
use core::str::FromStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use eyre::WrapErr as _;
use zeroize::Zeroizing;

/// Cap on a stdin or `@<path>` secret read. An authkey is ~120 bytes; 64 KiB is generous headroom for any
/// legitimate secret while a runaway source (`swoosh adopt - < /dev/zero`, or `@/dev/zero` -- NUL is valid
/// UTF-8, so `read_to_string` never bails on it) hits the cap instead of growing until it exhausts memory.
const READ_LIMIT: u64 = 64 * 1024;

/// Where one secret value's bytes come from, once an argv value has been resolved against the environment.
///
/// Parse-don't-validate: an argv string becomes exactly one of these arms at the CLI boundary, so
/// [`read`](Self::read) receives a decided source rather than a raw string it must re-interpret.
#[derive(Clone)]
pub enum SecretSource {
    /// The value itself, taken verbatim, from an argv literal or the environment fallback. Leaky when it
    /// came from argv, which is the caller's explicit choice.
    Literal(String),
    /// `-`: the value is read from standard input.
    Stdin,
    /// `@<path>`: the value is read from this file.
    File(PathBuf),
}

impl SecretSource {
    /// Resolve a secret's source from its parsed argv value and an environment fallback, enforcing that
    /// exactly one source wins. An argv value (in ANY form) takes precedence; absent that, a value in the
    /// environment is taken as a literal; absent both, this is a hard error naming every way to supply it.
    ///
    /// `env` is the already-looked-up environment value: the caller reads its OWN variable, so this one
    /// helper serves every secret slot no matter which variable names it. `what` names the missing secret
    /// and `env_var` spells the slot's environment variable, so the error tells the operator exactly what
    /// to do.
    pub fn resolve(
        arg: Option<Self>,
        env: Option<String>,
        what: &str,
        env_var: &str,
    ) -> eyre::Result<Self> {
        // The real run warns to stderr; the decision (WHICH source, and whether to warn) lives in
        // `resolve_to`, with the warning sink injected so a test can observe exactly when it fires.
        Self::resolve_to(arg, env, what, env_var, &mut std::io::stderr())
    }

    /// The body of [`resolve`](Self::resolve), with the argv-leak warning routed to an injected `warn` sink
    /// so a test can drive it with its own writer and assert precisely when the warning is (and is not)
    /// emitted, rather than trying to capture the process stderr.
    fn resolve_to<W: std::io::Write>(
        arg: Option<Self>,
        env: Option<String>,
        what: &str,
        env_var: &str,
        warn: &mut W,
    ) -> eyre::Result<Self> {
        match (arg, env) {
            // An explicit argv value always wins: `-`, `@<path>`, or a literal, the caller decided. A bare
            // literal on argv is the LEAKY form (visible in `ps` / `/proc/<pid>/cmdline`), so warn once, on
            // one line, non-fatal: the caller still gets the value, and a single line never corrupts a
            // stdout pipeline. `-` (stdin) and `@<path>` (a file) are the private forms and stay quiet. The
            // env fallback below is deliberately NOT warned: its partial-close exposure is already
            // documented, so a warning there would cry wolf.
            (Some(arg), _) => {
                if matches!(arg, Self::Literal(_)) {
                    // A broken stderr must not fail the command, so a failed write to the advisory warning
                    // sink is ignored: the secret still resolves.
                    let _ = writeln!(
                        warn,
                        "warning: passing the {what} as a bare argument leaks it to other processes (`ps`, `/proc/<pid>/cmdline`); prefer `-` to read stdin or `@<path>` to read a file"
                    );
                }
                Ok(arg)
            }
            // No argv value, but the environment has one: take it verbatim as a literal.
            (None, Some(env)) => Ok(Self::Literal(env)),
            // Neither: name every source so the operator is unblocked, not just told "missing".
            (None, None) => Err(eyre::eyre!(
                "no {what} provided: pass it as an argument, `-` to read stdin, `@<path>` to read a file, or set {env_var}"
            )),
        }
    }

    /// Read the resolved source to its secret value. Stdin and a file read into a zeroizing buffer FROM THE
    /// START, so even a mid-read IO error (an early `?`) drops a wiped buffer rather than a bare `String`
    /// holding a partial secret; the returned string likewise zeroizes on drop. Stdin and a file are read
    /// synchronously: this runs once at command start, does nothing else concurrently, and a secret slot
    /// WANTS to block until the piped input arrives.
    pub fn read(self) -> eyre::Result<Zeroizing<String>> {
        match self {
            // Verbatim: a literal is exactly what the caller typed or set. Take ownership in a zeroizing
            // wrapper so it wipes on drop like every other path.
            Self::Literal(value) => Ok(Zeroizing::new(value)),
            // A secret read from stdin or a file almost always carries a trailing newline (an `echo` into
            // the pipe, a text editor's final newline) that is not part of the value, so drop trailing
            // newline characters. Both cap the read at `READ_LIMIT` so an unbounded source cannot exhaust
            // memory. A literal, by contrast, is taken untouched.
            Self::Stdin => {
                let mut value = Zeroizing::new(String::new());
                std::io::stdin()
                    .lock()
                    .take(READ_LIMIT)
                    .read_to_string(&mut value)
                    .wrap_err("failed to read secret from stdin")?;
                // Length first, then truncate: `value` is a `Zeroizing<String>`, so the trim borrow and the
                // truncate borrow cannot overlap through the deref.
                let trimmed = value.trim_end_matches(['\n', '\r']).len();
                value.truncate(trimmed);
                Ok(value)
            }
            Self::File(path) => {
                // Open ONCE and keep the fd: the permission guard fstats THIS fd and the read consumes the
                // SAME fd, so a symlink swap between the check and the read cannot slip a different file past
                // the guard (TOCTOU-safe). `metadata(path)` then re-open by path would double-resolve.
                let file = std::fs::File::open(&path)
                    .wrap_err_with(|| format!("failed to read secret from {}", path.display()))?;
                guard_file_perms(&file, &path)?;
                let mut value = Zeroizing::new(String::new());
                file.take(READ_LIMIT)
                    .read_to_string(&mut value)
                    .wrap_err_with(|| format!("failed to read secret from {}", path.display()))?;
                let trimmed = value.trim_end_matches(['\n', '\r']).len();
                value.truncate(trimmed);
                Ok(value)
            }
        }
    }
}

/// Refuse a group- or world-accessible secret file. `@<path>` exists FOR privacy (keeping the seed off argv
/// and out of `ps`), so silently reading a file others can read defeats the point; the seed IS a full device
/// identity. Owner-only means no group/other bits are set (`mode & 0o077 == 0`), mirroring ssh's
/// "Permissions 0644 for 'id_rsa' are too open". The error names the file and hints `chmod 600`.
///
/// The mode is read from the OPEN fd (`fstat`), and the caller reads from that SAME fd, so this is
/// TOCTOU-safe: nothing can swap a permissive file for a strict one between the check and the read.
#[cfg(unix)]
fn guard_file_perms(file: &std::fs::File, path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let mode = file
        .metadata()
        .wrap_err_with(|| format!("failed to stat secret file {}", path.display()))?
        .mode();
    if mode & 0o077 != 0 {
        return Err(eyre::eyre!(
            "permissions {:04o} for secret file {} are too open: group or other can read it. \
             run `chmod 600 {}`",
            mode & 0o7777,
            path.display(),
            path.display(),
        ));
    }
    Ok(())
}

/// Non-unix has no portable file-mode equivalent, so the guarantee is unix-only: the file is read as given.
/// Fabricating a bogus check here would give false assurance, so we deliberately do nothing.
#[cfg(not(unix))]
fn guard_file_perms(_file: &std::fs::File, _path: &Path) -> eyre::Result<()> {
    Ok(())
}

impl FromStr for SecretSource {
    type Err = Infallible;

    /// Interpret one argv value. The prefixes are tested in a fixed order, `-` then `@`, so a literal that
    /// is neither can never be mistaken for a redirect; every other string is the value itself. Any string
    /// is a valid source, hence [`Infallible`].
    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        if arg == "-" {
            return Ok(Self::Stdin);
        }
        if let Some(path) = arg.strip_prefix('@') {
            return Ok(Self::File(PathBuf::from(path)));
        }
        Ok(Self::Literal(arg.to_owned()))
    }
}

impl core::fmt::Debug for SecretSource {
    /// Redact the value: a secret must never appear in debug output (a log line, a panic message, a
    /// derived `Debug` on the command that holds it). The source KIND is safe to show; the bytes are not.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Literal(_) => f.write_str("Literal(<redacted>)"),
            Self::Stdin => f.write_str("Stdin"),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
        }
    }
}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod secret_tests;
