//! The node home: the one directory every file this node owns derives from.
//!
//! A node is a DIRECTORY, not a lone key file. `--home <dir>` (env `SWOOSH_HOME`) names it; with neither,
//! the platform's per-user state place applies (`~/Library/Application Support/swoosh` on macOS,
//! `$XDG_STATE_HOME/swoosh` or `~/.local/state/swoosh` elsewhere). The key is always `<home>/machine/key`,
//! and the root it gates on, the certificate it presents, the contacts book, the links ledger, and the
//! revocation denylist all hang off the SAME dir, so one home moves the whole identity+trust unit together.
//! This is the `GNUPGHOME` / `CARGO_HOME` model: a home dir is a whole profile, not a key you point at.
//!
//! Every node path is a pure function of the home, so this type is the ONE place "what files make up one
//! node's state" is answered; a caller reads a path off it (`home.root_pub()`, `home.revoked()`) rather than
//! re-deriving one from a key file's parent in a scattered spot.

use std::path::{Path, PathBuf};

use eyre::eyre;

use crate::escape::{BLANK_LETTERS, EscapedPath};

mod lock;

pub use lock::{HomeWrite, LockError, Recorded, ServeLock, ServeLockError, serve_running};

/// The node home: the directory every file this node owns lives in.
///
/// Construct it once at the composition root from the `--home`/`SWOOSH_HOME` selection ([`Home::resolve`]),
/// then thread it where a verb needs a node path. It also remembers whether the home was named EXPLICITLY,
/// which is what a surface that RE-INVOKES swoosh must know: the `ssh` bridge forwards a named home to its
/// ProxyCommand so both halves read one node, and lets the default carry itself.
#[derive(Debug, Clone)]
pub struct Home {
    dir: PathBuf,
    selection: Selection,
}

/// How the home was chosen: defaulted to the platform's state place, or named explicitly
/// (`--home`/`SWOOSH_HOME`).
///
/// An enum, not a bare bool, so the "did the caller pin this home" question reads as intent at every use
/// site and a future selection source (say a config file) forces a decision here rather than silently
/// widening a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selection {
    /// The default home, when neither `--home` nor `SWOOSH_HOME` is given. It carries itself into a
    /// re-invocation, so nothing has to forward it.
    Default,
    /// A home named explicitly. A surface that re-invokes swoosh must forward it, or the second half
    /// reads a different node than the first. It selects WHERE this node's files live and nothing more:
    /// a verb's own intent still decides whether a key is written (see [`identity::resolve`]).
    ///
    /// [`identity::resolve`]: crate::identity::resolve
    Explicit,
}

impl Home {
    /// Resolve the home from the optional `--home`/`SWOOSH_HOME` selection: the named dir when given, else
    /// the platform default (`default_dir`). Fallible only in the default case (it reads `HOME`), and it rejects
    /// an explicit home that names an existing FILE (the home is a directory; the key lives inside it at
    /// `machine/key`).
    pub fn resolve(selected: Option<PathBuf>) -> eyre::Result<Self> {
        match selected {
            Some(dir) => {
                reject_home_file(&dir)?;
                Ok(Self {
                    dir,
                    selection: Selection::Explicit,
                })
            }
            None => Ok(Self {
                dir: default_dir()?,
                selection: Selection::Default,
            }),
        }
    }

    /// The home directory itself, for a caller that needs the dir rather than a file within it (the `ssh`
    /// bridge threads it into the re-invoked ProxyCommand's `--home`, and provisioning creates it).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the home was named explicitly (`--home`/`SWOOSH_HOME`) rather than defaulted, for a
    /// surface that re-invokes swoosh and must forward the same home; see [`Selection`].
    pub fn is_explicit(&self) -> bool {
        self.selection == Selection::Explicit
    }

    /// `<home>/machine/`: the directory that holds this machine's key, and nothing a backup should keep.
    /// The one directory system backups leave out, because a copy of the key acts as this machine.
    pub fn machine(&self) -> PathBuf {
        self.dir.join("machine")
    }

    /// `<home>/machine/key`: the ed25519 secret every verb binds under (0600). Always inside the home,
    /// never a path the user points at directly.
    pub fn key(&self) -> PathBuf {
        self.machine().join("key")
    }

    /// `<home>/home.lock`: held for a moment by every change to the home, as a [`HomeWrite`]. Never
    /// removed or replaced, so every holder locks one inode.
    pub fn home_lock(&self) -> PathBuf {
        self.dir.join("home.lock")
    }

    /// `<home>/serve.lock`: held by `swoosh serve` for its whole run, recording its pid and the root it
    /// admits, as a [`ServeLock`]. In the home rather than the runtime directory, so a command that resolves
    /// another runtime directory, or none, still finds it.
    pub fn serve_lock(&self) -> PathBuf {
        self.dir.join("serve.lock")
    }

    /// `<home>/root.pub`: the root that vouches for this machine, written by `join` and the first `invite`,
    /// read by the `serve` gate.
    pub fn root_pub(&self) -> PathBuf {
        self.dir.join("root.pub")
    }

    /// `<home>/key.cert`: your root's certificate for this machine's key, which this machine presents on
    /// connect: its name among your devices and its end date.
    pub fn key_cert(&self) -> PathBuf {
        self.dir.join("key.cert")
    }

    /// `<home>/serve.toml`: what `serve` runs. The services a bare `serve` resumes, the ones turned off, the
    /// relay this machine is reached through and the resolver it publishes to, each written under
    /// [`home_lock`](Self::home_lock) by the command that sets it. Not meant to be opened by a person.
    pub fn serve_toml(&self) -> PathBuf {
        self.dir.join("serve.toml")
    }

    /// `<home>/devices`: the newest list of your devices this machine has seen, signed by your root; where the
    /// root is kept, also the last list it signed, from which its next number and its records are read. A
    /// fold writes it (a root act's own cut, or one taken in an exchange with another device), and so does
    /// the making of a root, before this machine trusts it.
    pub fn devices(&self) -> PathBuf {
        self.dir.join("devices")
    }

    /// `<home>/synced`: when a sync last reached another device, in unix seconds.
    pub fn synced(&self) -> PathBuf {
        self.dir.join("synced")
    }

    /// `<home>/invited-by`: the key of the machine whose invite this machine joined, the first device a
    /// sync asks, and the name that invite gave this machine. Removed once a sync lands a list of the
    /// devices.
    pub fn invited_by(&self) -> PathBuf {
        self.dir.join("invited-by")
    }

    /// `<home>/devices.conflict`: a list of your devices your root signed other than the one in
    /// [`devices`](Self::devices), kept as evidence that two copies of the root signed: one seen at the
    /// number of the one in `devices`, or one another device passed on in an exchange, at any number.
    pub fn devices_conflict(&self) -> PathBuf {
        self.dir.join("devices.conflict")
    }

    /// `<home>/root.key`: your root, locked with its passphrase, when it is kept on this machine. The home's
    /// own [`devices`](Self::devices) is the list beside it: the root is the two together.
    pub fn root_key(&self) -> PathBuf {
        self.dir.join("root.key")
    }

    /// `<home>/revoked`: everything this machine refuses for good, in one grow-only file: the links it
    /// took back, the device keys it no longer admits, and the roots it no longer trusts. A running `serve`
    /// reads it live. Read and written only through [`crate::revoked`].
    pub fn revoked(&self) -> PathBuf {
        self.dir.join("revoked")
    }

    /// `<home>/revoked.written`: how many entries [`revoked`](Self::revoked) held after its last write, so a
    /// file that lost entries reads as damaged rather than as fewer revocations.
    pub fn revoked_written(&self) -> PathBuf {
        self.dir.join("revoked.written")
    }

    /// `<home>/links`: the ledger (0600) of every link this machine signed. The `serve` gate admits a
    /// link signed by this machine's own key only when its row is here, and revoke-by-holder and `grant
    /// ls` read it too.
    pub fn links(&self) -> PathBuf {
        self.dir.join("links")
    }

    /// `<home>/contacts.toml`: the address book of petnames this node resolves.
    pub fn contacts(&self) -> PathBuf {
        self.dir.join("contacts.toml")
    }

    /// `<home>/known_hosts`: the private host-key book `swoosh ssh` pins peers into, keyed on the
    /// immutable node id (not the petname) via ssh's `HostKeyAlias`. A node path like every other, so an
    /// isolated `--home` isolates its pins too.
    pub fn known_hosts(&self) -> PathBuf {
        self.dir.join("known_hosts")
    }

    /// The files whose contents decide whom this machine trusts: the pin, the links it signed, the
    /// contacts book, everything it refuses for good, what `serve` runs, and the host keys `swoosh ssh`
    /// pins (a writer who plants a host key there can sit between this machine and a peer).
    fn trust_files(&self) -> [PathBuf; 7] {
        [
            self.root_pub(),
            self.links(),
            self.contacts(),
            self.revoked(),
            self.revoked_written(),
            self.serve_toml(),
            self.known_hosts(),
        ]
    }

    /// Refuse a home one of whose [trust files](Self::trust_files) another user owns, or group or other
    /// can write: the check [`read_trust_file`] makes on each read, made on every file before any verb
    /// runs, so a file read by a library that does not make it is checked too. A file that is absent, or
    /// that cannot be stat'ed, passes: its reader reports what is wrong with it.
    ///
    /// # Errors
    ///
    /// [`LooseFile`] naming the first file that fails, and why.
    pub fn check_trust_files(&self) -> Result<(), LooseFile> {
        for path in self.trust_files() {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if let Some(why) = loose(&meta) {
                return Err(LooseFile { path, why });
            }
        }
        Ok(())
    }

    /// Refuse a home one of whose key files (this machine's key, and a root kept here) another user owns,
    /// or group or other holds any bit on, before any verb runs, so the refusal is this line and not the
    /// key store's, and a root key with loose modes never reads as a damaged one. A key that is absent, or
    /// that cannot be stat'ed, passes: its reader reports what is wrong with it.
    ///
    /// # Errors
    ///
    /// [`LooseFile`] naming the first key file that fails, and why.
    pub fn check_key_file(&self) -> Result<(), LooseFile> {
        for path in [self.key(), self.root_key()] {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if let Some(why) = loose_key(&meta) {
                return Err(LooseFile { path, why });
            }
        }
        Ok(())
    }

    /// The 16-char hex key scoping this home's runtime state: inline 64-bit FNV-1a over the
    /// canonicalized home path, the full 64 bits rendered as 16 lowercase hex chars. Dependency
    /// free and stable across daemon and client because both binaries carry this same function.
    /// Two different homes hash differently (the full-width hash, so collisions need a 2^64
    /// birthday, not 2^32), so two `--home`s never share a socket. A home that does not
    /// exist yet hashes the path it will canonicalize to once made, so a `serve` that claims a fresh
    /// home and every later verb find the same socket.
    pub fn home_key(&self) -> String {
        let canonical = canonical_to_be(&self.dir);
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in canonical.as_os_str().as_encoded_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        format!("{hash:016x}")
    }

    /// `<runtime>/swoosh-<uid>/<key>` (macOS) or `$XDG_RUNTIME_DIR/swoosh/<key>` (Linux): the
    /// per-home dir holding this node's control socket. A pure function of the home
    /// (via [`home_key`](Self::home_key)) over the per-user runtime root, so daemon and client
    /// resolve the same paths. Never `~/.config`, never `/tmp`, never an abstract socket.
    pub fn runtime_dir(&self) -> eyre::Result<PathBuf> {
        Ok(self.runtime_leaf(&runtime_root()?))
    }

    /// `<root>/<home_key>`: the per-home runtime leaf under an already-resolved per-user runtime
    /// root. The ONE derivation, shared by the client path ([`runtime_dir`](Self::runtime_dir),
    /// which resolves the root from the environment) and the daemon, which takes the root as a
    /// value from the composition edge and never reads the environment mid-stack.
    pub fn runtime_leaf(&self, root: &Path) -> PathBuf {
        root.join(self.home_key())
    }

    /// `<runtime_dir>/control.sock`: the local control socket rendezvous. See
    /// [`runtime_dir`](Self::runtime_dir).
    pub fn control_socket(&self) -> eyre::Result<PathBuf> {
        Ok(self.runtime_dir()?.join("control.sock"))
    }
}

/// `path` as `canonicalize` will name it once it exists: its deepest existing ancestor canonicalized (a
/// symlink in it resolved), then the rest joined on, `.` dropped and `..` taken lexically, since nothing
/// below that ancestor exists to be a link. Relative paths are taken against the cwd first.
pub(crate) fn canonical_to_be(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let parts: Vec<std::path::Component<'_>> = absolute.components().collect();
    let (mut resolved, made) = (0..=parts.len())
        .rev()
        .find_map(|kept| {
            let prefix: PathBuf = parts[..kept].iter().collect();
            std::fs::canonicalize(prefix)
                .ok()
                .map(|found| (found, kept))
        })
        .unwrap_or_else(|| (PathBuf::from("/"), 0));
    for part in &parts[made..] {
        match part {
            std::path::Component::CurDir | std::path::Component::RootDir => {}
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            std::path::Component::Normal(_) | std::path::Component::Prefix(_) => {
                resolved.push(part)
            }
        }
    }
    resolved
}

/// The per-user runtime root every `serve`'s socket lives under: `$XDG_RUNTIME_DIR/swoosh` on
/// Linux, `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `swoosh-<uid>` on macOS. Created and verified 0700 by the
/// single-instance acquire, never assumed. An unset or relative `XDG_RUNTIME_DIR` on Linux is a refusal,
/// never a fallback under the home, `/tmp` or the cwd. A client finds a `serve`'s socket only when the two
/// resolve the same root, so a fallback would add one more way for them to miss it.
pub fn runtime_root() -> eyre::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `confstr` with a null buffer and zero length only returns the needed size; the
        // second call writes into a live `Vec` sized from that result. Both calls pass a valid
        // constant and a valid-or-null buffer, so no memory is touched out of bounds.
        let len =
            unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, core::ptr::null_mut(), 0) };
        if len == 0 {
            return Err(eyre!(
                "could not resolve the per-user temp dir (confstr failed)"
            ));
        }
        let mut buf = vec![0 as libc::c_char; len];
        let got = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr(), len) };
        if got == 0 {
            return Err(eyre!(
                "could not resolve the per-user temp dir (confstr failed)"
            ));
        }
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect();
        let dir = String::from_utf8(bytes)
            .map_err(|_| eyre!("the per-user temp dir is not valid UTF-8"))?;
        let uid = unsafe { libc::geteuid() };
        Ok(PathBuf::from(dir).join(format!("swoosh-{uid}")))
    }
    #[cfg(not(target_os = "macos"))]
    {
        xdg_runtime_root(std::env::var_os("XDG_RUNTIME_DIR"))
    }
}

/// The runtime root under a given `XDG_RUNTIME_DIR`: `<it>/swoosh` when it is set and absolute, else the
/// refusal that names the variable. Split from [`runtime_root`] so the rule is one pure function over the
/// value, the same on every platform a test runs on.
#[cfg_attr(
    all(target_os = "macos", not(test)),
    allow(dead_code, reason = "macOS resolves its runtime root through confstr")
)]
pub(crate) fn xdg_runtime_root(value: Option<std::ffi::OsString>) -> eyre::Result<PathBuf> {
    let root = value.map(PathBuf::from).filter(|root| root.is_absolute());
    let Some(root) = root else {
        return Err(eyre!(
            "swoosh serve needs a private runtime directory. Set XDG_RUNTIME_DIR to a directory only you \
             can use (for example /run/user/$(id -u)), or run it as a systemd --user service."
        ));
    };
    Ok(root.join("swoosh"))
}

/// The default home, the platform's per-user state place: [`macos_state_home`] on macOS,
/// [`xdg_state_home`] elsewhere. Reads `HOME`, so it fails with a teaching error when unset (a caller can
/// always name the home explicitly with `--home <dir>` instead).
fn default_dir() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| eyre!("HOME is not set; pass --home <dir>"))?;
    #[cfg(target_os = "macos")]
    let dir = macos_state_home(Path::new(&home));
    #[cfg(not(target_os = "macos"))]
    let dir = xdg_state_home(Path::new(&home), std::env::var_os("XDG_STATE_HOME"));
    Ok(dir)
}

/// The macOS default home under the user's home directory `user`: `~/Library/Application Support/swoosh`.
#[cfg_attr(
    all(not(target_os = "macos"), not(test)),
    allow(dead_code, reason = "only macOS places its home here")
)]
pub(crate) fn macos_state_home(user: &Path) -> PathBuf {
    user.join("Library")
        .join("Application Support")
        .join("swoosh")
}

/// The Linux default home: `$XDG_STATE_HOME/swoosh` when the variable is set and absolute (the XDG rule
/// ignores a relative value), else `~/.local/state/swoosh` under the user's home directory `user`. A pure
/// function over the values, so the rule is tested the same on every platform.
#[cfg_attr(
    all(target_os = "macos", not(test)),
    allow(dead_code, reason = "macOS places its home under Application Support")
)]
pub(crate) fn xdg_state_home(user: &Path, xdg_state: Option<std::ffi::OsString>) -> PathBuf {
    xdg_state
        .map(PathBuf::from)
        .filter(|state| state.is_absolute())
        .unwrap_or_else(|| user.join(".local").join("state"))
        .join("swoosh")
}

/// Where a `recv:` with no directory saves: `~/Library/Application Support/swoosh-inbox` on macOS, else
/// `$XDG_DATA_HOME/swoosh/inbox` when that is set and absolute, else `~/.local/share/swoosh/inbox`. Never
/// inside the default home, which on macOS sits in the same base directory as `swoosh`, so the inbox there
/// is its sibling. Never the directory `serve` was started in: a push names its own path under the output
/// directory, so a `serve` started in `$HOME` would put the home's files in reach of every sender. `None`
/// when there is no `HOME` to place it under.
pub fn inbox() -> Option<PathBuf> {
    #[cfg(not(target_os = "macos"))]
    if let Some(data) = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|data| data.is_absolute())
    {
        return Some(data.join("swoosh").join("inbox"));
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)?;
    #[cfg(target_os = "macos")]
    let inbox = home
        .join("Library")
        .join("Application Support")
        .join("swoosh-inbox");
    #[cfg(not(target_os = "macos"))]
    let inbox = home
        .join(".local")
        .join("share")
        .join("swoosh")
        .join("inbox");
    Some(inbox)
}

/// A trust file this machine will not load, because someone other than its owner could have written it.
#[derive(Debug)]
pub struct LooseFile {
    /// The file.
    pub path: PathBuf,
    /// What is wrong with it.
    pub why: Loose,
}

impl core::fmt::Display for LooseFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The lead prints the path through the shared escaper: a home whose directory names hold CR, ESC or
        // a newline would otherwise rewrite this line or forge another, here and in the serve log.
        let path = EscapedPath(&self.path);
        match self.why {
            // The command names the absolute path, so it runs from any directory and a relative home that
            // starts with `-` or `=` is never read as an option or an expansion. When no word is sure to
            // read back as the path in every shell, the line names no command (O1).
            // A key: the lead names the full path too, so the line reads the same from any directory.
            Loose::Readable => {
                let full = std::path::absolute(&self.path).unwrap_or_else(|_| self.path.clone());
                write!(f, "{} can be read by others", EscapedPath(&full))?;
                match shell_word(&full) {
                    Some(word) => write!(f, ": chmod 600 {word}"),
                    None => Ok(()),
                }
            }
            Loose::Access => {
                let full = std::path::absolute(&self.path).unwrap_or_else(|_| self.path.clone());
                write!(f, "{} gives others access", EscapedPath(&full))?;
                match shell_word(&full) {
                    Some(word) => write!(f, ": chmod 600 {word}"),
                    None => Ok(()),
                }
            }
            Loose::Writable => {
                write!(f, "{path} can be written by others")?;
                match std::path::absolute(&self.path)
                    .ok()
                    .and_then(|full| shell_word(&full))
                {
                    Some(word) => write!(f, ": chmod 600 {word}"),
                    None => Ok(()),
                }
            }
            // No command: whether the file should be taken back, or swoosh run as its owner, is a judgment
            // only the person can make, and a `chown` needs root.
            Loose::Owner { owner, euid } => write!(
                f,
                "{path} is owned by {}, and swoosh is running as {}; it will not load another user's file",
                user_name(owner),
                user_name(euid)
            ),
        }
    }
}

/// `path` as one word that sh, bash, zsh, fish, csh and tcsh each read back as `path`, or `None` when
/// there is no such word this function can be sure of. Bare when every character is in
/// `[A-Za-z0-9_./,:@%+=-]`, which every one of them reads as itself past the first character (the
/// caller passes an absolute path, so the word starts with `/`). Else in single quotes, which only hold
/// when every character in them means itself in all six: so `None` for a `'` (no escape is common to
/// them), a `\` (fish reads `\'` and `\\` as escapes), a `!` (csh and tcsh expand history inside quotes),
/// and any character `char::escape_debug` escapes other than `"`: controls (a newline ends a csh command),
/// format and bidi characters, and, since std cannot tell them apart, grapheme-extending marks, which cost
/// only the command. A path that is not UTF-8 is `None` too, since the line cannot print its bytes as
/// themselves.
fn shell_word(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    let plain = |c: char| c.is_ascii_alphanumeric() || "_./,:@%+=-".contains(c);
    if !text.is_empty() && text.chars().all(plain) {
        return Some(text.to_owned());
    }
    let quotable = |c: char| c == '"' || (c != '!' && c.escape_debug().eq([c]));
    text.chars().all(quotable).then(|| format!("'{text}'"))
}

/// The user name `uid` has on this machine, or `uid <n>` when it has none, or one [`shown_name`] would not
/// print.
fn user_name(uid: u32) -> String {
    #[cfg(unix)]
    {
        // Grown on `ERANGE`, up to a cap no real passwd entry reaches.
        let mut buf = vec![0 as libc::c_char; 1024];
        loop {
            // SAFETY: `passwd` is plain C data (integers and pointers), for which all zeroes is a value.
            let mut pwd: libc::passwd = unsafe { core::mem::zeroed() };
            let mut found: *mut libc::passwd = core::ptr::null_mut();
            // SAFETY: `pwd` and `found` are live locals, and `buf` is a live buffer of `buf.len()` bytes;
            // `getpwuid_r` writes the entry's strings into `buf` and points `found` at `pwd` or null.
            let rc =
                unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
            if rc == libc::ERANGE && buf.len() < 1 << 16 {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc == 0 && !found.is_null() && !pwd.pw_name.is_null() {
                // SAFETY: on success `pw_name` points at a NUL-terminated string inside `buf`, which
                // outlives this borrow.
                let name = unsafe { core::ffi::CStr::from_ptr(pwd.pw_name) };
                if let Ok(name) = name.to_str() {
                    return shown_name(name, uid);
                }
            }
            break;
        }
    }
    format!("uid {uid}")
}

/// A passwd `name` as the owner line shows it: as itself when every character prints as itself (what
/// `char::escape_debug` leaves alone), it holds no blank letter, and it carries no leading or trailing
/// space, else `uid <n>`. A directory service can hand back any text, and a control, format or bidi
/// character, a blank letter, or a stray edge space in it would drive the terminal, misread as another
/// name, or reach the serve log unmarked.
fn shown_name(name: &str, uid: u32) -> String {
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|c| c.escape_debug().eq([c]) && !BLANK_LETTERS.contains(&c))
        && name == name.trim();
    if plain {
        return name.to_owned();
    }
    format!("uid {uid}")
}

impl core::error::Error for LooseFile {}

/// What makes a trust file loose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loose {
    /// Group or other can read the file: a key file, which holds a secret.
    Readable,
    /// Group or other can write the file.
    Writable,
    /// Group or other holds a bit on a key file that lets them neither read nor write it, which the key
    /// store refuses all the same.
    Access,
    /// Another user, not root, owns the file.
    Owner {
        /// The file's owner.
        owner: u32,
        /// This process's user, who must own it.
        euid: u32,
    },
}

/// What makes the file `meta` describes loose, or `None` when it is sound: another user owns it, or group
/// or other can write it. The owner and mode check a key file gets, less the read bits, since a trust file
/// holds no secret. Root may own one, as it may own a key file an administrator installed.
fn loose(meta: &std::fs::Metadata) -> Option<Loose> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        // SAFETY: `geteuid` takes no arguments and touches no memory.
        loose_by(meta.uid(), meta.mode(), unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// What makes the key file `meta` describes loose, or `None` when it is sound: another user owns it, or
/// group or other holds any bit on it.
fn loose_key(meta: &std::fs::Metadata) -> Option<Loose> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        // SAFETY: `geteuid` takes no arguments and touches no memory.
        loose_key_by(meta.uid(), meta.mode(), unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// The rule [`loose_key`] applies: [`loose_by`]'s owner rule, then [`Loose::Readable`] when group or other
/// can read the key, then [`loose_by`]'s write rule, then [`Loose::Access`] for any other group or other
/// bit, the rest of what the key store refuses, so none of its refusals reaches a person in its words.
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only unix has owners and modes to check")
)]
fn loose_key_by(owner: u32, mode: u32, euid: u32) -> Option<Loose> {
    match loose_by(owner, mode, euid) {
        Some(Loose::Owner { owner, euid }) => Some(Loose::Owner { owner, euid }),
        _ if mode & 0o044 != 0 => Some(Loose::Readable),
        Some(writable) => Some(writable),
        None => (mode & 0o077 != 0).then_some(Loose::Access),
    }
}

/// The line [`Home::check_key_file`] gives the key file at `path`, for a key store that refused it on its
/// modes or its owner: the key store's own text is never printed. The check ran before the verb, so only a
/// key changed since reaches here; it is stat'ed again and named as it is now, and one mended in between
/// is named for what the key store saw, a bit others held.
pub(crate) fn loose_key_file(path: PathBuf) -> LooseFile {
    let why = std::fs::metadata(&path)
        .ok()
        .and_then(|meta| loose_key(&meta))
        .unwrap_or(Loose::Access);
    LooseFile { path, why }
}

/// The rule [`loose`] applies, over a file's `owner` and `mode` and this process's `euid`: a file owned by
/// neither `euid` nor root is [`Loose::Owner`] whatever its mode, else one group or other can write is
/// [`Loose::Writable`]. Split out so a test walks the rule without a file another user owns.
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only unix has owners and modes to check")
)]
fn loose_by(owner: u32, mode: u32, euid: u32) -> Option<Loose> {
    if owner != euid && owner != 0 {
        return Some(Loose::Owner { owner, euid });
    }
    (mode & 0o022 != 0).then_some(Loose::Writable)
}

/// Open the trust file at `path` for reading, and check the open handle as [`loose`] does, so the bytes
/// read are the bytes checked. A loose file is a `PermissionDenied` error carrying the [`LooseFile`].
///
/// # Errors
///
/// Whatever the open or its `fstat` returns (`NotFound` for a missing file), or the loose file.
// `core::io::ErrorKind` is still unstable, so the error kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub fn open_trust_file(path: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::File::open(path)?;
    if let Some(why) = loose(&file.metadata()?) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            LooseFile {
                path: path.to_owned(),
                why,
            },
        ));
    }
    Ok(file)
}

/// [`std::fs::read_to_string`] for a trust file: the text of the file at `path`, read from a handle
/// [`open_trust_file`] checked.
///
/// # Errors
///
/// As [`open_trust_file`], or the read's own.
pub fn read_trust_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;

    let mut text = String::new();
    open_trust_file(path)?.read_to_string(&mut text)?;
    Ok(text)
}

/// [`read_trust_file`] on tokio's blocking pool, as `tokio::fs::read_to_string` reads, for an async caller.
///
/// # Errors
///
/// As [`read_trust_file`].
pub async fn read_trust_file_async(path: &Path) -> std::io::Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || read_trust_file(&path))
        .await
        .map_err(std::io::Error::other)?
}

/// The [`Loose`] an error from [`open_trust_file`] or [`read_trust_file`] carries, when it is one.
pub fn loose_in(error: &std::io::Error) -> Option<Loose> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<LooseFile>())
        .map(|loose| loose.why)
}

/// Reject a `--home` that names an existing FILE, instead of the confusing `Not a directory` the first file
/// IO under it would surface. The line names no directory to pass instead: the parent of the file named is
/// not the home when the file is the key at `machine/key`, and a home there would make a second key.
/// A no-op for a not-yet-created home (a fresh install creates the dir); it only fires on an existing file.
fn reject_home_file(dir: &Path) -> eyre::Result<()> {
    if dir.is_file() {
        return Err(eyre!(
            "--home wants a directory, not a file: {}",
            EscapedPath(dir)
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "home_tests.rs"]
mod home_tests;
