//! The node home: the one directory every file this node owns derives from.
//!
//! A node is a DIRECTORY, not a lone key file. `--home <dir>` (env `SWOOSH_HOME`) names it; with neither,
//! the default `~/.config/swoosh` applies. The identity key is always `<home>/identity.key`, and the
//! signet it gates on, the membership badge it presents, the contacts book, the mint-log ledger, and the
//! revocation denylist all hang off the SAME dir, so one home moves the whole identity+trust unit together.
//! This is the `GNUPGHOME` / `CARGO_HOME` model: a home dir is a whole profile, not a key you point at.
//!
//! Every node path is a pure function of the home, so this type is the ONE place "what files make up one
//! node's state" is answered; a caller reads a path off it (`home.signet()`, `home.revoked()`) rather than
//! re-deriving one from a key file's parent in a scattered spot.

use std::path::{Path, PathBuf};

use eyre::eyre;

/// The node home: the directory every file this node owns lives in.
///
/// Construct it once at the composition root from the `--home`/`SWOOSH_HOME` selection ([`Home::resolve`]),
/// then thread it where a verb needs a node path. It also remembers whether the home was named EXPLICITLY:
/// an explicit home pins the identity even for a reach-outward verb (which otherwise mints an ephemeral
/// key), the override the retired explicit `--key` carried.
#[derive(Debug, Clone)]
pub struct Home {
    dir: PathBuf,
    selection: Selection,
}

/// How the home was chosen: defaulted to `~/.config/swoosh`, or named explicitly (`--home`/`SWOOSH_HOME`).
///
/// An enum, not a bare bool, so the "did the caller pin this home" question reads as intent at every use
/// site and a future selection source (say a config file) forces a decision here rather than silently
/// widening a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selection {
    /// The default home, when neither `--home` nor `SWOOSH_HOME` is given. A reach-outward verb keeps its
    /// own intent (ephemeral by default), so a plain `swoosh ping` still mints a throwaway key.
    Default,
    /// A home named explicitly. Pins the identity for every verb, so an outward dial roots at this home's
    /// key rather than a fresh ephemeral one.
    Explicit,
}

impl Home {
    /// Resolve the home from the optional `--home`/`SWOOSH_HOME` selection: the named dir when given, else
    /// the default `~/.config/swoosh`. Fallible only in the default case (it reads `HOME`), and it rejects
    /// an explicit home that names an existing FILE with a teaching error (the home is a directory; the key
    /// lives INSIDE it at `identity.key`), the inverse of the old point-at-a-file mistake.
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

    /// Whether the home was named explicitly (`--home`/`SWOOSH_HOME`) rather than defaulted. An explicit
    /// home pins the identity even for a reach-outward verb; see [`Selection`] and [`identity::resolve`].
    ///
    /// [`identity::resolve`]: crate::identity::resolve
    pub fn is_explicit(&self) -> bool {
        self.selection == Selection::Explicit
    }

    /// `<home>/identity.key`: the ed25519 secret every verb binds under (0600). Always inside the home,
    /// never a path the user points at directly.
    pub fn identity_key(&self) -> PathBuf {
        self.dir.join("identity.key")
    }

    /// `<home>/signet`: the public [`NodeId`](bifrost::NodeId) of the signet this node trusts, written by
    /// `adopt`, read by the `serve` gate.
    pub fn signet(&self) -> PathBuf {
        self.dir.join("signet")
    }

    /// `<home>/badge`: the signet-signed, device-bound membership badge this device presents on connect.
    pub fn badge(&self) -> PathBuf {
        self.dir.join("badge")
    }

    /// `<home>/revoked`: the revocation denylist the expose gate honors, the next `serve` reads.
    pub fn revoked(&self) -> PathBuf {
        self.dir.join("revoked")
    }

    /// `<home>/disabled`: the newline list of DISABLED service names a running `serve` honors live (an
    /// mtime-watched oracle, the exact shape as [`revoked`](Self::revoked)). `service disable <svc>` adds a
    /// name and `service enable <svc>` removes one; a disable persists (fail-closed across a restart) and a
    /// disabled service refuses on the next stream with no restart.
    pub fn disabled(&self) -> PathBuf {
        self.dir.join("disabled")
    }

    /// `<home>/disabled.lock`: the flock file that serializes concurrent `enable`/`disable` edits so two
    /// racing toggles cannot lose each other's change. Separate from `disabled` itself because the toggle
    /// rewrites `disabled` by atomic rename (a new inode each time), so the lock must sit on a STABLE inode.
    pub fn disabled_lock(&self) -> PathBuf {
        self.dir.join("disabled.lock")
    }

    /// `<home>/grants`: the issuer-side mint-log ledger (0600) that makes revoke-by-holder and `grant ls`
    /// possible.
    pub fn grants(&self) -> PathBuf {
        self.dir.join("grants")
    }

    /// `<home>/contacts.toml`: the address book of petnames this node resolves.
    pub fn contacts(&self) -> PathBuf {
        self.dir.join("contacts.toml")
    }

    /// The 16-char hex key scoping this home's resident state: inline 64-bit FNV-1a over the
    /// canonicalized home path, the full 64 bits rendered as 16 lowercase hex chars. Dependency
    /// free and stable across daemon and client because both binaries carry this same function.
    /// Two different homes hash differently (the full-width hash, so collisions need a 2^64
    /// birthday, not 2^32), so two `--home`s never share a socket or lock.
    pub fn home_key(&self) -> String {
        let canonical = std::fs::canonicalize(&self.dir).unwrap_or_else(|_| {
            if self.dir.is_absolute() {
                self.dir.clone()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(&self.dir)
            }
        });
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in canonical.as_os_str().as_encoded_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        format!("{hash:016x}")
    }

    /// `<runtime>/swoosh-<uid>/<key>` (macOS) or `$XDG_RUNTIME_DIR/swoosh/<key>` (Linux): the
    /// per-home dir holding this node's resident socket and lock. A pure function of the home
    /// (via [`home_key`](Self::home_key)) over the per-user runtime root, so daemon and client
    /// resolve the same paths. Never `~/.config`, never `/tmp`, never an abstract socket.
    pub fn runtime_dir(&self) -> eyre::Result<PathBuf> {
        Ok(runtime_root()?.join(self.home_key()))
    }

    /// `<runtime_dir>/control.sock`: the local control socket rendezvous. See
    /// [`runtime_dir`](Self::runtime_dir).
    pub fn control_socket(&self) -> eyre::Result<PathBuf> {
        Ok(self.runtime_dir()?.join("control.sock"))
    }

    /// `<runtime_dir>/control.lock`: the flock file that is the single-instance truth. See
    /// [`runtime_dir`](Self::runtime_dir).
    pub fn control_lock(&self) -> eyre::Result<PathBuf> {
        Ok(self.runtime_dir()?.join("control.lock"))
    }
}

/// The per-user runtime root resident state lives under: `$XDG_RUNTIME_DIR/swoosh` on Linux,
/// `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `swoosh-<uid>` on macOS. Created and verified 0700 by the
/// single-instance acquire, never assumed. An unset or relative `XDG_RUNTIME_DIR` on Linux is a loud
/// error, never a `/tmp` or cwd fallback.
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
        let root = std::env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
            eyre!(
                "XDG_RUNTIME_DIR is not set; resident serve needs it (no /tmp fallback). \
                 Set it, e.g. XDG_RUNTIME_DIR=/run/user/$(id -u)"
            )
        })?;
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            return Err(eyre!(
                "XDG_RUNTIME_DIR must be an absolute path (got {root}); resident serve never \
                 roots at the cwd",
                root = root.display()
            ));
        }
        Ok(root.join("swoosh"))
    }
}

/// The default home, `~/.config/swoosh`. Reads `HOME`, so it fails with a teaching error when unset (a
/// caller can always name the home explicitly with `--home <dir>` instead).
fn default_dir() -> eyre::Result<PathBuf> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set; pass --home <dir>"))?;
    Ok(PathBuf::from(home).join(".config").join("swoosh"))
}

/// Reject a `--home` that names an existing FILE, with a teaching error instead of the confusing
/// `Not a directory` the first file IO under it would surface. A home is a DIRECTORY (the key lives inside
/// it at `identity.key`); pointing it at a file is the inverse of the old point-at-a-key-file mistake, so
/// name the fix. A no-op for a not-yet-created home (a fresh install creates the dir); it only fires on an
/// existing file.
fn reject_home_file(dir: &Path) -> eyre::Result<()> {
    if dir.is_file() {
        return Err(eyre!(
            "--home wants a directory, not a file: {file}. The key lives inside the home at \
             {file}/identity.key; pass the directory, e.g. {parent}",
            file = dir.display(),
            parent = dir.parent().unwrap_or(dir).display(),
        ));
    }
    Ok(())
}
