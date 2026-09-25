//! The node home: the one directory every file this node owns derives from.
//!
//! A node is a DIRECTORY, not a lone key file. `--home <dir>` (env `SWOOSH_HOME`) names it; with neither,
//! the default `~/.config/swoosh` applies. The key is always `<home>/key`, and the
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
/// then thread it where a verb needs a node path. It also remembers whether the home was named EXPLICITLY,
/// which is what a surface that RE-INVOKES swoosh must know: the `ssh` bridge forwards a named home to its
/// ProxyCommand so both halves read one node, and lets the default carry itself.
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
    /// the default `~/.config/swoosh`. Fallible only in the default case (it reads `HOME`), and it rejects
    /// an explicit home that names an existing FILE with a teaching error (the home is a directory; the key
    /// lives INSIDE it at `key`), the inverse of the old point-at-a-file mistake.
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

    /// `<home>/key`: the ed25519 secret every verb binds under (0600). Always inside the home,
    /// never a path the user points at directly.
    pub fn key(&self) -> PathBuf {
        self.dir.join("key")
    }

    /// `<home>/key.lock`: the lock that keeps a running node and a restore apart. Separate from
    /// `key`, because a restore replaces the key's inode, and a lock on a moving inode holds nothing.
    pub fn key_lock(&self) -> PathBuf {
        self.dir.join("key.lock")
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

    /// `<home>/relay`: the relay this node offers as its home relay, written by `serve --relay` and read
    /// by every later iroh bind under this home. A per-NODE setting: a peer dials you through whatever
    /// relay your published record names, so each node names its own.
    pub fn relay(&self) -> PathBuf {
        self.dir.join("relay")
    }

    /// `<home>/resolver`: the pkarr base this node publishes its address record to and looks peers up
    /// through, written by `serve --resolver` and read by every later iroh bind under this home. A
    /// FLEET-wide setting: two nodes find each other only through the same resolver.
    pub fn resolver(&self) -> PathBuf {
        self.dir.join("resolver")
    }

    /// `<home>/roster`: the newest update this machine holds from its root. Only a fold writes it: a root
    /// act's own cut, or one taken in an exchange with another device.
    pub fn roster(&self) -> PathBuf {
        self.dir.join("roster")
    }

    /// `<home>/roster.synced`: when a sync last reached another device, in unix seconds.
    pub fn roster_synced(&self) -> PathBuf {
        self.dir.join("roster.synced")
    }

    /// `<home>/roster.seed`: the key of the machine that made this machine's invite, the first device a
    /// sync asks.
    pub fn roster_seed(&self) -> PathBuf {
        self.dir.join("roster.seed")
    }

    /// `<home>/roster.lock`: the flock every fold holds, so two folds never read one floor and both write.
    pub fn roster_lock(&self) -> PathBuf {
        self.dir.join("roster.lock")
    }

    /// `<home>/roster.fork`: a second update seen at the number of the one in `roster`, kept as evidence
    /// that two copies of the root signed.
    pub fn roster_fork(&self) -> PathBuf {
        self.dir.join("roster.fork")
    }

    /// `<home>/root/`: the root, held here only by a machine that holds it.
    pub fn root(&self) -> PathBuf {
        self.dir.join("root")
    }

    /// `<home>/root.new/`: a root being written, before it is renamed to [`root`](Self::root).
    pub fn root_new(&self) -> PathBuf {
        self.dir.join("root.new")
    }

    /// `<home>/root.moving/`: a root renamed away by a move off this machine, before it is deleted.
    pub fn root_moving(&self) -> PathBuf {
        self.dir.join("root.moving")
    }

    /// `<home>/root.revoking/`: a root renamed away by its retirement here, before it is deleted.
    pub fn root_revoking(&self) -> PathBuf {
        self.dir.join("root.revoking")
    }

    /// `<home>/revoked`: the revocation denylist the expose gate honors, the next `serve` reads.
    pub fn revoked(&self) -> PathBuf {
        self.dir.join("revoked")
    }

    /// `<home>/revoked_keys`: the device keys this machine no longer admits, one key per line, which the
    /// `serve` gate refuses whatever the device presents and whose open sessions the live cut ends. It
    /// only ever grows, like [`revoked`](Self::revoked), and is written on the same rules: under
    /// [`revoked_keys_lock`](Self::revoked_keys_lock), with the count of keys it holds in
    /// [`revoked_keys_written`](Self::revoked_keys_written).
    pub fn revoked_keys(&self) -> PathBuf {
        self.dir.join("revoked_keys")
    }

    /// `<home>/revoked_keys.written`: how many keys [`revoked_keys`](Self::revoked_keys) held after its
    /// last write, so a file that lost keys reads as lost rather than as fewer revocations.
    pub fn revoked_keys_written(&self) -> PathBuf {
        self.dir.join("revoked_keys.written")
    }

    /// `<home>/revoked_keys.lock`: the flock every writer of [`revoked_keys`](Self::revoked_keys) takes.
    pub fn revoked_keys_lock(&self) -> PathBuf {
        self.dir.join("revoked_keys.lock")
    }

    /// `<home>/disabled_roots`: the root keys this node no longer trusts, one `ed01` key per line, which
    /// the `serve` gate refuses every cap rooted at and `fleet` and `adopt` refuse to follow. It only ever
    /// grows, and nothing here removes a key. Deliberately NOT [`disabled`](Self::disabled), the service
    /// toggle, whose list a re-enable shrinks: a root disable is terminal, and the two must never share a
    /// file or a reader.
    pub fn disabled_roots(&self) -> PathBuf {
        self.dir.join("disabled_roots")
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

    /// `<home>/links`: the ledger (0600) of every link this machine signed. The `serve` gate admits a
    /// link signed by this machine's own key only when its row is here, and revoke-by-holder and `grant
    /// ls` read it too.
    pub fn links(&self) -> PathBuf {
        self.dir.join("links")
    }

    /// `<home>/links.lock`: the flock every writer of [`links`](Self::links) takes, on a stable inode
    /// because a prune replaces `links` by rename.
    pub fn links_lock(&self) -> PathBuf {
        self.dir.join("links.lock")
    }

    /// `<home>/contacts.toml`: the address book of petnames this node resolves.
    pub fn contacts(&self) -> PathBuf {
        self.dir.join("contacts.toml")
    }

    /// `<home>/known_hosts`: the private host-key book `swoosh ssh` pins peers into, keyed on the
    /// immutable node id (not the petname) via ssh's `HostKeyAlias`. A node path like every other, so an
    /// isolated `--home` isolates its pins too; the default home's book stays at the historical
    /// `~/.config/swoosh/known_hosts`, since that IS the default home.
    pub fn known_hosts(&self) -> PathBuf {
        self.dir.join("known_hosts")
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
/// it at `key`); pointing it at a file is the inverse of the old point-at-a-key-file mistake, so
/// name the fix. A no-op for a not-yet-created home (a fresh install creates the dir); it only fires on an
/// existing file.
fn reject_home_file(dir: &Path) -> eyre::Result<()> {
    if dir.is_file() {
        return Err(eyre!(
            "--home wants a directory, not a file: {file}. The key lives inside the home at \
             {file}/key; pass the directory, e.g. {parent}",
            file = dir.display(),
            parent = dir.parent().unwrap_or(dir).display(),
        ));
    }
    Ok(())
}
