//! The key files swoosh keeps, and the one place their refusals are worded.
//!
//! Every key file is opened here, named for whose it is ([`Whose`]): this machine's key, your root kept in the
//! home, or a copy of your root in a directory the person typed. Whose it is fixes the file's kind too, so a
//! root is always strict and this machine's key never is.
//!
//! The key store words its refusals in its own vocabulary and names the path it acted on, which after a lock
//! change is the file a symbolic link resolved to. A copy handed over on a stick can name that file anything,
//! terminal escapes included, so nothing the key store says reaches a person. Each refusal is a [`Refused`]:
//! swoosh's words, swoosh's own path where one helps the person act, and no `source()`, so a `{report:#}`
//! prints exactly that. The key store's error is kept for the `debug` log and for [`Refused::kind`], which
//! code matches on.

use core::fmt;
use std::io;
use std::path::{Path, PathBuf};

use keystore::{Method, NewLock, Protection, PublicKey, Secret, Stored, Unlock};

use crate::escape::{Escaped, LINE_WIDTH, columns, peer_cell, room};
use crate::home::Home;

/// Whose key a key file holds, as a person knows it: the words every refusal of the file is said in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whose {
    /// This machine's own key, `<home>/machine/key`.
    Machine,
    /// Your root, kept in the home as `<home>/root.key`.
    Root,
    /// A copy of your root, in the directory the person typed.
    Copy(PathBuf),
}

impl Whose {
    /// The key, as a refusal names it.
    const fn key(&self) -> &'static str {
        match self {
            Self::Machine => "this machine's key",
            Self::Root => "your root",
            Self::Copy(_) => "the copy",
        }
    }

    /// The key's file, as a refusal names it.
    const fn file(&self) -> &'static str {
        match self {
            Self::Machine => "this machine's key file",
            Self::Root => "your root's key file",
            Self::Copy(_) => "the copy's key file",
        }
    }
}

/// A key file, named for whose it is. Every read, write and lock change of a key swoosh keeps goes through
/// one, so every refusal is a [`Refused`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    file: keystore::KeyFile,
    whose: Whose,
}

impl KeyFile {
    /// The key file at `path`, of the kind `whose` fixes: a root, kept here or copied, is strict.
    fn at(path: PathBuf, whose: Whose) -> Self {
        let file = match whose {
            Whose::Machine => keystore::KeyFile::new(path),
            Whose::Root | Whose::Copy(_) => keystore::KeyFile::strict(path),
        };
        Self { file, whose }
    }

    /// This machine's key file in `home`.
    pub fn machine(home: &Home) -> Self {
        Self::at(home.key(), Whose::Machine)
    }

    /// The root's key file kept in `home`.
    pub fn root(home: &Home) -> Self {
        Self::at(home.root_key(), Whose::Root)
    }

    /// The key file of the copy of a root in `dir`, the directory the person typed.
    pub fn copy(dir: &Path) -> Self {
        Self::at(
            dir.join(crate::home::ROOT_KEY),
            Whose::Copy(dir.to_path_buf()),
        )
    }

    /// A file named `name` beside this one, of the same kind and whose: where a new key is staged before it
    /// is put in this one's place.
    pub fn beside(&self, name: &str) -> Self {
        Self::at(self.file.path().with_file_name(name), self.whose.clone())
    }

    /// The key store's file, once a copy's is known not to be a link. A lock change follows a link and
    /// rewrites the file it names, so a copy whose `root.key` links to the home's would change the home's
    /// root while the line said the copy changed. A home's own key files are the home's to arrange, and are
    /// not held to this.
    fn checked(&self) -> Result<&keystore::KeyFile, Refused> {
        let link = matches!(self.whose, Whose::Copy(_))
            && std::fs::symlink_metadata(self.path())
                .is_ok_and(|meta| meta.file_type().is_symlink());
        if link {
            return Err(self.refused(Cause::Link));
        }
        Ok(&self.file)
    }

    /// The path swoosh named the file by: the one a refusal prints, never a path a link resolved to.
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// Whose key the file holds.
    pub const fn whose(&self) -> &Whose {
        &self.whose
    }

    /// The file's key: `None` only when nothing is at the path. See [`keystore::KeyFile::load`].
    ///
    /// # Errors
    ///
    /// The file is there and cannot be read as a key this build reads.
    pub fn load(&self) -> Result<Option<Stored>, Refused> {
        self.checked()?.load().map_err(|error| self.refuse(error))
    }

    /// Write `secret` under `protection` where nothing is. See [`keystore::KeyFile::write`].
    ///
    /// # Errors
    ///
    /// The write did not land, or landed and its directory was not synced ([`Refused::unsynced`]).
    pub fn write(&self, secret: &Secret, protection: Protection<'_>) -> Result<(), Refused> {
        self.checked()?
            .write(secret, protection)
            .map_err(|error| self.refuse(error))
    }

    /// Write `secret` unless the same key is already there. See [`keystore::KeyFile::adopt`].
    ///
    /// # Errors
    ///
    /// As [`write`](Self::write), and a different key at the path ([`Kind::Different`]).
    pub fn adopt(&self, secret: &Secret, protection: Protection<'_>) -> Result<(), Refused> {
        self.checked()?
            .adopt(secret, protection)
            .map_err(|error| self.refuse(error))
    }

    /// Put `new` on the file, opened `with` one of its locks. See [`keystore::KeyFile::add_lock`].
    ///
    /// # Errors
    ///
    /// The lock did not open the file, or the rewrite failed.
    pub fn add_lock(&self, with: Option<Unlock<'_>>, new: NewLock<'_>) -> Result<(), Refused> {
        self.checked()?
            .add_lock(with, new)
            .map_err(|error| self.refuse(error))
    }

    /// Take the lock of `method` off the file, opened `with` one of its locks. See
    /// [`keystore::KeyFile::remove_lock`].
    ///
    /// # Errors
    ///
    /// As [`add_lock`](Self::add_lock).
    pub fn remove_lock(&self, with: Unlock<'_>, method: Method) -> Result<(), Refused> {
        self.checked()?
            .remove_lock(with, method)
            .map_err(|error| self.refuse(error))
    }

    /// Open `locked`, read from this file, `with` one of its locks.
    ///
    /// # Errors
    ///
    /// The lock did not open it: a wrong passphrase and a damaged file are one [`Kind::Unlock`].
    // The one call of the key store's own unlock: every other site opens through here, so its refusal is
    // worded here (`clippy.toml`).
    #[allow(clippy::disallowed_methods)]
    pub fn unlock(&self, locked: &keystore::Locked, with: Unlock<'_>) -> Result<Secret, Refused> {
        locked.unlock(with).map_err(|error| self.refuse(error))
    }

    /// Read the file again and open it with the touch `with`: the read a touch makes on its own thread, so
    /// the key it opens is the one the file holds then.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is gone, is plain (it holds no `touch-id` lock to open), or did not open.
    pub fn reopen(&self, with: Unlock<'_>) -> Result<Secret, Refused> {
        match self.load()? {
            Some(Stored::Locked(locked)) => self.unlock(&locked, with),
            Some(Stored::Plain(_)) => Err(self.refuse(keystore::Error::NoLock {
                path: self.path().to_path_buf(),
                method: Method::TouchId,
            })),
            None => Err(self.absent()),
        }
    }

    /// The refusal of a read that needs the file and found nothing at the path.
    pub fn absent(&self) -> Refused {
        self.refuse(keystore::Error::Absent {
            path: self.path().to_path_buf(),
        })
    }

    /// `error`, which the key store answered for this file, as the refusal a person reads. The key store's
    /// own text is logged at `debug`, escaped, since its path may be a link's target. Crate-only, so the
    /// key store's error type stays out of this crate's API.
    pub(crate) fn refuse(&self, error: keystore::Error) -> Refused {
        tracing::debug!(
            whose = ?self.whose,
            error = %Escaped(&crate::escape::causes(&error)),
            "the key store refused a key file"
        );
        self.refused(Cause::Store(error))
    }

    /// The refusal of a copy's key file opened with no link followed and found a link (`ELOOP`); `None`
    /// for a home's own key file, which is not held to that.
    pub(crate) fn as_link(&self) -> Option<Refused> {
        matches!(self.whose, Whose::Copy(_)).then(|| self.refused(Cause::Link))
    }

    /// The refusal of this file for `cause`.
    fn refused(&self, cause: Cause) -> Refused {
        Refused(Box::new(Parts {
            whose: self.whose.clone(),
            path: self.path().to_path_buf(),
            cause,
        }))
    }

    /// One refusal of this file for each answer the key store gives at the pin, and for a copy its link
    /// refusal, for a test that holds every one to the screen's law.
    #[cfg(any(test, feature = "test-support"))]
    pub fn every_refusal(&self) -> Vec<Refused> {
        let mut refused: Vec<Refused> = key_store_errors()
            .into_iter()
            .map(|error| self.refuse(error))
            .collect();
        if matches!(self.whose, Whose::Copy(_)) {
            refused.push(self.refused(Cause::Link));
        }
        refused
    }
}

/// One of each answer the key store gives at the pin, as its variant is built, each naming a path swoosh
/// never does: a link's target.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn key_store_errors() -> Vec<keystore::Error> {
    use keystore::{EnclaveError, Error, FormatError, TouchIdError};

    let path = || PathBuf::from("/elsewhere/link-target");
    let key = Secret::take(&mut [0x11; 32]).public_key();
    let enclave = || EnclaveError::new(io::Error::other("the enclave said no"));
    vec![
        Error::Io {
            path: path(),
            source: io::Error::other("permission denied by the system"),
        },
        Error::NotAFile { path: path() },
        Error::Permissive {
            path: path(),
            mode: 0o644,
        },
        Error::Owner {
            path: path(),
            owner: 501,
        },
        Error::Format {
            path: path(),
            source: FormatError::Size { found: 16 },
        },
        Error::Format {
            path: path(),
            source: FormatError::Method { found: 9 },
        },
        Error::Unlock {
            path: path(),
            method: Method::Passphrase,
        },
        Error::Unlock {
            path: path(),
            method: Method::TouchId,
        },
        Error::Inconsistent { path: path() },
        Error::Occupied { path: path() },
        Error::Unconfirmed {
            path: path(),
            claimed: key,
        },
        Error::Different {
            path: path(),
            existing: key,
            incoming: key,
        },
        Error::PlainStrict { path: path() },
        Error::StrictPassphrase { path: path() },
        Error::StrictPassphraseNeeded { path: path() },
        Error::NoneOpensHere {
            path: path(),
            method: Method::TouchId,
        },
        Error::Absent { path: path() },
        Error::NoLock {
            path: path(),
            method: Method::TouchId,
        },
        Error::Sealed { path: path() },
        Error::Unverified { path: path() },
        Error::Changed { path: path() },
        Error::NoHardLinks {
            path: path(),
            source: io::Error::other("operation not supported"),
        },
        Error::Unsynced {
            path: path(),
            source: io::Error::other("the disk went away"),
        },
        Error::TouchId {
            path: path(),
            source: TouchIdError::Enclave(enclave()),
        },
        Error::TouchId {
            path: path(),
            source: TouchIdError::Declined(enclave()),
        },
    ]
}

/// A key file the key store refused, in swoosh's words. Its `source()` is `None` and its `Debug` names only
/// whose file it is and the key store's variant, so neither the key store's text nor the path it acted on
/// reaches a line, a log of a `{:?}`, or a panic. Boxed, so a `Result` that carries one stays small.
pub struct Refused(Box<Parts>);

/// What a [`Refused`] holds.
struct Parts {
    whose: Whose,
    /// The path swoosh named the file by.
    path: PathBuf,
    cause: Cause,
}

/// Why a key file was refused: the key store's answer, or swoosh's own check before it asked.
enum Cause {
    /// The key store's answer.
    Store(keystore::Error),
    /// A copy's key file is a link ([`KeyFile::checked`]).
    Link,
}

/// What a refusal was, for code that acts on it: only the cases a caller tells apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The path names something other than a regular file.
    NotAFile,
    /// Group or other holds a permission bit on the file.
    Permissive,
    /// The file is owned by another user.
    Owner,
    /// The bytes are not a key file this build reads; `method` is the lock method byte it does not know,
    /// where that is why.
    Format {
        /// The unknown lock method byte, where that is why.
        method: Option<u8>,
    },
    /// A lock of this method did not open the file: for a passphrase, a wrong one or a damaged file, which
    /// nothing tells apart.
    Unlock(Method),
    /// Nothing is at the path.
    Absent,
    /// An adopt found another key at the path: the one the file holds, or for a sealed file claims.
    Different(PublicKey),
    /// A touch was cancelled by the person or the system, or did not match.
    Declined,
    /// No touch came within the wait.
    TimedOut,
    /// A `touch-id` lock does not open on this Mac now, or this build has no enclave.
    NotHere,
    /// A copy's key file is a link.
    Link,
    /// Anything else, an enclave that failed included.
    Other,
}

impl Refused {
    /// What the refusal was.
    pub fn kind(&self) -> Kind {
        use keystore::{Error, TouchIdError};

        let error = match &self.0.cause {
            Cause::Store(error) => error,
            Cause::Link => return Kind::Link,
        };
        match error {
            Error::NotAFile { .. } => Kind::NotAFile,
            Error::Permissive { .. } => Kind::Permissive,
            Error::Owner { .. } => Kind::Owner,
            Error::Format { source, .. } => Kind::Format {
                method: match source {
                    keystore::FormatError::Method { found } => Some(*found),
                    _ => None,
                },
            },
            Error::Unlock { method, .. } => Kind::Unlock(*method),
            Error::Absent { .. } => Kind::Absent,
            Error::Different { existing, .. } => Kind::Different(*existing),
            Error::TouchId { source, .. } => match source {
                TouchIdError::Declined(_) => Kind::Declined,
                TouchIdError::TimedOut(_) => Kind::TimedOut,
                TouchIdError::NotHere(_) | TouchIdError::Unavailable => Kind::NotHere,
                _ => Kind::Other,
            },
            _ => Kind::Other,
        }
    }

    /// The refusal's first line alone, for a row that holds one line.
    pub fn head(&self) -> String {
        let line = self.to_string();
        match line.split_once('\n') {
            Some((head, _)) => head.to_owned(),
            None => line,
        }
    }

    /// Where the file is in place but its directory could not be synced, so a power loss could undo it: the
    /// words of the `failure` row said beside the written result, the system's own text last. `None` for
    /// every other refusal, which is a write that did not land.
    pub fn unsynced(&self) -> Option<String> {
        match &self.0.cause {
            Cause::Store(keystore::Error::Unsynced { source, .. }) => Some(format!(
                "the directory holding the key file could not be synced to disk: {source}"
            )),
            _ => None,
        }
    }

    /// The words of the `failure` row said beside a written result: [`unsynced`](Self::unsynced)'s where
    /// the write landed, else the refusal's [`head`](Self::head).
    pub fn failure(&self) -> String {
        self.unsynced().unwrap_or_else(|| self.head())
    }

    /// The system's own error, where the file or its directory could not be accessed; else the refusal back.
    ///
    /// # Errors
    ///
    /// The refusal, when it is not the key store's answer that the file could not be accessed.
    pub fn into_io(self) -> Result<io::Error, Self> {
        let Parts { whose, path, cause } = *self.0;
        match cause {
            Cause::Store(keystore::Error::Io { source, .. }) => Ok(source),
            cause => Err(Self(Box::new(Parts { whose, path, cause }))),
        }
    }

    /// The `copy` row under the head, for a copy: the head never holds a path, so it stays inside 80 columns.
    fn copy_row(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.whose {
            Whose::Copy(dir) => write!(f, "\n  copy   {}", path_cell(dir)),
            Whose::Machine | Whose::Root => Ok(()),
        }
    }

    /// The `file` row: swoosh's own path, escaped, never the path the key store acted on.
    fn file_row(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\n  file   {}", path_cell(&self.0.path))
    }

    /// The home holding the file: the directory above `machine/` for this machine's key, the one holding
    /// `root.key` for a root.
    fn home(&self) -> &Path {
        let dir = self.0.path.parent().unwrap_or(&self.0.path);
        match self.0.whose {
            Whose::Machine => dir.parent().unwrap_or(dir),
            Whose::Root | Whose::Copy(_) => dir,
        }
    }
}

/// The lines a person reads: a head with no `error:` (the caller prefixes it), then rows and details.
impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use keystore::Error;

        let (key, file) = (self.0.whose.key(), self.0.whose.file());
        let error = match &self.0.cause {
            Cause::Store(error) => error,
            // The file the link names never prints: it can hold escapes, and it is the path this exists to
            // keep off the line.
            Cause::Link => {
                write!(f, "{file} is a link")?;
                self.copy_row(f)?;
                self.file_row(f)?;
                return f.write_str("\n  The key file must be the file itself, not a link to it.");
            }
        };
        match error {
            Error::Io { .. } => {
                write!(f, "could not access {file}")?;
                self.copy_row(f)?;
                self.file_row(f)
            }
            Error::NotAFile { .. } => {
                write!(f, "{file} is not a regular file")?;
                self.copy_row(f)?;
                self.file_row(f)
            }
            Error::Permissive { .. } => {
                write!(f, "{file} gives other users access")?;
                self.copy_row(f)?;
                self.file_row(f)?;
                // A command a person pastes runs as printed, or is not printed: one cut to fit its line
                // would not run. Without one, the screen still says what to do.
                match chmod_operand(&self.0.path) {
                    Some(operand) if columns(&operand) <= room(CHMOD.len()) => {
                        write!(f, "\n\nTo fix it:\n{CHMOD}{operand}")
                    }
                    _ => f.write_str("\n  Take that access off the file."),
                }
            }
            Error::Owner { .. } => {
                write!(f, "{file} belongs to another user")?;
                self.copy_row(f)?;
                self.file_row(f)
            }
            Error::Format { .. } => {
                write!(f, "{file} is not one this build reads")?;
                self.copy_row(f)
            }
            // One byte string for a wrong passphrase and a damaged file: the cipher cannot tell them apart,
            // and a line that guessed would be an oracle.
            Error::Unlock {
                method: Method::Passphrase,
                ..
            } => {
                write!(f, "that passphrase does not open {key}")?;
                self.copy_row(f)?;
                f.write_str("\n  If you are sure it is right, the key file may be damaged.")
            }
            // A lock another program made with this Mac's enclave fails this way too, and is not damage.
            Error::Unlock {
                method: Method::TouchId,
                ..
            } => {
                write!(f, "Touch ID did not open {key}")?;
                self.copy_row(f)
            }
            Error::Inconsistent { .. } => {
                write!(f, "{file} is damaged")?;
                self.copy_row(f)
            }
            // A copy's directory is no home, and its `copy` row already names it.
            Error::NoHardLinks { .. } => {
                match &self.0.whose {
                    Whose::Copy(_) => {
                        f.write_str("the copy's disk cannot store a key file safely")?;
                        self.copy_row(f)?;
                    }
                    Whose::Machine | Whose::Root => write!(
                        f,
                        "this home's disk cannot store a key file safely\n  home   {}",
                        path_cell(self.home())
                    )?,
                }
                f.write_str("\n  The disk may not support hard links, which a key file needs.")
            }
            // The change landed, so this never reads as `could not use`; the system's text is the `failure`
            // row's alone ([`Refused::unsynced`]).
            Error::Unsynced { .. } => {
                write!(f, "{file} was written but not synced to disk")?;
                self.copy_row(f)?;
                f.write_str("\n  A power loss could undo the change.")
            }
            Error::TouchId { .. } => {
                write!(f, "Touch ID could not open {key}")?;
                self.copy_row(f)
            }
            // The two lock-change refusals that say what state the file was left in.
            Error::Unverified { .. } => {
                write!(f, "could not use {file}")?;
                self.copy_row(f)?;
                f.write_str("\n  The key file is as it was.")
            }
            Error::Changed { .. } => {
                write!(f, "could not use {file}")?;
                self.copy_row(f)?;
                f.write_str("\n  The key file changed while this ran, and was left as it now is.")
            }
            // Every other refusal, a variant this build does not know included: true of any `Err`, and it
            // claims nothing about the file or its locks. The key store's own text is at `debug`.
            _ => {
                write!(f, "could not use {file}")?;
                self.copy_row(f)
            }
        }
    }
}

/// Whose file and the key store's variant only: never its text, and never its path.
impl fmt::Debug for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match &self.0.cause {
            Cause::Store(error) => variant(error),
            Cause::Link => "Link",
        };
        f.debug_struct("Refused")
            .field("whose", &self.0.whose)
            .field("error", &variant)
            .finish()
    }
}

/// No source: the key store's error, its path and its chain stay off every line.
impl core::error::Error for Refused {}

/// The name of `error`'s variant.
fn variant(error: &keystore::Error) -> &'static str {
    use keystore::Error;

    match error {
        Error::Io { .. } => "Io",
        Error::NotAFile { .. } => "NotAFile",
        Error::Permissive { .. } => "Permissive",
        Error::Owner { .. } => "Owner",
        Error::Format { .. } => "Format",
        Error::Unlock { .. } => "Unlock",
        Error::Inconsistent { .. } => "Inconsistent",
        Error::Occupied { .. } => "Occupied",
        Error::Unconfirmed { .. } => "Unconfirmed",
        Error::Different { .. } => "Different",
        Error::PlainStrict { .. } => "PlainStrict",
        Error::StrictPassphrase { .. } => "StrictPassphrase",
        Error::StrictPassphraseNeeded { .. } => "StrictPassphraseNeeded",
        Error::NoneOpensHere { .. } => "NoneOpensHere",
        Error::Absent { .. } => "Absent",
        Error::NoLock { .. } => "NoLock",
        Error::Sealed { .. } => "Sealed",
        Error::Unverified { .. } => "Unverified",
        Error::Changed { .. } => "Changed",
        Error::NoHardLinks { .. } => "NoHardLinks",
        Error::Unsynced { .. } => "Unsynced",
        Error::TouchId { .. } => "TouchId",
        Error::Crypto { .. } => "Crypto",
        _ => "Other",
    }
}

/// The fix a loose file's refusal prints, before its operand.
const CHMOD: &str = "  chmod 600 -- ";

/// The room a row's value has after its label (`  file   `, `  copy   `, `  home   `, each as wide), less
/// the line's last column, as [`room`] counts it.
const ROW_ROOM: usize = LINE_WIDTH - "  file   ".len() - 1;

/// `path` as a row's value: escaped, and cut to the room the row leaves, as every row of text swoosh did not
/// write is, so a path of wide glyphs cannot wrap onto a line of its own.
fn path_cell(path: &Path) -> String {
    peer_cell(&path.to_string_lossy(), ROW_ROOM)
}

/// `path` as `chmod`'s operand, so the command runs as printed: bare where it starts with `/` or `.` and
/// holds only characters no shell reads specially; else single-quoted, a `'` in it written `'\''`, so a
/// `~` anywhere (zsh's `extendedglob` reads one mid-word), or a leading `=` or `-`, is never expanded or
/// read as an option. `None` where the path is not text or
/// holds a character the escaper writes as an escape (a control, one that hides or reorders text): the
/// row prints it escaped, and a command that would not run as printed is not printed. A quote or a
/// backslash, which the escaper also escapes, is plain text inside single quotes.
fn chmod_operand(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    let plain = |c: char| {
        matches!(c, '\'' | '"' | '\\')
            || (!crate::escape::BLANK_LETTERS.contains(&c) && c.escape_debug().eq([c]))
    };
    if !text.chars().all(plain) {
        return None;
    }
    let bare = text.starts_with(['/', '.'])
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c));
    if bare {
        return Some(text.to_owned());
    }
    Some(format!("'{}'", text.replace('\'', r"'\''")))
}

#[cfg(test)]
#[path = "key_file_tests.rs"]
mod key_file_tests;
