//! What a `serve` entry's target names: its [`Scheme`], parsed once, and the whole target as a link records
//! it ([`ServedTarget`]). What an engine may face is a question about the scheme, so it is asked of these
//! two types and never of a string.

use core::fmt;
use core::str::FromStr;
use std::collections::HashMap;

/// Declare [`Scheme`] from one list of variants and their texts, so the enum, [`Scheme::ALL`],
/// [`Scheme::as_str`] and [`Scheme::parse`] cannot list different schemes: a variant added here is in all
/// four, and every exhaustive `match` on the enum must then answer it.
macro_rules! schemes {
    ($($(#[$doc:meta])* $variant:ident => $text:literal,)+) => {
        /// Every scheme a `serve` entry can name: swoosh's own engines (`ping:`, `speed:`, `sshd:`, `recv:`,
        /// `proxy:`) and tightbeam's primitives. An enum so that what a scheme's engine may face is one
        /// exhaustive match: a scheme added here must answer [`runs_code`](Self::runs_code) and
        /// [`never_public`](Self::never_public), and `bind_entry` must bind it, before it compiles.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Scheme {
            $($(#[$doc])* $variant,)+
        }

        impl Scheme {
            /// Every scheme, for a test that walks them.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The scheme as a target spells it, without its `:`.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }

            /// The scheme spelled `text`, without its `:`, or `None` for one no `serve` binds.
            fn named(text: &str) -> Option<Self> {
                match text {
                    $($text => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

schemes! {
    /// `ping:`, the latency probe.
    Ping => "ping",
    /// `speed:`, the throughput test.
    Speed => "speed",
    /// `sshd:`, a shell on this machine.
    Sshd => "sshd",
    /// `recv:<dir>`, files pushed into a directory.
    Recv => "recv",
    /// `proxy:<url>`, requests made from this machine.
    Proxy => "proxy",
    /// `tcp:<host>:<port>`, a forward to a local address.
    Tcp => "tcp",
    /// `unix:<path>`, a forward to a local socket.
    Unix => "unix",
    /// `file:<path>`, a file's bytes.
    File => "file",
    /// `fifo:<path>`, a named pipe's bytes.
    Fifo => "fifo",
    /// `stdin:`, the serving process's stdin.
    Stdin => "stdin",
    /// `echo:`, the reflector.
    Echo => "echo",
}

impl Scheme {
    /// The scheme `target` (`sshd:`, `tcp:localhost:22`) names and the argument after its `:`, or `None`
    /// when it names none or one no `serve` binds.
    pub fn parse(target: &str) -> Option<(Self, &str)> {
        let (scheme, argument) = target.split_once(':')?;
        Some((Self::named(scheme)?, argument))
    }

    /// Whether the engine runs what a caller sends: a link to it is a way to run code on this machine as
    /// this user. Not caught here: a `unix:` or `tcp:` forward to a local service that itself runs code (a
    /// Docker socket); those need the target's own answer, which a forward does not have.
    pub fn runs_code(self) -> bool {
        match self {
            Self::Sshd => true,
            Self::Ping
            | Self::Speed
            | Self::Recv
            | Self::Proxy
            | Self::Tcp
            | Self::Unix
            | Self::File
            | Self::Fifo
            | Self::Stdin
            | Self::Echo => false,
        }
    }

    /// Whether the engine a gated `serve` binds for this scheme, given `argument` (what follows the `:`),
    /// declares it must never face an open gate (`type Exposure = Never`): it runs code, has no limits of
    /// its own, or writes this machine's disk. Such an engine is opened to anyone neither by `--public` nor
    /// by a link to anyone. The shell, the owner-tier `ping` and `speed` (an open one binds the metered
    /// engine instead), receiving files, and a `proxy:` scoped to no origin (an open relay). A forward and
    /// the reflector may face anyone; so may a raw stream, which opens only through `--public-unsafe`.
    pub fn never_public(self, argument: &str) -> bool {
        match self {
            Self::Sshd | Self::Ping | Self::Speed | Self::Recv => true,
            Self::Proxy => argument.is_empty(),
            Self::Tcp | Self::Unix | Self::Echo | Self::File | Self::Fifo | Self::Stdin => false,
        }
    }
}

/// A `serve` entry's target, parsed: a [`Scheme`] some `serve` binds, its argument, and no control
/// character, so it is one field of one ledger line. What a link records its service's name served when
/// it was made (`sshd:`, `tcp:localhost:22`), and what a running `serve` bound under a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedTarget {
    scheme: Scheme,
    /// The whole target as its entry spells it, scheme included.
    text: String,
}

impl ServedTarget {
    /// The target as its `serve` entry spells it.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The scheme it names.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Whether its engine runs what a caller sends ([`Scheme::runs_code`]).
    pub fn runs_code(&self) -> bool {
        self.scheme.runs_code()
    }

    /// Whether its engine must never face an open gate ([`Scheme::never_public`]).
    pub fn never_public(&self) -> bool {
        self.scheme.never_public(self.argument())
    }

    /// What follows the scheme's `:`.
    pub fn argument(&self) -> &str {
        self.text
            .split_once(':')
            .map_or("", |(_, argument)| argument)
    }
}

impl FromStr for ServedTarget {
    type Err = NotATarget;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some((scheme, _)) = Scheme::parse(text) else {
            return Err(NotATarget(text.to_owned()));
        };
        if text.chars().any(char::is_control) {
            return Err(NotATarget(text.to_owned()));
        }
        Ok(Self {
            scheme,
            text: text.to_owned(),
        })
    }
}

impl fmt::Display for ServedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ServedTarget {
    /// Whether a link made while its name served `made_for` may reach this target: only one made for this
    /// very target, or, when this engine may face anyone, one made while the name served nothing. So a
    /// name rebound to something else never takes its old links along, and a link made before its name
    /// served anything never reaches an engine that must never face an open gate.
    pub fn admits_made_for(&self, made_for: Option<&Self>) -> bool {
        match made_for {
            Some(made_for) => made_for == self,
            None => !self.never_public(),
        }
    }
}

/// What a running `serve` bound under each of its names, from the `name=target` entries it started with:
/// what a link it signed is checked against when it is presented, so a link reaches only the target it
/// was made for, whatever the name was rebound to since.
#[derive(Debug, Clone, Default)]
pub struct BoundTargets {
    /// Each name and its target; `None` for a target no link can record (a scheme [`Scheme`] does not
    /// know, or a control character), which admits no link.
    by_name: HashMap<String, Option<ServedTarget>>,
}

impl BoundTargets {
    /// The targets `entries` (`name=target`, names folded, as `serve` binds them) bind. An entry with no
    /// `=` binds no name, so it is not held. One whose target is no [`ServedTarget`] is held as admitting
    /// no link: tightbeam may still bind a scheme [`Scheme`] does not know, and a link made for anything
    /// must never reach an engine this gate cannot judge.
    pub fn of<'a>(entries: impl IntoIterator<Item = &'a str>) -> Self {
        let by_name = entries
            .into_iter()
            .filter_map(|entry| {
                let (name, target) = entry.split_once('=')?;
                Some((name.to_owned(), target.parse().ok()))
            })
            .collect();
        Self { by_name }
    }

    /// Whether a link to `service`, made while its name served `made_for`, may be admitted: the name is
    /// bound by no entry here (no engine of this run for it to reach), or the target bound under it
    /// [admits](ServedTarget::admits_made_for) what the link was made for.
    pub fn admits(&self, service: &str, made_for: Option<&ServedTarget>) -> bool {
        match self.by_name.get(service) {
            None => true,
            Some(Some(bound)) => bound.admits_made_for(made_for),
            Some(None) => false,
        }
    }
}

/// Text that is no [`ServedTarget`]: no scheme a `serve` binds, or a control character.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a target serve binds")]
pub struct NotATarget(pub String);

#[cfg(test)]
#[path = "scheme_tests.rs"]
mod scheme_tests;
