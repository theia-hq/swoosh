//! `swoosh join [<invite> | -] [--switch]`: make this machine one of your devices, from an invite.
//!
//! The invite comes from `swoosh invite` where your root is kept. With no argument, or `-`, it is read from
//! stdin; at a terminal with nothing piped, `join` first prints this machine's key and the `invite` line to
//! type where your root is kept, then waits for the paste. An invite that carries a key is a secret, so
//! given as an argument it is refused before anything in it is decoded.
//!
//! The order is fixed: check the invite, then this machine's standing, then write. The writes are
//! [`swoosh::joining::join`]'s, the pin last; then one exchange with the machine that made the invite, so
//! this machine holds your root's list of devices from the start.

use core::time::Duration;
use std::io::{self, BufRead, IsTerminal as _, Read as _, Write};
use std::time::SystemTime;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use keystore::{KeyFile, Stored};
use swoosh::home::Home;
use swoosh::identity::HomeLock;
use swoosh::invite::{Invite, PREFIX};
use swoosh::joining::{AdmitError, AdmitLock, Join};
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::root::Date;
use swoosh::standing::{Standing, StandingError};
use swoosh::sync::{Dial, NodeDial};
use swoosh::transport::ReachArgs;
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
use zeroize::Zeroizing;

/// The most bytes of stdin read as an invite: far above any invite, far below anything that costs a read
/// to hold.
const READ_CAP: u64 = 4096;

/// Make this machine one of your devices, from an invite.
#[derive(Debug, Args)]
pub struct JoinCmd {
    /// the invite, or `-` to read it from stdin (the default)
    #[arg(value_name = "invite")]
    pub invite: Option<String>,
    /// Join a different root than the one this machine is on.
    #[arg(long)]
    pub switch: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

/// Where `join` reads from and writes to, so a test can stand in for the terminal and the clock.
pub(crate) struct Io<'a, I: BufRead, P: Prompt, E: Write> {
    /// stdin.
    pub input: I,
    /// Whether stdin is a terminal with nothing piped.
    pub input_terminal: bool,
    /// Who is asked for a passphrase, and whether anyone can be.
    pub prompt: &'a P,
    /// This machine's hostname, for the name `join` suggests.
    pub hostname: &'a str,
    /// Now.
    pub now: SystemTime,
    /// stderr.
    pub err: E,
}

impl JoinCmd {
    /// Read the invite, check it and this machine's standing, write, and say what changed: everything but
    /// the first exchange. The machine to exchange with first, unless it is this one.
    pub(crate) async fn admit<I: BufRead, P: Prompt, E: Write>(
        &self,
        home: &Home,
        mut io: Io<'_, I, P, E>,
    ) -> eyre::Result<Option<NodeId>> {
        let text = self.read_invite(home, &mut io)?;
        let invite = Invite::parse(&text)?;
        drop(text);

        // The invite, alone.
        let root = invite.standing.root().node_id()?;
        let stored = KeyFile::device(home.key()).load()?;
        let stored_key = stored.as_ref().map(Stored::node_id);
        let own = match (&invite.seed, stored_key) {
            (Some(seed), stored) => {
                let carried = NodeId::from_ed25519_secret(seed);
                if let Some(stored) = stored
                    && stored != carried
                {
                    eyre::bail!(
                        "this invite carries its own key, and this machine already has one ({stored}). Use \
                         it on a fresh machine (an empty --home <dir>), or invite this machine's key: swoosh \
                         invite {} {stored}",
                        invite.name
                    );
                }
                carried
            }
            (None, Some(stored)) => stored,
            (None, None) => eyre::bail!(
                "this invite is for an existing machine's key, and this machine has no key yet. Ask for an \
                 invite with its key inside: swoosh invite {} --new-key",
                invite.name
            ),
        };
        if own == root {
            eyre::bail!("a machine cannot be its own root's device.");
        }
        let until = match invite.standing.cap().expiry() {
            Ok(Some(until)) => until,
            Ok(None) | Err(_) => eyre::bail!("this is not a swoosh invite"),
        };
        // Asked at the standing's own end, so an invite for this key that has ended reads as ended, not as
        // an invite for another key.
        let bound = invite
            .standing
            .cap()
            .verify_member_at_root_without_revocation(until, own.verify_key()?, root.verify_key()?)
            .is_ok();
        if !bound {
            match invite.seed {
                Some(_) => eyre::bail!("this is not a swoosh invite"),
                None => eyre::bail!(
                    "this invite is for another machine's key; this machine is {own}. Invite this machine: \
                     swoosh invite {} {own}",
                    invite.name
                ),
            }
        }
        if until <= io.now {
            eyre::bail!(
                "this invite ended on {}. With your root: swoosh invite {name} (for a device that starts from \
                 its invite each time: swoosh invite {name} --new-key), then join what it prints.",
                Date(unix(until)),
                name = invite.name
            );
        }
        if swoosh::config::is_disabled(home, root).await? {
            eyre::bail!("root:{root} was revoked on this machine; recovery is a new root.");
        }
        let locked = matches!(stored, Some(Stored::Locked(_)));
        if locked && invite.seed.is_none() && !io.prompt.terminal() {
            eyre::bail!(
                "this machine's key has a passphrase: run this with -t after --, and paste the invite at the \
                 prompt"
            );
        }

        // Then this machine's standing.
        let read = match Standing::read(home).await {
            Ok(read) => read,
            Err(StandingError::Damaged(what)) => {
                eyre::bail!("{}", swoosh::standing::damaged_line(&what))
            }
            Err(other) => return Err(other.into()),
        };
        for line in &read.finished {
            writeln!(io.err, "{line}")?;
        }
        let was = match read.standing {
            Standing::Unpinned => None,
            Standing::Device { pin, until: held } => {
                if pin == root && until < held {
                    eyre::bail!(
                        "this invite ends {}, before this machine's current date {}, so it changes nothing \
                         here. To end this device sooner: with your root, swoosh revoke me/{name}; then here, \
                         swoosh leave --new-key, and invite the new key.",
                        Date(unix(until)),
                        Date(unix(held)),
                        name = invite.name
                    );
                }
                if pin != root && !self.switch {
                    eyre::bail!(
                        "this machine trusts root:{pin}; this invite is from root:{root}. To move this \
                         machine to it: swoosh join --switch."
                    );
                }
                Some(pin)
            }
            Standing::HoldsRoot { .. } => eyre::bail!(
                "your root is kept on this machine, and a machine that keeps a root is that root's device \
                 and no other's. To move your root off it: swoosh move-root <dir>"
            ),
            Standing::InterruptedMint { root_key } => {
                eyre::bail!("{}", swoosh::standing::unfinished_line(root_key))
            }
        };
        let _admit = match AdmitLock::joining(home) {
            Ok(lock) => lock,
            Err(AdmitError::Held) => eyre::bail!("stop swoosh serve first."),
            Err(AdmitError::Io(error)) => return Err(error.into()),
        };

        // Then write.
        if let Some(seed) = &invite.seed {
            swoosh::identity::write(seed, home).await?;
        }
        swoosh::joining::join(
            home,
            Join {
                root,
                standing: &invite.standing,
                own,
                name: invite.name.clone(),
                from: invite.from,
                pin_changes: was != Some(root),
            },
        )
        .await?;

        writeln!(
            io.err,
            "joined root root:{root}: this machine is its device until {}.",
            Date(unix(until))
        )?;
        if let Some(was) = was.filter(|was| *was != root) {
            writeln!(
                io.err,
                "this machine now trusts root root:{root} (was root:{was})."
            )?;
            if HomeLock::is_held(home) {
                writeln!(io.err, "{}", sessions_end(was))?;
            }
        }
        writeln!(
            io.err,
            "Check that root:{root} is the root: line on the machine that keeps your root; the invite alone \
             does not prove who sent it."
        )?;
        if was.is_none() && !locked {
            writeln!(
                io.err,
                "this machine's key is not locked; swoosh lock locks it."
            )?;
        }
        Ok((invite.from != own).then_some(invite.from))
    }

    /// The invite's text: the argument, or a line of stdin. An argument that carries a key is refused at its
    /// field count, before anything in it is decoded, and its text is never echoed.
    fn read_invite<I: BufRead, P: Prompt, E: Write>(
        &self,
        home: &Home,
        io: &mut Io<'_, I, P, E>,
    ) -> eyre::Result<Zeroizing<String>> {
        if let Some(text) = self.invite.as_deref().filter(|text| *text != "-") {
            if fields(text) == 5 {
                eyre::bail!("this invite contains a private key; pass it on stdin: swoosh join");
            }
            return Ok(Zeroizing::new(text.to_owned()));
        }
        if io.input_terminal {
            let key = swoosh::identity::inspect(home)?.stored().node_id();
            let name = swoosh::names::suggested_from(io.hostname)
                .map_or_else(|| "<name>".to_owned(), |name| name.as_str().to_owned());
            writeln!(io.err, "This machine's key: {key}")?;
            writeln!(
                io.err,
                "On the machine where your root is kept:  swoosh invite {name} {key}"
            )?;
            writeln!(io.err, "Then paste the invite here:")?;
            io.err.flush()?;
        }
        let mut text = Zeroizing::new(String::new());
        (&mut io.input).take(READ_CAP).read_line(&mut text)?;
        Ok(text)
    }
}

/// How many `.`-separated fields an invite's text has after its prefix, read without decoding any.
fn fields(text: &str) -> usize {
    let text = text.trim();
    let body = text
        .get(..PREFIX.len())
        .filter(|head| head.eq_ignore_ascii_case(PREFIX))
        .and_then(|_| text.get(PREFIX.len()..))
        .unwrap_or(text);
    body.split('.').count()
}

/// The line a change of root prints while `serve` runs: what it cut, and what it did not.
pub(crate) fn sessions_end(was: NodeId) -> String {
    format!(
        "sessions this machine admitted under root root:{was} end now, including one you reached it through as \
         a device of that root. A session through a link this machine issued stays open."
    )
}

/// One exchange with `from`, the machine that made the invite, so this machine holds your root's list of
/// devices from the start. Never printed: a machine that does not answer now is asked at the next sync.
pub(crate) async fn pull(dial: &impl Dial, from: NodeId) {
    let _ = swoosh::sync::once(dial, from).await;
}

/// `when` in unix seconds.
fn unix(when: SystemTime) -> u64 {
    when.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

impl JoinCmd {
    /// Everything before the first exchange, on the real stdin, terminal and clock.
    pub async fn run_local(&self, home: &Home) -> eyre::Result<Option<NodeId>> {
        let stdin = io::stdin();
        let input_terminal = stdin.is_terminal();
        self.admit(
            home,
            Io {
                input: stdin.lock(),
                input_terminal,
                prompt: &Terminal,
                hostname: &swoosh::names::hostname(),
                now: SystemTime::now(),
                err: io::stderr(),
            },
        )
        .await
    }
}

/// The first exchange after a join, as a reaching verb: it binds this machine's key, which the join may
/// just have written, and presents the standing it just stored.
#[derive(Debug)]
pub struct JoinPull {
    /// The machine that made the invite.
    pub from: NodeId,
    /// The reach flags `join` was given.
    pub reach: ReachArgs,
}

impl swoosh::reaching::Reaching for JoinPull {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// The pull dials the machine that made the invite itself.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        None
    }

    /// `join` takes no `--present` and no peer, so there is nothing to conflict.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        Ok(())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, as this machine: the other device's gate admits it by the standing it presents.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: None,
        })
    }

    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        pull(&NodeDial::new(node, ctx.home), self.from).await;
        Ok(())
    }
}

#[cfg(test)]
#[path = "join_tests.rs"]
mod join_tests;
