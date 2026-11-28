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
use std::io::{self, BufRead, IsTerminal as _, Read as _};
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use keystore::Stored;
use swoosh::home::{Home, HomeWrite, ServeLock};
use swoosh::invite::{Invite, PREFIX};
use swoosh::joining::Join;
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::root::Date;
use swoosh::standing::{Disagreement, Standing, StandingError};
use swoosh::sync::Dial;
use swoosh::transport::ReachArgs;
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
use zeroize::Zeroizing;

use crate::commands::lock::Enclave;
use crate::screen::{Block, Cell, Paint, Screen};

/// The most bytes of stdin read as an invite: far above any invite, far below anything that costs a read
/// to hold.
const READ_CAP: u64 = 4096;

/// Make this machine one of your devices, from an invite.
#[derive(Debug, Args)]
pub struct JoinCmd {
    /// The invite, or `-` to read it from stdin (the default)
    #[arg(value_name = "invite")]
    pub invite: Option<String>,
    /// Join a different root than the one this machine is on.
    #[arg(long)]
    pub switch: bool,
    #[command(flatten)]
    pub reach: ReachArgs,
}

/// Where `join` reads from and writes to, so a test can stand in for the terminal and the clock.
pub(crate) struct Io<'a, I: BufRead, P: Prompt, E: Paint> {
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
    pub(crate) async fn admit<I: BufRead, P: Prompt, E: Paint>(
        &self,
        home: &Home,
        mut io: Io<'_, I, P, E>,
    ) -> eyre::Result<Option<NodeId>> {
        let (text, made) = self.read_invite(home, &mut io)?;
        let invite = Invite::parse(&text)?;
        drop(text);

        // The invite, alone.
        let root = invite.standing.root().node_id()?;
        let file = swoosh::key_file::KeyFile::machine(home);
        let stored = file.load()?;
        let stored_key = stored
            .as_ref()
            .map(|stored| swoosh::identity::key_of(&file, stored))
            .transpose()?;
        let own = match (&invite.seed, stored_key) {
            (Some(seed), stored) => {
                let carried = NodeId::from_ed25519_secret(seed);
                // A key this run made to print is no one's yet: the invite's own key takes its place.
                if let Some(stored) = stored
                    && stored != carried
                    && made != Some(stored)
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
        if swoosh::config::is_revoked(home, root)? {
            eyre::bail!("root:{root} was revoked on this machine; recovery is a new root.");
        }
        let locked = matches!(stored, Some(Stored::Locked(_)));
        if locked && invite.seed.is_none() && !io.prompt.terminal() {
            eyre::bail!(
                "this machine's key has a passphrase: run this with -t after --, and paste the invite at the \
                 prompt"
            );
        }

        // Then this machine's standing. A switch that stopped before its pin left this machine trusting
        // the root it was leaving: this join finishes the switch, whichever invite it is given.
        let (standing, switching) = standing(home).await?;
        let was = match standing {
            Standing::Unpinned => switching,
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
            Standing::HoldsRoot { .. } => eyre::bail!("{}", swoosh::root::KEPT_HERE),
            Standing::InterruptedMint { .. } => eyre::bail!(swoosh::standing::UNFINISHED_MINT),
        };
        // No `serve --admit` may run while this machine pins a root: asked under `home.lock` before any
        // write, and again under it for the writes, which a `serve --admit` records its root under.
        refuse_if_admitting(&HomeWrite::take(home).await?, home)?;

        // Then write.
        if let Some(seed) = &invite.seed {
            match made.filter(|made| *made != own) {
                Some(made) => {
                    let home_lock = HomeWrite::take(home).await?;
                    let serve_lock = ServeLock::take(&home_lock, home)?;
                    swoosh::identity::replace_made(&serve_lock, &home_lock, seed, made, home)?;
                }
                None => swoosh::identity::write(seed, home).await?,
            }
        }
        let home_lock = HomeWrite::take(home).await?;
        refuse_if_admitting(&home_lock, home)?;
        still(&home_lock, home, standing, switching).await?;
        // A root kept here is a revoked one, which every read takes as none: a revoke stopped after its
        // latch. It goes with the join, as it goes with a mint, so no later finish of that revoke can find
        // it beside this root's files.
        if Standing::revoked_root(home).await?.is_some() {
            match std::fs::remove_file(home.root_key()) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
                _ => {}
            }
        }
        swoosh::joining::join(
            &home_lock,
            home,
            Join {
                root,
                standing: &invite.standing,
                from: invite.from,
                name: &invite.name,
                // A stopped switch left the lists and `invited-by` of the root it was joining: written anew.
                pin_changes: was != Some(root) || switching.is_some(),
            },
        )?;
        // The root and the date print as the pin and the standing hold them now, read back under the lock
        // that wrote them, never as the invite named them: the check compares what this machine trusts.
        let Standing::Device {
            pin: pinned,
            until: held,
        } = Standing::read(home).await?
        else {
            eyre::bail!(
                "this command could not confirm which root this machine now trusts\n  To see what this \
                 machine trusts:\n    swoosh status"
            );
        };
        drop(home_lock);

        // A `serve` here reads the pin at every admission: it ended the old root's sessions, and admits the
        // new root's devices before the person has checked the key.
        let serving = swoosh::home::serve_running(home).await;
        let left = was
            .filter(|was| *was != pinned)
            .map(|was| format!("root:{was}"));
        let mut screen = Screen::default();
        if let Some(left) = &left {
            screen = screen.block(
                Block::default()
                    .text("This machine no longer trusts the root it had:".to_owned())
                    .row([Cell::Token(left)]),
            );
            if serving {
                screen = screen.block(sessions_end());
            }
        }
        let key = format!("root:{pinned}");
        let head = format!(
            "This machine is now me/{}, a device of this root, until {}:",
            invite.name,
            Date(unix(held))
        );
        // A long name takes the head past 80: it wraps before its date, so the key still follows the colon.
        let joined = match head.split_once(" until ") {
            Some((name, date)) if head.chars().count() > swoosh::escape::LINE_WIDTH => {
                Block::default()
                    .text(name.to_owned())
                    .text(format!("until {date}"))
            }
            _ => Block::default().text(head),
        };
        screen = screen.block(joined.row([Cell::Token(&key)])).block(
            Block::default()
                .text("An invite alone does not prove who sent it.".to_owned())
                .text(
                    "On the machine that keeps your root, check that swoosh status shows that key."
                        .to_owned(),
                )
                .text("If it does not, leave this root:".to_owned())
                .command("swoosh leave".to_owned()),
        );
        if serving {
            screen = screen
                .block(Block::default().text(
                    "A swoosh serve running here admits that root's devices now.".to_owned(),
                ));
        }
        if was.is_none() && !locked {
            screen = screen.block(unlocked(Enclave::BUILT));
        }
        screen.write(&mut io.err)?;
        Ok((invite.from != own).then_some(invite.from))
    }

    /// The invite's text: the argument, or a line of stdin. An argument that carries a key is refused at its
    /// field count, before anything in it is decoded, and its text is never echoed. Beside it, the key this
    /// run made to print, when the home had none.
    fn read_invite<I: BufRead, P: Prompt, E: Paint>(
        &self,
        home: &Home,
        io: &mut Io<'_, I, P, E>,
    ) -> eyre::Result<(Zeroizing<String>, Option<NodeId>)> {
        if let Some(text) = self.invite.as_deref().filter(|text| *text != "-") {
            if fields(text) == 5 {
                eyre::bail!("this invite contains a private key; pass it on stdin: swoosh join");
            }
            return Ok((Zeroizing::new(text.to_owned()), None));
        }
        let mut made = None;
        if io.input_terminal {
            // Made on disk, so the key printed here outlives a paste that never comes: the invite typed for
            // it on the root's machine still joins it next time.
            let key = match swoosh::identity::inspect(home)? {
                swoosh::identity::Inspected::Found(key) => key,
                swoosh::identity::Inspected::Made(key) => {
                    made = Some(key);
                    key
                }
            };
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
        Ok((text, made))
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

/// Refuse, under `home.lock`, while a `serve --admit` runs on this home: a machine that pins a root admits
/// no other root's devices.
fn refuse_if_admitting(home_lock: &HomeWrite, home: &Home) -> eyre::Result<()> {
    if ServeLock::admitting(home_lock, home)?.is_some() {
        eyre::bail!("swoosh serve is running; stop it first: swoosh stop");
    }
    Ok(())
}

/// This machine's standing as `join` reads it, and the root a stopped switch was leaving. A join that
/// stopped after its standing and before its pin is no standing yet, so running `join` again finishes it:
/// a first join reads as no standing, and a switch as no standing beside the root its pin still names.
/// Every other damaged home refuses with its line.
async fn standing(home: &Home) -> eyre::Result<(Standing, Option<NodeId>)> {
    match Standing::read(home).await {
        Ok(standing) => Ok((standing, None)),
        Err(StandingError::Damaged(Disagreement::StandingWithoutPin { .. })) => {
            Ok((Standing::Unpinned, None))
        }
        Err(StandingError::Damaged(Disagreement::StandingFromAnotherRoot { pin, .. })) => {
            Ok((Standing::Unpinned, Some(pin)))
        }
        Err(StandingError::Damaged(what)) => {
            eyre::bail!("{}", swoosh::standing::damaged_line(&what))
        }
        Err(other) => Err(other.into()),
    }
}

/// Refuse, under `home.lock`, when this machine's standing is no longer `was`, the one checked before the
/// key write and any prompt: another `join`, a `leave` or a mint ran meanwhile.
async fn still(
    _home_lock: &HomeWrite,
    home: &Home,
    was: Standing,
    switching: Option<NodeId>,
) -> eyre::Result<()> {
    let (now, now_switching) = standing(home).await?;
    if !now.same(&was) || now_switching != switching {
        eyre::bail!("{}", swoosh::standing::CHANGED);
    }
    Ok(())
}

/// What a first `join` says where this machine's key has no lock: a command per lock this build can put on
/// it, each alone on its line, so neither is a guess at which the person wants.
pub(crate) fn unlocked(enclave: Enclave) -> Block<'static> {
    let block = Block::default().text("This machine's key has no lock.".to_owned());
    let block = match enclave {
        Enclave::Here => block
            .text("To lock it with Touch ID:".to_owned())
            .command("swoosh lock touch-id".to_owned()),
        Enclave::Absent => block,
    };
    block
        .text("To lock it with a passphrase:".to_owned())
        .command("swoosh lock passphrase".to_owned())
}

/// What a change of root prints while `serve` runs, under the left root's block so `that root` has its
/// referent: what it cut, and what it did not.
pub(crate) fn sessions_end() -> Block<'static> {
    Block::default()
        .text(
            "Sessions this machine admitted under the root it no longer trusts end now,".to_owned(),
        )
        .text("including one you reached it through as a device of that root.".to_owned())
        .text("A session through a link this machine issued stays open.".to_owned())
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

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, as this machine: the other device's gate admits it by the standing it presents.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: None,
        })
    }
}

#[cfg(test)]
#[path = "join_tests.rs"]
mod join_tests;
