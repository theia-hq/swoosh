//! `swoosh adopt <invite>`: join a signet's family as this machine.
//!
//! The device half of `invite add`, one command for both invite shapes:
//!
//! - A BOUND invite (`invite:<signet>.<badge>`) was signed for a key this machine made and printed with
//!   `swoosh identity`. Adopting trusts the signet and stores the badge, KEEPING this machine's identity.
//!   The token carries no secret, so it is safe over any channel.
//! - A DERIVED invite (`invite:<seed>.<signet>.<badge>`, or a legacy `authkey:`) carries a child seed.
//!   Adopting writes that seed as this machine's identity, so it comes up AS the derived device. The seed
//!   is a device SECRET: hand this shape over a private channel only.
//!
//! Either way the write lands in swoosh's own store (the node home, the default `~/.config/swoosh/` or
//! `--home`/`SWOOSH_HOME`) -- the SAME store `swoosh serve` binds under -- so the served node id matches
//! the contact `invite add` recorded. The trusted signet lands beside it, where the serve gate reads it.
//!
//! An invite is a secret only for the derived shape, so it is not forced onto argv (visible in `ps` /
//! `/proc`): the value comes off the command line where the caller chooses, via the shared secret-input
//! convention (a literal, `-` for stdin, `@<path>` for a file, or `SWOOSH_AUTHKEY`). The `-`/`@`
//! redirection is an argv convention only: an invite read from `SWOOSH_AUTHKEY` is taken VERBATIM (a
//! leading `-` or `@` there is part of the token, not a stdin/file redirect).

use bifrost::NodeId;
use clap::Args;

use crate::home::Home;
use crate::invite::Invite;
use crate::secret::SecretSource;
use crate::{config, identity};

/// The environment variable an operator may set instead of putting the invite on argv. A PARTIAL close
/// only: the value is owner-readable in `/proc/<pid>/environ`, but every child the process spawns inherits
/// it (and `swoosh ssh` spawns `ssh`), so it is a convenience, never a full close of the argv leak. The
/// name keeps the legacy spelling so a CI secret provisioned before the invite rename still lands.
const AUTHKEY_ENV: &str = "SWOOSH_AUTHKEY";

/// Adopt an invite: trust its signet and store its badge (a derived invite also becomes its identity).
#[derive(Debug, Args)]
pub struct AdoptCmd {
    /// the invite to adopt (a secret for a derived invite; `-` stdin, `@<path>` file, or SWOOSH_AUTHKEY)
    #[arg(
        value_name = "invite",
        long_help = "The invite to adopt. A derived invite (`invite add` with no `--for`) carries a \
                     device SECRET and adopting it becomes that identity; a bound invite (`invite add \
                     --for <key>`) carries no secret and leaves this machine's identity alone. Give it as \
                     a literal, `-` to read stdin, or `@<path>` to read a file. argv is visible to other \
                     processes (`ps`, `/proc`), so prefer stdin or a file when the invite carries a \
                     secret.\n\nOr set SWOOSH_AUTHKEY: a convenience, not a full close (spawned children \
                     inherit it). The env value is taken VERBATIM: a leading `-` or `@` has no special \
                     meaning there, so it must be the invite itself, never a redirection."
    )]
    pub invite: Option<SecretSource>,
}

impl AdoptCmd {
    /// Parse the invite and write what it carries into this home: the identity (derived shape only), the
    /// trusted signet, and the membership badge.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        // Take the invite off argv where the caller chooses: argv leaks (`ps`, `/proc/<pid>/cmdline`), so
        // a derived invite's device seed may come from stdin (`-`), a file (`@<path>`), or the environment,
        // resolving to exactly one source. Read it, then parse; the token string zeroizes when it drops.
        let token = SecretSource::resolve(
            self.invite,
            std::env::var(AUTHKEY_ENV).ok(),
            "invite",
            AUTHKEY_ENV,
        )?
        .read()?;
        match Invite::parse(&token)? {
            Invite::Bound { signet, badge } => {
                // A bound invite admits a key this machine already holds, so there must already BE an
                // identity: minting one here would produce a key the badge is not bound to, and writing
                // the badge anyway would store a credential the far gate must refuse.
                let Some(secret) = identity::load(home).await? else {
                    eyre::bail!(
                        "this invite is bound to a device key, but this machine has no identity yet; run \
                         `swoosh identity` to make one, then have the owner run `swoosh invite add <label> \
                         --for <that key>`"
                    );
                };
                let node = secret.node_id();
                // Trust the signet: the default gate admits its members and delegates. The signet lands
                // beside the identity, in the SAME home, which `swoosh serve` reads via `load_signet`.
                config::write_signet(home, signet).await?;
                // Store the signet-signed membership badge beside the seed, so this device PRESENTS the
                // badge the signet minted for it when it dials a family-gated node, rather than self-signing
                // (which roots at this key and is refused).
                config::write_badge(home, &badge).await?;
                println!(
                    "this machine is already {}; trusting signet {}",
                    node.short(),
                    signet.short()
                );
                println!(
                    "stored your membership badge: this device now reaches your gated services."
                );
            }
            Invite::Derived {
                seed,
                signet,
                badge,
            } => {
                // Compute the adopted node id before the seed drops (the zeroizing wrapper wipes it).
                let node = NodeId::from_ed25519_secret(&seed);
                // Become the derived device: write the child seed as SWOOSH's persisted identity -- the
                // SAME store `swoosh serve` binds under -- so this node comes up AS the adopted device.
                identity::write(&seed, home).await?;
                // Trust the signet, exactly as the bound shape does.
                config::write_signet(home, signet).await?;
                // Store the badge when the invite carried one; a legacy two-field authkey has none, and
                // the device falls back to self-signing (only useful for the signet holder).
                if let Some(badge) = &badge {
                    config::write_badge(home, badge).await?;
                }
                println!("adopted this machine as {}  [mine]", node.short());
                println!(
                    "trusting signet {}: `swoosh serve` now admits its members and delegates.",
                    signet.short()
                );
                if badge.is_some() {
                    println!(
                        "stored your membership badge: this device now reaches your gated services."
                    );
                }
            }
        }
        Ok(())
    }
}
