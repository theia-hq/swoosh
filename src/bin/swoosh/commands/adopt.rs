//! `swoosh adopt <invite>`: join a signet's family as this machine.
//!
//! The device half of `invite add`, one command for both invite shapes:
//!
//! - A BOUND invite (`invite:<signet>.<badge>`) was signed for a key this machine made and printed with
//!   `swoosh identity`. Adopting trusts the signet and stores the badge, KEEPING this machine's identity.
//!   The token carries no secret, so it is safe in transit; it is NOT authenticated, so the badge is
//!   checked against this machine's key, and the full signet is printed for an out-of-band compare,
//!   before anything is written.
//! - A DERIVED invite (`invite:<seed>.<signet>.<badge>`) carries a child seed.
//!   Adopting writes that seed as this machine's identity, so it comes up AS the derived device. The seed
//!   is a device SECRET: hand this shape over a private channel only.
//!
//! Either way the write lands in swoosh's own store (the node home, the default `~/.config/swoosh/` or
//! `--home`/`SWOOSH_HOME`) -- the SAME store `swoosh serve` binds under -- so the served node id matches
//! the contact `invite add` recorded. The trusted signet lands beside it, where the serve gate reads it.
//!
//! An invite is a secret only for the derived shape, so it is not forced onto argv (visible in `ps` /
//! `/proc`): the value comes off the command line where the caller chooses, via the shared secret-input
//! convention (a literal, `-` for stdin, `@<path>` for a file, or `SWOOSH_INVITE`). The `-`/`@`
//! redirection is an argv convention only: an invite read from `SWOOSH_INVITE` is taken VERBATIM (a
//! leading `-` or `@` there is part of the token, not a stdin/file redirect).

use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use eyre::WrapErr as _;
use swoosh::home::Home;
use swoosh::invite::Invite;
use swoosh::secret::SecretSource;
use swoosh::{config, identity};
use tightbeam::identity::AsVerifyKey as _;

/// The environment variable an operator may set instead of putting the invite on argv. A PARTIAL close
/// only: the value is owner-readable in `/proc/<pid>/environ`, but every child the process spawns inherits
/// it (and `swoosh ssh` spawns `ssh`), so it is a convenience, never a full close of the argv leak.
const INVITE_ENV: &str = "SWOOSH_INVITE";

/// Adopt an invite: trust its signet and store its badge (a derived invite also becomes its identity).
#[derive(Debug, Args)]
pub struct AdoptCmd {
    /// the invite to adopt (a secret for a derived invite; `-` stdin, `@<path>` file, or SWOOSH_INVITE)
    #[arg(
        value_name = "invite",
        long_help = "The invite to adopt. A derived invite (`invite add` with no `--for`) carries a \
                     device SECRET and adopting it becomes that identity; a bound invite (`invite add \
                     --for <key>`) carries no secret and leaves this machine's identity alone. Give it as \
                     a literal, `-` to read stdin, or `@<path>` to read a file. argv is visible to other \
                     processes (`ps`, `/proc`), so prefer stdin or a file when the invite carries a \
                     secret.\n\nOr set SWOOSH_INVITE: a convenience, not a full close (spawned children \
                     inherit it). The env value is taken VERBATIM: a leading `-` or `@` has no special \
                     meaning there, so it must be the invite itself, never a redirection."
    )]
    pub invite: Option<SecretSource>,
    /// re-root this machine when the invite names a different signet, or replace a differing stored badge
    #[arg(long)]
    pub force: bool,
}

impl AdoptCmd {
    /// Parse the invite and write what it carries into this home: the identity (derived shape only), the
    /// trusted signet, and the membership badge.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        // Take the invite off argv where the caller chooses: argv leaks (`ps`, `/proc/<pid>/cmdline`), so
        // a derived invite's device seed may come from stdin (`-`), a file (`@<path>`), or the environment,
        // resolving to exactly one source. Resolve QUIETLY: only the derived shape carries a secret, so the
        // leak warning waits until the shape is parsed. The token string zeroizes when it drops.
        let from_argv = matches!(self.invite, Some(SecretSource::Literal(_)));
        let token = SecretSource::resolve_quiet(
            self.invite,
            std::env::var(INVITE_ENV).ok(),
            "invite",
            INVITE_ENV,
        )?
        .read()?;
        let invite = Invite::parse(&token)?;
        if from_argv && matches!(invite, Invite::Derived { .. }) {
            swoosh::secret::warn_argv_leak(&mut std::io::stderr(), "invite");
        }
        match invite {
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
                // The token is unauthenticated transport: anyone can name any signet. Verify the badge
                // actually roots at the named signet AND binds THIS machine, unexpired, before any write.
                verify_badge(&badge, node, signet)?;
                admit_signet(home, signet, self.force).await?;
                // The credential half of the same rule: a token is not authenticated, so an old or
                // revoked badge replayed under the live signet must not silently overwrite this one.
                admit_badge(home, &badge, self.force).await?;
                // Trust the signet: the default gate admits its members and delegates. The signet lands
                // beside the identity, in the SAME home, which `swoosh serve` reads via `load_signet`.
                config::write_signet(home, signet).await?;
                // Store the signet-signed membership badge beside the seed, so this device PRESENTS the
                // badge the signet minted for it when it dials a family-gated node, rather than self-signing
                // (which roots at this key and is refused).
                config::write_badge(home, &badge).await?;
                println!("this machine is already {node}; trusting signet {signet}");
                println!("{}", COMPARE_SIGNET);
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
                // Same device-side check as the bound arm, on the node the seed derives: the badge must
                // root at the named signet and bind this device before the seed or badge is persisted.
                verify_badge(&badge, node, signet)?;
                admit_signet(home, signet, self.force).await?;
                // Same badge guard as the bound arm, before the seed write: a differing stored badge
                // cannot be displaced by a replayed token without `--force`.
                admit_badge(home, &badge, self.force).await?;
                // Become the derived device: write the child seed as SWOOSH's persisted identity -- the
                // SAME store `swoosh serve` binds under -- so this node comes up AS the adopted device.
                identity::write(&seed, home).await?;
                // Trust the signet, exactly as the bound shape does.
                config::write_signet(home, signet).await?;
                // Store the badge the derived invite carries, so this device presents the signet-signed
                // credential when it dials a family-gated node.
                config::write_badge(home, &badge).await?;
                println!("adopted this machine as {node}  [mine]");
                println!(
                    "trusting signet {signet}: `swoosh serve` now admits its members and delegates."
                );
                println!("{}", COMPARE_SIGNET);
                println!(
                    "stored your membership badge: this device now reaches your gated services."
                );
            }
        }
        Ok(())
    }
}

/// The out-of-band check every adopt prints. The badge inside is signed by the signet it names, but the
/// token itself is not signed at all, so anyone who can swap the message can name their own key as the
/// signet. Comparing the full signet with the owner is the one check that catches that substitution.
const COMPARE_SIGNET: &str = "compare that signet with the owner out of band before serving: the token is \
                              not signed by the signet it names, so it alone does not prove who sent it.";

/// Verify a carried badge is a usable credential for THIS machine: a well-formed membership cap, rooted
/// at `signet`, bound to `node`, and unexpired now. The invite token is unauthenticated transport, so
/// this is the check that keeps a forged, mismatched, or stale badge off disk.
fn verify_badge(badge: &str, node: NodeId, signet: NodeId) -> eyre::Result<()> {
    let cap = nauthy::Cap::parse(badge)
        .wrap_err("the invite's badge is not a well-formed membership link")?;
    cap.verify_member_at_root_without_revocation(
        SystemTime::now(),
        node.verify_key(),
        signet.verify_key(),
    )
    .wrap_err_with(|| {
        format!(
            "the invite's badge does not bind this machine ({node}) at signet {signet}: it is bound to \
             another key, rooted elsewhere, or expired. Ask the owner to sign a fresh invite for this \
             machine's key: `swoosh invite add <label> --for {node}`"
        )
    })?;
    Ok(())
}

/// Refuse to silently re-root this machine: when the home already trusts a DIFFERENT signet than the
/// invite names, adopting would switch the gate's root, so it takes an explicit `--force`. An absent
/// signet file is first provisioning, not a switch.
async fn admit_signet(home: &Home, signet: NodeId, force: bool) -> eyre::Result<()> {
    if force {
        return Ok(());
    }
    if let Some(trusted) = config::load_signet(home).await? {
        if trusted != signet {
            eyre::bail!(
                "this machine already trusts signet {trusted}; adopting this invite would re-root it at \
                 {signet}. Re-run with --force if that is intended"
            );
        }
    }
    Ok(())
}

/// Refuse to silently replace this machine's stored badge. A bound invite's token is not authenticated,
/// and the carried badge passes verification without a revocation check, so a replayed old or revoked
/// token under the SAME signet would otherwise overwrite the live credential (the signet compare cannot
/// catch it). A differing stored badge takes the same explicit `--force` as a differing signet: an absent
/// badge is first provisioning, and re-adopting the exact bytes already stored is a no-op.
async fn admit_badge(home: &Home, badge: &str, force: bool) -> eyre::Result<()> {
    if force {
        return Ok(());
    }
    if let Some(stored) = config::load_badge(home).await? {
        if stored.as_str() != badge {
            eyre::bail!(
                "this machine already stores a different membership badge than this invite carries; \
                 adopting it would replace the stored badge. Re-run with --force if that is intended"
            );
        }
    }
    Ok(())
}
