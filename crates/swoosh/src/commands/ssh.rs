//! `swoosh ssh <peer>`: reach a peer's sshd over the overlay, then hand the terminal to the system ssh.
//!
//! A LAUNCHER, a third verb category beside the local and reach families. Like a local verb it reads the
//! contact store (to resolve the peer to a raw key) and binds no bifrost `Node`; unlike a local verb it
//! ends up reaching a peer. It does so not by dialing itself but by `exec`ing the system `ssh` with a
//! `ProxyCommand` of `tightbeam connect <key> --service <name> --stdio`: tightbeam owns the `Node`, pipes
//! the overlay stream over ssh's stdin/stdout, and ssh talks to the far sshd as if it were local. This is
//! the recipe from tightbeam's README, made a first-class swoosh verb so `swoosh ssh alice` is a drop-in
//! for `ssh <host>`.
//!
//! The peer resolves in-process, BEFORE ssh runs, through the same `Target`/contact-store lookup
//! `ping`/`speed` use, so `alice/desk` is fine here (ssh never sees the `/`; it sees only the resolved
//! key in the `ProxyCommand` and a stable placeholder host). Everything after `--` is forwarded to ssh
//! verbatim (a remote command, `-p`, `-i`), so swoosh interprets nothing the user means for ssh.
//!
//! `ssh` is spec'd as a group that will also own `ssh config` (emit `~/.ssh/config` blocks) once contacts
//! carry advertised-service metadata; that leaf is HELD and deliberately not built. This one shipping op
//! takes the peer positionally, the shape CLI-DESIGN reserves for it.

use clap::Args;

use crate::contacts::{Contacts, Target};

/// The exposed service name reached when the user names none: a host's sshd under the default label.
const DEFAULT_SERVICE: &str = "ssh";

/// The system binaries a launch shells out to: the far sshd is reached by `SSH` over a `PROXY`-built
/// overlay stream. Named as constants so a "not found on PATH" error can point at the exact binary.
const SSH: &str = "ssh";
const PROXY: &str = "tightbeam";

/// Reach a peer's sshd over the overlay; runs the system ssh.
#[derive(Debug, Args)]
pub struct SshCmd {
    /// The peer to reach: a saved petname (`alice`, `alice/desk`) or a raw bifrost node id.
    #[arg(value_name = "peer")]
    pub peer: Target,
    /// The exposed service name to reach on the host.
    #[arg(long, value_name = "name", default_value = DEFAULT_SERVICE)]
    pub service: String,
    /// Args forwarded verbatim to the system ssh, after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ssh args"
    )]
    pub args: Vec<String>,
}

impl SshCmd {
    /// Resolve the peer to a raw key, then replace this process with the system `ssh` reaching it over the
    /// overlay. On success swoosh's PID *becomes* ssh (unix); a resolve or PATH failure returns before any
    /// exec, so a caller prints its clean message and exits non-zero. Prints nothing on the success path.
    pub fn run(self, contacts: &Contacts) -> eyre::Result<()> {
        // Resolve in-process, before ssh sees anything: take the first device for a bare petname (as
        // `speed` does), the exact one for `alice/desk`, and pass a raw key straight through. The peer as
        // typed is kept for the placeholder host, so known_hosts stays stable per peer.
        let candidates = self.peer.candidates(contacts)?;
        let Some(first) = candidates.into_iter().next() else {
            // `candidates` never yields an empty success (an unknown name is a clean error), but a match
            // keeps this total rather than resting on that invariant with an unwrap.
            eyre::bail!("could not resolve {}: no known device", self.peer);
        };
        let host = self.peer.to_string();
        let argv = ssh_argv(&first.node.to_string(), &self.service, &host, &self.args);
        exec_ssh(argv)
    }
}

/// The `ssh` argv for a resolved peer: `-o ProxyCommand=<recipe>`, a stable placeholder `host`, then the
/// passthrough `args` verbatim.
///
/// Pure so it is unit-testable (the `exec` itself is not): given the resolved `key`, the `service` name,
/// the placeholder `host`, and the user's trailing ssh `args`, it assembles the exact argv `exec_ssh`
/// hands to `ssh`. The `ProxyCommand` value is `tightbeam connect <key> --service <name> --stdio`, one
/// shell word per token because ssh splits `ProxyCommand` on whitespace, and none of key/service/host
/// contains any (a `NodeId` is base32, the service is a single name, the host is the peer as typed with no
/// spaces). The passthrough args land after the host, so they read to ssh exactly as if typed after a
/// bare `ssh <host>`.
fn ssh_argv(key: &str, service: &str, host: &str, args: &[String]) -> Vec<String> {
    let proxy_command = format!("{PROXY} connect {key} --service {service} --stdio");
    let mut argv = vec![
        "-o".to_owned(),
        format!("ProxyCommand={proxy_command}"),
        host.to_owned(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// Replace this process with `ssh <argv>` on unix; spawn-and-wait elsewhere.
///
/// unix `exec` is what lets ssh own the tty (an interactive session, password/passphrase prompts, a
/// remote pty) as if invoked directly: swoosh's PID becomes ssh, so there is no wrapper process in the
/// signal or job-control path. A non-unix fallback spawns and mirrors ssh's exit code, since `exec` is a
/// unix primitive. Either way a missing `ssh` on PATH surfaces as a clean error before ssh takes over.
#[cfg(unix)]
fn exec_ssh(argv: Vec<String>) -> eyre::Result<()> {
    use std::os::unix::process::CommandExt as _;

    // `exec` only returns on failure (otherwise the image is replaced); the most common failure is `ssh`
    // not being on PATH, so name that binary in the error, matching the launcher's other PATH errors.
    let error = std::process::Command::new(SSH).args(&argv).exec();
    Err(eyre::Report::new(error).wrap_err(format!("could not run `{SSH}` (is it on PATH?)")))
}

#[cfg(not(unix))]
fn exec_ssh(argv: Vec<String>) -> eyre::Result<()> {
    use eyre::WrapErr as _;

    // No `exec` off unix: spawn ssh, wait, and mirror its exit status so a caller still sees ssh's result.
    let status = std::process::Command::new(SSH)
        .args(&argv)
        .status()
        .wrap_err_with(|| format!("could not run `{SSH}` (is it on PATH?)"))?;
    match status.code() {
        Some(0) | None => Ok(()),
        Some(code) => Err(eyre::eyre!("ssh exited with status {code}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real base32 `NodeId` string, so the assembled `ProxyCommand` carries the exact key form a
    /// resolved peer would (parsed through the boundary, not hand-built).
    const KEY: &str = "bf01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";

    #[test]
    fn argv_wires_the_proxy_command_then_host() {
        let argv = ssh_argv(KEY, "ssh", "alice/desk", &[]);
        assert_eq!(
            argv,
            vec![
                "-o".to_owned(),
                format!("ProxyCommand=tightbeam connect {KEY} --service ssh --stdio"),
                "alice/desk".to_owned(),
            ]
        );
    }

    #[test]
    fn argv_forwards_passthrough_args_after_the_host() {
        let args = vec!["-p".to_owned(), "2222".to_owned(), "ls".to_owned()];
        let argv = ssh_argv(KEY, "ssh", "bob", &args);
        assert_eq!(
            argv,
            vec![
                "-o".to_owned(),
                format!("ProxyCommand=tightbeam connect {KEY} --service ssh --stdio"),
                "bob".to_owned(),
                "-p".to_owned(),
                "2222".to_owned(),
                "ls".to_owned(),
            ]
        );
    }

    #[test]
    fn argv_honors_a_non_default_service() {
        let argv = ssh_argv(KEY, "admin-ssh", "alice", &[]);
        assert_eq!(
            argv[1],
            format!("ProxyCommand=tightbeam connect {KEY} --service admin-ssh --stdio")
        );
    }
}
