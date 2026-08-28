//! `swoosh ssh <peer>`: reach a peer's sshd over the overlay, then hand the terminal to the system ssh.
//!
//! A LAUNCHER, a third verb category beside the local and reach families. Like a local verb it reads the
//! contact store (to resolve the peer to a raw key) and binds no bifrost `Node` in this process; unlike a
//! local verb it ends up reaching a peer. It does so by `exec`ing the system `ssh` with a `ProxyCommand`
//! that re-invokes THIS binary — `<self> tunnel-connect <key> --service <name> --stdio`, via
//! `current_exe()` (see [`self_invocation`]) — and that hidden re-invocation binds the `Node` under
//! swoosh's OWN identity and pipes the overlay stream over ssh's stdin/stdout, so ssh talks to the far
//! sshd as if it were local. One binary, no `tightbeam` on PATH and no `$PATH` lookup at all, and the dial
//! carries swoosh's key — so a membership badge presented there binds to the identity the family gate
//! proves. `swoosh ssh alice` is a drop-in for `ssh <host>`.
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

/// The system binary a launch shells out to: the far sshd is reached by the system `SSH`, whose overlay
/// transport is THIS binary re-invoked as its `ProxyCommand` (see [`self_invocation`]) — no separate
/// `tightbeam` binary. Named as a constant so a "not found on PATH" error can point at the exact binary.
const SSH: &str = "ssh";

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
        let proxy = self_invocation()?;
        let argv = ssh_argv(
            &proxy,
            &first.node.to_string(),
            &self.service,
            &host,
            &self.args,
        );
        exec_ssh(argv)
    }
}

/// The `ssh` argv for a resolved peer: `-o ProxyCommand=<recipe>`, a stable placeholder `host`, then the
/// passthrough `args` verbatim.
///
/// Pure so it is unit-testable (the `exec` itself is not): given the shell-quoted `proxy` (this binary's
/// own path, see [`self_invocation`]), the resolved `key`, the `service`, the placeholder `host`, and the
/// user's trailing ssh `args`, it assembles the exact argv [`exec_ssh`] hands to `ssh`. The `ProxyCommand`
/// value is `<self> tunnel-connect <key> --service <name> --stdio`: ssh runs it to bridge the overlay
/// stream in-process, under swoosh's own identity, with no `tightbeam` binary and no `$PATH` lookup. ssh
/// splits `ProxyCommand` on whitespace, so `proxy` is pre-quoted and the other tokens are whitespace-free
/// (a `NodeId` is base32, the service is a single name). The passthrough args land after the host.
fn ssh_argv(proxy: &str, key: &str, service: &str, host: &str, args: &[String]) -> Vec<String> {
    let proxy_command = format!("{proxy} tunnel-connect {key} --service {service} --stdio");
    let mut argv = vec![
        "-o".to_owned(),
        format!("ProxyCommand={proxy_command}"),
        host.to_owned(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// This binary's own path, shell-quoted for use as the ssh `ProxyCommand` executable.
///
/// Using `current_exe()` — not the bare name `swoosh`, and not a separate `tightbeam` — means ssh spawns
/// exactly THIS binary by absolute path (no `$PATH` entry needed) and the overlay bridge runs in-process
/// under swoosh's own identity. ssh runs a `ProxyCommand` through `/bin/sh -c` and splits it on
/// whitespace, so the path is shell-quoted to survive an install directory with a space.
fn self_invocation() -> eyre::Result<String> {
    use eyre::WrapErr as _;

    let exe = std::env::current_exe()
        .wrap_err("could not locate this executable to build the ssh ProxyCommand")?;
    let path = exe
        .to_str()
        .ok_or_else(|| eyre::eyre!("this executable's path is not valid UTF-8"))?;
    Ok(shell_quote(path))
}

/// Single-quote `s` for `/bin/sh`, so a path with spaces stays one shell word. A literal single quote is
/// emitted as the standard `'\''` break-out-and-back-in; the common no-quote path is a plain wrap.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
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

    /// A stand-in for this binary's own quoted path ([`self_invocation`]'s output), fixed so the argv is
    /// deterministic in tests (the real path is `current_exe()` at runtime).
    const PROXY: &str = "'/opt/bin/swoosh'";

    #[test]
    fn argv_wires_the_self_invoked_proxy_command_then_host() {
        let argv = ssh_argv(PROXY, KEY, "ssh", "alice/desk", &[]);
        assert_eq!(
            argv,
            vec![
                "-o".to_owned(),
                format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --stdio"),
                "alice/desk".to_owned(),
            ]
        );
    }

    #[test]
    fn argv_forwards_passthrough_args_after_the_host() {
        let args = vec!["-p".to_owned(), "2222".to_owned(), "ls".to_owned()];
        let argv = ssh_argv(PROXY, KEY, "ssh", "bob", &args);
        assert_eq!(
            argv,
            vec![
                "-o".to_owned(),
                format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service ssh --stdio"),
                "bob".to_owned(),
                "-p".to_owned(),
                "2222".to_owned(),
                "ls".to_owned(),
            ]
        );
    }

    #[test]
    fn argv_honors_a_non_default_service() {
        let argv = ssh_argv(PROXY, KEY, "admin-ssh", "alice", &[]);
        assert_eq!(
            argv[1],
            format!("ProxyCommand={PROXY} tunnel-connect {KEY} --service admin-ssh --stdio")
        );
    }

    #[test]
    fn shell_quote_wraps_and_escapes() {
        assert_eq!(shell_quote("/opt/bin/swoosh"), "'/opt/bin/swoosh'");
        // A path with a space stays one shell word so ssh's whitespace split does not break it.
        assert_eq!(shell_quote("/My Apps/swoosh"), "'/My Apps/swoosh'");
        // A literal single quote breaks out and back in, keeping the whole path one word.
        assert_eq!(shell_quote("/a'b/swoosh"), r"'/a'\''b/swoosh'");
    }
}
