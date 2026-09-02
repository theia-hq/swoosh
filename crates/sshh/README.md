# sshh

A keyless SSH server over an already-authenticated byte stream. theia's equivalent of Tailscale SSH.

The caller hands `serve` one stream that a capability-gated overlay has ALREADY mutually authenticated (QUIC
+ raw-public-key TLS, addressed by ed25519 node id) and encrypted; the peer was authorized by a capability.
SSH's own transport job is therefore already done, so this server accepts the SSH `none` auth method and
goes straight to a shell: the capability IS the auth, exactly as Tailscale SSH accepts `none` behind
WireGuard. A standard `ssh` / `scp` client works unchanged, with no ssh keys to manage.

## Safety

A shell has no auth of its own, so everything rests on the stream being pre-authenticated:

- **The capability is the auth.** Only ever hand `serve` a stream a real gate already admitted, never a raw
  socket, never an open gate. `serve` demands a `nauthy::Admitted` witness with no public constructor, so
  "authorize before serve" is a compile-time precondition, not a check you remember to write.
- **It refuses to run as root**, so a privileged process cannot hand every caller a root shell.
- **The host key is derived from the node's own identity**, so a client's `known_hosts` pins the machine.
- **A revoked capability is refused at connect** (revocation plus a short cap TTL is the recall story; it
  does not cut a session already in progress).

## Why its own crate

`sshh` lives apart from the byte-moving layer so its heavy, security-sensitive dependency tree (`russh`,
`ssh-key`, `pty-process`) stays out of a lean, reach-only client. The composing consumer wraps `serve` in a
gated handler behind its `ssh` feature.

## License

Licensed under either of Apache-2.0 or MIT at your option.
