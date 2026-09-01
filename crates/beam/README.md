# beam

Receive a pushed file behind a keyed node's `beam:` service. This is the receive half of file transfer: a
sender dials the node, opens one stream per file, and drives a verified transfer to a waiting receiver. This
crate is that receiver's per-stream work: read one blob off an already-authorized stream, verify it end to
end (BLAKE3, by `bifrost-wire`), and save it under an output directory.

A sender-supplied name is reduced to a safe relative path first, so a peer can never write outside the
output directory (no `../` escape, no absolute path). A truncated or tampered transfer fails the hash and is
rejected rather than saved.

## How it composes

`beam` is a service crate: it knows what to DO with an admitted stream, never how the peer was reached or
gated. A caller that owns composition ([swoosh](https://github.com/theia-hq/swoosh)) wraps `receive_file` in
a GATED handler and injects it into [tightbeam](https://github.com/theia-hq/tightbeam)'s registry, so every
pushed file rides the same gate as every other service. The sender side (dial, expand directories, pipeline
concurrent streams) is a swoosh client verb driving `bifrost-wire` directly.

## License

Licensed under either of Apache-2.0 or MIT at your option.
