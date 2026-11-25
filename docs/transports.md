# Transports

swoosh reaches every machine over iroh. It finds peers across the internet, punching through NATs. You
give it a key; it does the rest. There is no transport to choose, and no addresses to pass.

## <a id="iroh"></a>iroh

Finding a peer and the relay fallback are iroh's: a serving node publishes where it can be reached to
n0's public discovery service, and when a direct path fails, n0's public relays forward encrypted bytes
they cannot read.

A relayed path is not a settled one. A session can start relayed and upgrade to direct the moment a hole
punch lands, so the same peer can read `relayed` on one run of
[`swoosh status`](reference/commands/status.md) and `direct` on the next. That is the punch landing, not
a fault, and either path is encrypted end to end.

## <a id="self-run"></a>Run the relay and the resolver yourself

Both are programs from the iroh project. Run them on a host with a certificate the public trusts:
swoosh accepts `https` only, and a self-signed certificate is refused.

- `iroh-relay` forwards encrypted bytes between peers that cannot reach each other directly.
- `iroh-dns-server` stores and serves the signed address records a node publishes and a dialer reads.

Point swoosh at them with `--relay <url>` and `--resolver <url>`. The resolver URL is the server's
`/pkarr` path, not its bare host:

<!-- pending live-run: needs iroh-relay and iroh-dns-server on a host with a public certificate -->
```console
$ swoosh serve --relay https://relay.example --resolver https://dns.example/pkarr
```

`serve` remembers each URL it was given under the node home, so every later command under that home
reaches the same two servers with no flags to repeat. While `serve` runs, other commands under that home refuse `--local`, `--relay` and `--resolver`; set them on `serve`
instead. Otherwise a flag on a command overrides the remembered one for that run.

**A resolver is a fleet setting; a relay is a node setting.** Two peers find each other only if both
resolve through the same resolver, so every node in a fleet names the same one. A relay travels in the
record a node publishes, and you dial a peer through whatever relay the peer's record names, so each node
names its own.

Either flag stands alone. `--relay` without `--resolver` leaves finding a peer to n0, and the banner says
so:

<!-- pending live-run: needs iroh-relay on a host with a public certificate; 192.168.x.x stands in for the announced LAN address -->
```text
how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  records    n0's public discovery: your addresses, for anyone with your key
  relay      https://relay.example/
  local      automatic; your devices just need the key (mDNS), announced at:
             192.168.x.x:58131
```

An `iroh-relay` relays for anyone by default. Its `access` setting names the node ids allowed to relay;
its `limits` settings cap connections and bandwidth per client.

## <a id="peer"></a>Advanced: `--peer`, when discovery cannot reach them

`--peer <key>=<address>` (or `SWOOSH_PEER`) gives a peer's address by hand. You need it only when
discovery cannot reach the peer: a locked-down network where automatic discovery is blocked, or under
`--local`. Take an address from the `local` lane of the banner a peer's `serve` printed and pass it back:

<!-- manual: needs a direct peer and its address -->
```console
$ swoosh ping ed01hcq6… --peer ed01hcq6…=127.0.0.1:50902 -c 4
```

You almost never need this: iroh discovers the peer from its key. If a dial cannot reach a peer, the peer
is likely offline or discovery is down, not missing an address.

## <a id="local"></a>`--local`: this network only

`--local` uses no relay and publishes no record: swoosh finds a machine on this network by mDNS, or at
the address `--peer` gives.

## <a id="variables"></a>Every flag here has a variable

The flags on this page are left out of `--help`. Each can be set once in the environment instead:
`SWOOSH_LOCAL`, `SWOOSH_PEER`, `SWOOSH_RELAY`, `SWOOSH_RESOLVER`. A flag beats its
variable. `SWOOSH_PEER` takes several `<key>=<address>`, comma-separated.

## Next

- [Getting started](getting-started.md) the first run.
- [Demo](demo.md) admit a second machine and refuse a stranger.
- [Troubleshooting](troubleshooting.md) when a dial cannot reach.
