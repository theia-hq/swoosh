# Changelog

All notable changes to swoosh, newest first.

## Unreleased

### New
- **`swoosh lock` adds a lock to this machine's key.** `swoosh lock passphrase` and, on macOS, `swoosh lock
  touch-id` each add a lock beside the ones the key has, and any one opens it. `--remove` takes one off.
  `swoosh root lock touch-id` adds the same lock beside your root's passphrase. `status` says whether each
  lock opens here.
- **The Touch ID dialog says which command asked.** It reads `use this machine's key for swoosh serve`.
- **Bare `swoosh lock` shows the key's locks and how to add one.**
- **`revoke root:<key>` ends a root for good on the machine it runs on.** It needs a terminal and the
  8 characters after the key's `ed01` typed back. Where the root is kept, it asks for the root's passphrase
  and deletes the root; on one of its devices, the machine leaves it; anywhere else, this machine never
  trusts it.
- **`share` makes a link to one service.** `swoosh share <service> <who>` makes one for a person (`bob`:
  every machine of the root you saved for them), one machine (`bob/laptop`, or a key), or `anyone`. It
  says on stderr what the link gives and until when, and prints only the link on stdout; `--save <file>`
  writes it to a new private file instead. `--expires` takes a span like `2h`, `90d` or `1h30m`, from 1h to
  365d (default 1h), and the line prints it as typed. `swoosh share <link>` makes a copy of a link for
  `anyone` that ends sooner: any span up to its link's end.
  A link to `anyone` for ssh, `ping`, `speed` or a receive service needs `--once`: it works once, lasts
  15 minutes at most, and cannot be copied.

### Changed
- **A `--local` dial that finds nothing says what to do.** The refusal names `swoosh status` on the other machine and
  the `--peer` form with its key.
- **`stop me/<name>` runs through `swoosh serve` too.** It warns when this machine's standing is about to
  expire, and ends on the same lines as the other commands that dial: `swoosh serve` stopping, a `swoosh serve`
  that does not answer, a dial that times out. A dial that times out now reads `could not reach me/nas: it is
  offline or not running swoosh serve` and `Nothing was stopped.`
- **`ping` and `status <machine>` run through `swoosh serve` too, and their lines drop `via iroh`.**
  `status` reads `me/nas, path: direct, rtt 12.031 ms`; `ping` prints the device, then a `path:` row from a
  reading taken after the run. If that fails, the path is left out, stderr says
  `warning: could not read the path of this run`, and the exit code is unchanged.
- **`speed`, `ping` and `status <machine>` print the same refusal with or without `swoosh serve`.** A machine that
  refuses `speed` prints `error: stream refused: unavailable: <why>`, as `send` does, and `speed` prints its title
  only once the stream is open. A `ping` or `status <machine>` that gets no answer in time prints
  `me/nas: unreachable` either way; `speed` and `send` print an error whose words differ by path.
- **A `swoosh serve` that stops answering is named, and the expiring-standing warning follows the run.** `ping`,
  `speed`, `status <machine>`, `send`, `forward` and `proxy` end with `error: swoosh serve did not answer here` and
  exit 1; `send` stops there instead of skipping each file, and a `forward <port>` or `proxy` connection that fails later
  keeps its warning. Through `serve`, `ping`, `speed`, `status` and `send` also warn when this machine's standing
  is about to expire, as they do without it.
- **`forward <machine> <service> -` runs through `swoosh serve` like `forward <port>`.** It warns when this machine's
  standing is about to expire, as the other commands do, and a refusal prints the same line with or without `serve`.
  A machine that hangs up on it prints `stream: early eof`, where it printed `early eof`. Without `serve`, it can end
  with `the machine did not answer the request to open a stream in time`.
- **`send` ends on a socket to `swoosh serve` that cannot be trusted.** It exits 1 and prints one error
  instead of a `skip` line per remaining file: the two below.
- **A socket that another process answers is named.** If the process answering `swoosh serve`'s socket is not the one
  `serve` recorded, or `serve.lock` records none, `ping`, `speed`, `send`, `forward`, `proxy`, `status <machine>`,
  `stop`, `sync`, `invite` and bare `service` exit 1 (`ssh` exits 255) and print
  `error: another process is answering swoosh serve's socket`, then the process number and path, and `Nothing was sent
  through it.` A socket path that is not yours alone, or a process answering as another user or one that cannot be
  identified, prints `error: swoosh serve's socket is not private to you` and the second line names the cause. `revoke`, `root restore` and
  `join` do their change first, then print it too. Bare `status` prints either text as a notice on stderr and exits 0.
- **`send` says what to rerun when `swoosh serve` stops after files were sent.** The ending asks to rerun without
  the files already marked `sent`, or says every file was marked `sent` when none are left.
- **`forward <port>` and `proxy` run through `swoosh serve` too.** If `serve` stops, both end with
  `error: swoosh serve stopped here and ended the connection to me/nas`. A `proxy` request that fails gets a
  `502` whose body is one line, `proxy failed: <what went wrong>`, and `proxy` still prints its URL first.
- **While `serve` runs, `ping`, `speed`, `status <machine>`, `send`, `forward`, `proxy` and `stop` refuse `--local`,
  `--relay` and `--resolver`,** and the `SWOOSH_` variables that set them. Set them on `serve`.
- **`speed` runs through `swoosh serve` too, and its title drops `via iroh`.** It reads
  `speed test to <machine> (<mode>)` on both paths. The `path:` line comes from a reading taken after the
  run; if that fails, there is no `path:` line, stderr says `warning: could not read the path of this run`,
  and the exit code is unchanged.
- **`send` runs through `swoosh serve` too, and says which file failed.** Every `skip <file>:` line names its
  file. If the machine cannot be reached before any file is admitted, `send` stops; once files are going, a file
  that cannot be reached is skipped. An unreadable home, a `serve` error or a malformed reply also ends the run.
  A `send` to `anyone` presents the link alone, with or without `serve`.
- **`sync`, `invite`, `revoke`, `join` and `root restore` run through `swoosh serve` too.** `--local`, `--relay`
  and `--resolver` do not apply while `serve` runs, and the command refuses before it writes anything. More than
  16 `--peer` addresses for one key, or an address no machine can be reached at, is a usage error (exit 2). If,
  after a `revoke`, `invite` or `root restore` has landed, `serve` is another version, has stopped or does not
  answer, the command prints that line and exits 1.
- **`forward <machine> <service> -` tells a finished stream from a cut-off one.** It exits 0 only when the other
  side ends cleanly and, if you sent anything, the other machine holds it; any other end prints
  `error: connection lost` and exits 1, with or without `swoosh serve` running. With a file or pipe on stdin, it
  no longer cuts the upload when the other side finishes first.
- **`forward <port>` and `proxy` keep listening when one connection fails, and say so once.** A connection that
  could not open prints `warning: a connection to me/nas failed: <why>` on stderr, then nothing more until a
  connection works again. A connection that opened never warns, whatever ends it. This holds by `swoosh serve`
  and without it. A `forward <port>` listener stays up across a dropped connection, with or without `serve`:
  the next connection redials. It ends when a new connection is refused (a revoke, a lapsed badge or link, or
  `serve` stopping) with the refusal's line, and a host that cuts the session no longer ends it. The same holds
  for `proxy`, with or without `serve`. A machine that
  refuses the stream ends it with `error: stream refused: <why>`, and a failed connection's cause line reads the
  same through `serve` as without it. A machine that refuses you mid-run ends a `proxy` run with the refusal
  (`proxy` answers the request with a `403` first). A `proxy` client waiting on a host that was cut gets a
  `502` for its own request, and one mid-body is reset. A request that ends the run also answers the clients
  still waiting, with a `502` whose body is `proxy failed: <what went wrong>`. The `502` body of `proxy` no
  longer carries raw peer text. Each holds at most 96 connections at once, so one listener cannot fill the streams a machine allows.
- **A forward to a port, or a TCP service you serve, that the other machine cuts off now ends with a reset, not a clean
  close.** A cut-off transfer no longer reads as complete. A forward's local client is also reset when the session
  is lost or the stream is refused.
- **`service off` takes any service name.** It no longer needs the name saved or a running serve, and says
  `It is not saved here.` when the name is not saved. `service on` takes a saved name or one marked off; for a
  marked name that is not saved it says `<name> is no longer off. It is not saved here.`. A change that would
  grow `serve.toml` past 64 KiB is refused, nothing is written, and the error names `service rm` and `service on` as ways to make room.
- **`service` and `status` show what the running serve holds.** `swoosh service` lists a bound service
  that is not saved (`on, not saved`) and a name marked off with no saved service (`off, no service saved`).
  A service the serve is refusing, such as one just removed, reads `refusing new connections`; `status` shows
  it as `(refusing new connections)` and names bound services that are not saved. `service on`, `off` and `rm`
  say `not saved here` where they said `not listed here`.
- **The quirk and Noise transports and the `--transport` flag are gone.** swoosh reaches every machine over
  iroh, with no selector. `SWOOSH_TRANSPORT` is gone too.
- **Every command that dials takes one machine.** It can be `me/<name>`, `<person>/<name>`, a key, a `swoosh:`
  link, or a file holding a link. A bare name of one of your devices (`desk`) is refused, with the command to
  type instead (`swoosh ping me/desk`). A person alone (`alice`) works when one of their machines is saved,
  and swoosh says which on stderr (`alice is alice/laptop.`). With several saved, it lists them and stops:
  `ping`, `speed`, `status` and `proxy` no longer dial every machine of a person. A refused dial names the
  machine and the service (`error: me/nas refused ssh`); for one of your own devices it also says why, when
  it can tell, and what to run there.
- **`--local`, `--peer`, `--relay` and `--resolver` are no longer listed in `--help`.** They
  work as before, and each can now be set in the environment: `SWOOSH_LOCAL`,
  `SWOOSH_PEER`, `SWOOSH_RELAY`, `SWOOSH_RESOLVER`. A flag beats its variable. `serve --quiet` (or
  `SWOOSH_QUIET`), and `--service` on `ssh`, `send` and `proxy`, are hidden too.
- **`swoosh serve recv:<dir>` serves `recv`.** That is the name `send` dials, so `send` needs no
  `--service`. `recv:` alone saves into the inbox.
- **`stop` takes one of your own devices.** `swoosh stop` stops swoosh serve here; `swoosh stop me/<name>`
  stops it on one of your devices, and that machine prints which device stopped it. A contact's machine, a
  key or a link is refused. `--at` is gone.
- **`service add`, `rm`, `on` and `off` replace `service ls`, `enable` and `disable`.** `swoosh service add
  <service>…` and `swoosh service rm <service>…` change this machine's list of services, which a bare
  `swoosh serve` serves. A removed service stops answering at once; an added one is served from the next
  time `serve` starts. `swoosh service on <service>` and `swoosh service off <service>` turn a listed service
  on or off at once, and one turned off stays off across restarts. All four act on this machine only.
  `swoosh status me/<name>` ends its line with what that device serves: `; serving: ssh, web`.
- **`swoosh serve <name=target …>` serves exactly those services for that run only.** It no longer saves
  them, repairs the saved list, or turns a service back on. A bare `swoosh serve` serves the saved list,
  or `ping` and `speed` if none is saved. The banner says which, and shows a saved service that differs from
  the one running.
- **`swoosh serve --with <service>` and `--without <service>` change the saved services for that run only.** Both
  repeat. `--with ssh` adds a service, `--without ping` omits one, and with none saved the starting list is
  `ping` and `speed`. Nothing is saved, and later saved changes do not alter the running selection. A name
  already saved is accepted with the same target and refused with a different one; omitting a name that is not
  in the list is refused. They cannot be combined with service definitions.
- **`swoosh service` shows a relative saved path as written.** Only a hand edit of `serve.toml` can save one
  (`service add` stores the full path); the row says it resolves where `swoosh serve` starts. `status` and
  `service on`, `off` and `rm` no longer depend on the current directory.
- **`swoosh share <service>` refuses a relative saved path when no `serve` is running.** It makes no link;
  start `swoosh serve`, then share.
- **`service add` shows the path it stored.** `Added public to the saved list as file:/a/public.`
- **A service definition is checked in full before `serve` or `service add` starts anything.** A refusal
  names the entry's position and the kind of problem, such as an invalid name or target, and does not
  repeat what you typed.
- **The `serve` banner and `service` list share one row layout.** A row that would pass 80 columns is split
  onto separate lines.
- **`serve` syncs your device list as it starts, then once an hour.** Until that first sync ends, it asks a
  stop from another device to wait.
- **`forward` replaces `reach`, and `proxy` replaces `fetch`.** `swoosh forward <machine> <service> <port | ->`
  always names where the bytes go: a local port, or `-` for stdout; with neither it stops and says so.
  `swoosh proxy <machine> <url>` takes the machine first, in place of `--via`. A machine serves a proxy with
  `swoosh serve proxy:<url>`, named `proxy`, or `<name>=proxy:<url>`; `swoosh serve proxy` alone, or
  `<name>=proxy:` with no URL, is refused.
- **A proxy serves a whole site.** `swoosh serve proxy:<url>` takes a site with no path or query, such as
  `proxy:https://example.com`; a request may ask for any path on that site, and none on another.
- **`swoosh proxy`'s local URL answers only requests made to it.** It prints the URL alone on stdout, with a
  random part in its path; a request without that part, or with a Host that names another address, is
  refused, so only a client given the URL can use it.
- **`--present` is gone.** Give a link, or a file holding one, where the machine goes:
  `swoosh ssh swoosh:…` or `swoosh ssh ./nas.link`.
- **`swoosh ssh` to a key or a link gives ssh the full key of the machine it dials as the host.** ssh's own
  lines, such as `Connection to <key> closed.`, `%h`, and `Host` blocks in your ssh config get the full key,
  where they got its first 16 characters. A petname still reaches ssh as typed.
- **`serve` warns when a shell, `ping`, `speed` or a receive service has live links made for something
  else, and those links are refused when used.** A link made for one target is
  refused by any other. Adding one to `serve.toml` while `serve` runs prints the same warning and leaves
  the running services as they are.
- **`share` replaces `grant`.** `grant issue` is `share <service> <who>`, and `grant narrow` is
  `share <link>`. A link for `anyone` can always be copied, so `--delegable` is gone.
- **Root keys take the form `root:ed01…`.** `contact add <person>`, `serve --admit`, `share` and `revoke`
  take a root in that form; a root is refused as a machine. `contact add alice/laptop <key>` saves one
  machine. swoosh can learn a contact's root from their machines you saved and asks before saving it.
  Replacing a saved root needs a code typed at a terminal and ends the links you gave the old root.
  A saved machine's key is never replaced; one key cannot be saved under two names. `contact signet` is gone.
- **`contact rm` refuses while links you shared with that contact are live.** It names the fix,
  `swoosh revoke <name>`.
- **`revoke me/<name>` prints `revoked` only once your root has revoked the device.** If it cannot
  use your root, it prints an `error:` saying the device is blocked on this machine only and names the
  fix, then exits 1.
- **`path:` names the path that carries bytes.** A direct path with a relay kept on standby reads
  `direct`, where it read `through a relay`, and a relayed one names its relay:
  `path: relayed through euc1-1.relay.n0.iroh.link`. `ping`, `speed` and `status <machine>` print the
  same words.
- **`ping -v` prints the path on its own line.** It prints first, then again each time the path
  changes, instead of on every probe line.
- **A received file's line names who sent it.** It now reads
  `<service>: received <path> (<bytes> bytes) from <key>`, where `<key>` is the machine that sent the file.
- **Connections to one machine are limited, each kind apart.** At most 64 ordinary streams, 128 `proxy`
  pipes and 4 `speed` connections at a time, so one kind cannot starve another. Past a limit, the command
  says `too many streams open to this machine; try again when one closes`.
- **A machine that does not answer a request to open a stream times out.** Ordinary exchanges such as
  `sync` and renewal wait 4 seconds, `proxy` pipes 10. The command says
  `the machine did not answer the request to open a stream in time`, drops the stalled session and dials
  again on the next request.
- **A `proxy` of up to 128 pipes rides one session.** An iroh session carries at least 224 streams at once, so
  a fan-out past 100 pipes no longer times out.
- **`send` waits at most 10 minutes for the receiver to answer each file.** Then it reports
  `the receiver did not answer within 10 minutes; the file may have arrived`. Before, it had no limit.
- **Bare `status` lists the routes every `serve` answers,** under `internal routes`, with who reaches each, while
  `serve` runs.
- **No service can be named `control`, `lookup`, `me`, `root` or `anyone`.** Every command that takes a service
  name refuses them with exit 2, and so does `serve.toml`, including its `off` list.

### Fixed
- **`share` refuses a link to a service whose saved definition is invalid.**
- **A busy `swoosh serve` is no longer read as absent.** When `serve` holds this home but a command cannot
  reach its socket (another `XDG_RUNTIME_DIR`, `serve` still starting, a full accept queue on macOS), the
  command stops with `swoosh serve is running for this home, but this command cannot reach it` and the fix,
  and no longer starts a second node beside it. A lock file that cannot be read, is another user's, or does
  not answer in time stops it with `could not lock <home.lock>`.
- **`revoke`, `root restore` and `join` with a reach flag refuse before the act** when `serve` holds the home
  but cannot be reached, is of another version, does not answer, or has a socket another process answers or that is not yours alone, and print `Nothing was changed.`
- **A root act that lands and then cannot reach `serve` says so.** `root restore` and `join` print
  `The change is made and saved here. Your devices have not been told yet.` before the error. `revoke me/<name>`
  prints `me/<name> is blocked on this machine, not yet on your other devices` and
  `to finish, run it again: swoosh revoke me/<name>`. The first line also comes before the errors for a
  `swoosh serve` of another version or one that does not answer.
  If `serve` is another version, stops answering, or stops after the first exchange of a `revoke` that no newer list held back, the error
  adds that the sync `serve` runs as it starts tells your devices. After `invite`, `root restore` or a `revoke` a
  newer list held back, a stopped `serve` ends with `Start it again.` and no such clause.
- **A command that dials a machine checks it is not this machine first.** `ping me/<this machine>` and the other
  commands that dial end with `<name> is this machine` (`that key is this machine's` for a key) and exit 2, with
  or without `swoosh serve`, before anything is opened, minted or asked. A sealed key no longer asks for its
  passphrase to say so.
- **A `swoosh serve` of another version, or one that does not answer, ends a command before its own bind.** The lines
  are `swoosh serve on this machine is a different version` and `swoosh serve did not answer here`. A `serve` that
  closes the connection without answering is checked against `serve.lock`: held, it counts as not answering; held while its key is
  replaced, it reads `this machine's key is being replaced`; released, the command runs on its own.
- **A damaged key file is named before the passphrase is asked.** Without `swoosh serve`, a command that dials
  any machine and finds a sealed key file whose header names no key prints the damaged-key line.
- **Updated SSH and filesystem dependencies** following RUSTSEC-2026-0495 and RUSTSEC-2026-0486.
- **Updated the QUIC transport dependencies** following RUSTSEC-2026-0523, RUSTSEC-2026-0524 and RUSTSEC-2026-0538.
- **Local badge expiry refusal uses the effective expiry bound.** Renewal expiry checks include the endpoint. Displayed dates and renewal warnings are unchanged.
- **A push could replace a file in the receiving directory, or write outside it through a symlink.**
  A pushed file now lands only as a new file inside that directory.
  A name already taken there is refused, and `send` prints a `skip` line and exits non-zero.
- **Another machine could make swoosh run out of memory on iroh, its default transport.** The machine sent
  data out of order, and swoosh held it without limit (RUSTSEC-2026-0185). Any machine that knew your
  machine's key could do it, and so could a machine you connected to. swoosh now drops a connection that sends
  data with too many gaps, and a machine can leave at most 16 MiB of unread data per connection.
- **`swoosh root restore` on a machine that was not one of your devices left revoked devices admitted.**
  `swoosh serve` there let in a device your root had revoked until its standing expired or the root next
  issued a device list. Restore now applies the revocations on every machine.

## v0.14.1

### Fixed
- **A live session ends when its earliest grant expires, and a refused stream no longer extends a
  session.** Picks up tightbeam v0.14.1.

## v0.14.0

### Changed
- **A disabled root key is honoured by every verb, not only at admission.** A key listed in
  `<home>/disabled_roots` is refused everywhere:
  - `serve` refuses any capability rooted there, whatever the revocation list says. A list it cannot
    read stops the node rather than trusting every root.
  - `fleet --pull` refuses a disabled signet before it dials and again before it writes, so no roster
    that key signed is followed.
  - `adopt` refuses an invite signed by a disabled signet, even with `--force`, and writes nothing.
- **A running `serve` ends live sessions whose access has ended.** About once a second it re-checks
  every session, and one whose capability has since been revoked, whose root has since been disabled,
  or whose every grant has expired is closed. Before, such a session ran until its peer left. A shell
  on a cut ssh session is hung up.
- **`grant issue` refuses on an adopted device.** A grant signed there roots at the device's own key,
  which no node in the fleet admits, not even the device itself. It now says so and points to the
  machine that holds the signet, or to `grant attenuate` to pass on a narrower copy of a link you hold.

## v0.13.0

### New
- **A key can be sealed under a passphrase, backed up and restored.** `swoosh identity` gains three
  leaves:
  - `protect plain|passphrase` rewrites the key file under that method without changing the key; on an
    empty home it creates the key already sealed.
  - `export <path> [--force]` writes a backup, always sealed under a passphrase chosen for it, to a file
    and never to the terminal. It works on filesystems without hard links or permission modes, such as
    FAT sticks.
  - `restore <path> [--force]` puts a backup's key into the home. A wrong passphrase changes nothing, a
    different key already at home needs `--force`, and the command says that revocations do not come back
    with the key.

  Passphrases are read only from the terminal (`/dev/tty`), never from arguments, the environment or
  stdin, and the terminal is restored on any exit, Ctrl-C included. Bare `swoosh identity` prints a
  `protection:` line and never asks for a passphrase. A sealed home with no terminal to ask on (a
  service, `serve &`) refuses cleanly and says to use `protect plain` for unattended nodes.
- **A running node holds `<home>/identity.lock`,** so a restore cannot replace the key a node is serving
  with.

### Changed
- **A received file prints as one plain line, and `--quiet` turns it off.** Each file a receive service
  lands now prints `<service>: received <path> (<bytes> bytes)` on stderr, for example
  `inbox: received notes.txt (1500 bytes)`. The sender chooses the path, so control characters in it and
  letters that print as blank space are shown escaped, and a long path is cut short.

  This replaces the log event v0.12.0 added (`error,transfer=info`). The default log filter is back to
  `error`, and `RUST_LOG` no longer controls these lines.

  If stderr falls behind, swoosh drops lines rather than slowing a transfer down. The file still lands.
  Once stderr catches up, one line says how many were dropped. Lines still waiting when swoosh exits are
  lost.

## v0.12.0

A peer cannot decide how much of your memory to spend, and a size problem stops posing as a forgery.

### Fixed
- **`swoosh service ls --at <peer>` let the node you asked exhaust your own machine.** The reply was
  read with no bound at all, so a hostile node could stream until the client died, at one byte of
  its bandwidth per byte of your memory. This is the server attacking the client, which is the
  direction nobody looks. The serving side had no bound either, so an honest host did not even
  provide an accidental ceiling.

  Both ends now hold one bound, derived from what the decoder already accepts rather than chosen, so
  the reader's cap cannot drift away from the format. The encoder enforces the two field limits
  rather than a byte total, because a menu can sit far under any byte ceiling and still be refused
  by its own decoder, and an encoder that can emit a frame it cannot read is a defect in itself.

- **A full fleet's roster was reported as a forgery.** The read cap sat below the largest roster the
  parser accepts, so a legitimate roster at that size was truncated in transit and then failed its
  signature check. `swoosh fleet <peer>` answered "roster is not signed by your signet; refusing to
  hydrate": a size problem wearing a forgery's clothes, and an operator reading it would go looking
  for an attack that never happened.

  The cap is now derived from the same limits the parser enforces, including the signature envelope
  the first estimate of this missed, and a test pins the largest admissible roster to exactly that
  size so a framing change cannot quietly loosen it. A node that streams past the cap is now named
  as the thing that overran, in a sentence that tells you to check which node you meant.

### Changed
- Advances to bifrost v0.4.0, nauthy v0.4.0, tightbeam v0.11.0 and services v0.3.0, which between
  them close two remote CPU-exhaustion classes in capability verification, cap a framed read a peer
  could size to four gigabytes, and teach three wires to say which version they speak instead of
  closing the stream without a word.

## v0.11.4

A refusal this build cannot read is not an answer about you.

### Changed
- **Advances to bifrost v0.3.0, tightbeam v0.9.0 and services v0.2.0**, where the refusal type
  stopped being a closed set. Nothing on the wire moved, and nothing you run behaves differently
  today.

  One place had to decide something new. When an exit node refuses a fetch, swoosh turns that
  refusal into an HTTP status, and the split is between a ruling about YOU and a failure of
  THEIRS: not admitted serves `403`, and the node's own failures serve `502`, so a downloader can
  tell "you are not allowed through this node" from "the node or origin is having a bad day"
  without reading a log. A refusal from a newer node, of a class this build has no name for,
  carries no ruling this build can read. It serves `502`, because `502` claims nothing about the
  caller, and says so in the log rather than guessing: `403` would invent an authorization answer
  out of a message that carried none.

  You will only ever see that line if this binary is older than the node it dialed.

## v0.11.3

Ten changes, no new capability. The thing gets more honest, not bigger.

### Fixed
- **`forward` refused a member of your own fleet.** It dialed as a stranger while `ping`, `speed`,
  `ssh` and `fetch` presented the member badge, on the same runner, to the same peer, through the
  same gate. It was never adjudicated: it was transcribed out of a badge wildcard while the verb in
  the same arm was fixed. The fix is not the flip. The credential now rides the declaration that
  already answers whether a verb dials, so a serving verb holding a dial credential and a dialing
  verb holding none are both unrepresentable, and there is no spelling of "not applicable" left for
  the next verb to inherit.
- **`--service` defaulted to a name nothing could serve,** in three call sites, through four
  releases. Zero-config `forward` against zero-config `serve` had never once worked.
- **A device learned its fleet exactly once, ever.** The roster's version and the puller's
  anti-rollback floor were ONE field, and it advanced only on pulling, which a signet holder never
  does. So every cut was stamped epoch 0 and every pull after the first was silently refused as a
  same-epoch replay. Restarting did not help. They are two types now, version 0 is unrepresentable,
  and the cutter cannot read the floor.
- **An explicit `--home` decided WHETHER a key existed, not just where it lived,** so an outward
  dial created the signet its own doc promised never to create.
- **A failed dial from an unprovisioned home minted your fleet root.** The `swoosh ssh` bridge
  declared a persisting identity while every sibling did not, and a dial to a peer that was never
  there wrote the key a later `serve` would gate everything on.
- **`adopt` could silently destroy your signet.** The key write had no guard while the two siblings
  in the same transaction were both flag-gated. It refuses now, and `--force` deliberately does not
  reach it: what that flag waves through is re-issuable, and this key has no issuer and no second
  copy.

### Added
- **Every address the banner hands over says how far it reaches:** the internet, this network, this
  tunnel, this machine. One line per class, preferring v4. The widest mark used to PREDICT where
  the others CLASSIFY, and a firewall falsified it.
- **A badge says when it dies.** An expired one refuses locally instead of collecting the uniform
  refusal that names nothing, a warning lands 30 days out, and `swoosh identity` states the badge's
  life. Renewal stopped needing the flag that also disables the re-root guard, so re-running
  `invite add` is the whole of it.
- **A refused dial says what the peer would have to serve.** It cannot become an oracle: the
  function that writes the sentence takes no error, no session and no response, so the wire is not
  in scope and cannot be read even by accident.
- **`docs/signet-backup.md`.** No doc anywhere mentioned backing up a key. The gap was silence
  about loss, not a broken promise.

### Changed
- **`forward` is `reach <peer> <service>`,** both positional, stdout by default. A service earns a
  top-level verb only when its client is a program rather than a pipe, and this one's body was
  open-the-stream-and-copy. `echo hello | swoosh reach <key> echo` now works with no flags.
- **`fleet <peer>`.** A flag that is never optional is a positional in costume.
- **The hidden `tunnel-connect` leaf is gone.** `swoosh ssh` proxies through the public `reach`, so
  the exact line that carries an ssh session is one you can run by hand to debug a launch.
- **Pins:** bifrost v0.2.3, nauthy v0.3.1, tightbeam v0.8.2, services v0.1.8.

## v0.11.2

The lane hands a peer an address that works, and says how far it goes.

### Fixed
- **The `direct` lane reads the BIND's dialable set, not the mDNS announcement.** The announcement
  reports how far an ANNOUNCEMENT reached, which is a different fact from how far an ADDRESS goes: on
  a network that blocks multicast the report is empty while the host's addresses are exactly as
  dialable as ever, and the lane offered loopback alone.
- **A temporary IPv6 address is no longer offered** (bifrost v0.2.3). It was deprecated within about
  a day, so a peer's copy rotted; it was also the one address privacy addressing exists to keep
  unpublished, and it was being multicast onto every network this node joined.
- **A failed interface read no longer reads as "this host is loopback-only".** The lane says the list
  is short and why.
- **`swoosh status` reports the first dialable address** rather than loopback.

### Changed
- **One line per reach class, preferring v4.** Eight rows on an ordinary two-interface laptop offered
  at most four decisions, and the banner's job is a glance. No flag and no `+k more`: machinery for a
  case nobody has.
- **Every row states who can route to it:** `the internet`, `this network`, `this tunnel`,
  `this machine`. A bare line reads as a default and there is no default, because this host cannot
  know where the operator's peer is. The widest mark was `anywhere`, which PREDICTED where the other
  three CLASSIFY: this lane renders only for a bind with no relay and no NAT traversal, so a global
  v6 behind a default-deny inbound firewall is the common case and the promise was falsifiable by a
  firewall.
- **The gloss says why a short list is short,** in one clause, loudest first. When addresses were
  dropped but every class still has a row it says nothing: a count of hidden expiring addresses is a
  fact nobody acts on.
- **The tunnel mark names no link.** One row renders per class, so the name could no longer tell two
  overlays apart; it was redundant where it informed and empty where it did not. The banner now holds
  no externally sourced string, so the over-budget fallback, the runtime width check and the
  control-character guard are gone and the 80-column bound is arithmetic rather than a measurement.
- **Pins:** bifrost v0.2.3, tightbeam v0.8.1, services v0.1.7.

## v0.11.1

A direct-only bind hands over an address again, and a fan-out reports every device.

### Fixed
- **`ping` no longer abandons the rest of your devices for one broken peer.** A device that answered the
  dial and then broke mid-exchange ended the whole run with its error, so every device after it went
  untried and you learned nothing about them, while `swoosh status` reported all of them. It is a line
  now, beside the refused and unreachable lines it already had: it says the node was reached, names what
  broke rather than a round-trip time, and the run continues to the next device with a verdict that is
  not green.
- **A direct-only bind hands over an address again.** `serve --transport quirk+noise` printed no `direct`
  lane at all, so the banner gave the operator nothing to pass to a peer, on a transport that has no relay
  and no NAT traversal and where an address is the whole of its reach. The lane was not merely empty: a
  wildcard bind's dial hint is rewritten to loopback and the lane filtered loopback out, and swoosh binds
  wildcard always, so it could never render. It now lists every address the bind is dialable at, the ones
  that reach this host from another machine first and loopback last, marked as reaching only this machine.
  A direct-only `local` lane drops its own address list, so one banner carries one list.
- **The demo script runs the binary you just built.** It looked for one under this repo's own `target`
  directory, which is the wrong place whenever the build writes somewhere else, and the stale binary
  sitting there ran instead. The demo passed and proved nothing. It asks cargo where the binary lands now,
  always builds first, and refuses to run if one is missing. It also hands the second node the loopback
  address rather than the first address in the banner, because both nodes run on one machine.

## v0.11.0

Every service target carries a scheme, so a near-miss is a refusal rather than a different service.

### Changed
- **Every service target carries a scheme: a TCP forward is now `tcp:<host>:<port>`.** The bare
  `host:port` form is gone, not deprecated: `swoosh serve web=127.0.0.1:8080` becomes
  `swoosh serve web=tcp:127.0.0.1:8080`. It was the one target without a scheme, so a hostname followed by
  a colon and a number was indistinguishable from a scheme carrying an argument, and an entry that missed
  an engine's exact spelling silently became a forward to a host of that name. Now `ping=ping:80` is a
  parse error saying `ping:` takes no argument, a scheme nothing serves is refused by name, and the
  readiness banner tells a forward from an engine by its scheme rather than by sniffing for a port.
  `unix:<path>` is unchanged.
- **`swoosh serve --help` lists every target it accepts.** Both halves: the four engines swoosh serves
  (`ping:`, `speed:`, `roster:`, `sshd:`) and the six forms it forwards or streams. A refused target points
  there, because the tunnel grammar refuses by naming the forms it routes and cannot name the engines
  layered on top of it, so a mistyped `png:` used to be handed a legal set with no `ping:` in it.
- **The sibling pins follow tightbeam v0.7.0 and services v0.1.4,** which is where this grammar lives.

## v0.10.0

Reach a relay and a resolver you run yourself, and a banner that tells the truth about how peers find you.

### New
- **`--relay` and `--resolver` (reach family).** Point a node at a relay and a resolver you run
  (`iroh-relay` and `iroh-dns-server`). `serve` remembers each under the node home, so every later command
  under that home reaches the same two servers. Name one without the other; what you do not name stays
  n0's.

### Changed
- **A relayed path can turn direct, and the docs now say so.** No behaviour change: a session that starts
  through a relay upgrades to a direct path the moment a hole punch lands, so `swoosh status` can read
  `relayed` on one run and `direct` on the next. That read as a fault to a first-time reader.
- **The readiness banner discloses the address records it publishes.** A default internet bind now prints
  `records  n0's public discovery: your addresses, for anyone with your key`. It used to print that line
  only when you named your own relay or resolver, so the banner disclosed the mDNS announcement on your
  LAN and stayed quiet about the larger one. A node naming its own resolver reads the same consequence.
- **The sibling pins move forward together.** bifrost, nauthy, tightbeam, and the service engines (fetch,
  measure, sshh, transfer) are each pinned to a newer revision, so a build of this version records exactly
  the revision set the address fix below is built on.

### Fixed
- **`swoosh status` no longer prints a healthy line for a peer that answered nothing.** A node that took
  the dial and then broke mid-exchange rendered its path and the transport's own round-trip estimate, and
  held a fan-out's exit code green. A probe that fails and a probe that goes unanswered are each their own
  line now, both saying the node was reached, neither reporting a time, and neither counting as healthy.
  The unanswered case is the common one: the engine folds a broken exchange into loss and returns an empty
  report rather than an error.
- **The published checksum verifies with the command people actually type.** Each release asset's
  `.sha256` file now carries the standard two-field line (the hash, then the file it names), so
  `shasum -a 256 -c swoosh-<target>.sha256` works on a downloaded asset. It previously held a bare hash,
  which that command rejects; the installer had been rebuilding the line itself, so nothing here caught it.
- **`--at` says what it does.** Its help line gave only the value grammar, so the bare form of `stop` and
  `service ls` read as an omission rather than the default. The short line now names the flag's job and the
  long line keeps the grammar and states the bare form.
- **The readiness banner reports the addresses this node was actually announced at.** A node bound to every
  interface advertised the loopback rewrite of that bind, so a peer that heard it was sent back to its own
  machine, and the banner printed `reachable on this machine only` over an address it could not back.
  Discovery now takes the sockets the transport really bound: a bind to every interface is announced at this
  host's own addresses, a bind to `127.0.0.1` is announced exactly as bound, and the banner's `local` line
  names the outcome it observed, whether that is the addresses it announced at, this host alone, or finding
  peers while announcing nothing, with the cause. An address no peer could dial is no longer printed at all.
- **A corrupt stored membership badge fails closed.** A `<home>/badge` that is not a usable `sheer:` link now refuses every family dial and a plain `adopt` with the fix named (`swoosh adopt --force <invite>`, or move the file aside), instead of being carried to the peer and refused there.

## v0.9.1

`--home` keeps its ssh pins to itself, the installer names each reason a provenance check was skipped, a
dialing command no longer overwrites the serving node's address record, and the credential noun is `invite`
everywhere.

### Changed
- **BREAKING: the credential noun is `invite` everywhere.** `SWOOSH_INVITE` replaces `SWOOSH_AUTHKEY`, the
  action input is `invite`, and a pre-rename `authkey:` token is refused with a teaching error; no compat
  alias ships.

### Fixed
- **A dialing command no longer overwrites the node's address record.** Only `serve` publishes; every other
  reaching verb resolves without writing, so a short-lived process cannot send dialers to a dead relay path.
- **`ssh`'s host-key pins follow the selected home.** `--home <dir>` (or `SWOOSH_HOME`) now keeps
  `known_hosts` beside that home's identity, so an isolated run no longer appends to the default book,
  and a run with `HOME` unset works.
- **The installer names the cause when it skips provenance verification.** `gh not found`,
  `gh not authenticated`, and `verification failed` are distinct lines, each saying the checksum still
  holds, so a skipped check reads as a cause, not a mystery.

## v0.9.0

Invite replaces mint, a node is a home, quirk gets Noise, and revocation lands live.

### New
- **`--transport quirk+noise`.** quirk behind a Noise handshake that proves the peer's key and encrypts
  the session: the same direct-only backend, with the key proven before any byte flows. It is the only
  quirk spelling that serves gated traffic, and the only one that carries a credential.
- **`--local` (reach family).** No internet discovery or relays: dials and advertisements resolve over
  local mDNS or a `--peer` hint only. A no-op on `quirk`/`quirk+noise`, which are already direct-only.
- **`service enable <svc>` / `disable <svc>`.** Turn a served service off or on live, no restart: the change
  is written to `<home>/disabled` and the running node honors it on the next connection, the same
  mtime-watched, fail-closed mechanism as revocation.
- **`invite add --expires <duration>`.** Choose a device badge's lifetime (default 90 days, previously a hardcoded
  year); a controlled reused-secret case can opt into `--expires 365d`.
- **`adopt` verifies the badge, and `--force` re-roots.** Adoption checks the badge binds this machine's key
  and is unexpired before storing it; a differing badge, or an invite naming a different signet, is refused
  unless you pass `--force`.
- **`serve --resident`, and the bare control verbs.** A resident `serve` holds the home's lock and serves
  the local control socket, so a bare `stop`, `service ls`, or `status` acts on your own running node.

### Changed
- **BREAKING: bare `--transport quirk` refuses every serve and every credential-bearing dial.** quirk
  never proves the peer holds the key it presents; the key travels in plaintext, so `swoosh serve` refuses
  over it and a credential is never written to it. Use `--transport quirk+noise` for gated or
  credential-bearing quirk traffic; bare `quirk` stays the base `quirk+noise` builds on, and `iroh` stays
  the default.
- **BREAKING: `swoosh beam` is now `swoosh send`.** The file-push verb was renamed for clarity; the `beam`
  crate and internals are unchanged, and there is no back-compat alias.
- **BREAKING: the file-receive scheme `beam:` is now `recv:`, and its output dir rides the scheme.**
  `swoosh serve inbox=recv:<dir>` sets where arrivals land (a bare `recv:` writes to `.`); the node-wide
  `--out` flag is gone, since the output dir is a per-service fact. `send --service` defaults to `recv`.
- **BREAKING: `mint` is now `invite add`, and `authkey:` is now `invite:`.** One create verb: `invite add
  <label>` derives a device identity (the old `mint`), and `invite add <label> --for <key>` signs a
  membership badge for a key the device made (no secret in the token). `invite ls` and `invite rm <label>`
  list and cancel by the same ledger; legacy `authkey:` tokens still adopt, the old `--to` is `--for`, and
  a stale `mint` invocation errors forward.
- **`send` and `fetch` take `--service <name>`** to reach a receiver or exit published under a non-default
  name, matching `ssh` and `forward`.
- **BREAKING: `--key <file>` is now `--home <dir>` (env `SWOOSH_HOME`).** A node is selected by its home
  directory; the key lives at `<home>/identity.key` (the GNUPGHOME model). `--key` errors forward.
- **BREAKING: every `serve` entry must be `name=target`.** A bare entry no longer takes the `default` name;
  it is refused at startup with a message naming the form (`membership` and `cluster` are reserved, never
  service names).
- **BREAKING: `stop` and `service` reshaped for local-vs-peer.** A peer is now `--at <peer>`; a bare `stop`
  or `service ls` acts on your own node over its control socket, which needs a resident `serve`
  (`serve --resident`); `service` is a group: `ls` / `enable` / `disable`.
- **`control.stop` and `control.services` are member-only.** A delegated `sheer:` slip reaches the gate but
  is refused at the route, so only your own devices can stop or inspect a node.
- **Revocation lands live.** A revoke reaches a running node's next connection: the gate re-reads the
  denylist when the file changes (`(mtime, len)` stamp, fail-closed), not only when `serve` starts.
- **Diagnostic metering is exposure-coupled.** A family-gated `ping`/`speed` route binds the owner engine
  (no run interval, no transfer slot, no byte or wall-clock cap: a member speed run can saturate the
  link), while `--public ping`/`--public speed` binds the metered engine (ping: one run per caller per
  second, a 60-second/1 GiB stream cap; speed: one transfer at a time, a 64 MiB/15-second stream cap).
  The uncapped engine cannot be opened at all, so a public diagnostic is always capped by construction.
- **The serve engines now come from `theia-hq/services`.** The in-repo `fetch`, `measure`, `sshh`, and
  `transfer` copies are gone; the node consumes the services repo at a pinned rev. The `sshd` route keeps
  the same host key and ceilings, and the public diagnostics now carry their caps in shipped builds.
- **BREAKING: one spelling per act; the five convenience aliases no longer resolve.** `swoosh id`,
  `service list`, `grant list`, `contact list`, and `contact remove` are parse errors now; the canonical
  forms are `identity`, `service ls`, `grant ls`, `contact ls`, and `contact rm`.
- **BREAKING: `swoosh ssh` now requires `--` before ssh flags.** Everything after the separator goes
  to ssh verbatim; before it, every flag is swoosh's own. `swoosh ssh desk -p 2222` is now a parse
  error, and `swoosh ssh desk -- -p 2222` works.

### Fixed
- **`stop` no longer reports a false failure while landing.** A teardown race in the v0.8.0 client could
  print an error after the node had already stopped; a peer that vanishes mid-stop now reads as a
  completed stop, a live peer keeps the loud error, and a gate refusal is never probed away.
- **A hostile filename cannot forge a send line.** Every path `send` prints or wraps is escaped and capped,
  so a peer-supplied name cannot fake a skip or an error line.
- **The serve banner tells the truth about local discovery.** A blocked mDNS advertise now says so on the
  reach line instead of a hardcoded `automatic`.
- **A corrupt key file is an error, never replaced.** A present identity that does not decode is no longer
  overwritten by a freshly minted key, and the key file is written atomically (temp, fsync, rename).
- **Store files were world-readable.** The signet, membership badge, contacts book, and revocation denylist
  landed `0644` in a `0755` store dir; they are now written `0600` inside a `0700` store dir, so the trust
  graph and revocation metadata are not exposed to other local users.
- **Minted device badges are now revocable.** `invite add` records the badge in the grant ledger, so
  `swoosh invite rm <label>` cuts a lost or leaked device (it previously found no record and bailed).
  The default badge lifetime also dropped from 365 to 90 days.
- **Each `recv:<dir>` receives into its own dir.** Two receive services on one node no longer both write to
  the first-named directory.
- **A received file prints again, on stderr.** The `recv:` engine emits a structured info event (`path`,
  `bytes`) when a pushed file lands, and the default filter surfaces it (`error,transfer=info`), so
  `swoosh serve` no longer goes silent on a successful receive. The event rides stderr, so stdout keeps
  carrying only the verb's own output, and the peer-supplied path is escaped and capped before it reaches
  the line. `RUST_LOG=error` silences the event. The final activity shape is not settled yet.
- **A stale `SWOOSH_KEY` env errors forward** instead of silently selecting the default identity.

## v0.8.0

Try it in one line with echo, open raw streams only when you say so, clean shutdown on every verb.

### New
- **`echo:` service.** `swoosh serve demo=echo:` serves a symmetric reflector that sends back whatever a
  peer sends. It is safe to open to anyone with a plain `--public` (no `--public-unsafe`), so it is the
  easiest first thing to try across two machines. The serve banner names it plainly.
- **`swoosh serve --public-unsafe <names>`.** Open a named raw stream (`file:`, `fifo:`, `stdin:`) to
  strangers. `--public` alone opens handlers, forwards, and `echo:`; a raw byte source hands out bytes with
  no responder to gate them, so it stays gated unless you additionally name it here. Requires `--public`,
  and a keyless shell is still refused outright.

### Changed
- **Rooted on nauthy 0.1.0.** The authentication core is now the first standalone nauthy release, with its
  generic capability vocabulary and rooted gate. swoosh keeps its own signet and fleet vocabulary on top;
  no command changes.
- **Every reaching verb closes the node before exiting.** `ping`, `speed`, `beam`, `forward`, and the rest
  now tear the connection down cleanly instead of printing `Aborting ungracefully`, so the peer sees a
  clean close rather than a dropped connection it has to time out.
- **`swoosh service --at <your-own-node>` teaches instead of failing.** Reading your own node's services is
  not wired yet (it lands with the daemon); asking for it now says so plainly.

### Fixed
- **Serving a `file:` source to a Linux peer works.** A regular file cannot register with epoll on Linux,
  so `file:` sources failed to start there while working on macOS; fixed in the pinned tightbeam.

### Internal
- **Release robustness (Track C).** A lock-source guard and pre-commit hook keep the committed lock in
  shipping-form, cargo-deny checks dependency sources in CI, and the release build asserts the exact rev
  pins (decision (A)) and fills the GitHub release notes from this CHANGELOG. No behaviour change.

## v0.7.0

Grant one service to a device, a whole person, or anyone; a clearer serve banner.

### New
- **`swoosh grant issue <svc> --for <who>`** bind a slip to a device or a whole fleet, with the kind in a
  typed prefix: `--for <person>/<device>` or a raw key binds ONE device (standing access, locked to one
  machine's key, inert if stolen, non-delegable); `--for fleet:<person>` or `--for fleet:<signet-key>`
  binds a whole fleet (every device that person's signet vouches for, now or later, revocable at once). A
  bare `--for <person>` is refused: you type `fleet:` to widen, so a device bind never silently becomes a
  fleet bind. `fleet:<person>` binds that person's signet recorded with `swoosh contact signet`.
- **`swoosh contact signet <petname> <key>`** record a person's signet root under their petname, so
  `grant issue --for fleet:<petname>` binds their fleet by name instead of a pasted key.
- **`swoosh grant ls`** list the grants you have issued, grouped by service, each with its holder and
  remaining lifetime.
- **`swoosh grant revoke <peer>`** refuse every grant you issued to a device or person at once; the
  existing `revoke <link>` still refuses a single link. Both write a node-local denylist the gate loads
  when `serve` starts, so a revoke takes effect on the node's next `serve`, not on a running one (live
  revocation lands with the daemon).
- **`swoosh serve --public <svc>`** open named services to anyone, unauthenticated, per service: the
  deliberate opt-out from the signet gate. A service with no safe public form, such as a keyless shell,
  is refused by name.
- **`swoosh service --at <peer>`** read the services a peer serves and the gate on each, a `SERVICE  GATE`
  table; you see only what that peer's gate admits you for. Reading your OWN node's services is coming with
  the daemon.
- **`swoosh serve <name>=fetch:<origin>`** pin a fetch service to one origin: the node fetches only that
  origin and refuses any other before it connects. A bare `fetch:` is unconstrained, but opening one to the
  public (`--public`) now requires a scope, so an open fetch service can never be an anonymous any-origin
  relay. Origin URLs carrying userinfo are rejected.
- **`swoosh id`** a short alias for `swoosh identity`: print this node's key, minting one if there is none.

### Changed
- **`signet` is now a reserved device label.** A contact device literally labelled `signet` (added as
  `alice/signet` before this release) is now read as that person's signet root, not a device. Pre-release
  this is near-zero incidence; if you have one, re-add it under a different label.
- **`swoosh serve --for <duration>` is now `--expires <duration>`.** `--for` is reserved for naming WHO a
  grant binds (`grant issue --for`), so serve's bounded-time timer moved to `--expires`, matching
  `grant issue --expires`. Same local timer; `--for` no longer sets a duration.
- **Reformatted `swoosh serve` banner.** The node id stands alone, copy-clean; a `how peers reach you`
  section names each channel (internet, LAN, direct); services are grouped by who can reach them, safest
  first, with one escalating danger marker so an open service always reads louder than a gated one.
- **`swoosh adopt` no longer takes the authkey on argv.** The authkey is a device secret, and the command
  line is visible to other processes (`ps`, `/proc`). Pass it as `-` (stdin), `@<path>` (a file), or set
  `SWOOSH_AUTHKEY`; a literal still works but is discouraged.
- **Clearer `--present` help.** The `sheer:` link flag on the reach verbs (`ping`, `speed`, `status`,
  `beam`, `forward`, `service`, `stop`) now reads plainly: your own devices need no link, the dial
  presents your membership badge; pass a `sheer:` slip only to reach as a delegate.
- **`control.*` reads `never public` in the serve banner.** The always-gated node-control line is glossed
  `never public` (it can never be opened with `--public`, unlike the other gated services), instead of
  `always family-gated`.
- **A refused fan-out no longer reads as unreachable.** When `ping` or `status` reaches a peer but the gate
  refuses the probe, the error says `reached, but refused` and stops there. Over quirk it no longer also
  prints the `pass --peer` addressing hint, which applies only when the peer was never reached at all.
- **Reach verbs take petnames uniformly.** `stop` and the other reach verbs now resolve a petname
  (`alice`, `me/laptop`) the same way `ping` did, instead of taking only a raw key.
- **`swoosh serve` exits 0 on a graceful `control.stop`.** A requested stop is a success, so a stopped node
  no longer exits non-zero.

## v0.6.0

Push files to a key, stop a remote node, and honest failures.

### New
- **`swoosh beam <path>... <peer>`** push a file or directory to a peer, verified end to end. The
  receiver runs `swoosh serve beam=beam:` (files land in the cwd, or `--out <dir>`). A directory expands
  to every file, streamed concurrently and BLAKE3-checked on arrival, so a truncated or tampered transfer
  is rejected, never written. Gated by your signet: only members (or a `sheer:` cap you hand out with
  `--present`) can push.
- **`swoosh stop <peer>`** tell a peer's node to stop serving, by its key or a `sheer:` link. Same
  graceful stop as Ctrl-C, via the gated `control.stop` service; stops the node, not the machine. Gated
  like diagnostics, so a single-owner node stops only for its own devices.
- **`swoosh serve --for <duration>`** serve for a bounded time (`30m`, `2h`, `1d`), then stop by itself.
  A local timer; pairs with `swoosh stop` to tear a session down early.

### Changed
- **Loud failures.** `ping`, `speed`, `status`, and `fetch` now error and exit non-zero when a node
  refuses a service, instead of faking a healthy line, 100% loss, or 0.00 MiB/s.
- **`+lossy` fan-out** (tightbeam): a raw-stream source fans out to many receivers over unreliable
  datagrams, dropping frames under load rather than blocking. See tightbeam's README.
- **Library-contained CLI.** tightbeam's command structs moved into its binary; swoosh calls its grant
  logic (`mint_link` / `narrow_link` / `revoke_into`) directly. No behaviour change: same flags, same wire.
