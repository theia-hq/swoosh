Back to [Commands index](../commands.md).

# <a id="join"></a>`swoosh join`

Make this machine one of your devices, from an invite.

<!-- generated: usage from `swoosh join -h`; option lines curated -->
```
Usage: swoosh join [OPTIONS] [invite]
  [invite]   the invite, or `-` to read it from stdin (the default)
  --switch   Join a different root than the one this machine is on.
```

**Example.** At a terminal, `swoosh join` alone prints this machine's key and the `swoosh invite` line to
type where your root is kept, then waits for you to paste what that prints. `swoosh join < laptop.invite`
reads the invite from a file.

**Things to know.** An invite from `invite <name> --new-key` carries a key, so it is a secret: given as an
argument it is refused before anything in it is read, because other processes can read a command line.
Pass it on stdin. An invite from `invite <name> <key>` carries no secret, and joins only the machine that
made that key. `join` checks the invite, then this machine, and writes nothing until both pass. It then
asks the machine that made the invite for your list of devices once. The invite is not signed as a whole,
so compare the root `join` prints with the `root:` line of `swoosh status` where your root is kept. A
machine that already trusts a root moves to another only with `--switch`, and a machine that keeps your
root is its own device and joins no other.

See also [`swoosh leave`](leave.md), [Commands index](../commands.md) and
[Common options](../commands.md#common-options).
