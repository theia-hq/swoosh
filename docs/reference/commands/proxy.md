Back to [Commands index](../commands.md).

# <a id="proxy"></a>`swoosh proxy`

Get a local URL that reaches a site through a machine you name.

<!-- generated: usage from `swoosh proxy -h`; option lines curated -->
```
Usage: swoosh proxy [OPTIONS] <machine> <url>
  <machine>      A machine: me/<name>, <person>/<name>, a person, a key, or a link
  <url>          a site, or a file on it; a path on the local URL resolves against it
  --port <n>     The local port to listen on (default: any free port)
```

**Example.** On `nas`: `swoosh serve proxy:https://example.com`. Then, here:

<!-- manual: needs a live peer -->
```console
$ swoosh proxy me/nas https://example.com/big.iso
```

It prints a local URL, `http://127.0.0.1:<port>/<token>/`, on stdout. Point curl or a browser at it: the
request leaves from `nas`, and `Range` passes through, so a stopped download resumes.

**Things to know.** The machine must serve a proxy for that site (`swoosh serve proxy:<url>` there). Until it does, each
request gets an error that names that line.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
