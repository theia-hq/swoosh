Back to [Commands index](../commands.md).

# <a id="stop"></a>`swoosh stop`

Stop swoosh serve on this machine, or on one of your own devices.

<!-- generated: usage from `swoosh stop -h`; option lines curated -->
```
Usage: swoosh stop [OPTIONS] [me/<name>]
  [me/<name>]  One of your own devices; leave it out to stop this machine
```

**Example.** End a CI runner's hold early, from your laptop:

<!-- manual: needs a live peer -->
```console
$ swoosh stop me/ci-runner
Stopped me/ci-runner (ed01q7m2xk4p…).
It serves again when swoosh serve next runs on ci-runner.
```

Bare `swoosh stop` stops swoosh serve on this machine: `Stopped swoosh serve here (pid 4121).`

**Things to know.** It stops swoosh serve, not the machine. A machine that
[runs swoosh serve at login](../../use-cases/run-at-login.md#the-limit) starts it again on its own. `stop` takes
only your own devices, by name; a contact's machine, a key or a link is refused, because only
[your devices can stop a machine](../services.md#control-stop). The stopped machine prints which device stopped it.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
