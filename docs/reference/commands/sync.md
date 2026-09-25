Back to [Commands index](../commands.md).

# <a id="sync"></a>`swoosh sync`

Bring your device list up to date with your other devices, both ways.

<!-- generated: usage from `swoosh sync -h`; option lines curated -->
```
Usage: swoosh sync [OPTIONS]
```

**Example.** `swoosh sync` asks every device of yours at once. It takes the newest list of your devices
from any device that holds a newer one, and gives it to any device that lacks it.

**Things to know.** Each device has 5 seconds to answer, and `sync` spends 20 seconds at most. It prints
one report, and names every device that did not answer. It runs only on one of your devices. Your
devices also do this on their own: every `swoosh serve` asks once an hour, and a command that reaches one
of your devices asks it when this machine has not heard from any device for an hour.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
