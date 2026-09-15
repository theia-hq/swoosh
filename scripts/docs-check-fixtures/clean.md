# Clean vector

A capture binds its console block:

<!-- capture: swoosh status -->
```console
$ swoosh status
direct to bf01hcq6…
```

Generated content binds a plain fence:

<!-- generated: status -->
```
Usage: swoosh status [OPTIONS] [peer]
```

A live-run annotation:

<!-- live-run: iroh rtt varies by path -->
```console
$ swoosh ping bf01hcq6… --transport iroh
rtt 24 ms
```

A pending annotation:

<!-- pending live-run: needs n0 discovery reachable -->
```console
$ swoosh ping bf01hcq6… --transport iroh
rtt 24 ms
```

A manual annotation:

<!-- manual: opens an interactive ssh session -->
```console
$ swoosh ssh bf01hcq6…
```
