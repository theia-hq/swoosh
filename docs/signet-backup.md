# Backing up your signet

Your [signet](keys.md#signet) is one file of 32 bytes. It is the key that means "me": it signs every
device you enrol and roots every grant your gates admit. Nothing else holds a copy, and there is nobody
to issue you another. Copy it somewhere that outlives the machine it is on.

## Copy it

`swoosh identity` prints the key and the file it lives in. Copy that file:

<!-- manual: the backup destination is a path only the operator knows -->
```console
$ swoosh identity
bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
key: ~/.config/swoosh/identity.key
$ cp ~/.config/swoosh/identity.key /Volumes/backup/swoosh-signet.key
```

Run the command on the machine that holds the signet: on a [device](keys.md#device) you adopted,
`swoosh identity` prints that device's key instead.

The file is the raw key with nothing wrapped around it, so whoever holds the copy is you. Put it where
you would put a password, not in a shared folder and not in a repository.

## Restore it

Copy it back, make it owner-only, and read the key:

<!-- manual: the backup source is a path only the operator knows -->
```console
$ mkdir -p ~/.config/swoosh
$ cp /Volumes/backup/swoosh-signet.key ~/.config/swoosh/identity.key
$ chmod 600 ~/.config/swoosh/identity.key
$ swoosh identity
bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
key: ~/.config/swoosh/identity.key
```

The same key printing back is the restore working. Your devices already trust that key, so they admit
you again with nothing to re-run on them.

swoosh refuses a key file it cannot trust and names the fix. A copy pulled off a USB stick or out of an
archive usually lands readable by everyone:

```
Error: permissions 0644 for the identity key ~/.config/swoosh/identity.key are too open: group or other can read it. run `chmod 600 ~/.config/swoosh/identity.key`
```

Any length but 32 bytes is a truncated or foreign file. swoosh stops rather than minting a fresh key
over it, so the bad copy is still there to replace:

```
Error: identity key ~/.config/swoosh/identity.key is 31 bytes; an ed25519 key is exactly 32. refusing to overwrite it: restore a valid key or move the file aside
```

## If you lose it

Your fleet does not fall over. Each device already holds what it needs.

**Still works.** A device you adopted holds its own key, your signet's public half, and a membership
badge your signet already signed. It keeps serving, keeps admitting your other devices, and keeps
reaching your gated services. Grants you handed out keep working until they expire. `swoosh grant
revoke` still works: it writes a local file and signs nothing.

**Stops.** You cannot enrol another machine. Only the signet can sign a badge your gates admit, and
`swoosh invite add` refuses to sign anywhere else:

```
Error: this machine trusts signet bf01hcq6…, but its own key is bf01imv3…: a badge signed here would root at bf01imv3… and be admitted nowhere that signet gates. Run `invite add` on the machine that holds the signet (the one whose `swoosh identity` prints bf01hcq6…).
```

You cannot renew a badge either. A membership badge lasts 90 days unless the invite set another window,
and only the signet can sign the next one. So a fleet that loses its signet keeps running and then ages
out, one device at a time, as each badge expires.

## A restored signet forgets what you revoked

Revocations are a separate file. `revoked` sits beside `identity.key` in the same directory, one line
per recalled grant, and the key carries none of it. Restore the key alone into an empty directory and
that node starts with no denylist, so every grant you had revoked is admitted again. Restore a copy of
the whole directory and you get the revocations that existed when you took the copy, not the ones you
wrote after it.

Copy the directory rather than the key alone, and take a fresh copy each time you revoke.

## Next

- [Keys](keys.md) the model your signet sits at the root of.
- [`swoosh identity`](reference/commands/identity.md) the verb that prints the key and its path.
- [`swoosh invite`](reference/commands.md#invite) enrolling a device.
