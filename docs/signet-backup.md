# Backing up your signet

Your [signet](keys.md#signet) is the key that means "me": it signs every device you enrol and roots every
grant your gates admit. Nothing else holds a copy, and there is nobody to issue you another. Back it up
somewhere that outlives the machine it is on.

## Seal it first

On the machine that will hold your signet, create the key sealed under a passphrase before anything else:

<!-- manual: the passphrase is typed at the terminal -->
```console
$ swoosh identity protect passphrase
new passphrase for ~/.config/swoosh/identity.key:
repeat the new passphrase:
ed012xdjkuwbokai5brwac6varo7xsvuxba6wmfkottpronrhjavyp4q
protection: passphrase
```

Doing this first means the key never sits on the disk in the clear. A key that is already there is sealed
the same way, but copies made while it was plain (old backups, snapshots) stay plain.

The passphrase is asked for at the terminal, every time the key is used: by `swoosh serve`, by a dial, by
`invite add`. A machine that must start with nobody at the keyboard keeps a plain key: there is no
unlock agent, and a sealed key started by a service manager exits asking for a terminal. Start a sealed
node in the foreground; `swoosh serve &` stops at the prompt until you bring it back with `fg`.

## Back it up

`swoosh identity export` writes a sealed copy to a file:

<!-- manual: the backup destination is a path only the operator knows -->
```console
$ swoosh identity export /Volumes/backup/signet.key
passphrase for ~/.config/swoosh/identity.key:
new passphrase for /Volumes/backup/signet.key:
repeat the new passphrase:
exported to /Volumes/backup/signet.key
restore with `swoosh identity restore /Volumes/backup/signet.key`
```

The backup is always sealed, under a passphrase you choose as you export it. A sealed key is unlocked
first, and its backup still gets a passphrase of its own: the stick is likelier to be lost than the
machine, so do not reuse the one you type every day. The file and its passphrase together are you, so keep them apart: the file
on a stick or in an archive, the passphrase in your head or your password manager.

Run the command on the machine that holds the signet: on a [device](keys.md#device) you adopted, it backs
up that device's key instead. A device does not need a backup; its owner can enrol it again.

## Restore it

On a new machine, restore the backup into the home:

<!-- manual: the backup source is a path only the operator knows -->
```console
$ swoosh identity restore /Volumes/backup/signet.key
passphrase for /Volumes/backup/signet.key:
restored ed012xdjkuwbokai5brwac6varo7xsvuxba6wmfkottpronrhjavyp4q
only the key came back; this home has no revocation list, so grants you revoked work again
```

The same key printing back is the restore working. Your devices already trust that key, so they admit you
again with nothing to re-run on them. The restored key stays sealed under the backup's passphrase.

A wrong passphrase changes nothing:

```
Error: could not unlock the backup /Volumes/backup/signet.key: wrong passphrase, or the file is damaged
```

A home that already holds a different key keeps it unless you pass `--force`, because that key may be the
only copy of another identity: export it first. A sealed key at home needs `--force` even when it claims to
be the same identity, since only its passphrase could prove that. Stop any `swoosh serve` on the home first: a restore refuses to run under a
node that is serving.

## A restore brings back the key, nothing else

Revocations are a separate file. `revoked` sits beside `identity.key` in the home, one line per recalled
grant, and the backup carries none of it. Restore into an empty home and that node starts with no denylist,
so every grant you had revoked is admitted again until it expires. Copy `revoked` from your old home, or
revoke those grants again.

A restore is for a lost key. If the key may have been stolen, restoring it gives you back the key the thief
also holds; make a new signet and enrol your devices again instead.

## If you lose it

Your fleet does not fall over. Each device already holds what it needs.

**Still works.** A device you adopted holds its own key, your signet's public half, and a membership
badge your signet already signed. It keeps serving, keeps admitting your other devices, and keeps
reaching your gated services. Grants you handed out keep working until they expire. `swoosh grant
revoke` still works: it writes a local file and signs nothing.

**Stops.** You cannot enrol another machine. Only the signet can sign a badge your gates admit, and
`swoosh invite add` refuses to sign anywhere else:

```
Error: this machine trusts signet ed01hcq6…, but its own key is ed01imv3…: a badge signed here would root at ed01imv3… and be admitted nowhere that signet gates. Run `invite add` on the machine that holds the signet (the one whose `swoosh identity` prints ed01hcq6…).
```

You cannot renew a badge either. A membership badge lasts 90 days unless the invite set another window,
and only the signet can sign the next one. So a fleet that loses its signet keeps running and then ages
out, one device at a time, as each badge expires.

## Next

- [Keys](keys.md) the model your signet sits at the root of.
- [`swoosh identity`](reference/commands/identity.md) the verb that prints the key, backs it up, and restores it.
- [`swoosh invite`](reference/commands.md#invite) enrolling a device.
