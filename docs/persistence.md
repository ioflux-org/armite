# Data Persistence

Everything created through the API survives a restart, a crash and a
`kill -9`: resource groups, vaults, secrets (every version, soft-deleted
ones included) and role assignments. Nothing is lost that the server
acknowledged, because every change is on disk before the response is
sent.

## Where

| what                  | where                                     | created                 |
| --------------------- | ----------------------------------------- | ----------------------- |
| `journal`, `snapshot` | the data directory (config `state.dir`)   | first boot, first write |
| `state.key`           | `~/.armite/` (next to the CA key), 0600 | first boot              |
| `azurite/`            | the data directory, Azurite's own files   | first storage account   |

The data directory is `~/.local/share/armite` on Linux,
`~/Library/Application Support/armite` on macOS, `%LOCALAPPDATA%\armite`
on Windows — or `$ARMITE_HOME/state` when `ARMITE_HOME` is set, as
in Docker (`/data/state`). The state files are encrypted (AES-256-GCM)
with the key, so the data directory on its own cannot be read, and
without `state.key` it cannot be opened. Deleting the data directory is
the way to start over: the keys stay, clients stay trusted. Deleting the
keys alone leaves data nobody can read — delete both instead.

To supply your own key instead of the generated one, set `state.key`
in `armite.yaml` or `ARMITE_STATE_KEY` to a base64 32-byte value
(`openssl rand -base64 32`). Then the state directory is unreadable to
anyone who does not also have that value.

Blob contents are Azurite's and are not encrypted; account metadata and
keys are Armite's and are.

## How

Each change is one record: the new state of one resource, assignment or
secret, or its deletion. Records are appended to the journal and synced
to disk one at a time; the response goes out after the sync. On boot the
snapshot is loaded, then the journal replayed over it.

When the journal grows past `state.compact_after_mb` (default 8), the
current state is written to a new snapshot and the journal trimmed, in
the background, without pausing requests. Set it to 0 to never compact.

A crash in the middle of a write leaves a torn record at the end of the
journal. On the next boot it is dropped and logged; everything before
it is intact. Anything else that fails to open - a changed byte, a
different key - stops the boot with
`record cannot be opened: corrupted, or sealed with another key`.

## Starting over

Stop the server and delete the state directory; the key can stay. With
compose: `docker compose down -v` removes both volumes.

To run without persistence, set `state.dir: ""`: everything stays in
memory and dies with the process, as before.

## Seeds and the journal

`role_assignments` in the configuration are applied at every boot as
"must exist": a seed that is already there - replayed from the journal,
or granted by a client under its own name - is left alone. Removing a
seed from the configuration does not revoke it; revoke it through the
API (`az role assignment delete`) or start over.

## Throughput

Every write costs one `fsync`, a few milliseconds on a local disk. That
is a few hundred resource writes per second, far more than any client
sends. Filesystems that are slow or unreliable at syncing make it worse:
on WSL, keep the state directory on the Linux filesystem, not under
`/mnt/c`.
