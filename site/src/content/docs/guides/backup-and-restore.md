---
title: Backup and restore
description: What Jay backs up, what it does not, and the procedure for rebuilding an installation from scratch.
---

Jay backs up **half** of your data, and it is not the half you would guess.

The hourly job snapshots the metadata database, verifies the snapshot by opening
it, deletes it if it fails verification, and prunes old ones while keeping at
least three. That is a careful, honest job — over `meta/jay.db` and nothing
else. **Object bytes have no backup at all.** There is no replication, no
sync-out and no remote target, and since Jay has no
[object versioning](/jay/internals/limits/), a `PUT` over an existing key
destroys the previous bytes permanently.

So a complete backup is two jobs, and only one of them is Jay's.

| What | Who backs it up | Why |
|---|---|---|
| `meta/jay.db` — buckets, object records, tokens, multipart state | **Jay**, hourly, into `JAY_METADATA_BACKUP_DIR` | It is the only copy taken inside a consistent bbolt transaction |
| `buckets/` — the object bytes | **You**, with `restic`, `rclone`, `borg`, a snapshot of the volume, anything | They are immutable once written, so an ordinary file-level tool is safe and correct |
| `quarantine/`, `tmp/`, `multipart/` | Nobody | Evidence, scratch space and in-flight uploads. See [what a restore does not bring back](#what-a-restore-does-not-bring-back) |

## Do not just back up the data directory

The obvious move is to point `restic` at `JAY_DATA_DIR` and call it done. It is
the wrong move, and it fails silently.

`meta/jay.db` is a live bbolt file. Copying it from a running server captures it
mid-transaction, and a snapshot taken that way can be unrestorable — which is
worse than not having one, because it satisfies a retention policy while being
useless. That is the exact failure the hourly job's verification step exists to
prevent, and a file-level copy walks straight around it.

:::caution
If your backup tool copies `JAY_DATA_DIR` wholesale, **exclude `meta/`**. Use
Jay's own verified snapshots for the metadata and your tool for `buckets/`.
:::

## Backing up

### Object bytes

Anything file-level works, because objects are written with a temp file and an
atomic `rename`: a file under `buckets/` is either absent or complete, never
half-written, and it never changes afterwards.

```bash
# restic to a separate disk
restic -r /mnt/backup/jay backup /var/lib/jay/buckets

# or rclone to object storage
rclone sync /var/lib/jay/buckets remote:jay-objects
```

An incremental run is cheap for the same reason: existing files never change, so
only new keys are transferred.

### Metadata

Jay writes it. Your only job is to say where, and to make sure that "where" is
not the disk you are protecting against.

```bash
JAY_METADATA_BACKUP_DIR=/mnt/backup/jay-metadata
```

Left unset, snapshots land in `<JAY_DATA_DIR>/backups` — the same filesystem as
the database they protect, where one disk failure takes the original and every
copy of it together. Jay warns about this at startup and reports it on
`/health/ready`:

```json
{
  "status": "ready",
  "durability": {
    "metadata_backup": "hourly verified snapshot of meta/jay.db (bbolt): accounts, buckets, object records, tokens, multipart state",
    "object_bytes_backup": "none — object bytes under buckets/ — jay keeps no copy of them; back that directory up separately",
    "metadata_backup_dir": "/var/lib/jay/backups",
    "metadata_backup_shares_data_filesystem": true
  }
}
```

Snapshot files are named `jay-<timestamp>.db`. Pick the newest one that predates
whatever you are recovering from; they are ordinary bbolt files and any of them
can be inspected offline.

## Restoring

The order is not a preference. **Object bytes first, metadata second.**

Jay reconciles metadata against the filesystem before it accepts traffic, and it
quarantines both directions of disagreement rather than deleting anything. Boot
with metadata whose files are not there yet and every record is quarantined —
correctly, and unhelpfully. It does not undo itself when the files show up
later: the records stay quarantined, and the newly arrived files become orphans
that the next boot quarantines too. You end up holding both halves of every
object and serving none of them.

### 1. Stop Jay

```bash
systemctl stop jay      # or: docker compose down
```

Restoring underneath a running server races the very reconciliation you are
about to depend on.

### 2. Restore the object bytes

```bash
mkdir -p /var/lib/jay
restic -r /mnt/backup/jay restore latest --target / --include /var/lib/jay/buckets
```

### 3. Restore the metadata snapshot

Copy the chosen snapshot into place under the name Jay expects:

```bash
mkdir -p /var/lib/jay/meta
cp /mnt/backup/jay-metadata/jay-20260907T120000Z.db /var/lib/jay/meta/jay.db
```

### 4. Check ownership and start

```bash
chown -R jay:jay /var/lib/jay
systemctl start jay
```

Startup recovery runs before the first request is served. Its final log line is
the restore's report card:

```json
{"msg":"recovery: reconciliation complete","buckets":4,"quarantined_meta":0,"quarantined_files":0,"orphaned_files":0,"cleaned_tmp":0}
```

**Four zeros is a clean restore.** Anything else is a real finding:

| Field | What a non-zero value means |
|---|---|
| `quarantined_meta` | Records whose file is missing. Your object backup is older than the snapshot, or incomplete |
| `quarantined_files` | Files no record points at. Your object backup is *newer* than the snapshot — those keys were written after it was taken |
| `orphaned_files` | Files that could not even be moved into quarantine. A permissions problem, usually step 4 |

A mismatch in either direction is recoverable, because nothing was deleted.
Once the missing files are back in place, `POST /_jay/quarantine/revalidate`
re-checks a quarantined record and restores it if it now verifies —
`jay-admin quarantine-list` shows what is waiting. Files quarantined as orphans
sit intact in `quarantine/`, named after their original location with the
slashes flattened, so the object ID in the filename is what ties one back to a
record. See the [Admin API](/jay/reference/admin-api/).

### 5. Verify with data, not with a green light

A process that starts is not a restore that worked.

```bash
# Readiness passed, and says what it is protecting from here on
curl -s localhost:9001/health/ready

# The objects are actually there and actually readable
jay ls jay://your-bucket/
jay cp jay://your-bucket/a-known-key /tmp/check && sha256sum /tmp/check
```

`jay ls -l` prints the SHA-256 Jay has on record for each key; comparing it
against the bytes you just downloaded is the check that a listing alone does not
give you. The [scrubber](/jay/internals/architecture/) will do this across the
whole store on its own schedule, but it starts 30 seconds after boot and works
through a bucket a page at a time — do not wait for it to tell you whether the
restore worked.

## What a restore does not bring back

- **In-flight multipart uploads.** Parts live in `multipart/`, which is not part
  of either backup. Their records survive in the snapshot and the garbage
  collector reclaims them after 24 hours of inactivity. Clients must re-upload.
- **Quarantined objects.** `quarantine/` is evidence of an earlier problem, not
  live data.
- **Overwritten versions.** There are none to bring back. A `PUT` over a key
  replaced the file, and no backup Jay takes contains the old bytes.
- **Anything written after the snapshot.** The metadata snapshot is hourly, so
  the worst case is an hour of object records lost. Their *files* will be on
  disk if you restored a newer `buckets/`, and startup recovery quarantines them
  as orphans rather than deleting them — the bytes are recoverable by hand, the
  keys and content types are not.

## Rehearse it

An untested restore procedure is a guess. Rehearsing this one costs a temp
directory:

```bash
# A throwaway install pointed at the restored data, on ports nobody uses
JAY_DATA_DIR=/tmp/jay-drill \
JAY_LISTEN_ADDR=:19000 JAY_ADMIN_ADDR=:19001 JAY_NATIVE_ADDR= \
JAY_ADMIN_TOKEN=$JAY_ADMIN_TOKEN JAY_SIGNING_SECRET=$JAY_SIGNING_SECRET \
jay
```

`JAY_SIGNING_SECRET` has to be the same one the original used, or every stored
token is unreadable and the drill fails on authentication rather than on
anything about your data. It is not in either backup — keep it wherever you keep
secrets, and check that you still have it *before* you need it.

The procedure on this page is executed on every test run against a real store, a
real snapshot and a real reconciliation pass, including the two failure modes
described above (`recovery/restore_test.go`). If it changes here, it changes
there.
