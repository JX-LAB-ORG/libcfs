# Using cfs — a task guide

`README.md` explains what the container is; `cfs-tool --help` lists every
command and flag. This file is the order you actually do things in, with the
outputs to expect and the places it will surprise you.

Every `cfs-tool` command exits **0 on success, 1 on failure**, and writes the
diagnosis to stderr. Nothing is ever written to a container that fails
verification on open.

---

## 1. Build

```sh
make -C libcpool          # cpenc.o, bwt.o — the block codec
make -C libcfs            # cfs-tool, cfs_preload.so, cfs_block_hook.so,
                          # and cfs-fuse when libfuse3 is installed
```

Nothing is linked beyond libc, libm and libdl. `libcpool` must be built first:
the container's blocks are CPEnc streams and the codec objects are shared.

Check what you have:

```sh
./cfs-tool --version      # cfs-tool 0.1.0 (container format 2, block codec 7)
```

---

## 2. Two things share the name "container"

| | What it is | How you use it |
|---|---|---|
| **Container of files** | `pack` writes a directory tree into one file; `cfs-tool` reads it back by path | `cfs-tool cat`, FUSE, the file hook |
| **Virtual disk** | `mkfs` writes a real filesystem (ext4/fat32/exfat/swap) plus an optional partition table into one file | `mount`, losetup, the block hook |

Both are the same file format with the same block codec. The **disk** form is
an ordinary `.img` living inside the container, reachable as the reserved
entry `@block`; the **file** form is an ordinary namespace of paths. A
container can hold both. `pack` is the namespace tool; a disk is what you
mount when you need a real filesystem's semantics (permissions, ownership,
fsck, tools that expect a block device).

---

## 3. Ordinary files

```sh
./cfs-tool pack /some/dir out.cfs          # directory -> container
./cfs-tool ls out.cfs                       # list the root ("/" is optional)
./cfs-tool ls out.cfs sub/dir               # list a directory
./cfs-tool cat out.cfs notes.md             # write a file to stdout
./cfs-tool stat out.cfs notes.md            # size, mtime, mode, block count
./cfs-tool write out.cfs notes.md notes.md  # copy one host file in
./cfs-tool unpack out.cfs notes.md out.md   # copy one file out
./cfs-tool mkdir out.cfs drafts
./cfs-tool mv out.cfs a.txt b.txt
./cfs-tool symlink out.cfs target link
./cfs-tool rm out.cfs notes.md
./cfs-tool trunc out.cfs big.bin 0          # truncate to 0 bytes
```

`pack` preserves **type, size, mtime and symlinks**. It does not store
permission bits or ownership: they are not part of this namespace, and
`cfs-tool chmod`/`chown` deliberately do not exist. If you need them, put the
data in a disk (section 4) — a real filesystem inside the container has them.

### Deduplication is not a command

Every write path — `pack`, `write`, the FUSE mount, the hook — runs
content-defined chunking (average 4KB, minimum 1KB) and merges identical
chunks. 50 copies of the same 1MB file occupy one copy. Nothing needs to be
scheduled, and `cfs-tool dedup` exists only to merge containers written by
older versions.

```sh
./cfs-tool dedup out.cfs --stats    # what would merge
./cfs-tool dedup out.cfs --gc       # reclaim once past the thresholds
```

### Uncompressed containers

```sh
./cfs-tool pack /some/dir out.cfs --raw     # store blocks uncompressed
```

Use this when the data is already compressed or incompressible and you want
the cycles back. The choice is recorded in the superblock and honoured by
every reader, including the hooks.

---

## 4. A disk inside a container

```sh
./cfs-tool mkfs ext4 64M disk.cfs -p 1 --disk ssd   # ext4 in MBR partition 1
./cfs-tool mkfs fat32 512M usb.cfs --disk usb       # whole-disk FAT32
./cfs-tool mkfs exfat 1G sd.cfs --disk sd
./cfs-tool mkfs swap 64M swap.cfs
```

`-p <n>` formats inside partition *n*; `-g` builds a GPT instead of an MBR.
`--disk ssd|hdd|usb|sd` only declares the drive identity — it is what
`blkid`/`file` and partitioning software use to decide alignment and
trim behaviour, and it changes nothing about how the bytes are stored.

The produced container is a **real disk image**, so the usual tools work on
it once it is exported:

```sh
./cfs-tool cat disk.cfs @block > disk.img      # export the disk image
sudo losetup -f --show disk.img                # /dev/loop0
sudo mount /dev/loop0p1 /mnt/disk              # partition 1
sudo umount /mnt/disk && sudo losetup -d /dev/loop0
```

Installing from an ISO:

```sh
./cfs-tool install alpine.iso 1G root.cfs -p 1
```

This is `mkfs ext4 -p 1` followed by unpacking the ISO; the result boots when
the container is exported and loop-mounted (or attached as a block device).

Partition table editing, when you need it:

```sh
./cfs-tool partlabel disk.cfs mbr
./cfs-tool partadd disk.cfs linux 2048 65535 --boot     # sectors; end inclusive
./cfs-tool partadd disk.cfs linux 1M 32M                # or K/M/G suffixes
./cfs-tool partlist disk.cfs
./cfs-tool parttype disk.cfs 1 fat32
./cfs-tool partdel disk.cfs 1
./cfs-tool partwrite disk.cfs 1 payload.bin             # write a file into a partition
```

Types: `linux fat32 fat16 efi swap ntfs 0xNN`.

---

## 5. Four ways to reach the data

### 5.1 `cfs-tool` — always works

No mount, no kernel support, no root. This is the reference implementation
and the thing to compare against when another path looks wrong.

### 5.2 FUSE — a real mount point

```sh
sudo mkdir -p /mnt/cfs
./cfs-fuse disk.cfs /mnt/cfs
fusermount3 -u /mnt/cfs
```

Needs `/dev/fuse` and `fusermount3` (package `fuse3`). Implements
`getattr, readdir, open, read, write, create, mkdir, unlink, rename,
truncate, symlink, readlink, utimens, statfs`. `chmod`/`chown` are not
implemented, for the same reason the namespace has no permission bits.

### 5.3 The file hook — no root, one process tree

```sh
LD_PRELOAD=./cfs_preload.so CFS_FILE=$PWD/out.cfs CFS_MOUNT=/tmp/mnt \
    cat /tmp/mnt/notes.md
```

or, interactively:

```sh
./cfs-tool mount out.cfs /tmp/mnt      # spawns $SHELL with the hook loaded
```

What to expect, and what not to:

- **Whole-file semantics.** A container path behaves like a file that is read
  into memory on open and written back on close. Files larger than RAM are
  not practical.
- **`ls` works, `ls -l` lies.** The hook interposes libc's `stat`, but modern
  coreutils use `statx`/`readlinkat`, which it does not intercept: sizes and
  symlink targets from those tools come from the host directory (which is
  empty), not from the container. Use the shell builtins (`test -e`,
  `test -L`) or `cfs-tool stat`.
- **Shell redirection is not captured.** In `echo hi > /tmp/mnt/x`, bash's
  `dup2` of a virtual fd only updates the hook's private table; a child
  process writes to its real stdout. Write through the library, FUSE,
  `cfs-tool write`, or `test/preload_probe.c`.
- **One writer per container.** see section 7.
- **Membership follows the environment.** The process that mounts the file
  sets `CFS_MOUNT_TREE`; children that inherit it are inside the tree and
  never take the lock themselves.

`test/preload_probe.c` is the in-process way to exercise this path:

```sh
cc -O2 test/preload_probe.c -o test/preload_probe
LD_PRELOAD=./cfs_preload.so CFS_FILE=$PWD/out.cfs CFS_MOUNT=/tmp/mnt \
    ./test/preload_probe write /tmp/mnt/hello hi
```

### 5.4 The block hook — `/dev/vda` without root... until `mount`

```sh
LD_PRELOAD=./cfs_block_hook.so \
CFS_BLOCK_FILE=$PWD/disk.cfs CFS_BLOCK_DEV=/dev/vda CFS_BLOCK_PARTS=1 \
    mount /dev/vda /mnt/disk
```

The hook answers the ioctls and I/O a block device gets (`BLKGETSIZE64`,
`BLKSSZGET`, `BLKRRPART`, `BLKPG`, reads and writes at any offset), exposing
the whole disk and its partitions (`/dev/vda1`, `CFS_BLOCK_PARTS=1`).
`CFS_SECTOR_SIZE=4096` presents 4K sectors.

`mount` still needs the privilege it always needs.

---

## 6. Check and reclaim

```sh
./cfs-tool verify out.cfs            # structure: superblock, inode/block tables,
                                     # dedup references, @store accounting
./cfs-tool verify out.cfs --deep     # also decodes every block and re-reads
                                     # every file through the library
./cfs-tool compact out.cfs           # rewrite, reclaim orphaned blocks
```

`verify` parses the container itself rather than going through the library,
so a container the library refuses to open can still be inspected; `--deep`
is the cross-check that needs the library.

Physical quota, for a container that must not grow past a host limit:

```sh
CFS_MAX_PHYSICAL=$((100*1024*1024)) ./cfs-tool write out.cfs big.bin big.bin
```

Data blocks are refused past it (`CFS_ENOSPC`); the superblock and inode
table are never refused, so "full" means full, not broken.

---

## 7. Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `CFS_FILE` | file hook | container to serve |
| `CFS_MOUNT` | file hook | host directory that becomes the mount point |
| `CFS_MOUNT_TREE` | file hook | set by the process that took the lock; inherited by children, which then never take it |
| `CFS_NO_LOCK` | library, hooks | `1` skips the advisory lock. For inspecting an idle container; it does **not** make concurrent writing safe |
| `CFS_MAX_PHYSICAL` | library, tool | hard cap, in bytes, on the host file (0 = unlimited) |
| `CFS_BLOCK_FILE` | block hook | container backing the device |
| `CFS_BLOCK_DEV` | block hook | device name to present (`/dev/vda`) |
| `CFS_BLOCK_PARTS` | block hook | `1` exposes `/dev/vdaN` partitions |
| `CFS_SECTOR_SIZE` | block hook | `512` (default) or `4096` |
| `CFS_RAW` | `cfs-fuse` | serve a container uncompressed |
| `CFS_PDBG` | file hook | print hook diagnostics to stderr |

---

## 8. When it goes wrong

**`[cfs] <file> is locked by another process: Device or resource busy`**
Another process holds the container's exclusive lock — typically a `cfs-tool`
command, a FUSE mount, or another container tree. The hook retries for 400ms
first. Wait for the holder to exit, or use `CFS_NO_LOCK=1` for a read-only
inspection.

**The hook reads empty files / `[cfs] FAILED to open`**
The container was not opened at all, so every path fell through to the host
filesystem. Check `CFS_FILE` and `CFS_MOUNT` are absolute and that the file
exists; set `CFS_PDBG=1` to see the hook's decisions.

**A file removed in another process is still "there"**
Each process loads the inode table when it opens the container. A long-lived
process (your shell) does not see deletions made by a *different* process
until it restarts. `cfs-tool` and FUSE always read the current state.

**`cat: cannot open ...: No such file or directory` for a path you just listed**
You are inside a path that resolves outside `CFS_MOUNT` (the hook only serves
paths under it), or the process is a child of a tree whose mount point has a
different name.

**Disk full on the test machine**
A container being packed into `/tmp` on a machine where `/tmp` is a small
tmpfs is the usual cause. Pack into a real filesystem.

**`cfs-fuse: error: fuse3 not found`**
The binary is only built when `pkg-config --exists fuse3` succeeds. Install
`fuse3`/`fuse3-dev` (or `libfuse3-dev`), then `make cfs-fuse`.

---

## 9. Using it as a library

```c
#include "cfs.h"

CFS *c = cfs_open("out.cfs", CFS_RDWR);
if (!c) return 1;                       /* errno says why */

cfs_write(c, "hello.txt", "hi\n", 3);

size_t n; void *buf = cfs_read_all(c, "hello.txt", &n);
write(1, buf, n);
free(buf);
cfs_close(c);                           /* releases the lock */
```

`cfs_open` takes the container's advisory lock before reading anything: one
writer at a time, readers shared. `cfs_tool.c`, `cfs-fuse.c` and both hooks
are built on exactly this API and nothing else, so anything they can do is
available to a program.
