# libcfs — the Container File System (CFS)

![license](https://img.shields.io/badge/license-GPL--3.0--only-blue)

> One file holding a whole filesystem or disk image: compressed, deduplicated,
> mountable, and with a security boundary around whatever runs inside it.

## What it is

`cfs` is a container format (`LIBCFS02`) and the tools around it:

- **Container**: superblock + inode table + CPEnc-compressed blocks. Ordinary
  files are split at 64MB; the `@block` virtual block device splits at 8MB,
  which caps the decompress-modify-recompress cost of a random write.
- **`@block` virtual block device**: a reserved entry carrying a standard
  MBR/GPT partition table. Sparse (unwritten regions read as zero), and it
  declares its own drive identity (SSD / HDD / USB / SD) at creation time.
- **Formatters, written from scratch**: ext4 / FAT32 / exFAT / swap. They write
  the on-disk structures directly — no external tools, no mounting. An ISO9660
  reader and an ext4 installer let you install a bootable root filesystem from
  an ISO.
- **Deduplication on the write path**: a file of 1KB or more is chunked with
  content-defined boundaries (~4KB average) and only unseen chunks enter
  `@store`; the file becomes a `(logical, length, store_offset)` reference
  table. No maintenance command is needed. Measured: 50 copies of a 1MB text
  file pack to **180KB in one pass** (10.1MB without dedup), near-duplicates
  to 207KB, and all-unique data keeps 98.6% of the old throughput. The older
  `cfs-tool dedup` merge still exists for containers written before this; GC
  reclaims store bytes nothing references.
- **Three mount paths**: an `LD_PRELOAD` hook (**no kernel module**), standard
  kernel FUSE, and exporting `@block` for `losetup`.

## What it is not

This section matters more than the one above:

- **Not a general-purpose compressor.** cpenc beats xz on *smooth numeric
  data* (measured +11% to +104%; historically 317x vs 24x on structured
  tables) and loses to xz/zstd by 20–60% on *text, JSON and ELF*. Its real
  advantage is speed: 4–20x faster to compress than zstd-19 / xz / brotli.
  Decompression runs at 82–371 MB/s — about 2.5x xz, 1.1–3.4x slower than
  zstd.
- **No `lsblk`-style device enumeration.** `LD_PRELOAD` can serve ioctls and
  can answer reads of `/sys/block/*/queue/*`, but it cannot fake a complete
  device enumeration. Enumerating needs a real mount, or virt-kernel's device
  model.
- **No NTFS or XFS formatter.** Pre-format with an external tool and write it
  into `@block` byte for byte (verified to work transparently).
- **Not for text archives.** On text, xz -9 (6.77x whole-file, 5.99x with
  independent 512KB blocks), zstd -19 (6.14x) and bzip2 all beat cpenc on
  ratio, and xz/zstd decode faster. cfs's niche is repetition and random
  access, not prose.
- **Not a compressed-memory tier.** The encoder runs at 11–160 MB/s, well
  below the hundreds of MB/s to GB/s a page-fault write path needs. Use
  zram/zstd for that.
- **No archive recompression.** Unpacking a `.tar.gz` and recompressing with
  cpenc saves nothing (single digits against gzip, a net loss against xz/zstd)
  and cannot reproduce the original bytes (standards specify the decoder, and
  no mainstream format records the encoder version).
- **`verify` only detects; it does not repair.** It can say which field of
  which inode is wrong, but it will not change it.

## Building

```sh
git clone https://github.com/JX-LAB-ORG/cpenc ../libcpool   # the CPEnc codec
make -C ../libcpool
make                       # cfs-tool / cfs-fuse / cfs_block_hook.so / cfs_preload.so
```

aarch64 and x86-64 both build with `-Wall -O3` and no warnings. On x86 the
default is `-march=x86-64-v2` (scalar decode); the AVX2 kernel needs
`make ARCHFLAGS=-march=x86-64-v3`.

The AVX2 kernel (`cpenc_avx2.h`) on real x86 hardware measures **3.44x** at
the core level (1MB group, nz=16, 4 bits per symbol, 800 → 2754 MB/s —
`make test/avx2_lut_check` prints that number), but **end to end it barely
shows**: real data lands 100% on REF2/SEG blocks, where the time goes to
reference copies rather than LUT expansion (94MB tar: 524 → 529 MB/s). It
exists for LUT-shaped blocks, not as a general speedup.

## Quick start

### Storing files

```sh
./cfs-tool pack /some/dir out.cfs          # directory -> container
./cfs-tool ls out.cfs /                    # list
./cfs-tool cat out.cfs /file.txt           # read out (leading slash optional)
./cfs-tool verify out.cfs --deep           # self-check
./cfs-tool dedup out.cfs --stats           # content-addressed merge, cross-file dedup
```

### Making a disk

```sh
./cfs-tool mkfs ext4 64M disk.cfs -p 1 --disk ssd   # ext4 in MBR partition 1
./cfs-tool mkfs fat32 512M usb.cfs --disk usb       # whole-disk FAT32
./cfs-tool mkfs exfat 1G sd.cfs --disk sd           # common SD card format
./cfs-tool cat disk.cfs @block > disk.img           # export it as an ordinary image
```

Supported: `ext4 | fat32 | exfat | swap`; `-p <n>` puts it in a partition,
`-g` uses GPT. Installing from an ISO:

```sh
./cfs-tool install alpine.iso 1G root.cfs -p 1      # mkfs + unpack the ISO into it
```

### Mounting

```sh
# 1. FUSE (standard kernel support, no module to write)
./cfs-fuse disk.cfs /mnt/cfs

# 2. LD_PRELOAD: turn one process's /dev/vda into the container's @block
LD_PRELOAD=./cfs_block_hook.so CFS_BLOCK_FILE=disk.cfs CFS_BLOCK_DEV=/dev/vda \
    mount /dev/vda /mnt

# 3. Export and loop-mount (the most standard path, least tied to this project)
./cfs-tool cat disk.cfs @block > disk.img && losetup -f --show disk.img
```

`./cfs-tool mount disk.cfs /mnt` is a convenience wrapper for the second: it
`chdir`s to the mount point and spawns a shell that already has `LD_PRELOAD`
set.

## Commands

| Command | Purpose |
|---|---|
| `pack <dir> <cfs> [--raw]` | pack a directory into a container |
| `write <cfs> <path> <src>` | write one file |
| `unpack <cfs> <path> <out>` | extract one file |
| `ls` / `cat` / `stat` / `mkdir` / `rm` / `mv` / `symlink` / `trunc` | ordinary file operations |
| `mkfs <type> <size> <cfs> [-p n] [-g] [--disk ssd\|hdd\|usb\|sd]` | format |
| `disktype <cfs> [kind]` | query or set the drive identity |
| `install <iso> <size> <cfs> [-p n] [-g]` | install ext4 from an ISO |
| `partlabel` / `partadd` / `partdel` / `parttype` / `partlist` / `partwrite` | partition table |
| `dedup <cfs> [--stats] [--dry] [--no-compact] [--gc]` | merge / dedup / reclaim |
| `compact <cfs>` | rewrite and reclaim orphaned blocks |
| `verify <cfs> [--deep]` | self-check (see below) |
| `mount <cfs> [pt]` | convenience wrapper for the preload path |

`verify` inspects **the container's own structure**, not the filesystem inside
it: superblock ranges, the inode table, every block table (including the
`orig_size` prefix-sum invariant the read path depends on, overlaps between
blocks, and whether block headers match the table), whether DEDUP references
stay inside `@store`, the dead-byte ratio in `@store`, and the physical
footprint. `--deep` also decodes every block and re-reads every file through
the library as a cross-check. The structural walk parses the container itself
rather than going through `cfs_open()`, so a container the library refuses to
open can still be inspected; the `--deep` cross-check opens it afterwards, and
skips that half when the open fails.

## Security model

These switches exist for "run a client inside the container": the boundary has
to hold against whatever runs inside it.

| Mechanism | Semantics |
|---|---|
| **Single writer** `cfs_lock` | `flock`: writers exclusive, readers shared. `cfs_open` takes the lock before reading anything. `CFS_NO_LOCK=1` skips it (for inspecting a container known to be idle; it does **not** make concurrent writing safe) |
| **Declared capacity is a hard limit** | Going past the size set by `cfs_block_resize` returns `CFS_ENOSPC`; growing is explicit. Reads never change the container |
| **Physical quota** `CFS_MAX_PHYSICAL` | Upper bound, in bytes, on the host file (0 = unlimited). Data blocks are held to it; the inode table and superblock are **never** refused — full has to mean "full", not "broken" |
| **Short writes** | `cfs_block_write_some()` returns the bytes actually written, and the hook turns that into a short write for the guest (real-disk semantics) |

## Container format

`cfs_format.h` is the only format contract, and its comments are complete. The
essentials:

```
[SuperBlock 40B][InodeTable][DataBlocks...]      each block = one CPEnc stream
@store    the merge layer's append stream (an ordinary entry, located by an ordinary block table)
CFS_MODE_DEDUP=3   blocks[] hold a reference table, not content
```

The reference-table encoding, the `@store` convention and the GC thresholds
are all documented in that header. An older reader meeting an unknown mode
**errors out rather than silently returning wrong data**.

## Testing

```sh
make test       # 13 suites
make stress     # random writes / block-limit fallback / partition loops
make testall    # test + cfs-tool smoke test + ext4/exfat fsck acceptance + block hook test
make fuzz       # container fuzzing (needs clang + compiler-rt)
```

Acceptance is judged by **external tools** wherever possible rather than by
self-assertion: `e2fsck -fn`, `fsck.exfat -n`, real loop mounts, and 33 probes
against the block hook. On a machine without those tools the two fsck suites
print `SKIP` with the reason instead of pretending to pass; the large 1G cases
need about 1.1G of scratch, which `TMPDIR` or `CFS_FSCK_WORK` can move (`/tmp`
is often a small tmpfs). The project's own `verify` proves only that the
container is self-consistent, never that its contents are correct — that
requires an external tool.

## Layout

| File | Contents |
|---|---|
| `cfs.c` / `cfs.h` / `cfs_internal.h` | container core, block layer, merge layer, locking and quotas |
| `cfs_format.h` | **the format contract** |
| `cfs_dedup.[ch]` | reference-table codec, CDC, feature index |
| `cfs_mkfs_{ext4,fat32,exfat,swap}.c` | the formatters |
| `cfs_ext4_install.c` / `cfs_iso9660.c` | ISO install |
| `cfs_part.c` | MBR/GPT |
| `cfs_block_hook.c` | LD_PRELOAD block device |
| `cfs_preload.c` / `cfs-fuse.c` | file-level mounts |
| `cfs_verify.c` | container self-check |
| `cfs-tool.c` | command line |
| `test/` | tests and benchmarks |

## Known limits

- Device enumeration: the preload path cannot do it (see above).
- `verify` does not repair, and there is no interactive `fsck`-style repair
  flow. It checks structure and re-decodes, but it **cannot see silent
  corruption that decodes to different bytes** (the encoder once lowercasing
  uppercase hex was that class); only comparing against the original catches
  that.
- The merge layer's GC thresholds (`CFS_DEDUP_FRAG_MAX` / `CFS_DEDUP_DEAD_MAX`)
  are empirical values, not derived.
- `compact` needs twice the host space for a while (it holds the container and
  the rebuilt copy at once) and refuses under a quota.
- Fuzzing covers the **two layers that can be fed automatically**: cpenc's
  block codec (two targets: malformed input, and encoder round-trip) and the
  container/partition parsing and write paths. The mount layers (FUSE, the
  preload syscall hooks) are not in the targets — they are separate process
  boundaries, and only their path logic is covered, by unit tests. See the
  testing section above for how to run them.
- cpenc has been compared head to head against xz/zstd/gzip/lz4 on a real disk
  image (673MB ext4, 3.68x, 4.29 MB/s compress, 164 MB/s decompress); the
  reproduction script is `test/bench_image.sh` in the cpenc repository.

## License

GNU General Public License v3.0 (`LICENSE`), plus one **section 7(b)
additional term** (`NOTICE`):

> The copyright notice and the name "JX-LAB-ORG" must be preserved with the
> program; a derived work must keep "JX-LAB-ORG" in its appropriate legal notices,
> alongside the notices for its own changes.

GPLv3 section 10 forbids adding further restrictions, but section 7(b)
expressly permits a term requiring preservation of author attributions — so
this is written as a 7(b) term, not as an extra license condition, which
would be void as a further restriction. It adds only "the attribution travels
with the work" and changes no right the GPL grants.
