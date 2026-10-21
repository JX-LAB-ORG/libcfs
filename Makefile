.PHONY: test testall clean fuzz

# Target-specific ISA flags: NEON on aarch64, a conservative x86-64 baseline
# elsewhere (the NEON paths are compiled out there).  Override with ARCHFLAGS=.
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
ARCHFLAGS ?= -march=armv8-a+simd
else
ARCHFLAGS ?= -march=x86-64-v2
endif
CFLAGS = -std=gnu11 -fPIC -Wall -O3 $(ARCHFLAGS) -I. -I..

OBJS = cfs.o cfs_part.o cfs_dedup.o cfs_verify.o cfs_mkfs_ext4.o cfs_mkfs_fat32.o cfs_mkfs_exfat.o cfs_ext4_install.o cfs_iso9660.o
CPENC = ../libcpool/cpenc.o ../libcpool/bwt.o

all: $(OBJS) cfs-tool cfs_block_hook.so

cfs.o: cfs.c cfs_internal.h cfs.h cfs_format.h ../libcpool/cpenc.h
	cc $(CFLAGS) -c cfs.c -o cfs.o

cfs_part.o: cfs_part.c cfs_part.h cfs_internal.h cfs_format.h
	cc $(CFLAGS) -c cfs_part.c -o cfs_part.o

cfs_dedup.o: cfs_dedup.c cfs_dedup.h cfs_format.h
	cc $(CFLAGS) -c cfs_dedup.c -o cfs_dedup.o

# Container self-check: needs the same codec cfs.c decodes with, but none of
# cfs.c's internals — it parses the container itself (see cfs_verify.c).
cfs_verify.o: cfs_verify.c cfs.h cfs_format.h cfs_dedup.h ../libcpool/cpenc.h
	cc $(CFLAGS) -c cfs_verify.c -o cfs_verify.o

# Shared codec lives in the sibling project; build it on demand so a clean
# checkout can run the tests without a manual step there first.
../libcpool/%.o:
	$(MAKE) -C ../libcpool $*.o

cfs_mkfs_fat32.o: cfs_mkfs_fat32.c cfs.h
	cc $(CFLAGS) -c cfs_mkfs_fat32.c -o cfs_mkfs_fat32.o

cfs_mkfs_exfat.o: cfs_mkfs_exfat.c cfs.h
	cc $(CFLAGS) -c cfs_mkfs_exfat.c -o cfs_mkfs_exfat.o

cfs_mkfs_ext4.o: cfs_mkfs_ext4.c cfs.h
	cc $(CFLAGS) -c cfs_mkfs_ext4.c -o cfs_mkfs_ext4.o

cfs_ext4_install.o: cfs_ext4_install.c cfs.h
	cc $(CFLAGS) -c cfs_ext4_install.c -o cfs_ext4_install.o

cfs_iso9660.o: cfs_iso9660.c cfs_iso9660.h cfs.h
	cc $(CFLAGS) -c cfs_iso9660.c -o cfs_iso9660.o

test/iso_mk.o: test/iso_mk.c
	cc $(CFLAGS) -c test/iso_mk.c -o test/iso_mk.o

test/ext2_read.o: test/ext2_read.c
	cc $(CFLAGS) -c test/ext2_read.c -o test/ext2_read.o

cfs_preload.so: cfs_preload.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o
	cc $(CFLAGS) -fPIC cfs_preload.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -shared -ldl -lm -o cfs_preload.so

cfs-tool: cfs-tool.c cfs.o cfs_part.o cfs_dedup.o cfs_verify.o cfs_mkfs_fat32.o cfs_mkfs_exfat.o cfs_mkfs_ext4.c cfs_mkfs_swap.c cfs_ext4_install.o cfs_iso9660.o ../libcpool/cpenc.o ../libcpool/bwt.o
	cc $(CFLAGS) cfs-tool.c cfs.o cfs_part.o cfs_dedup.o cfs_verify.o cfs_mkfs_fat32.o cfs_mkfs_exfat.o cfs_mkfs_ext4.c cfs_mkfs_swap.c cfs_ext4_install.o cfs_iso9660.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o cfs-tool

cfs_block_hook.so: cfs_block_hook.c cfs.o cfs_part.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o
	cc $(CFLAGS) -fPIC cfs_block_hook.c cfs.o cfs_part.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -shared -ldl -lm -o cfs_block_hook.so

# cfs-fuse needs libfuse3 (apk add fuse3-dev); built only where available
HAS_FUSE := $(shell pkg-config --exists fuse3 2>/dev/null && echo yes)
ifeq ($(HAS_FUSE),yes)
all: cfs-fuse
cfs-fuse: cfs-fuse.c cfs.o cfs_part.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o
	cc $(CFLAGS) $(shell pkg-config --cflags fuse3) cfs-fuse.c cfs.o cfs_part.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o $(shell pkg-config --libs fuse3) -lm -o cfs-fuse
endif

test: $(OBJS) $(CPENC) test/iso_mk.o test/ext2_read.o
	cc $(CFLAGS) test/cfs_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_test
	./test/cfs_test
	@echo "=== cfs_rw_test ==="
	cc $(CFLAGS) test/cfs_rw_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_rw_test
	./test/cfs_rw_test
	@echo "=== cfs_dir_test ==="
	cc $(CFLAGS) test/cfs_dir_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_dir_test
	./test/cfs_dir_test
	@echo "=== cfs_new_test ==="
	cc $(CFLAGS) test/cfs_new_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_new_test
	./test/cfs_new_test
	@echo "=== cfs_compact_test ==="
	cc $(CFLAGS) test/cfs_compact_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_compact_test
	./test/cfs_compact_test
	@echo "=== cfs_block_test ==="
	cc $(CFLAGS) test/cfs_block_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_block_test
	./test/cfs_block_test
	@echo "=== cfs_part_test ==="
	cc $(CFLAGS) test/cfs_part_test.c cfs.o cfs_part.o cfs_dedup.o cfs_mkfs_ext4.c cfs_mkfs_fat32.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_part_test
	./test/cfs_part_test
	@echo "=== cfs_install_test ==="
	cc $(CFLAGS) test/cfs_install_test.c cfs.o cfs_part.o cfs_dedup.o cfs_mkfs_ext4.o cfs_ext4_install.o cfs_iso9660.o test/iso_mk.o test/ext2_read.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_install_test
	./test/cfs_install_test
	@echo "=== cfs_dedup_test ==="
	cc $(CFLAGS) test/cfs_dedup_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_dedup_test
	./test/cfs_dedup_test
	@echo "=== cfs_dedup_write_test ==="
	cc $(CFLAGS) test/cfs_dedup_write_test.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_dedup_write_test
	./test/cfs_dedup_write_test
	@echo "=== cfs_dedup_codec_test ==="
	cc $(CFLAGS) test/cfs_dedup_codec_test.c cfs_dedup.c -o test/cfs_dedup_codec_test
	./test/cfs_dedup_codec_test

# Container-level benchmark: sequential/random I/O, small files, compact.
bench: test/bench_cfs test/bench_gen test/bench_tables
	$(MAKE) -C ../libcpool bench

test/bench_tables: test/bench_tables.c
	cc $(CFLAGS) test/bench_tables.c -o test/bench_tables

test/bench_gen: test/bench_gen.c
	cc $(CFLAGS) test/bench_gen.c -o test/bench_gen

# Build the corpora and run the whole survey (see test/bench_all.sh).
corpus: test/bench_gen test/bench_tables
	sh ./test/bench_corpus.sh
	./test/bench_gen /root/bench/corpus 32
	./test/bench_tables /root/bench/corpus 32

bench-run: bench corpus
	bash ./test/bench_all.sh

check-bench:
	sh -n test/bench_corpus.sh
	bash -n test/bench_all.sh
	bash -n test/bench_tools.sh
	bash -n test/bench_dedup.sh
	@echo "bench scripts: syntax ok"

# Drop the corpora and scratch the benchmark run leaves behind.
clean-bench:
	rm -rf /root/bench/corpus /root/bench/plain.bin /root/bench/bench.cfs
	rm -rf /tmp/benchtools.* /tmp/benchdedup.*

test/bench_cfs: test/bench_cfs.c cfs.o cfs_dedup.o $(CPENC)
	cc $(CFLAGS) test/bench_cfs.c cfs.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/bench_cfs

# Deep stress tests (random writes, block-cap fallback, part loops).  The
# "flaky under PRoot" note that used to live here was a bug in the test
# itself (a 512-byte buffer written 1024 bytes wide), now fixed.
stress: $(OBJS) $(CPENC)
	cc $(CFLAGS) test/cfs_stress_test.c cfs.o cfs_part.o cfs_dedup.o ../libcpool/cpenc.o ../libcpool/bwt.o -lm -o test/cfs_stress_test
	./test/cfs_stress_test

testall: test cfs-tool cfs_preload.so cfs_block_hook.so
	@echo "=== cfs-tool smoke test ==="
	./cfs-tool 2>&1 | head -1
	@echo "=== ext4 fsck acceptance ==="
	cc $(CFLAGS) test/iso_gen.c test/iso_mk.o -o test/iso_gen
	chmod +x test/cfs_ext4_fsck_test.sh
	./test/cfs_ext4_fsck_test.sh
	@echo "=== block hook test ==="
	cc $(CFLAGS) test/vblk_probe.c -o test/vblk_probe
	chmod +x test/cfs_block_hook_test.sh
	./test/cfs_block_hook_test.sh
	@echo "Tests: $(shell make test 2>&1 | grep '=== 0 failures ===' | wc -l)/10 passed"

# Fuzz the container parser: libFuzzer + UBSan + guard pages (needs compiler-rt).
fuzz:
	sh test/fuzz.sh $(SECS)

clean:
	rm -f $(OBJS) cfs_preload.o cfs_preload.so cfs-tool cfs_block_hook.so cfs-fuse
	rm -f test/iso_mk.o test/ext2_read.o test/vblk_probe test/iso_gen
	rm -f test/cfs_test test/cfs_rw_test test/cfs_dir_test test/cfs_new_test test/cfs_compact_test test/cfs_block_test test/cfs_part_test test/cfs_stress_test test/vblk_probe
	rm -f test/cfs_dedup_test test/cfs_dedup_write_test test/cfs_dedup_codec_test
	rm -f test/bench_cfs test/fuzz_cfs
