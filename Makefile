.PHONY: test testall clean

CFLAGS = -std=gnu11 -Wall -O3 -march=armv8-a+simd -I. -I..

all: cfs.o cfs_part.o cfs-tool cfs_block_hook.so

cfs.o: cfs.c cfs_internal.h cfs.h cfs_format.h ../libcpool/cpenc.h
	cc $(CFLAGS) -c cfs.c -o cfs.o

cfs_part.o: cfs_part.c cfs_part.h cfs_internal.h
	cc $(CFLAGS) -c cfs_part.c -o cfs_part.o

cfs_mkfs_fat32.o: cfs_mkfs_fat32.c cfs.h
	cc $(CFLAGS) -c cfs_mkfs_fat32.c -o cfs_mkfs_fat32.o

cfs_preload.so: cfs_preload.c cfs.o ../libcpool/cpenc.o
	cc $(CFLAGS) -fPIC cfs_preload.c cfs.o ../libcpool/cpenc.o -shared -ldl -lm -o cfs_preload.so

cfs-tool: cfs-tool.c cfs.o cfs_part.o cfs_mkfs_fat32.o cfs_mkfs_ext4.c ../libcpool/cpenc.o
	cc $(CFLAGS) cfs-tool.c cfs.o cfs_part.o cfs_mkfs_fat32.o cfs_mkfs_ext4.c ../libcpool/cpenc.o -lm -o cfs-tool

cfs_block_hook.so: cfs_block_hook.c cfs.o cfs_part.o ../libcpool/cpenc.o
	cc $(CFLAGS) -fPIC cfs_block_hook.c cfs.o cfs_part.o ../libcpool/cpenc.o -shared -ldl -lm -o cfs_block_hook.so

# cfs-fuse needs libfuse3 (apk add fuse3-dev); built only where available
HAS_FUSE := $(shell pkg-config --exists fuse3 2>/dev/null && echo yes)
ifeq ($(HAS_FUSE),yes)
all: cfs-fuse
cfs-fuse: cfs-fuse.c cfs.o cfs_part.o ../libcpool/cpenc.o
	cc $(CFLAGS) $(shell pkg-config --cflags fuse3) cfs-fuse.c cfs.o cfs_part.o ../libcpool/cpenc.o $(shell pkg-config --libs fuse3) -lm -o cfs-fuse
endif

test: cfs.o
	cc $(CFLAGS) test/cfs_test.c cfs.o ../libcpool/cpenc.o -lm -o test/cfs_test
	./test/cfs_test
	@echo "=== cfs_rw_test ==="
	cc $(CFLAGS) test/cfs_rw_test.c cfs.o ../libcpool/cpenc.o -lm -o test/cfs_rw_test
	./test/cfs_rw_test
	@echo "=== cfs_dir_test ==="
	cc $(CFLAGS) test/cfs_dir_test.c cfs.o ../libcpool/cpenc.o -lm -o test/cfs_dir_test
	./test/cfs_dir_test
	@echo "=== cfs_new_test ==="
	cc $(CFLAGS) test/cfs_new_test.c cfs.o ../libcpool/cpenc.o -lm -o test/cfs_new_test
	./test/cfs_new_test
	@echo "=== cfs_compact_test ==="
	cc $(CFLAGS) test/cfs_compact_test.c cfs.o ../libcpool/cpenc.o -lm -o test/cfs_compact_test
	./test/cfs_compact_test
	@echo "=== cfs_block_test ==="
	cc $(CFLAGS) test/cfs_block_test.c cfs.o ../libcpool/cpenc.o -lm -o test/cfs_block_test
	./test/cfs_block_test
	@echo "=== cfs_part_test ==="
	cc $(CFLAGS) test/cfs_part_test.c cfs.o cfs_part.o cfs_mkfs_ext4.c cfs_mkfs_fat32.o ../libcpool/cpenc.o -lm -o test/cfs_part_test
	./test/cfs_part_test

# Deep stress tests (random writes, block-cap fallback, part loops).
# NOTE: known flaky under PRoot/Termux (stack-layout-sensitive corruption,
# see PLAN.md) — run on real hardware (GCP) where ASAN is available.
stress: cfs.o cfs_part.o
	cc $(CFLAGS) test/cfs_stress_test.c cfs.o cfs_part.o ../libcpool/cpenc.o -lm -o test/cfs_stress_test
	./test/cfs_stress_test

testall: test cfs-tool cfs_preload.so cfs_block_hook.so
	@echo "=== cfs-tool smoke test ==="
	./cfs-tool 2>&1 | head -1
	@echo "=== block hook test ==="
	cc $(CFLAGS) test/vblk_probe.c -o test/vblk_probe
	chmod +x test/cfs_block_hook_test.sh
	./test/cfs_block_hook_test.sh
	@echo "Tests: $(shell make test 2>&1 | grep '=== 0 failures ===' | wc -l)/7 passed"

clean:
	rm -f cfs.o cfs_part.o cfs_mkfs_fat32.o cfs_preload.o cfs_preload.so cfs-tool cfs_block_hook.so
	rm -f test/cfs_test test/cfs_rw_test test/cfs_dir_test test/cfs_new_test test/cfs_compact_test test/cfs_block_test test/cfs_part_test test/cfs_stress_test test/vblk_probe
