# libcfs

> 压缩存储容器：把一个文件系统或磁盘镜像装进一个可去重、可挂载、有安全边界的容器。

## 它是什么

`cfs` 是一个容器格式（`LIBCFS02`）和一套配套工具：

- **容器**：superblock + inode 表 + CPEnc 压缩块。普通文件的块按 64MB 切，`@block` 虚拟块设备按 8MB 切（限制随机写的解压-改-重压代价）。
- **虚拟块设备 `@block`**：一个保留条目，走标准 MBR/GPT 分区表，支持稀疏（未写区域读作零），并自带**盘身份**（SSD / HDD / USB / SD，创建时声明）。
- **自研格式化器**：ext4 / FAT32 / exFAT / swap，**直接写盘结构，不需要外部工具，也不需要挂载**。另有 ISO9660 读取器和 ext4 安装器，可以从 ISO 装一个可引导的根文件系统。
- **合并层**：内容寻址去重。未匹配的字节追加进 `@store`，每个文件变成一个 `(logical, length, store_offset)` 引用表；标记清除式 GC 回收无人引用的字节。测过的数字：真实 4GB 镜像 **+10.1%**，4 份近似副本 **1/3.9**，运行时随机写 **3.7×**。
- **三条挂载路径**：`LD_PRELOAD` 钩子（**零内核模块**）、标准内核 FUSE、导出 `@block` 后 `losetup`。

## 它不是什么

这一节比上面那节重要：

- **不是一个通用压缩器。** cpenc 在**平滑的数值数据**上赢 xz（实测 +11%…+104%，历史上结构化表 317x vs 24x），在**文本 / JSON / ELF** 上输 xz/zstd 20–60%。它真正的优势在**压缩速度**：比 zstd-19 / xz / brotli 快 4–20 倍。解压 82–371 MB/s，比 xz 快约 2.5 倍，比 zstd 慢 1.1–3.4 倍。
- **不提供 `lsblk` 式设备枚举。** `LD_PRELOAD` 能服务 ioctl、能直接读 `/sys/block/*/queue/*` 的属性文件，但伪造不出完整的设备枚举。要枚举只能真挂载，或走 virt-kernel 的设备模型。
- **没有 NTFS / XFS 格式化器。** 外来文件系统请用外部工具预格式化，再按字节写进 `@block`（已验证透明）。
- **不做压缩包重压缩。** 把 `.tar.gz` 解开用 cpenc 重压：省不下空间（对 gzip 只有个位数，对 xz/zstd 是负收益），而且重建不出**原字节**（标准只规定解码器，主流格式都不记录编码器版本）。
- **`verify` 只检测，不修复。** 它能指出哪个 inode 的哪个字段不对，但不会改。

## 构建

```sh
make -C ../libcpool        # 编解码器在兄弟仓库
make                       # 产出 cfs-tool / cfs-fuse / cfs_block_hook.so / cfs_preload.so
```

aarch64 与 x86-64 都用 `-Wall -O3` 构建，零警告。x86 上默认 `-march=x86-64-v2`（标量解码）；AVX2 内核需要 `make ARCHFLAGS=-march=x86-64-v3`。

AVX2 内核（`cpenc_avx2.h`）在 x86 真机上实测：core 级 **3.44x**（1MB 组、nz=16、4bit/符号，800 → 2754 MB/s，`make test/avx2_lut_check` 会打印这个数字），但**端到端几乎不体现**——真实数据的分块 100% 落在 REF2/SEG 上，时间花在引用拷贝而不是 LUT 展开（94MB tar：524 → 529 MB/s）。它是为 LUT 型块准备的，不是通用加速。

## 快速开始

### 存文件

```sh
./cfs-tool pack /some/dir out.cfs          # 目录 → 容器
./cfs-tool ls out.cfs /                    # 列出
./cfs-tool cat out.cfs /file.txt           # 读出（前导斜杠可有可无）
./cfs-tool verify out.cfs --deep           # 容器自检
./cfs-tool dedup out.cfs --stats           # 内容寻址合并，跨文件去重
```

### 做一块盘

```sh
./cfs-tool mkfs ext4 64M disk.cfs -p 1 --disk ssd   # ext4 在 MBR 分区 1 里
./cfs-tool mkfs fat32 512M usb.cfs --disk usb       # 整盘 FAT32
./cfs-tool mkfs exfat 1G sd.cfs --disk sd           # SD 卡常用格式
./cfs-tool cat disk.cfs @block > disk.img           # 导出来就是普通镜像
```

支持 `ext4 | fat32 | exfat | swap`；`-p <n>` 放进分区，`-g` 用 GPT。ISO 安装：

```sh
./cfs-tool install alpine.iso 1G root.cfs -p 1      # mkfs + 解出 ISO 内容
```

### 挂载

```sh
# 1. FUSE（标准内核支持，不需要写模块）
./cfs-fuse disk.cfs /mnt/cfs

# 2. LD_PRELOAD：把一个进程的 /dev/vda 变成容器里的 @block
LD_PRELOAD=./cfs_block_hook.so CFS_BLOCK_FILE=disk.cfs CFS_BLOCK_DEV=/dev/vda \
    mount /dev/vda /mnt

# 3. 导出后走 loop（最标准、最不依赖本项目的路径）
./cfs-tool cat disk.cfs @block > disk.img && losetup -f --show disk.img
```

`./cfs-tool mount disk.cfs /mnt` 是第二种的便捷封装：它 `chdir` 到挂载点并开一个已经 `LD_PRELOAD` 好的 shell。

## 命令

| 命令 | 作用 |
|---|---|
| `pack <dir> <cfs> [--raw]` | 目录打包进容器 |
| `write <cfs> <path> <src>` | 写入单个文件 |
| `unpack <cfs> <path> <out>` | 取出单个文件 |
| `ls` / `cat` / `stat` / `mkdir` / `rm` / `mv` / `symlink` / `trunc` | 常规文件操作 |
| `mkfs <type> <size> <cfs> [-p n] [-g] [--disk ssd\|hdd\|usb\|sd]` | 格式化 |
| `disktype <cfs> [kind]` | 查询/设置盘身份 |
| `install <iso> <size> <cfs> [-p n] [-g]` | 从 ISO 装 ext4 |
| `partlabel` / `partadd` / `partdel` / `parttype` / `partlist` / `partwrite` | 分区表 |
| `dedup <cfs> [--stats] [--dry] [--no-compact] [--gc]` | 合并/去重/回收 |
| `compact <cfs>` | 重排，回收孤儿块 |
| `verify <cfs> [--deep]` | 容器自检（见下） |
| `mount <cfs> [pt]` | preload 方式的便捷封装 |

`verify` 检查的是**容器自身**的结构，不是里面的文件系统：superblock 范围、inode 表、每个块表（含读路径依赖的 `orig_size` 前缀和不变式、块间重叠、块头与表是否一致）、DEDUP 引用表是否越界、`@store` 的死字节比例、物理足迹。`--deep` 还会解码每个块并通过库重读每个文件做交叉验证。它**不走 `cfs_open()`**，所以连库都打不开的容器也能查。

## 安全模型

这几个开关是为"容器当客户机跑"设计的：容器的边界必须挡得住里面跑的东西。

| 机制 | 语义 |
|---|---|
| **单写者** `cfs_lock` | `flock`：写者独占、读者共享。`cfs_open` 在读任何东西之前上锁。`CFS_NO_LOCK=1` 跳过（用于检查一个确认空闲的容器，**不**让并发写变安全） |
| **声明容量 = 硬上限** | 越过 `cfs_block_resize` 声明的容量就返回 `CFS_ENOSPC`，扩容只能显式调用。读不会改变容器 |
| **物理配额** `CFS_MAX_PHYSICAL` | 容器文件在宿主上最多占多少字节（0 = 不限）。数据块受它约束，inode 表和 superblock **永不拒绝**——满了要是"满"，不能是"坏" |
| **短写** | `cfs_block_write_some()` 返回实际写入字节数，hook 据此给客户机 short write（真盘语义） |

## 容器格式

`cfs_format.h` 是唯一的格式契约，注释齐全。要点：

```
[SuperBlock 40B][InodeTable][DataBlocks...]      每块 = 一段 CPEnc 流
@store    合并层的追加流（普通条目，用普通块表定位）
CFS_MODE_DEDUP=3   blocks[] 存引用表而不是内容
```

引用表编码、`@store` 约定、GC 阈值都在那个头文件的注释里。老读取端碰到未知 mode 会**报错而不是静默给错数据**。

## 测试

```sh
make test       # 10 套件
make stress     # 随机写 / 块上限回退 / 分区循环
make testall    # test + cfs-tool 冒烟 + ext4 fsck 验收 + 块设备 hook 测试
```

验收尽量**用外部工具判定**，而不是自证：`e2fsck -fn`、`fsck.vfat`、真机 loop 挂载、块设备 hook 的 33 项探针。项目里自己写的 `verify` 只证明"容器自洽"，证明不了"内容正确"——那件事只能靠外部工具。

## 文件组成

| 文件 | 内容 |
|---|---|
| `cfs.c` / `cfs.h` / `cfs_internal.h` | 容器核心、块层、合并层、锁与配额 |
| `cfs_format.h` | **格式契约** |
| `cfs_dedup.[ch]` | 引用表编解码、CDC、特征索引 |
| `cfs_mkfs_{ext4,fat32,exfat,swap}.c` | 自研格式化器 |
| `cfs_ext4_install.c` / `cfs_iso9660.c` | ISO 安装 |
| `cfs_part.c` | MBR/GPT |
| `cfs_block_hook.c` | LD_PRELOAD 块设备 |
| `cfs_preload.c` / `cfs-fuse.c` | 文件级挂载 |
| `cfs_verify.c` | 容器自检 |
| `cfs-tool.c` | 命令行 |
| `test/` | 测试与基准 |

## 已知边界

- 设备枚举：preload 做不到（见上）。
- `verify` 不修复，也没有 `fsck` 那样的交互修复流程。
- **没有模糊测试**：格式解析对畸形输入的安全性还没有证据。
- 合并层的 GC 阈值（`CFS_DEDUP_FRAG_MAX` / `CFS_DEDUP_DEAD_MAX`）是实测调出来的经验值，没有理论推导。
- `compact` 需要临时双倍宿主空间（它同时持有容器和重建副本），配额下会拒绝。
- 真实磁盘镜像上 cpenc 与 xz/zstd 的正面对比**还没有测**——这是产品定位上唯一还缺的大数字。
