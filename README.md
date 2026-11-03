# libc-layout-processor

v0.1.0 · Linux x86-64 · 实验性项目

Linux x86-64 项目：每次启动重新排列 ld、libc 的函数；主程序用 C 声明决定 libc 的许可规则。

**应用只用 GCC 编译，然后直接运行。没有 Python 二次处理、patchelf 或启动器。** Python 只用于下面的一次性库构建。

## 1. 库在项目的 lib 目录

已编译好的库放在 `lib/`。使用现有库时直接看第 2、3 节；以下命令仅用于重新构建。

在 Linux / WSL Ubuntu 的 Bash 终端执行。需要 Python 3.10+、GCC/G++、GNU binutils、make、gawk、bison、Linux 头文件。

```bash
cd /path/to/libc-layout-processor
PROJECT="$PWD"
LIB="$PROJECT/lib"

python3 -B -m libc_layout doctor
mkdir -p "$PROJECT/build"
tar -xf sources/glibc-2.43.tar.gz -C "$PROJECT/build"
python3 -B -m libc_layout build --native \
  --source "$PROJECT/build/glibc-2.43" --out "$PROJECT/build/native" --jobs 8 --skip-check

mkdir -p "$LIB"
cp "$PROJECT/build/native/pair/ld-linux-x86-64.so.2" \
   "$PROJECT/build/native/pair/"lib*.so* \
   "$PROJECT/build/native/pair/libc_nonshared.a" "$LIB/"
```

`lib/` 包含 `libc.so` 链接脚本、`libc.so.6`、`ld-linux-x86-64.so.2`、`libc_nonshared.a` 和配套库。`build/` 存放构建中间文件；构建命令要求 `build/native` 事先不存在。替换库前先停止使用这套库的程序。`--skip-check` 跳过 glibc 自带测试，不代表业务兼容性验证。

## 2. C 源码写规则

```c
#include "libc_layout_policy.h"
#include <stdio.h>

FG_POLICY_WHITELIST();
FG_ALLOW(puts);
FG_DENY(system);

int main(void) {
    puts("hello, protected app");
    return 0;
}
```

声明写在函数外。白名单保留指定函数，以及程序导入、启动和内部依赖所需的函数；其余 libc 函数不生成。`FG_DENY` 是硬约束：必要依赖与禁止项冲突时，ld 报错并以 127 退出，不进入 main。

## 3. 正常 GCC 编译，直接运行

在项目目录的 Bash 终端执行：

```bash
PROJECT="$PWD"
LIB="$PROJECT/lib"
mkdir -p "$PROJECT/build"
gcc -O2 -fno-builtin -I"$PROJECT/include" \
  "$PROJECT/examples/policy_demo.c" \
  -L"$LIB" \
  -Wl,--dynamic-linker="$LIB/ld-linux-x86-64.so.2" \
  -Wl,-rpath,"$LIB" \
  -o "$PROJECT/build/app"

"$PROJECT/build/app"
```

输出 `hello, protected app`。换自己的程序时，只换源文件、输出名，保留 `-I`、`-L`、`--dynamic-linker` 和 `-rpath`。多源文件工程把声明放进一个最终链接到主程序的源文件即可。

- `-L`：链接时选本项目 libc，避免误用系统库。
- `--dynamic-linker`：程序启动时选本项目 ld。
- `-rpath`：运行时找到配套库。上例记录绝对路径，移动库目录后应重新链接。

包含策略头文件却链接旧 ld，会因缺少 `_dl_fg_policy_v1` 报错，不会悄悄忽略规则。没有任何规则的程序仍使用完整函数随机化。

## GDB + pwndbg 调试

在 WSL / Linux 中启动 GDB；pwndbg 保持原来的加载方式。在 GDB 提示符输入：

```gdb
source /absolute/path/to/libc-layout-processor/native/debug/gdb_fgkaslr.py
start
break puts
continue
```

脚本会读取本次进程的真实布局，加载修正后的函数符号。之后直接用普通命令即可：

```gdb
p/x (void*)puts
disassemble puts
bt
nearpc
```

`nearpc` 是 pwndbg 命令，其余原生 GDB 也支持。要自动加载，把上面的 `source` 行加到自己的 `~/.gdbinit`，放在 pwndbg 的加载行之后。

| 命令 | 用途 |
| --- | --- |
| `fg-status` | 查看已修正的库和各自加载基址 |
| `fg-refresh` | 手动重新读取布局、重建调试符号 |
| `fg-address puts` | 查询真实地址，同时设置 `$fg_address` |
| `fg-break puts` | 在真实入口设置地址断点；IFUNC 指向解析器 |
| `fg-off` / `fg-on` | 卸载并恢复原 GDB 设置 / 重新启用 |

每次重新运行请用 `start` 先停住，再继续；也可以 attach 到已经启动的本地进程。每次停下时脚本会检查新增/卸载的库。`break puts` 这种符号断点会随新符号重新定位；`break *0x...` 是固定地址断点，重新启动前要删除重设。`fg-break` 建立的地址断点在进程退出或 `fg-off` 时自动删除。多个 namespace 可用 `fg-address puts 0x基址` 区分，基址见 `fg-status`。

地址修正只读被调试内存，不改原始库，临时符号文件随会话清理；断点仍按 GDB 常规机制处理。它临时关闭自动库符号加载，改为分别加载修正库和普通库；`fg-off` 恢复原设置，但原磁盘函数地址本来就不适用于随机布局。禁止函数不会被错误注册到保护区。IFUNC 名字对应解析器，不保证是最终选择的 CPU 实现；完整 DWARF 源码行号、局部变量位置不在本脚本的修正范围内。

IFUNC 在临时符号视图中按普通解析器函数注册，查询不会主动执行解析器。默认符号版本保留普通函数名，兼容版本显示为 `函数名__fg_compat_版本`，避免旧版本遮蔽默认版本。仍可用原始版本名查询，例如 `fg-address memcpy@GLIBC_2.2.5 libc.so.6`。

当前支持本地 Linux/WSL、x86-64、项目 v5 元数据。这里使用 GDB 的 [add-symbol-file 符号加载机制](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Files.html)，不需要另外给 pwndbg 打补丁。

## 实际发生什么

编译时把规则写进主程序的 ELF note。启动时，原生 ld 在依赖映射完成、重定位之前读取规则，计算依赖闭包，只生成保留函数的随机布局。

- 正常调用仍走 PLT/GOT 或已修补的直接调用，不增加逐次许可检查。
- 被排除函数的导出地址指向 `PROT_NONE` 保护区，读取、执行会触发 SIGSEGV；不会缺页后自动补载。
- 不改磁盘上的 libc。原文件仍有完整代码；限制的是该进程生成后的 libc 代码区。
- 这不是系统调用沙箱，也不保证仅凭一条函数黑名单覆盖同类功能。
- 选择集合仍在启动时计算；减少了代码生成和修补量，但启动时间是否下降应以实际程序测量为准。

API、动态插件和限制见 [规则说明](native/docs/POLICY.md)。内部格式见 [FORMAT](native/docs/FORMAT.md)。最终库位于项目的 `lib/`，构建中间文件位于 `build/`。

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| `libc_layout/` | Python 构建、ELF 处理与检查工具 |
| `native/` | 按 runtime / linker / tools / debug / docs 分层；见 [目录说明](native/README.md) |
| `include/` | 应用使用的策略头文件 |
| `examples/` | 最小示例与策略示例 |
| `lib/` | 预构建的 Linux x86-64 ld / libc 及配套链接文件 |
| `sources/` | 重建所需的 glibc 源码包 |
| `tests/` | Python 工具回归测试与原生 C bootstrap 测试 |
| `LICENSES/` | 第三方许可证与版权声明 |

编译产物统一放在 `build/`（已忽略），不提交调试历史和本地实验文件。
预构建库仅用于实验；发布整理不代表已通过 glibc 全量测试或生产兼容性测试。

## 开发验证

在仓库根目录执行 `python3 -B -m unittest discover -s tests -v`。
原生 C 测试、目录职责及命名约定见 [native 开发说明](native/README.md)。

## 许可

项目自有代码使用 [0BSD](LICENSE)，允许商用、修改、再分发，不要求署名或公开修改。
该许可不覆盖第三方代码：`sources/` 中的 glibc 源码、`lib/` 中的 glibc 及其派生二进制，
以及补丁中引用的上游代码继续遵循各自原有许可。
第三方许可及版权声明保留于 [LICENSES](LICENSES/) 和上游源码包中。
重新分发第三方二进制时，应同时满足其对应源码和许可义务。
