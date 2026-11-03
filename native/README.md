# Native support

Linux x86-64 原生加载器支持。此目录按执行阶段组织，不存放构建产物。

| 目录 | 职责 | 主要入口 |
| --- | --- | --- |
| `runtime/` | 随 glibc 编译的 C 运行时代码 | `dl-fgkaslr.c`、`dl-fg-policy.c` |
| `linker/` | 隔离 bootstrap 页并预留随机布局空间 | `bootstrap.ld`、`code_capacity.S` |
| `tools/` | 构建时修改私有 glibc 源码、导出 ELF 库对 | `patch_glibc.py`、`export_pair.py` |
| `debug/` | GDB / pwndbg 的运行时符号修正 | `gdb_fgkaslr.py` |
| `docs/` | 运行时格式与应用策略说明 | [FORMAT](docs/FORMAT.md)、[POLICY](docs/POLICY.md) |

## 构建流程

在仓库根目录执行 `python3 -B -m libc_layout build --native ...`。
构建器调用 `tools/patch_glibc.py`，将 `runtime/` 文件复制到私有 glibc 的 `elf/`，
再由 `tools/export_pair.py` 打包库对。补丁逻辑以 `apply_glibc_patches()` 为唯一来源；
不再保存与源文件重复、容易失步的整份静态补丁。
`linker/` 文件由编译器包装器引用，所有产物仍放在指定的构建输出目录。

## 命名约定

- C 内部函数使用 `fg_` 前缀和描述性动词，如 `fg_translate_address()`、`fg_apply_patch()`。
- 策略内部函数使用 `fg_policy_` 前缀；类型使用 `fg_*`，整数类型使用 `fg_*_t`。
- `_dl_fg_*`、`_fg_start` 是 glibc 集成入口，保留原名；`_dl_fg_policy_v1` 是应用链接契约。
- `.fgboot`、`.fgspace`、ELF note 与 v5 元数据布局保持不变，不因目录整理而改名。
- Python 使用 `snake_case` 函数和 `PascalCase` 类；CLI 入口统一为 `main()`。
- C 使用 GNU 风格（两空格缩进），Python 使用 Black 格式。

## 调试

GDB 中执行 `source /absolute/path/to/native/debug/gdb_fgkaslr.py`。
`fg-status`、`fg-refresh`、`fg-address`、`fg-break`、`fg-on`、`fg-off` 命令保持不变。
脚本仍是独立文件，无需安装本项目 Python 包。
根目录的 `gdb_fgkaslr.py` 仅作兼容转发，已有 `.gdbinit` 的旧路径仍然有效。

## 验证

仓库根目录执行：

```bash
python3 -B -m unittest discover -s tests -v
```

原生 C 辅助函数测试需 Linux x86-64 与 GCC：

```bash
mkdir -p build/tests
gcc -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin \
  tests/native_runtime_test.c -o build/tests/native_runtime_test
build/tests/native_runtime_test
```

本目录的项目自有代码采用根目录 0BSD；上游 glibc 代码继续保留其原许可。
