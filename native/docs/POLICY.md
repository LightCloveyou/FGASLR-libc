# C 许可 API

按[项目 README](../../README.md) 构建一次库，以普通 GCC 指定 ld/libc 编译程序，直接运行。没有应用后处理命令。

## 声明

```c
#include "libc_layout_policy.h"
FG_POLICY_WHITELIST();
FG_ALLOW(puts);
FG_DENY(system);
```

声明位于函数外，最终必须链接进**主程序**。插件内的策略声明不参与合并。规则在 ELF 的 PT_NOTE 中，保留普通 `--gc-sections` 和 `strip --strip-all` 后仍有效；不要手动删除策略 note。

| API | 含义 |
| --- | --- |
| `FG_POLICY_WHITELIST()` | 默认白名单：指定函数、已导入函数和必要依赖被保留 |
| `FG_POLICY_BLACKLIST()` | 默认保留所有函数，仅排除禁止项；依赖冲突仍报错 |
| `FG_ALLOW(puts)` | 许可函数及其内部依赖 |
| `FG_DENY(system)` | 硬禁止；若是必要依赖，启动退出 127 |
| `FG_LOAD(puts)` | 与 FG_ALLOW 相同，不是运行时开关 |
| `FG_ALLOW_NAME("puts")` | 字符串形式的许可 |
| `FG_DENY_NAME("system")` | 字符串形式的禁止 |

未指定模式时采用白名单。重复同一规则可以；同一程序混用两种模式、允许和禁止同一个函数或别名都会报冲突。基名覆盖该名字的符号版本。规则只管 libc 函数，不管应用函数、libm 等其他库。最多 256 条声明，每个名称最多 127 字节。

## 何时生效

1. GCC 把声明写进 ELF；链接时要求配套 ld 导出 `_dl_fg_policy_v1`。
2. 启动时 ld 读取主程序规则和已映射依赖的导入表。
3. ld 加入启动、函数指针数据和函数内部依赖，只生成保留的 libc 单元。
4. 排除单元的符号地址指向永久保护区；没有后续解禁或按需补载。

白名单是保守闭包，不是“只剩声明的函数”。规则在编译时写入，闭包在启动时确定，不是编译期裁剪磁盘 libc。普通内部相对跳转只修补目标偏移，不变成函数解释器。

## dlsym / dlopen

通过字符串查找的函数不会出现在普通导入表中，应预先声明：

```c
FG_ALLOW(strptime); /* 后面会 dlsym(..., "strptime") */
```

`dlsym` 对被排除函数可能返回非空保护区地址；非空不代表可调用。

晚加载的插件不会扩展已固定的许可集合。插件若导入已排除的 libc 函数，ld 报错并终止进程（127），而不是仅让 dlopen 返回失败。需要的函数请提前在主程序中 `FG_ALLOW`。动态加载的依赖库也受这条检查；新 namespace 中的配套 libc 按主程序规则生成；插件应显式带上配套库的 rpath，误加载系统 libc 会报错退出。

线程创建不会恢复排除项；fork 继承现有布局，exec 重新随机。该模式与旧的自动缺页加载不同；使用 `build --native` 即可。

## 报错怎么处理

| 关键文字 | 处理 |
| --- | --- |
| `undefined reference to _dl_fg_policy_v1` | 链接到了旧库；检查 -L 是否指向新 pair |
| `matching policy-enabled libc metadata required` | ld/libc 不配套；使用同次构建的整套库 |
| `unknown libc function` | 名称拼错，或该 libc 没有此函数 |
| `denied function is required` | 必要代码依赖禁止项；调整程序或规则 |
| `conflicting whitelist/blacklist modes` | 多个源文件的模式不一致 |
| `late import of forbidden function` | 插件需要的函数未预先许可 |

不拦截所有可能的系统调用或第三方代码。磁盘库仍含原始指令；可信部署文件和加载环境是前提。恢复普通程序只需去掉策略头/声明，以原来的系统 GCC 链接命令重新编译，不修改系统库。
