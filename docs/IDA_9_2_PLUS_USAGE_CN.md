# Lighthouse for IDA 9.2+ 中文使用文档

本文档面向 IDA Pro 9.2 及以上版本，说明 Lighthouse 的安装、覆盖率数据生成、加载、分析和常见问题排查流程。

## 1. 插件简介

Lighthouse 是一个面向逆向工程场景的代码覆盖率浏览与分析插件。它可以把动态执行产生的覆盖率数据映射回 IDA 数据库，并在反汇编视图、函数图、Hex-Rays 伪代码和覆盖率总览窗口中展示命中情况。

典型用途包括：

- 对比不同输入样本触发的代码路径。
- 快速定位 fuzzing、调试或动态插桩命中的函数与基本块。
- 分析多份覆盖率之间的交集、差集和并集。
- 反查某个基本块由哪些覆盖率样本命中。
- 导出简单的 HTML 覆盖率报告。

## 2. IDA 9.2+ 兼容性说明

IDA 9.2 起官方将 IDAPython 的 Qt 绑定迁移到 Qt 6 / PySide6。这个版本的 Lighthouse 已做以下适配：

- 在 IDA 9.2 及以上优先加载 `PySide6`，旧版 IDA 继续兼容 `PyQt5`。
- 使用 `shiboken6.wrapInstance` 包装 IDA `TWidget`，不再只依赖 `sip.wrapinstance`。
- 为 PySide6 补齐 `pyqtSignal`、`pyqtSlot`、`QAction`、`exec_()` 等 PyQt 风格兼容别名。
- 增加 IDA 9.x 分模块 API 兼容层，将 `ida_kernwin`、`ida_bytes`、`ida_graph` 等模块中的常用符号回填到旧的 `idaapi` 调用路径。
- 兼容新版 `IDB_Hooks.renamed()` 回调签名。

参考资料：

- Hex-Rays 文档：<https://docs.hex-rays.com/user-guide/plugins/migrating-pyqt5-code-to-pyside6>
- IDAPython 示例：<https://docs.hex-rays.com/9.0/developer-guide/idapython/idapython-examples>

## 3. 环境要求

推荐环境：

- IDA Pro 9.2 或更高版本。
- IDAPython 随 IDA 自带的 Python 环境。
- Hex-Rays Decompiler 可选；没有反编译器时，Lighthouse 仍可在反汇编和图视图中工作。

不需要安装额外 Python 依赖。不要把系统 Python 的 PySide6、PyQt5 或 sip 强行复制到 IDA 的 Python 环境中，优先使用 IDA 自带运行时。

## 4. 安装

### 4.1 查找 IDA 用户插件目录

在 IDA 的 Python Console 中执行：

```python
import idaapi, os
print(os.path.join(idaapi.get_user_idadir(), "plugins"))
```

常见路径示例：

- Windows：`%APPDATA%\Hex-Rays\IDA Pro\plugins`
- Linux：`~/.idapro/plugins`
- macOS：`~/.idapro/plugins`

以控制台实际输出为准。

### 4.2 复制插件文件

把本仓库 `plugins` 目录内的内容复制到 IDA 的用户插件目录。复制后结构应类似：

```text
<IDA 用户目录>/plugins/
  lighthouse_plugin.py
  lighthouse/
    __init__.py
    integration/
    painting/
    reader/
    ui/
    util/
```

注意是复制 `plugins` 目录里面的内容，而不是只复制顶层仓库。

### 4.3 重启并验证

重启 IDA 并打开任意 IDB。正常加载后，IDA Output 窗口会出现类似信息：

```text
[Lighthouse] Loaded v0.9.4 - (c) Markus Gaasedelen - 2026
```

菜单中会出现：

- `File -> Load file -> Code coverage file...`
- `File -> Load file -> Code coverage batch...`
- `View -> Open subviews -> Coverage Overview`

如果菜单没有出现，请查看本文“常见问题排查”。

## 5. 准备覆盖率数据

Lighthouse 支持几类覆盖率格式：

- `drcov`：DynamoRIO drcov 格式，常见于动态插桩。
- `modoff`：模块名加偏移格式。
- `trace`：绝对地址或基本块地址列表。
- `tenet`：Tenet trace 相关格式。

仓库提供了示例数据：

```text
testcase/drcov.log
testcase/modoff.log
testcase/trace.log
```

也提供了采集脚本目录：

```text
coverage/frida/
coverage/pin/
```

覆盖率数据必须能映射到当前 IDA 数据库中的目标模块。最常见的问题是覆盖率日志里的模块名、镜像基址或文件名与当前 IDB 不匹配。

## 6. 一键运行并加载覆盖率

本版本为 IDA 增加了自动运行目标程序并加载覆盖率的菜单：

```text
File -> Load file -> 运行并加载覆盖率...
```

该功能会使用 DynamoRIO 的 `drcov` 工具执行当前 IDB 对应的 exe，程序退出后自动把生成的 `drcov*.log` 加载进 Lighthouse。

插件会读取目标 exe 的 PE 头来判断 32 位或 64 位，并自动选择对应的 `bin32\drrun.exe` 或 `bin64\drrun.exe`。如果 DynamoRIO 返回架构不匹配错误，插件会自动尝试另一套 `drrun.exe`。

本源码包已经在以下目录内置 DynamoRIO：

```text
plugins/lighthouse/third_party/dynamorio/
```

复制插件到 IDA 后，默认会优先使用：

```text
plugins/lighthouse/third_party/dynamorio/bin64/drrun.exe
plugins/lighthouse/third_party/dynamorio/bin32/drrun.exe
```

执行流程：

1. 在 IDA 中打开目标 exe 对应的 IDB，并等待自动分析完成。
2. 点击 `File -> Load file -> 运行并加载覆盖率...`。
3. 如果插件没有找到 `drrun.exe`，会提示你选择 DynamoRIO 目录下的 `bin64\drrun.exe` 或 `bin32\drrun.exe`。
4. 输入程序运行参数；没有参数可以留空。如果程序使用 `scanf` / `cin` / `fgets` 从标准输入读取内容，把输入写到“标准输入内容”框里。多个输入按读取顺序写多行。
5. 目标程序会在 DynamoRIO 下运行，退出后插件自动加载新生成的覆盖率日志。
6. `覆盖率总览` 会自动打开并显示命中的函数、基本块和指令。

插件会优先搜索以下位置：

- `LIGHTHOUSE_DRRUN` 或 `DYNAMORIO_DRRUN` 环境变量指向的 `drrun.exe`。
- `DYNAMORIO_HOME` 或 `DYNAMORIO_ROOT` 环境变量。
- 插件目录下的 `lighthouse/third_party/dynamorio/bin64/drrun.exe` 或 `bin32/drrun.exe`。
- 系统 `PATH` 中的 `drrun.exe`。

DynamoRIO 是第三方运行时，随包附带其原始 `License.txt`、`README` 和 `ACKNOWLEDGEMENTS` 文件。

生成的日志默认保存在：

```text
<目标 exe 所在目录>/lighthouse_drcov/<程序名_时间戳>/
```

如果目标 exe 路径中包含单引号、反引号等可能导致 DynamoRIO 参数解析异常的字符，插件会自动复制或硬链接到临时安全路径执行，生成后再把日志搬回目标 exe 所在目录。

注意：

- 这是覆盖率采集，不是函数调用追踪。它能告诉你哪些函数、基本块、指令被执行过。
- `覆盖率 %`、`命中块`、`命中指令` 不是函数调用次数。
- 函数调用次数和调用顺序需要单独的函数入口 trace 功能。
- 如果目标程序需要交互输入，程序退出前插件会等待 DynamoRIO 运行结束。

## 7. 加载单个覆盖率文件

1. 在 IDA 中打开并完成目标程序分析。
2. 点击 `File -> Load file -> Code coverage file...`。
3. 选择一个或多个覆盖率文件。
4. 如果 Lighthouse 无法自动匹配模块，会弹出模块选择窗口。
5. 选择正确模块后，Lighthouse 会构建元数据并映射覆盖率。

加载成功后：

- 命中的指令或基本块会被高亮。
- `Coverage Overview` 会显示每个函数的覆盖率。
- 覆盖率下拉框会出现新加载的数据集。

## 8. 批量加载覆盖率

批量加载适合 fuzzing 或大量样本分析。

1. 点击 `File -> Load file -> Code coverage batch...`。
2. 选择多份覆盖率文件。
3. 输入批量覆盖率名称。
4. Lighthouse 会把多份覆盖率聚合为一个数据集，并记录每个基本块由哪些文件命中。

批量加载后可以使用右键菜单的 `Xrefs coverage sets...` 查看某个地址被哪些覆盖率文件命中。

## 9. Coverage Overview 窗口

打开方式：

```text
View -> Open subviews -> Coverage Overview
```

主要列含义：

- 函数名：IDA 中的函数名称。
- 地址：函数起始地址。
- 覆盖率：该函数被覆盖的指令或基本块比例。
- 复杂度：函数控制流复杂度近似值。
- 命中统计：已执行指令、基本块等统计信息。

常用操作：

- 单击行：定位到函数。
- 右键函数：复制名称、复制地址、重命名、设置标签、清除标签、批量加前缀、清理前缀。
- 点击表头：按覆盖率、地址、名称等排序。
- 覆盖率下拉框：切换、删除或管理已加载覆盖率。

### 9.1 搜索和标签

覆盖率总览保留原版底部 Shell 搜索方式：

```text
/函数名
/地址片段
/标签
```

也可以在覆盖率表格中按 `Ctrl+F` 弹出搜索框。搜索会匹配函数名、函数地址和标签。

在表格中右键函数，可以使用：

```text
设置标签
清除标签
批量设置标签
批量清除标签
```

标签会保存到目标程序或 IDB 所在目录：

```text
<目标程序或 IDB 所在目录>/lighthouse_tags/<程序名>.tags.json
```

这样关闭 IDA 后再次打开同一个程序仍能继续使用之前的标签；切换到另一个程序时，不会看到上一个程序的标签。

## 10. 覆盖率组合 Shell

`Coverage Overview` 底部的输入框可以用于组合覆盖率、过滤函数和跳转。

### 10.1 覆盖率别名

加载的覆盖率会自动分配大写字母别名：

```text
A, B, C, ... Z
```

聚合覆盖率使用：

```text
*
```

### 10.2 组合运算

支持的运算符：

- `|`：并集。
- `&`：交集。
- `^`：异或。
- `-`：差集。
- `(...)`：控制优先级。

示例：

```text
A & B
```

表示同时被 A 和 B 命中的代码。

```text
A - B
```

表示只被 A 命中、没有被 B 命中的代码。

```text
(A | B) - C
```

表示 A 或 B 命中，但 C 没有命中的代码。

组合结果会生成一个新的可选覆盖率视图，便于继续浏览和对比。

### 10.3 搜索过滤

输入 `/` 开头的内容可以过滤函数：

```text
/parse
```

这会只显示名称中包含 `parse` 的函数，并重新计算当前可见函数范围内的覆盖率统计。

### 10.4 跳转

输入地址或函数名可以快速跳转：

```text
401000
```

或：

```text
sub_401000
```

## 10. 覆盖率反查

加载覆盖率后，在 IDA 反汇编视图或图视图中右键基本块或指令，选择：

```text
Xrefs coverage sets...
```

该窗口会列出命中当前地址的覆盖率数据集或具体文件。双击条目可以切换到对应覆盖率，或从批量数据中展开单份样本进行分析。

## 11. Hex-Rays 伪代码高亮

如果当前 IDA 安装了 Hex-Rays Decompiler，Lighthouse 会尝试把覆盖率映射到伪代码行。

注意事项：

- 伪代码高亮依赖 IDA 的 ctree 到基本块映射，复杂优化或异常控制流可能不完全精确。
- 如果覆盖率已经加载但伪代码没有刷新，可以关闭并重新打开伪代码窗口，或切换一次覆盖率数据集。
- 没有 Hex-Rays 时不影响反汇编和图视图高亮。

## 12. HTML 覆盖率报告

在 `Coverage Overview` 的设置菜单中选择：

```text
Generate HTML report
```

报告适合分享函数级覆盖情况。它不是完整交互式报告，重点用于快速查看当前覆盖率名称、函数覆盖率和基本统计。

## 13. 主题与配色

Lighthouse 会根据 IDA 当前界面颜色推断使用浅色或深色主题。你也可以在设置菜单中切换主题。

主题文件位于：

```text
plugins/lighthouse/ui/resources/themes/
```

用户自定义主题可以放到 Lighthouse 用户目录中。主题是 JSON 文件，修改前建议先复制默认主题作为模板。

## 14. 推荐工作流

单样本分析：

1. 在 IDA 中打开目标程序并等待自动分析完成。
2. 加载该样本的覆盖率文件。
3. 在 `Coverage Overview` 中按覆盖率排序。
4. 跳转到高覆盖率或关键函数查看命中路径。

多样本对比：

1. 分别加载多个覆盖率文件。
2. 使用 `A - B` 查找样本 A 独有路径。
3. 使用 `A & B` 查找公共路径。
4. 使用 `(A | B | C) - D` 查找一组样本与另一组样本的差异路径。

Fuzzing 结果分析：

1. 使用批量加载聚合大量覆盖率。
2. 在感兴趣基本块上使用覆盖率反查。
3. 双击具体命中样本，单独展开分析。
4. 给关键函数批量加前缀，辅助后续审计。

## 15. 常见问题排查

### 15.1 IDA 启动后没有菜单

检查：

- `lighthouse_plugin.py` 是否直接位于 IDA 用户插件目录下。
- `lighthouse/` 包目录是否与 `lighthouse_plugin.py` 同级。
- IDA Output 窗口是否有 Python 异常。
- 是否把仓库根目录整体复制到了插件目录，导致目录层级多了一层。

### 15.2 提示无法导入 PyQt5、PySide6 或 sip

IDA 9.2+ 应使用 IDA 自带的 `PySide6` 和 `shiboken6`。请确认使用的是本适配版本的插件，并避免从系统 Python 混用 Qt 绑定。

### 15.3 加载覆盖率后没有任何命中

常见原因：

- 覆盖率日志的模块名与当前 IDB 不匹配。
- 日志记录的是偏移，但 IDB 镜像基址不同。
- 目标程序不是生成覆盖率时运行的同一个文件。
- IDA 自动分析未完成。

处理建议：

- 在模块选择窗口中手动选择正确模块。
- 确认覆盖率日志中模块基址与 IDA `Edit -> Segments -> Rebase program...` 后的基址关系。
- 用仓库 `testcase` 中的样例先验证插件本身可用。

### 15.4 覆盖率颜色没有刷新或残留

可以尝试：

- 切换覆盖率下拉框。
- 在设置菜单中选择 `Force clear paint (slow!)`。
- 关闭并重新打开 IDB。
- 如果正在调试，先停止调试会话后再刷新。

### 15.5 Coverage Overview 打开为空

检查：

- 当前覆盖率是否已经加载。
- 当前 IDB 是否存在函数。
- 自动分析是否完成。
- 是否加载了与当前二进制无关的覆盖率数据。

### 15.6 批量加载很慢

批量加载会构建函数、基本块和指令元数据。大型 IDB 或上万份覆盖率会明显耗时。

建议：

- 先确认目标模块匹配正确，再批量导入。
- 将无关覆盖率文件分批排除。
- 对非常大的样本集先生成聚合覆盖率，再导入 IDA。

## 16. 卸载

关闭 IDA 后，从用户插件目录删除：

```text
lighthouse_plugin.py
lighthouse/
```

重新启动 IDA 即可完成卸载。

## 17. 开发者验证建议

修改插件后建议至少做以下检查：

1. 使用本机 Python 执行语法编译：

   ```powershell
   python -m compileall -q plugins
   ```

2. 在 IDA 9.2+ 打开测试程序 `testcase/boombox.exe`。
3. 加载 `testcase/drcov.log`。
4. 确认 `Coverage Overview`、反汇编高亮、图视图高亮、覆盖率组合和右键反查均可用。
5. 如果安装了 Hex-Rays，确认伪代码窗口能显示覆盖率高亮。
