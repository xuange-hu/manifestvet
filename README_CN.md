# manifestvet（中文说明）

[![CI](https://github.com/xuange-hu/manifestvet/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/manifestvet/actions/workflows/ci.yml)
![tests-294%20passing](https://img.shields.io/badge/tests-294%20passing-brightgreen)
![dependencies-0](https://img.shields.io/badge/dependencies-0-blue)
![rules-40](https://img.shields.io/badge/rules-40-informational)

**用攻击者的视角读 Android 清单文件 —— 每条结论都带字节偏移，不依赖 aapt、Java 和任何第三方包。**

[English](README.md) · [规则全表](docs/rules.md) · [AXML 格式笔记](docs/axml.md)

```console
$ manifestvet scan app-release.apk
app-release.apk
  package=com.example.vault  minSdk=19  targetSdk=29  components=16  format=axml  shift=0
  45 findings  critical=2  high=15  medium=16  low=10  note=2  risk=100/100

[critical] MVT001  Application is debuggable
           android:debuggable="true" -- JDWP is reachable, private data is readable via adb
           at line 19, offset 0xcc0
           bytes: debuggable="true"
           fix:   Remove android:debuggable, or gate it on a build type (debuggable true only in debug).
```

## 目录

- [三步跑通](#三步跑通)
- [为什么要有这个工具](#为什么要有这个工具)
- [规则](#规则)
- [MCP](#mcp)
- [怎么验证它没瞎报](#怎么验证它没瞎报)
- [已知边界](#已知边界)
- [许可](#许可)

## 三步跑通

```bash
# 1. 不用安装，直接跑内置语料（三个清单，覆盖全部 40 条规则）
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet demo

# 2. 审 APK、单个清单文件，或整棵源码树
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet scan path/to/app.apk
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet scan app/src/main/AndroidManifest.xml

# 3. 接进 CI
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet scan app-release.apk \
    --format sarif --fail-on high > manifestvet.sarif
```

`scan` 接受 `.apk`、`.aab`、`.zip`、裸 `AndroidManifest.xml`（**编译后的二进制或源码 XML 都行**），
或者一个目录（自动跳过 `build/`、`.gradle/`、`intermediates/`）。

Python 3.10+，运行时零依赖，`mcp` 是唯一可选 extra。

## 为什么要有这个工具

现成的清单检查器要么包一层 `aapt`/`apktool`（于是必须装 JDK 和 Android SDK，而且只能告诉你
「清单里写了什么」，不给判断），要么把格式塞进一个重框架里。这个项目由此定下三条设计：

**1. 字节级证据。** 每条结论带 `ResXMLTree_node` 的字节偏移（能落到具体属性就落到属性），
外加 aapt 记录的源码行号。`--format sarif` 直接变成 GitHub code scanning 的行内注释；
`manifestvet attrs` 把整棵树连偏移、资源 id 一起打出来，让结论可被复核，而不是被信任。

**2. AXML 自己解析，不调外部工具。** 编译后的清单里不存在属性名：`android:exported` 就是整数
`0x01010010`，名字只能通过 resource map 反查。误读就发生在这一步，所以这一步自己实现、
用真实 aapt2 产物做语义断言、并写在 [docs/axml.md](docs/axml.md) 里。

**3. 审的是模型，不是 XML。** 规则问的是一个 `App` 对象：「哪些组件能被别的 App 在没有权限的
情况下触达？」——这意味着 `android:exported` 的平台默认值、`<application android:permission>`
的继承、`protectionLevel` 的位掩码，都要在 `model.py` 里一次性算对。

## 规则

40 条，分三遍。完整说明（为什么、怎么修）见 [docs/rules.md](docs/rules.md)。

| 遍 | 看什么 | 例子 |
|---|---|---|
| 1 元素 | 单个节点 | `debuggable`、`allowBackup` 默认值、明文流量、`sharedUserId`、`minSdk`/`targetSdk` |
| 2 组件 | 组件 + 它的 intent-filter | 无保护的 exported service、`grantUriPermissions`、`host="*"`、任务劫持 |
| 3 全应用 | 组件之间的关系 | 谁都能拿到的权限当门禁（`INTERNET`）、authority 重复、门禁引用了不存在的权限 |

其中真正抓到 bug 而不是挑风格的四条：

- **MVT037**：导出的组件用 normal/dangerous 级权限当门禁。任何 App 声明
  `android.permission.INTERNET` 装完就有，门禁形同虚设 —— 这是 Android 清单里最常见的
  假安全感。
- **MVT039**：`android:permission="com.example.app.SIG"`，但清单里没有这个名字的 `<permission>`。
  平台静默忽略，组件实际敞开，文件看起来却是受保护的。
- **MVT038**：两个 provider 抢同一个 authority。要么后者装不上，要么它回答了本该属于前者的查询。
- **MVT018/19**：`grantUriPermissions` 配 `path="/"` —— 一个 `content://` URI 变成可转手的
  能力，任何 App 拿到就能读那个文件。

## MCP

7 个工具，给 Claude Code / Cursor / Cline 用：

```json
{
  "mcpServers": {
    "manifestvet": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/xuange-hu/manifestvet[mcp]", "manifestvet-mcp"]
    }
  }
}
```

`manifestvet_scan`（路径）、`manifestvet_manifest`（直接贴 XML 文本）、
`manifestvet_components`（攻击面表格：组件/是否导出/门禁/门禁是否形同虚设）、
`manifestvet_explain`、`manifestvet_rules`、`manifestvet_sarif`、`manifestvet_demo`。

`manifestvet mcp --check` 在命令行打同一份清单。

## 怎么验证它没瞎报

- `manifestvet demo` 在**运行时**生成三份清单、编译成 AXML、断言 40 条规则在语料上全部命中
  （`tests/test_demo.py`）。没有任何二进制夹具入库，所以规则不可能悄悄失去覆盖。
- 解析器对真实 aapt2 产物做**语义**断言：包名、`targetSdkVersion`、`debuggable`、
  provider `exported=false`、receiver 的 `android.permission.DUMP` 门禁。
- 源码 XML 与 AXML 两条路径必须给出**完全相同的结论** —— 开发机上的清单和 CI 里的产物
  不允许有分歧。
- `ruff` 全绿，3.10 / 3.11 / 3.12 / 3.13 四腿测试。

## 已知边界

- 不审 Java/Kotlin 代码：导出组件即使内部做了参数校验，仍然会被报出来 —— 这条结论说的是
  「可达」，不是「代码写得糙」。
- `protectionLevel` 解的是位掩码，不建模自定义权限组。
- `@0x7f...` 形式的资源按 id 输出，解析它需要 `resources.arsc`，不在清单审计的范围内。
- AAB 只读 `base/manifest/AndroidManifest.xml`；多 feature 模块请直接指向源码树。

## 许可

MIT。
