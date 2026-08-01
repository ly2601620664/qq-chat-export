# QQ 聊天记录导出工具 (QQ Chat Export)

导出并分析 QQ MsgBackup 聊天数据库：捕获 SQLCipher 密钥、解密数据库、解析 Protobuf 消息、计算关系指标、生成按时间排序的阅读分块。

## 工作流程

```
MsgBackup/        capture-key         keys.json
(加密数据库)  ──────────────────►   (16 字节密钥)
                     │
                     ▼
               decrypt (C#)          decrypted/*.sqlite
              ───────────────────►  (标准 SQLite)
                     │
                     ▼
                  parse               messages.jsonl
              ───────────────────►  (Protobuf -> JSON)
                     │
           ┌─────────┼─────────┐
           ▼         ▼         ▼
       metrics    chunks    inspect
       (.json)    (*.txt)   (调试用)
```

## 前置要求

- **Python 3.10+** 及 pip
- **PCQQ 9.x**（旧版桌面 QQ，非 NTQQ）已安装在 Windows 上
- **.NET Framework 4.x**（用于编译 C# 解密工具）
- **Frida**（通过 pip 自动安装）

> **注意：** 本工具针对旧版 PCQQ (9.x) 的 MsgBackup 数据库格式。NTQQ 使用不同的存储格式。

## 安装

```bash
git clone https://github.com/ly2601620664/qq-chat-export.git
cd qq-chat-export
pip install -r requirements.txt
pip install -e .
```

## 使用方法

### 第一步：捕获加密密钥

```bash
qq-chat-export capture-key --output keys.json
```

该命令会启动 PCQQ 并注入一个只读的 Frida Hook。如有提示请登录。Hook 会捕获每个数据库的 16 字节 SQLCipher 密钥，**不会修改任何 QQ 文件**。

可选参数：
- `--timeout 180` - 捕获时长（秒）
- `--no-launch` - 附加到已运行的 PCQQ 进程而非启动新实例
- `--qq-exe PATH` - 指定 QQ.exe 路径
- `--kernel-util PATH` - 指定 KernelUtil.dll 路径

### 第二步：编译解密工具

```bat
cd rekey
csc /platform:x86 /target:exe /reference:System.Web.Extensions.dll /out:PcqqOfflineRekey.exe PcqqOfflineRekey.cs
cd ..
```

必须编译为 **32 位 (x86)**，因为 PCQQ 的 KernelUtil.dll 是 32 位的。

### 第三步：解密数据库

```bash
qq-chat-export decrypt ^
  --input ./MsgBackup ^
  --output-dir ./decrypted ^
  --keys ./keys.json ^
  --kernel-util "C:\Program Files (x86)\Tencent\QQ\Bin\KernelUtil.dll" ^
  --rekey-tool ./rekey/PcqqOfflineRekey.exe
```

解密后生成标准 SQLite `.sqlite` 文件，可用任何 SQLite 工具打开。

### 第四步：解析消息

```bash
qq-chat-export parse ^
  --database ./decrypted/messages.sqlite ^
  --output ./messages.jsonl ^
  --report ./parse_report.json ^
  --self-uin 100000001 ^
  --peer-uin 100000002
```

将 Protobuf 格式的 `extensionData` BLOB 解析为结构化 JSON，包含发送方、接收方、正文、引用文本及内容类型（文本/媒体/系统）。

### 第五步：分析

计算对话指标：

```bash
qq-chat-export metrics --input ./messages.jsonl --output ./metrics.json
```

生成按时间排序的阅读分块：

```bash
qq-chat-export chunks --input ./messages.jsonl --output-dir ./chunks --days-per-chunk 3
```

查看原始 Protobuf 字段（调试用）：

```bash
qq-chat-export inspect ./decrypted/messages.sqlite --self-uin 100000001 --peer-uin 100000002 --limit 20
```

## 工作原理

### 密钥捕获

使用 [Frida](https://frida.re) Hook PCQQ 的 `KernelUtil.dll` 中的 `sqlite3_key()` 函数。当 QQ 打开自己的加密数据库时，Hook 被触发并捕获 16 字节 SQLCipher 密钥。Hook 是**只读**的 —— 只读取密钥参数，从不写入或修改任何 QQ 数据库。

### 离线解密

C# 工具通过 `LoadLibraryEx` 加载 `KernelUtil.dll`（内置 SQLCipher），通过字节特征码查找 `sqlite3_open`/`sqlite3_key`/`sqlite3_exec`/`sqlite3_close`，用捕获的密钥打开加密数据库，重设为空密钥（即解密），然后移除 PCQQ 的 1024 字节扩展头。

### Protobuf 解析

QQ 将消息内容以嵌套 Protobuf 格式存储在 `extensionData` BLOB 列中。本工具包含一个零依赖的 wire-format 解析器，无需 `.proto` 文件即可遍历字段：

| 字段路径 | 含义 |
|----------|------|
| `1.1` | 发送方 UIN |
| `1.2` | 接收方 UIN |
| `5.40800.45101` | 主要文本内容 |
| `5.40800.47413` | 引用（回复）文本 |
| `5.40800.45402` | 图片/媒体文件名 |

## 隐私与安全

- **所有处理均在本地完成。** 数据不会发送到任何服务器。
- 密钥捕获 Hook 是**只读**的 —— 从不修改 QQ 数据库。
- `.gitignore` 排除所有敏感数据：密钥、数据库、解析后的消息、分析输出。
- **切勿提交** `keys.json`、`*.sqlite`、`*.jsonl` 或 `secrets/`、`input/`、`decrypted/` 目录中的任何文件。

## 项目结构

```
qq-chat-export/
├── qq_backup_export/       # Python 包
│   ├── cli.py              # 统一命令行入口
│   ├── capture_key.py      # Frida 密钥捕获（只读）
│   ├── protobuf_wire.py    # Protobuf wire-format 解析器
│   ├── backup_parser.py    # QQ 备份消息解析器
│   ├── metrics.py          # 关系指标计算
│   ├── review_chunks.py    # 按时间排序的阅读分块生成器
│   └── inspect.py          # 原始 Protobuf 检查器
├── rekey/                  # C# 离线解密工具
│   ├── PcqqOfflineRekey.cs
│   └── README.md           # 编译说明
├── tests/                  # 单元测试（14 项，全部通过）
├── docs/
│   └── architecture.md     # 流水线架构
├── examples/
│   └── sample_messages.jsonl
├── .gitignore
├── .gitattributes
├── LICENSE                 # MIT
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 测试

```bash
python -m unittest discover -s tests -v
```

## 许可证

MIT —— 详见 [LICENSE](LICENSE)。

## 致谢

- [Frida](https://frida.re) - 动态插桩框架
- [qq-win-db-key](https://github.com/Withington/qq-win-db-key) - PCQQ/NTQQ 密钥提取的参考研究
- [qq_msg_decode](https://github.com/ihmily/qq_msg_decode) - QQ 消息 Protobuf 结构参考
