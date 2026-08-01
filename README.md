# QQ MsgBackup Export Toolkit

Export and analyze QQ MsgBackup chat databases: capture SQLCipher keys, decrypt databases, parse protobuf messages, compute relationship metrics, and build review chunks for full chronological reading.

## Pipeline

```
MsgBackup/        capture-key         keys.json
(encrypted)   ──────────────────►   (16-byte keys)
                     │
                     ▼
               decrypt (C#)          decrypted/*.sqlite
              ───────────────────►  (standard SQLite)
                     │
                     ▼
                  parse               messages.jsonl
              ───────────────────►  (protobuf -> JSON)
                     │
           ┌─────────┼─────────┐
           ▼         ▼         ▼
       metrics    chunks    inspect
       (.json)    (*.txt)   (debug)
```

## Prerequisites

- **Python 3.10+** with pip
- **PCQQ 9.x** (old desktop QQ, not NTQQ) installed on Windows
- **.NET Framework 4.x** (for compiling the C# rekey tool)
- **Frida** (installed automatically via pip)

> **Note:** This toolkit targets the old PCQQ (9.x) format with MsgBackup databases. NTQQ uses a different storage format.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/qq-backup-export.git
cd qq-backup-export
pip install -r requirements.txt
pip install -e .
```

## Usage

### Step 1: Capture encryption keys

```bash
qq-backup-export capture-key --output keys.json
```

This launches PCQQ with a read-only Frida hook. Log in if prompted. The hook captures the 16-byte SQLCipher key for each database **without modifying any QQ files**.

Options:
- `--timeout 180` - capture duration in seconds
- `--no-launch` - attach to an already-running PCQQ instead of launching
- `--qq-exe PATH` - override QQ.exe location
- `--kernel-util PATH` - override KernelUtil.dll location

### Step 2: Build the decryption tool

```bat
cd rekey
csc /platform:x86 /target:exe /reference:System.Web.Extensions.dll /out:PcqqOfflineRekey.exe PcqqOfflineRekey.cs
cd ..
```

Must be compiled as **32-bit (x86)** because PCQQ's KernelUtil.dll is 32-bit.

### Step 3: Decrypt databases

```bash
qq-backup-export decrypt \
  --input ./MsgBackup \
  --output-dir ./decrypted \
  --keys ./keys.json \
  --kernel-util "C:\Program Files (x86)\Tencent\QQ\Bin\KernelUtil.dll" \
  --rekey-tool ./rekey/PcqqOfflineRekey.exe
```

This produces standard SQLite `.sqlite` files that can be opened with any SQLite tool.

### Step 4: Parse messages

```bash
qq-backup-export parse \
  --database ./decrypted/messages.sqlite \
  --output ./messages.jsonl \
  --report ./parse_report.json \
  --self-uin 100000001 \
  --peer-uin 100000002
```

Parses the protobuf `extensionData` BLOBs into structured JSON with sender, receiver, text, quoted text, and content kind (text/media/system).

### Step 5: Analyze

Compute conversation metrics:

```bash
qq-backup-export metrics --input ./messages.jsonl --output ./metrics.json
```

Build chronological review chunks for full reading:

```bash
qq-backup-export chunks --input ./messages.jsonl --output-dir ./chunks --days-per-chunk 3
```

Inspect raw protobuf fields for debugging:

```bash
qq-backup-export inspect ./decrypted/messages.sqlite --self-uin 100000001 --peer-uin 100000002 --limit 20
```

## How It Works

### Key Capture

Uses [Frida](https://frida.re) to hook `sqlite3_key()` in PCQQ's `KernelUtil.dll`. The hook fires when QQ opens its own encrypted databases, capturing the 16-byte SQLCipher key. The hook is **read-only** - it reads the key parameter but never writes to or modifies any QQ database.

### Offline Decryption

The C# tool loads `KernelUtil.dll` (which bundles SQLCipher) via `LoadLibraryEx`, finds `sqlite3_open`/`sqlite3_key`/`sqlite3_exec`/`sqlite3_close` by byte-pattern signature, opens the encrypted database with the captured key, rekeys to empty (decrypts), then strips PCQQ's 1024-byte extended header.

### Protobuf Parsing

QQ stores message content as nested protobuf in the `extensionData` BLOB column. A dependency-free wire-format parser walks the fields without needing `.proto` files:

| Field path | Meaning |
|------------|---------|
| `1.1` | Sender UIN |
| `1.2` | Receiver UIN |
| `5.40800.45101` | Primary text content |
| `5.40800.47413` | Quoted (replied) text |
| `5.40800.45402` | Image/media filename |

## Privacy & Security

- **All processing is local.** No data is sent to any server.
- The key capture hook is **read-only** - it never modifies QQ databases.
- The `.gitignore` excludes all sensitive data: keys, databases, parsed messages, and analysis output.
- **Never commit** `keys.json`, `*.sqlite`, `*.jsonl`, or any file in `secrets/`, `input/`, `decrypted/`.

## Project Structure

```
qq-backup-export/
├── qq_backup_export/       # Python package
│   ├── cli.py              # Unified CLI
│   ├── capture_key.py      # Frida key capture (read-only)
│   ├── protobuf_wire.py    # Protobuf wire-format parser
│   ├── backup_parser.py    # QQ backup message parser
│   ├── metrics.py          # Relationship metrics
│   ├── review_chunks.py    # Chronological review chunk builder
│   └── inspect.py          # Raw protobuf inspector
├── rekey/                  # C# offline decryption tool
│   ├── PcqqOfflineRekey.cs
│   └── README.md           # Build instructions
├── tests/                  # Unit tests (14 tests, all passing)
├── docs/
│   └── architecture.md     # Pipeline architecture
├── examples/
│   └── sample_messages.jsonl
├── .gitignore
├── LICENSE                 # MIT
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Testing

```bash
python -m unittest discover -s tests -v
```

## License

MIT - see [LICENSE](LICENSE).

## Acknowledgments

- [Frida](https://frida.re) - dynamic instrumentation framework
- [qq-win-db-key](https://github.com/Withington/qq-win-db-key) - reference research for PCQQ/NTQQ key extraction
- [qq_msg_decode](https://github.com/ihmily/qq_msg_decode) - reference for QQ message protobuf structure
