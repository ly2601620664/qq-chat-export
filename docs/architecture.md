# Architecture

## Pipeline

```
MsgBackup/          capture-key        keys.json
(encrypted)    ──────────────────►   (16-byte keys)
                       │
                       ▼
                 decrypt (C#)         decrypted/*.sqlite
            ───────────────────►    (standard SQLite)
                       │
                       ▼
                   parse              messages.jsonl
            ───────────────────►    (protobuf -> JSON)
                       │
           ┌───────────┼───────────┐
           ▼           ▼           ▼
       metrics      chunks      inspect
       (.json)      (*.txt)     (debug)
```

## Components

### 1. Key Capture (capture_key.py)

Uses Frida to hook `sqlite3_key()` in PCQQ's KernelUtil.dll **read-only**.
The hook fires when QQ opens its own encrypted databases, capturing the
16-byte SQLCipher key.

### 2. Offline Decryption (PcqqOfflineRekey.cs)

A 32-bit C# tool that loads KernelUtil.dll to access SQLCipher functions.
Opens each encrypted database with the captured key, rekeys to empty
(decrypt), then strips PCQQ's 1024-byte extended header.

### 3. Protobuf Parser (protobuf_wire.py)

A minimal, dependency-free Protobuf wire-format parser. QQ stores message
content as nested protobuf in the `extensionData` BLOB column. Key paths:

- `1.1` = sender UIN
- `1.2` = receiver UIN
- `5.40800.45101` = primary text content
- `5.40800.47413` = quoted (replied) text
- `5.40800.45402` = image/media filename

### 4. Backup Parser (backup_parser.py)

Reads the decrypted SQLite database, iterates the `msg_3_<peerUin>` table,
and normalizes each row into JSON with timestamp, sender, receiver, text,
quoted text, content kind, and parse status.

### 5. Metrics (metrics.py)

Computes message/character/media counts, active days, turn structure,
response latency, and session initiators.

### 6. Review Chunks (review_chunks.py)

Groups messages into time-bounded chunks and renders them as readable text
with merged consecutive turns for full chronological reading.
