# PcqqOfflineRekey - Offline Database Decryption

## Overview

`PcqqOfflineRekey.cs` decrypts PCQQ MsgBackup databases **offline**
(without QQ running) using a key captured by `capture-key`.

PCQQ wraps each SQLite database with a 1024-byte extended header and
encrypts the content with SQLCipher (AES-256, 16-byte key). This tool:

1. Loads `KernelUtil.dll` from a PCQQ installation (contains SQLCipher).
2. Opens the encrypted database with the captured key.
3. Rekeys to an empty key (effectively decrypting).
4. Strips the 1024-byte PCQQ extended header.
5. Writes a standard SQLite database file.

## Build (command line)

```bat
cd rekey
csc /platform:x86 /target:exe ^
   /reference:System.Web.Extensions.dll ^
   /out:PcqqOfflineRekey.exe ^
   PcqqOfflineRekey.cs
```

Must be compiled as **32-bit (x86)** because KernelUtil.dll is 32-bit.

## Usage

```bat
PcqqOfflineRekey.exe <encrypted-input> <rekey-working-copy> <standard-output> <capture-json> <key-database-path> <KernelUtil.dll> <allowed-root>
```

Or use the Python CLI wrapper:

```bash
qq-backup-export decrypt --input ./MsgBackup --output-dir ./decrypted --keys ./keys.json --kernel-util KernelUtil.dll --rekey-tool ./rekey/PcqqOfflineRekey.exe
```
