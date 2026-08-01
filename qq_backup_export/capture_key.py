from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import frida
import psutil


OLD_QQ = Path(os.environ.get("PCQQ_EXE", r"C:\Program Files (x86)\Tencent\QQ\Bin\QQ.exe"))
KERNEL_UTIL = Path(os.environ.get("PCQQ_KERNEL_UTIL", r"C:\Program Files (x86)\Tencent\QQ\Bin\KernelUtil.dll"))

HOOK_SOURCE = r"""
'use strict';

const state = { installed: false, loaderHooks: [] };

function report(event, fields) {
    fields.event = event;
    fields.pid = Process.id;
    send(fields);
}

function findSingle(module, pattern, label) {
    const hits = Memory.scanSync(module.base, module.size, pattern);
    if (hits.length !== 1) {
        report('diagnostic', {
            label: label,
            message: 'pattern match count is ' + hits.length,
            pattern: pattern
        });
        return null;
    }
    return hits[0].address;
}

function bytesToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let output = '';
    for (let i = 0; i < bytes.length; i++) {
        output += bytes[i].toString(16).padStart(2, '0');
    }
    return output;
}

function installKeyHook() {
    if (state.installed) {
        return true;
    }

    const module = Process.findModuleByName('KernelUtil.dll');
    if (module === null) {
        return false;
    }

    const keyAddress = findSingle(
        module,
        '55 8b ec 56 6b 75 10 11 83 7d 10 10 74 0d 68 17 02 00 00 e8',
        'sqlite3_key'
    );
    const nameAddress = findSingle(
        module,
        '55 8b ec ff 75 0c ff 75 08 e8 ba d1 02 00 59 59 85',
        'sqlite3_db_filename'
    );
    if (keyAddress === null || nameAddress === null) {
        return false;
    }

    const dbFilename = new NativeFunction(nameAddress, 'pointer', ['pointer', 'pointer']);
    Interceptor.attach(keyAddress, {
        onEnter(args) {
            try {
                const keyLength = args[2].toInt32();
                if (keyLength <= 0 || keyLength > 512) {
                    report('diagnostic', {
                        label: 'sqlite3_key',
                        message: 'ignored implausible key length ' + keyLength
                    });
                    return;
                }

                let database = '<unknown>';
                try {
                    const namePointer = dbFilename(args[0], ptr(0));
                    if (!namePointer.isNull()) {
                        database = namePointer.readUtf8String();
                    }
                } catch (error) {
                    database = '<name read failed: ' + error.message + '>';
                }

                report('key', {
                    database: database,
                    key_length: keyLength,
                    key_hex: bytesToHex(args[1].readByteArray(keyLength))
                });
            } catch (error) {
                report('diagnostic', {
                    label: 'sqlite3_key',
                    message: error.stack || error.message
                });
            }
        }
    });

    state.installed = true;
    report('hook-installed', {
        module_path: module.path,
        key_offset: keyAddress.sub(module.base).toString(),
        name_offset: nameAddress.sub(module.base).toString()
    });
    return true;
}

function hookLoader(name) {
    const address = Module.findExportByName('kernel32.dll', name);
    if (address === null) {
        return;
    }
    state.loaderHooks.push(Interceptor.attach(address, {
        onLeave() {
            setImmediate(installKeyHook);
        }
    }));
}

if (!installKeyHook()) {
    hookLoader('LoadLibraryA');
    hookLoader('LoadLibraryW');
    hookLoader('LoadLibraryExA');
    hookLoader('LoadLibraryExW');
    report('waiting', { message: 'waiting for KernelUtil.dll' });
}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture PCQQ SQLite keys without modifying QQ databases."
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="JSON file written locally with captured keys.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Maximum capture time in seconds (default: 180).",
    )
    parser.add_argument(
        "--no-launch",
        action="store_true",
        help="Attach to existing old PCQQ processes instead of launching QQ.",
    )
    parser.add_argument(
        "--qq-exe",
        type=Path,
        default=None,
        help="Path to QQ.exe (overrides PCQQ_EXE env var).",
    )
    parser.add_argument(
        "--kernel-util",
        type=Path,
        default=None,
        help="Path to KernelUtil.dll (overrides PCQQ_KERNEL_UTIL env var).",
    )
    return parser.parse_args()


def normalized_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(value)))


def main() -> int:
    args = parse_args()
    qq_exe = args.qq_exe or OLD_QQ\n    kernel_util = args.kernel_util or KERNEL_UTIL\n    if not qq_exe.is_file() or not kernel_util.is_file():
        print("Old PCQQ 9.x installation was not found.", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    expected_qq = normalized_path(qq_exe)
    captured: list[dict[str, object]] = []
    captured_ids: set[tuple[int, str, str]] = set()
    attached: dict[int, frida.core.Session] = {}
    scripts: dict[int, frida.core.Script] = {}
    lock = threading.RLock()
    stop_event = threading.Event()
    device = frida.get_local_device()

    def persist() -> None:
        payload = {
            "format": "pcqq-sqlite-key-capture-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "qq_executable": str(OLD_QQ),
            "kernel_util_sha256": hashlib.sha256(KERNEL_UTIL.read_bytes()).hexdigest(),
            "captures": captured,
        }
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8"
        )
        os.replace(temporary, args.output)

    def on_message(pid: int, message: dict[str, object], data: object) -> None:
        if message.get("type") == "error":
            print(f"PID {pid}: hook error: {message.get('stack')}", file=sys.stderr)
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        event = str(payload.get("event", "unknown"))
        if event == "key":
            key_hex = str(payload.get("key_hex", ""))
            database = str(payload.get("database", "<unknown>"))
            identifier = (pid, database.casefold(), key_hex)
            with lock:
                if identifier in captured_ids:
                    return
                captured_ids.add(identifier)
                captured.append(
                    {
                        "captured_at": datetime.now(timezone.utc).isoformat(),
                        "pid": pid,
                        "database": database,
                        "key_length": int(payload.get("key_length", 0)),
                        "key_hex": key_hex,
                        "key_sha256": hashlib.sha256(bytes.fromhex(key_hex)).hexdigest(),
                    }
                )
                persist()
            print(
                f"Captured key for {database} "
                f"(length={payload.get('key_length')}, fingerprint={captured[-1]['key_sha256'][:12]})."
            )
        elif event == "hook-installed":
            print(
                f"PID {pid}: key hook installed at {payload.get('key_offset')} "
                f"in {payload.get('module_path')}."
            )
        elif event == "diagnostic":
            print(
                f"PID {pid}: {payload.get('label')}: {payload.get('message')}",
                file=sys.stderr,
            )

    def is_old_qq(pid: int) -> bool:
        try:
            return normalized_path(psutil.Process(pid).exe()) == expected_qq
        except (psutil.Error, OSError):
            return False

    def attach(pid: int, enable_child_gating: bool = True) -> bool:
        with lock:
            if pid in attached or not is_old_qq(pid):
                return False
        try:
            session = device.attach(pid)
            if enable_child_gating:
                try:
                    session.enable_child_gating()
                except frida.Error as error:
                    print(f"PID {pid}: child gating unavailable: {error}")
            script = session.create_script(HOOK_SOURCE)
            script.on("message", lambda message, data, current=pid: on_message(current, message, data))
            script.load()
            with lock:
                attached[pid] = session
                scripts[pid] = script
            print(f"Attached read-only key hook to old PCQQ PID {pid}.")
            return True
        except frida.Error as error:
            print(f"PID {pid}: attach failed: {error}", file=sys.stderr)
            return False

    def on_child_added(child: object) -> None:
        pid = int(getattr(child, "pid"))
        try:
            attach(pid)
        finally:
            try:
                device.resume(pid)
            except frida.Error:
                pass

    device.on("child-added", on_child_added)

    if args.no_launch:
        found = False
        for process in psutil.process_iter(["pid", "exe"]):
            if process.info.get("exe") and normalized_path(process.info["exe"]) == expected_qq:
                found = attach(int(process.info["pid"])) or found
        if not found:
            print("No running old PCQQ process was found.", file=sys.stderr)
            return 3
    else:
        pid = device.spawn([str(qq_exe)])
        if not attach(pid):
            device.resume(pid)
            return 4
        device.resume(pid)
        print(f"Launched old PCQQ PID {pid}; complete login if the window asks for it.")

    deadline = time.monotonic() + args.timeout
    try:
        while time.monotonic() < deadline and not stop_event.wait(0.1):
            for process in psutil.process_iter(["pid", "exe"]):
                executable = process.info.get("exe")
                if executable and normalized_path(executable) == expected_qq:
                    attach(int(process.info["pid"]), enable_child_gating=False)
    except KeyboardInterrupt:
        print("Capture stopped by user.")
    finally:
        for session in list(attached.values()):
            try:
                session.detach()
            except frida.Error:
                pass

    print(f"Capture finished with {len(captured)} unique key event(s).")
    return 0 if captured else 5


if __name__ == "__main__":
    raise SystemExit(main())
