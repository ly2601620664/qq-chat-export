from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _dispatch(module: str, argv: list[str]) -> int:
    old = sys.argv
    sys.argv = [module] + argv
    try:
        if module == 'capture_key':
            from . import capture_key
            return capture_key.main()
        if module == 'backup_parser':
            from . import backup_parser
            return backup_parser.main()
        if module == 'metrics':
            from . import metrics
            return metrics.main()
        if module == 'review_chunks':
            from . import review_chunks
            return review_chunks.main()
        if module == 'inspect':
            from . import inspect
            return inspect.main()
    finally:
        sys.argv = old
    print(f'Unknown module: {module}', file=sys.stderr)
    return 2


def cmd_capture_key(args):
    argv = ['--output', str(args.output), '--timeout', str(args.timeout)]
    if args.no_launch:
        argv.append('--no-launch')
    if args.qq_exe:
        argv.extend(['--qq-exe', str(args.qq_exe)])
    if args.kernel_util:
        argv.extend(['--kernel-util', str(args.kernel_util)])
    return _dispatch('capture_key', argv)


def cmd_decrypt(args):
    rekey_exe = args.rekey_tool
    if not rekey_exe or not rekey_exe.is_file():
        print('Rekey tool not found. Build rekey/PcqqOfflineRekey.exe first.', file=sys.stderr)
        return 2
    input_dir = args.input
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    capture = json.loads(args.keys.read_text(encoding='utf-8'))
    key_entries = capture.get('captures', [])
    encrypted_files = {}
    for entry in key_entries:
        basename = Path(entry.get('database', '')).name
        if not basename:
            continue
        candidate = input_dir / basename
        if candidate.is_file():
            encrypted_files[basename] = candidate
    if not encrypted_files:
        print(f'No encrypted databases matching capture entries found in {input_dir}', file=sys.stderr)
        return 3
    exit_code = 0
    for basename, encrypted_path in sorted(encrypted_files.items()):
        db_key_path = next((e['database'] for e in key_entries if Path(e['database']).name == basename), None)
        if not db_key_path:
            print(f'Skipping {basename}: no key in capture JSON', file=sys.stderr)
            exit_code = max(exit_code, 3)
            continue
        rekey_copy = output_dir / (basename + '.rekey.tmp')
        standard_output = output_dir / (basename + '.sqlite')
        if standard_output.exists():
            print(f'Skipping {basename}: output already exists')
            continue
        cmd = [str(rekey_exe), str(encrypted_path), str(rekey_copy), str(standard_output), str(args.keys), db_key_path, str(args.kernel_util), str(output_dir)]
        print(f'Decrypting {basename} ...')
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr)
        if result.returncode != 0:
            print(f'Failed to decrypt {basename} (exit {result.returncode})', file=sys.stderr)
            exit_code = max(exit_code, result.returncode)
        else:
            if rekey_copy.exists():
                rekey_copy.unlink()
            print(f'  -> {standard_output}')
    return exit_code


def cmd_parse(args):
    argv = ['--database', str(args.database), '--output', str(args.output), '--report', str(args.report), '--self-uin', str(args.self_uin), '--peer-uin', str(args.peer_uin)]
    return _dispatch('backup_parser', argv)


def cmd_metrics(args):
    argv = ['--input', str(args.input), '--output', str(args.output)]
    return _dispatch('metrics', argv)


def cmd_chunks(args):
    argv = ['--input', str(args.input), '--output-dir', str(args.output_dir), '--days-per-chunk', str(args.days_per_chunk)]
    return _dispatch('review_chunks', argv)


def cmd_inspect(args):
    argv = [str(args.database), '--self-uin', str(args.self_uin), '--peer-uin', str(args.peer_uin), '--limit', str(args.limit), '--offset', str(args.offset)]
    if args.message_type is not None:
        argv.extend(['--message-type', str(args.message_type)])
    return _dispatch('inspect', argv)


def build_parser():
    parser = argparse.ArgumentParser(prog='qq-backup-export', description='QQ MsgBackup export toolkit: capture keys, decrypt, parse, and analyze.')
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('capture-key', help='Capture PCQQ SQLite keys via Frida (read-only).')
    p.add_argument('--output', type=Path, required=True, help='JSON file for captured keys.')
    p.add_argument('--timeout', type=int, default=180, help='Capture timeout in seconds.')
    p.add_argument('--no-launch', action='store_true', help='Attach to running PCQQ instead of launching.')
    p.add_argument('--qq-exe', type=Path, help='Path to QQ.exe (overrides PCQQ_EXE env).')
    p.add_argument('--kernel-util', type=Path, help='Path to KernelUtil.dll (overrides PCQQ_KERNEL_UTIL env).')
    p.set_defaults(func=cmd_capture_key)

    p = sub.add_parser('decrypt', help='Offline decrypt MsgBackup databases using captured keys.')
    p.add_argument('--input', type=Path, required=True, help='Directory containing encrypted MsgBackup files.')
    p.add_argument('--output-dir', type=Path, required=True, help='Directory for decrypted .sqlite files.')
    p.add_argument('--keys', type=Path, required=True, help='Capture JSON from capture-key step.')
    p.add_argument('--kernel-util', type=Path, required=True, help='Path to KernelUtil.dll from PCQQ install.')
    p.add_argument('--rekey-tool', type=Path, required=True, help='Path to PcqqOfflineRekey.exe.')
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser('parse', help='Parse decrypted messages to JSONL.')
    p.add_argument('--database', type=Path, required=True, help='Decrypted .sqlite file.')
    p.add_argument('--output', type=Path, required=True, help='Output .jsonl file.')
    p.add_argument('--report', type=Path, required=True, help='Output parse report .json file.')
    p.add_argument('--self-uin', type=int, required=True, help='Your QQ UIN.')
    p.add_argument('--peer-uin', type=int, required=True, help='Peer QQ UIN.')
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser('metrics', help='Compute relationship metrics from parsed messages.')
    p.add_argument('--input', type=Path, required=True, help='Parsed messages .jsonl file.')
    p.add_argument('--output', type=Path, required=True, help='Output metrics .json file.')
    p.set_defaults(func=cmd_metrics)

    p = sub.add_parser('chunks', help='Build chronological review chunks for full reading.')
    p.add_argument('--input', type=Path, required=True, help='Parsed messages .jsonl file.')
    p.add_argument('--output-dir', type=Path, required=True, help='Directory for chunk .txt files.')
    p.add_argument('--days-per-chunk', type=int, default=3, help='Days per chunk (default: 3).')
    p.set_defaults(func=cmd_chunks)

    p = sub.add_parser('inspect', help='Inspect raw protobuf fields in a decrypted database.')
    p.add_argument('database', type=Path, help='Decrypted .sqlite file.')
    p.add_argument('--self-uin', type=int, required=True)
    p.add_argument('--peer-uin', type=int, required=True)
    p.add_argument('--limit', type=int, default=12)
    p.add_argument('--offset', type=int, default=0)
    p.add_argument('--message-type', type=int)
    p.set_defaults(func=cmd_inspect)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
