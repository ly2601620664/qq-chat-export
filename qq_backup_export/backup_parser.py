from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path

from .protobuf_wire import Field, ParseError, iter_text_leaves, parse_message


PRIMARY_TEXT_PATH = (5, 40800, 45101)
MEDIA_FIELDS = {45402, 45424, 45503, 45600, 45802, 45803, 45804}
SYSTEM_FIELDS = {48214, 48271, 48274}
METADATA_FIELDS = {29, 40020, 40021, 40093, 40095, 49154}


def _field_paths(fields, prefix=()):
    for field in fields:
        path = prefix + (field.number,)
        yield path, field
        if field.children:
            yield from _field_paths(field.children, path)


def _envelope_uins(fields: list[Field]) -> tuple[int | None, int | None]:
    header = next((field for field in fields if field.number == 1 and field.children), None)
    if header is None:
        return None, None
    sender = next(
        (int(field.value) for field in header.children if field.number == 1 and field.wire_type == 0),
        None,
    )
    receiver = next(
        (int(field.value) for field in header.children if field.number == 2 and field.wire_type == 0),
        None,
    )
    return sender, receiver


def _party(uin: int | None, self_uin: int, peer_uin: int) -> str:
    if uin == self_uin:
        return "self"
    if uin == peer_uin:
        return "peer"
    if uin == 0:
        return "system"
    return "unknown"


def _looks_like_metadata(text: str, path: tuple[int, ...]) -> bool:
    stripped = text.strip()
    if not stripped or path[-1] in METADATA_FIELDS:
        return True
    lowered = stripped.lower()
    if lowered.startswith("u_") or lowered == "nt_1":
        return True
    if "http://" in lowered or "https://" in lowered or "/download?" in lowered:
        return True
    if "fileid=" in lowered or "rkey=" in lowered or "multimedia.nt.qq.com.cn" in lowered:
        return True
    if re.fullmatch(r"[0-9a-fA-F]{16,64}(?:\.[a-zA-Z0-9]{2,5})?", stripped):
        return True
    if len(stripped) >= 48 and re.fullmatch(r"[A-Za-z0-9_\-]+", stripped):
        return True
    return False


def _extract_json_text(value: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    found: list[str] = []

    def visit(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key in {"txt", "text", "title", "summary"} and isinstance(child, str):
                    found.append(child)
                else:
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(parsed)
    return found


def _deduplicate(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        value = value.strip()
        if value and value not in result:
            result.append(value)
    return result


def normalize_message(row, self_uin: int, peer_uin: int) -> dict:
    blob = bytes(row["extensionData"])
    base = {
        "id": row["_id"],
        "chat_type": row["chatType"],
        "chat_uin": row["chatUin"],
        "message_type": row["msgType"],
        "timestamp": row["msgTime"],
        "time_iso": datetime.fromtimestamp(row["msgTime"]).astimezone().isoformat(),
        "sequence": row["msgSeq"],
        "random": row["msgRandom"],
        "payload_sha256": hashlib.sha256(blob).hexdigest(),
    }
    try:
        fields = parse_message(blob)
    except ParseError as error:
        return base | {
            "sender_uin": None,
            "receiver_uin": None,
            "speaker": "unknown",
            "receiver": "unknown",
            "text": "",
            "quoted_text": [],
            "placeholders": ["[未解析消息]"],
            "content_kind": "unknown",
            "parse_status": "error",
            "parse_error": str(error),
        }

    sender, receiver = _envelope_uins(fields)
    leaves = list(iter_text_leaves(fields))
    primary = _deduplicate([leaf.text for leaf in leaves if leaf.path == PRIMARY_TEXT_PATH])
    quoted = _deduplicate(
        [
            leaf.text
            for leaf in leaves
            if leaf.path == (5, 40800, 47413)
            or leaf.path[-2:] == (47423, 45101)
            or leaf.path[-3:] == (40900, 40800, 45101)
        ]
    )
    all_paths = [path for path, _ in _field_paths(fields)]
    is_media = any(MEDIA_FIELDS.intersection(path) for path in all_paths)
    is_system = sender == 0 or any(SYSTEM_FIELDS.intersection(path) for path in all_paths)
    fallback: list[str] = []
    if not primary and not is_media:
        for leaf in leaves:
            if _looks_like_metadata(leaf.text, leaf.path) or leaf.text in quoted:
                continue
            fallback.extend(_extract_json_text(leaf.text) or [leaf.text])
    text_parts = primary or _deduplicate(fallback)
    placeholders = ["[图片/表情]"] if is_media else []
    kind = "text" if text_parts else "media" if is_media else "system" if is_system else "unknown"
    return base | {
        "sender_uin": sender,
        "receiver_uin": receiver,
        "speaker": _party(sender, self_uin, peer_uin),
        "receiver": _party(receiver, self_uin, peer_uin),
        "text": "\n".join(text_parts),
        "quoted_text": quoted,
        "placeholders": placeholders,
        "content_kind": kind,
        "text_source": "primary" if primary else "fallback" if text_parts else "none",
        "parse_status": "ok" if text_parts or placeholders or is_system else "partial",
        "parse_error": None,
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_database(
    database: Path,
    output: Path,
    report_path: Path,
    self_uin: int,
    peer_uin: int,
) -> dict:
    uri = database.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    counters = {
        "speaker": Counter(),
        "content_kind": Counter(),
        "parse_status": Counter(),
        "text_source": Counter(),
    }
    total = 0
    text_characters = 0
    first_timestamp = None
    last_timestamp = None
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'msg_3_%'"
            )
        ]
        if len(tables) != 1 or not re.fullmatch(r"msg_3_\d+", tables[0]):
            raise ValueError(f"expected one message table, found {tables}")
        table = tables[0]
        query = (
            f"SELECT _id,chatType,chatUin,msgType,msgTime,msgSeq,msgRandom,extensionData "
            f"FROM {table} ORDER BY msgTime,msgSeq,msgRandom"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="\n") as destination:
            for row in connection.execute(query):
                parsed = normalize_message(row, self_uin, peer_uin)
                destination.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                total += 1
                text_characters += len(parsed["text"])
                first_timestamp = parsed["timestamp"] if first_timestamp is None else first_timestamp
                last_timestamp = parsed["timestamp"]
                for key in counters:
                    counters[key][parsed.get(key, "none")] += 1
    finally:
        connection.close()

    report = {
        "database": str(database.resolve()),
        "database_sha256": _file_sha256(database),
        "quick_check": quick_check,
        "table": table,
        "source_rows": total,
        "output_rows": total,
        "self_uin": self_uin,
        "peer_uin": peer_uin,
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "first_time_iso": datetime.fromtimestamp(first_timestamp).astimezone().isoformat(),
        "last_time_iso": datetime.fromtimestamp(last_timestamp).astimezone().isoformat(),
        "text_characters": text_characters,
        "counts": {key: dict(value) for key, value in counters.items()},
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only parser for PCQQ MsgBackup messages")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--self-uin", type=int, required=True)
    parser.add_argument("--peer-uin", type=int, required=True)
    args = parser.parse_args()
    report = parse_database(
        args.database,
        args.output,
        args.report,
        args.self_uin,
        args.peer_uin,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
