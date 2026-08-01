from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from .protobuf_wire import Field, iter_text_leaves, parse_message


def iter_varints(fields: list[Field] | tuple[Field, ...], prefix: tuple[int, ...] = ()):
    for field in fields:
        path = prefix + (field.number,)
        if field.wire_type == 0:
            yield path, int(field.value)
        if field.children:
            yield from iter_varints(field.children, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('database', type=Path)
    parser.add_argument('--self-uin', type=int, required=True)
    parser.add_argument('--peer-uin', type=int, required=True)
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--message-type", type=int)
    args = parser.parse_args()

    uri = args.database.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'msg_3_%'"
        ).fetchone()[0]
        where = "WHERE msgType = ?" if args.message_type is not None else ""
        parameters = (
            (args.message_type, args.limit, args.offset)
            if args.message_type is not None
            else (args.limit, args.offset)
        )
        rows = connection.execute(
            f"SELECT _id,chatType,chatUin,msgType,msgTime,msgSeq,msgRandom,extensionData "
            f"FROM {table} {where} ORDER BY msgTime,msgSeq,msgRandom LIMIT ? OFFSET ?",
            parameters,
        )
        for row in rows:
            fields = parse_message(row[7])
            texts = [
                {"path": ".".join(map(str, leaf.path)), "text": leaf.text}
                for leaf in iter_text_leaves(fields)
                if len(leaf.text) <= 500
            ]
            uin_varints = [
                {"path": ".".join(map(str, path)), "value": value}
                for path, value in iter_varints(fields)
                if value in {0, args.self_uin, args.peer_uin}
            ]
            print(
                json.dumps(
                    {
                        "id": row[0],
                        "chat_type": row[1],
                        "chat_uin": row[2],
                        "message_type": row[3],
                        "timestamp": row[4],
                        "sequence": row[5],
                        "random": row[6],
                        "uin_varints": uin_varints,
                        "texts": texts,
                    },
                    ensure_ascii=False,
                )
            )
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
