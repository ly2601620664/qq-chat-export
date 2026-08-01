from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


SPEAKER_LABELS = {"self": "我", "peer": "对方", "system": "系统", "unknown": "未知"}


def load_messages(path: Path) -> list[dict]:
    messages = []
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            if line.strip():
                messages.append(json.loads(line))
    return sorted(messages, key=lambda item: (item["timestamp"], item["sequence"], item["random"]))


def message_content(message: dict) -> str:
    text = message.get("text", "").strip().replace("\r", " ").replace("\n", " ↵ ")
    placeholders = " ".join(message.get("placeholders", []))
    quoted = [value.strip().replace("\n", " ↵ ") for value in message.get("quoted_text", []) if value.strip()]
    pieces = []
    if quoted:
        pieces.append("↩引用「" + "／".join(quoted[:2]) + "」")
    if text:
        pieces.append(text)
    if placeholders:
        pieces.append(placeholders)
    if not pieces:
        pieces.append("[未解析消息]")
    return " ".join(pieces)


def build_turns(messages: list[dict], maximum_same_speaker_gap: int = 300) -> list[dict]:
    turns: list[dict] = []
    for message in messages:
        if (
            not turns
            or turns[-1]["speaker"] != message["speaker"]
            or message["timestamp"] - turns[-1]["end"] > maximum_same_speaker_gap
        ):
            turns.append(
                {
                    "speaker": message["speaker"],
                    "start": message["timestamp"],
                    "end": message["timestamp"],
                    "contents": [message_content(message)],
                    "message_count": 1,
                }
            )
        else:
            turns[-1]["end"] = message["timestamp"]
            turns[-1]["contents"].append(message_content(message))
            turns[-1]["message_count"] += 1
    return turns


def render_turn(turn: dict) -> str:
    start = datetime.fromtimestamp(turn["start"]).astimezone()
    end = datetime.fromtimestamp(turn["end"]).astimezone()
    time_label = start.strftime("%m-%d %H:%M:%S")
    if end != start:
        time_label += "–" + end.strftime("%H:%M:%S")
    speaker = SPEAKER_LABELS.get(turn["speaker"], turn["speaker"])
    count = f" ×{turn['message_count']}" if turn["message_count"] > 1 else ""
    return f"[{time_label}]{count} {speaker}：" + " ｜ ".join(turn["contents"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Build complete chronological review chunks")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--days-per-chunk", type=int, default=3)
    args = parser.parse_args()

    messages = load_messages(args.input)
    first_day = datetime.fromtimestamp(messages[0]["timestamp"]).astimezone().date()
    grouped: dict[int, list[dict]] = defaultdict(list)
    for message in messages:
        day = datetime.fromtimestamp(message["timestamp"]).astimezone().date()
        grouped[(day - first_day).days // args.days_per_chunk].append(message)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"source_messages": len(messages), "represented_messages": 0, "chunks": []}
    for output_number, chunk_index in enumerate(sorted(grouped), 1):
        chunk_messages = grouped[chunk_index]
        turns = build_turns(chunk_messages)
        represented = sum(turn["message_count"] for turn in turns)
        manifest["represented_messages"] += represented
        first = datetime.fromtimestamp(chunk_messages[0]["timestamp"]).astimezone()
        last = datetime.fromtimestamp(chunk_messages[-1]["timestamp"]).astimezone()
        path = args.output_dir / f"chunk_{output_number:02d}.txt"
        header = (
            f"# 完整阅读分段 {output_number:02d}\n"
            f"# 范围：{first.isoformat()} 至 {last.isoformat()}\n"
            f"# 原始消息：{len(chunk_messages)}；合并发言轮次：{len(turns)}\n\n"
        )
        path.write_text(header + "\n".join(render_turn(turn) for turn in turns), encoding="utf-8")
        manifest["chunks"].append(
            {
                "file": path.name,
                "first": first.isoformat(),
                "last": last.isoformat(),
                "messages": len(chunk_messages),
                "turns": len(turns),
                "characters": path.stat().st_size,
            }
        )

    if manifest["represented_messages"] != manifest["source_messages"]:
        raise RuntimeError("review chunks do not represent every source message")
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
