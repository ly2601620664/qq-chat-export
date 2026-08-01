from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


PARTIES = ("self", "peer")


def _participant_metrics(messages: list[dict], speaker: str) -> dict:
    selected = [message for message in messages if message["speaker"] == speaker]
    return {
        "messages": len(selected),
        "text_messages": sum(bool(message.get("text")) for message in selected),
        "text_characters": sum(len(message.get("text", "")) for message in selected),
        "media_messages": sum(message.get("content_kind") == "media" for message in selected),
        "active_days": len(
            {
                datetime.fromtimestamp(message["timestamp"]).astimezone().date().isoformat()
                for message in selected
            }
        ),
    }


def _build_turns(messages: list[dict]) -> list[dict]:
    turns: list[dict] = []
    for message in messages:
        if not turns or turns[-1]["speaker"] != message["speaker"]:
            turns.append(
                {
                    "speaker": message["speaker"],
                    "start": message["timestamp"],
                    "end": message["timestamp"],
                    "message_count": 1,
                    "text_characters": len(message.get("text", "")),
                }
            )
        else:
            turn = turns[-1]
            turn["end"] = message["timestamp"]
            turn["message_count"] += 1
            turn["text_characters"] += len(message.get("text", ""))
    return turns


def _daily_metrics(messages: list[dict]) -> dict:
    days: dict[str, dict[str, Counter]] = defaultdict(
        lambda: {
            "messages": Counter(),
            "characters": Counter(),
            "media": Counter(),
        }
    )
    for message in messages:
        day = datetime.fromtimestamp(message["timestamp"]).astimezone().date().isoformat()
        speaker = message["speaker"]
        days[day]["messages"][speaker] += 1
        days[day]["characters"][speaker] += len(message.get("text", ""))
        days[day]["media"][speaker] += message.get("content_kind") == "media"
    return {
        day: {name: dict(counter) for name, counter in values.items()}
        for day, values in sorted(days.items())
    }


def _summary(values: list[int]) -> dict:
    if not values:
        return {"count": 0, "median": None, "mean": None, "p90": None}
    ordered = sorted(values)
    p90_index = min(len(ordered) - 1, int(0.9 * len(ordered)))
    return {
        "count": len(values),
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "p90": ordered[p90_index],
    }


def compute_metrics(messages: list[dict], session_gap_seconds: int = 6 * 3600) -> dict:
    ordered = sorted(messages, key=lambda item: item["timestamp"])
    interpersonal = [message for message in ordered if message["speaker"] in PARTIES]
    turns = _build_turns(interpersonal)

    latency = {speaker: [] for speaker in PARTIES}
    for previous, current in zip(turns, turns[1:]):
        latency[current["speaker"]].append(max(0, current["start"] - previous["end"]))

    initiators = Counter()
    sessions = 0
    previous_message = None
    for message in interpersonal:
        if previous_message is None or message["timestamp"] - previous_message["timestamp"] >= session_gap_seconds:
            sessions += 1
            initiators[message["speaker"]] += 1
        previous_message = message

    turn_details = {
        "total": len(turns),
        **{
            speaker: {
                "turns": sum(turn["speaker"] == speaker for turn in turns),
                "message_counts": [
                    turn["message_count"] for turn in turns if turn["speaker"] == speaker
                ],
                "max_consecutive_messages": max(
                    [turn["message_count"] for turn in turns if turn["speaker"] == speaker],
                    default=0,
                ),
            }
            for speaker in PARTIES
        },
    }
    return {
        "total_messages": len(ordered),
        "interpersonal_messages": len(interpersonal),
        "system_messages": sum(message["speaker"] == "system" for message in ordered),
        "unknown_speaker_messages": sum(
            message["speaker"] not in (*PARTIES, "system") for message in ordered
        ),
        "participants": {
            speaker: _participant_metrics(interpersonal, speaker) for speaker in PARTIES
        },
        "turns": turn_details,
        "response_latency_seconds": latency,
        "response_latency_summary": {
            speaker: _summary(values) for speaker, values in latency.items()
        },
        "sessions": {
            "gap_seconds": session_gap_seconds,
            "total": sessions,
            "initiated_by": {speaker: initiators[speaker] for speaker in PARTIES},
        },
        "daily": _daily_metrics(interpersonal),
    }


def load_jsonl(path: Path) -> list[dict]:
    messages: list[dict] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if line.strip():
                try:
                    messages.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid JSONL at line {line_number}: {error}") from error
    return messages


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute neutral QQ interaction metrics")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session-gap-hours", type=float, default=6.0)
    args = parser.parse_args()

    messages = load_jsonl(args.input)
    metrics = compute_metrics(messages, int(args.session_gap_hours * 3600))
    if messages:
        metrics["date_range"] = {
            "first": datetime.fromtimestamp(min(m["timestamp"] for m in messages))
            .astimezone()
            .isoformat(),
            "last": datetime.fromtimestamp(max(m["timestamp"] for m in messages))
            .astimezone()
            .isoformat(),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    summary = {
        "total_messages": metrics["total_messages"],
        "participants": metrics["participants"],
        "sessions": metrics["sessions"],
        "response_latency_summary": metrics["response_latency_summary"],
        "turns": {
            "total": metrics["turns"]["total"],
            "self": {
                "turns": metrics["turns"]["self"]["turns"],
                "max_consecutive_messages": metrics["turns"]["self"][
                    "max_consecutive_messages"
                ],
            },
            "peer": {
                "turns": metrics["turns"]["peer"]["turns"],
                "max_consecutive_messages": metrics["turns"]["peer"][
                    "max_consecutive_messages"
                ],
            },
        },
        "date_range": metrics.get("date_range"),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
