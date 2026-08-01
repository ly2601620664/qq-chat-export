import sys
import unittest
from pathlib import Path


from qq_backup_export.metrics import compute_metrics


def item(timestamp: int, speaker: str, text: str = "x", kind: str = "text") -> dict:
    return {
        "timestamp": timestamp,
        "speaker": speaker,
        "text": text,
        "content_kind": kind,
        "placeholders": [] if kind == "text" else ["[图片/表情]"],
    }


class RelationshipMetricsTests(unittest.TestCase):
    def test_counts_messages_characters_and_media(self):
        result = compute_metrics(
            [
                item(1_700_000_000, "self", "你好"),
                item(1_700_000_001, "self", "呀"),
                item(1_700_000_010, "peer", "", "media"),
                item(1_700_000_020, "system", "系统"),
            ]
        )
        self.assertEqual(result["participants"]["self"]["messages"], 2)
        self.assertEqual(result["participants"]["self"]["text_characters"], 3)
        self.assertEqual(result["participants"]["peer"]["media_messages"], 1)
        self.assertEqual(result["system_messages"], 1)

    def test_groups_consecutive_messages_into_turns(self):
        result = compute_metrics(
            [
                item(1_700_000_000, "self"),
                item(1_700_000_002, "self"),
                item(1_700_000_010, "peer"),
                item(1_700_000_012, "peer"),
                item(1_700_000_020, "self"),
            ]
        )
        self.assertEqual(result["turns"]["total"], 3)
        self.assertEqual(result["turns"]["self"]["message_counts"], [2, 1])
        self.assertEqual(result["turns"]["peer"]["message_counts"], [2])

    def test_response_latency_uses_turn_switches(self):
        result = compute_metrics(
            [
                item(1_700_000_000, "self"),
                item(1_700_000_005, "self"),
                item(1_700_000_020, "peer"),
                item(1_700_000_050, "self"),
            ]
        )
        self.assertEqual(result["response_latency_seconds"]["peer"], [15])
        self.assertEqual(result["response_latency_seconds"]["self"], [30])

    def test_session_initiator_after_six_hour_gap(self):
        start = 1_700_000_000
        result = compute_metrics(
            [
                item(start, "self"),
                item(start + 10, "peer"),
                item(start + 6 * 3600 + 20, "peer"),
                item(start + 6 * 3600 + 30, "self"),
            ]
        )
        self.assertEqual(result["sessions"]["total"], 2)
        self.assertEqual(result["sessions"]["initiated_by"], {"self": 1, "peer": 1})


if __name__ == "__main__":
    unittest.main()
