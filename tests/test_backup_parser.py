import sys
import unittest
from pathlib import Path


from qq_backup_export.backup_parser import normalize_message


SELF = 100000001
PEER = 100000002


def varint(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def scalar(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def message(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def payload(sender: int, receiver: int, body: bytes) -> bytes:
    return message(1, scalar(1, sender) + scalar(2, receiver)) + message(5, body)


def row(blob: bytes) -> dict:
    return {
        "_id": 7,
        "chatType": 3,
        "chatUin": str(PEER),
        "msgType": 1,
        "msgTime": 1782063266,
        "msgSeq": 88,
        "msgRandom": 99,
        "extensionData": blob,
    }


class QQBackupParserTests(unittest.TestCase):
    def test_maps_self_sender_and_primary_text(self):
        body = message(40800, message(45101, "你好".encode()))
        parsed = normalize_message(row(payload(SELF, PEER, body)), SELF, PEER)
        self.assertEqual(parsed["speaker"], "self")
        self.assertEqual(parsed["receiver"], "peer")
        self.assertEqual(parsed["text"], "你好")

    def test_maps_peer_sender(self):
        body = message(40800, message(45101, "在吗".encode()))
        parsed = normalize_message(row(payload(PEER, SELF, body)), SELF, PEER)
        self.assertEqual(parsed["speaker"], "peer")
        self.assertEqual(parsed["text"], "在吗")

    def test_keeps_quoted_text_separate(self):
        quote = message(47413, "旧消息".encode())
        body = message(40800, quote + message(45101, "我的回复".encode()))
        parsed = normalize_message(row(payload(SELF, PEER, body)), SELF, PEER)
        self.assertEqual(parsed["text"], "我的回复")
        self.assertEqual(parsed["quoted_text"], ["旧消息"])

    def test_marks_media_without_counting_filename_as_text(self):
        image = message(45402, b"AABBCCDDEEFF0011.jpg")
        body = message(40800, image)
        parsed = normalize_message(row(payload(PEER, SELF, body)), SELF, PEER)
        self.assertEqual(parsed["text"], "")
        self.assertEqual(parsed["content_kind"], "media")
        self.assertIn("[图片/表情]", parsed["placeholders"])

    def test_retains_malformed_payload(self):
        parsed = normalize_message(row(bytes.fromhex("0a05ff")), SELF, PEER)
        self.assertEqual(parsed["parse_status"], "error")
        self.assertEqual(len(parsed["payload_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
