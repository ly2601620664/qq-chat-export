import sys
import unittest
from pathlib import Path


from qq_backup_export.protobuf_wire import ParseError, iter_text_leaves, parse_message, read_varint


class ProtobufWireTests(unittest.TestCase):
    def test_read_varint(self):
        value, offset = read_varint(bytes.fromhex("9601"), 0)
        self.assertEqual(value, 150)
        self.assertEqual(offset, 2)

    def test_parse_scalar_wire_types(self):
        payload = bytes.fromhex(
            "089601"  # field 1, varint 150
            "110807060504030201"  # field 2, fixed64
            "1d04030201"  # field 3, fixed32
        )
        fields = parse_message(payload)
        self.assertEqual([field.number for field in fields], [1, 2, 3])
        self.assertEqual(fields[0].value, 150)
        self.assertEqual(fields[1].value, 0x0102030405060708)
        self.assertEqual(fields[2].value, 0x01020304)

    def test_parse_nested_message_and_text(self):
        payload = bytes.fromhex("0a050801120178")
        fields = parse_message(payload)
        self.assertEqual(fields[0].number, 1)
        self.assertEqual(len(fields[0].children), 2)
        leaves = list(iter_text_leaves(fields))
        self.assertEqual([(leaf.path, leaf.text) for leaf in leaves], [((1, 2), "x")])

    def test_preserves_offsets_and_raw_bytes(self):
        payload = bytes.fromhex("1203e4bda0")
        field = parse_message(payload)[0]
        self.assertEqual(field.start, 0)
        self.assertEqual(field.end, len(payload))
        self.assertEqual(field.raw, "你".encode("utf-8"))
        self.assertEqual(list(iter_text_leaves([field]))[0].text, "你")

    def test_rejects_truncated_length_delimited_field(self):
        with self.assertRaises(ParseError):
            parse_message(bytes.fromhex("0a05ff"))


if __name__ == "__main__":
    unittest.main()
