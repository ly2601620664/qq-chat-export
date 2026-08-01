from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Field:
    number: int
    wire_type: int
    value: int | bytes
    raw: bytes
    start: int
    end: int
    children: tuple["Field", ...] = ()


@dataclass(frozen=True)
class TextLeaf:
    path: tuple[int, ...]
    text: str
    raw: bytes


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise ParseError("truncated or oversized varint")


def parse_message(data: bytes, depth: int = 0, max_depth: int = 12) -> list[Field]:
    if depth > max_depth:
        raise ParseError("maximum nesting depth exceeded")
    fields: list[Field] = []
    offset = 0
    while offset < len(data):
        start = offset
        key, offset = read_varint(data, offset)
        number = key >> 3
        wire_type = key & 7
        if number <= 0:
            raise ParseError("invalid field number")

        if wire_type == 0:
            value, offset = read_varint(data, offset)
            raw = data[start:offset]
            children: tuple[Field, ...] = ()
        elif wire_type == 1:
            end = offset + 8
            if end > len(data):
                raise ParseError("truncated fixed64")
            value = int.from_bytes(data[offset:end], "little")
            offset = end
            raw = data[start:offset]
            children = ()
        elif wire_type == 2:
            length, offset = read_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise ParseError("truncated length-delimited field")
            value = data[offset:end]
            offset = end
            raw = value
            children = _try_parse_children(value, depth + 1, max_depth)
        elif wire_type == 5:
            end = offset + 4
            if end > len(data):
                raise ParseError("truncated fixed32")
            value = int.from_bytes(data[offset:end], "little")
            offset = end
            raw = data[start:offset]
            children = ()
        else:
            raise ParseError(f"unsupported wire type {wire_type}")

        fields.append(
            Field(
                number=number,
                wire_type=wire_type,
                value=value,
                raw=raw,
                start=start,
                end=offset,
                children=children,
            )
        )
    return fields


def _try_parse_children(data: bytes, depth: int, max_depth: int) -> tuple[Field, ...]:
    if not data or depth > max_depth:
        return ()
    try:
        children = parse_message(data, depth, max_depth)
    except ParseError:
        return ()
    return tuple(children)


def _decode_printable_utf8(data: bytes) -> str | None:
    if not data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    printable = sum(character.isprintable() for character in text)
    if printable / len(text) < 0.85:
        return None
    return text


def iter_text_leaves(
    fields: list[Field] | tuple[Field, ...],
    prefix: tuple[int, ...] = (),
) -> Iterator[TextLeaf]:
    for field in fields:
        path = prefix + (field.number,)
        if field.wire_type != 2:
            continue
        text = _decode_printable_utf8(field.raw)
        if text is not None:
            yield TextLeaf(path=path, text=text, raw=field.raw)
        elif field.children:
            yield from iter_text_leaves(field.children, path)
