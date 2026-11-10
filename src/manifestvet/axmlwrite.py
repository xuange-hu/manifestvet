"""Compile a plain-text manifest into AXML.

Needed for two things, both of which keep the repo free of binary fixtures:

* ``manifestvet demo`` generates a genuinely compiled manifest at runtime, so the
  demo exercises the exact code path a real APK takes;
* the tests can round-trip: text -> AXML -> parse, and assert the tree, the
  attribute names (through the resource map) and the byte offsets survive.

It also lets the tests cover the UTF-16 string pool and both resource-map
alignments, which no real APK on hand happens to use.
"""

from __future__ import annotations

import struct

from . import srctext
from .attrnames import ANDROID_NS, ATTR_IDS
from .axml import Element

_NAME_TO_ID = {name: res_id for res_id, name in ATTR_IDS.items()}

CHUNK_XML = 0x0003
CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_NS = 0x0100
CHUNK_END_NS = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103

UTF8_FLAG = 0x0100
NO_INDEX = 0xFFFFFFFF


class _Pool:
    def __init__(self, utf16: bool) -> None:
        self.utf16 = utf16
        self.strings: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value is None:
            value = ""
        existing = self._index.get(value)
        if existing is not None:
            return existing
        self._index[value] = len(self.strings)
        self.strings.append(value)
        return self._index[value]

    def encode(self) -> bytes:
        blobs = bytearray()
        offsets: list[int] = []
        for text in self.strings:
            offsets.append(len(blobs))
            if self.utf16:
                raw = text.encode("utf-16-le")
                blobs += struct.pack("<H", len(raw) // 2) + raw + b"\x00\x00"
            else:
                raw = text.encode("utf-8")
                blobs += struct.pack("<H", len(text.encode("utf-16-le")) // 2)
                blobs += struct.pack("<B", len(raw)) + raw + b"\x00"
        while len(blobs) % 4:
            blobs += b"\x00"
        header_size = 28
        strings_start = header_size + 4 * len(self.strings)
        size = strings_start + len(blobs)
        out = bytearray()
        out += struct.pack("<HHIIIIII", CHUNK_STRING_POOL, header_size, size, len(self.strings), 0,
                           0 if self.utf16 else UTF8_FLAG, strings_start, 0)
        for offset in offsets:
            out += struct.pack("<I", offset)
        out += blobs
        return bytes(out)


def _element_chunk(pool: _Pool, element: Element, resource_ids: list[int]) -> bytes:
    name_index = pool.add(element.name)
    ns_index = pool.add(element.namespace) if element.namespace else NO_INDEX
    attr_bytes = bytearray()
    count = 0
    for attribute in element.attributes:
        res_id = _NAME_TO_ID.get(attribute.name, 0) if attribute.namespace == ANDROID_NS else 0
        if res_id:
            # The writer keeps the pool aligned the aapt2 way (string index ==
            # resource-map index), so zero-padding the tail is enough.
            while len(resource_ids) < pool.add(attribute.name) + 1:
                resource_ids.append(0)
            resource_ids[pool.add(attribute.name)] = res_id
            a_name = pool.add(attribute.name)
        else:
            a_name = pool.add(attribute.name)
        a_ns = pool.add(attribute.namespace) if attribute.namespace else NO_INDEX
        value = attribute.value
        if isinstance(value, bool):
            data_type, data = 0x12, (0xFFFFFFFF if value else 0)
            raw = pool.add("true" if value else "false")
        elif isinstance(value, int):
            data_type, data = 0x10, value & 0xFFFFFFFF
            raw = pool.add(str(value))
        elif isinstance(value, str) and value.startswith("@0x"):
            data_type, data = 0x01, int(value[3:], 16)
            raw = pool.add(value)
        elif isinstance(value, str) and value.lower() in {"true", "false"}:
            # aapt types attributes from the resource table, so a boolean arrives
            # as TYPE_INT_BOOLEAN, not as the string "true". The writer has no
            # res table, so it infers -- and the reader must be tested against
            # the typed form, which is what a real manifest contains.
            data_type, data = 0x12, (0xFFFFFFFF if value.lower() == "true" else 0)
            raw = pool.add(value)
        elif isinstance(value, str) and value.lstrip("-").isdigit():
            data_type, data = 0x10, int(value) & 0xFFFFFFFF
            raw = pool.add(value)
        else:
            data_type, data = 0x03, pool.add(str(value))
            raw = pool.add(str(value))
        attr_bytes += struct.pack("<IIIHBBI", a_ns, a_name, raw, 8, 0, data_type, data)
        count += 1
    size = 36 + 20 * count
    out = bytearray()
    out += struct.pack("<HHIIIII", CHUNK_START_ELEMENT, 16, size, element.line, NO_INDEX, ns_index, name_index)
    out += struct.pack("<HHHHHH", 20, 20, count, 0, 0, 0)
    out += attr_bytes
    return bytes(out)


def _end_chunk(pool: _Pool, element: Element) -> bytes:
    name_index = pool.add(element.name)
    ns_index = pool.add(element.namespace) if element.namespace else NO_INDEX
    return struct.pack("<HHIIIII", CHUNK_END_ELEMENT, 16, 24, element.line, NO_INDEX, ns_index, name_index)


def _namespace_chunk(pool: _Pool, kind: int, prefix: str, uri: str) -> bytes:
    return struct.pack(
        "<HHIIIII", kind, 16, 24, 0, NO_INDEX, pool.add(prefix), pool.add(uri)
    )


def compile_text(xml_text: str, *, utf16: bool = False) -> bytes:
    """Compile XML text to AXML bytes.

    ``utf16`` selects the string-pool encoding; aapt uses UTF-8, other packers do
    not, and the reader has to handle both.
    """
    doc = srctext.parse(xml_text.encode("utf-8"))
    if doc.root is None:  # pragma: no cover - srctext raises first
        raise ValueError("no root element")

    pool = _Pool(utf16)
    # Reserve the attributes' string slots first so the resource map stays dense;
    # this mirrors aapt's layout and keeps the shift at 0.
    resource_ids: list[int] = []
    body = bytearray()
    body += _namespace_chunk(pool, CHUNK_START_NS, "android", ANDROID_NS)

    def emit(element: Element) -> None:
        nonlocal body
        body += _element_chunk(pool, element, resource_ids)
        for child in element.children:
            emit(child)
        body += _end_chunk(pool, element)

    emit(doc.root)
    body += _namespace_chunk(pool, CHUNK_END_NS, "android", ANDROID_NS)

    string_pool = pool.encode()
    if resource_ids:
        while resource_ids and resource_ids[-1] == 0:
            resource_ids.pop()
        res_map = struct.pack("<HHI", CHUNK_RESOURCE_MAP, 8, 8 + 4 * len(resource_ids))
        res_map += b"".join(struct.pack("<I", rid) for rid in resource_ids)
    else:
        res_map = b""

    total = 8 + len(string_pool) + len(res_map) + len(body)
    return struct.pack("<HHI", CHUNK_XML, 8, total) + string_pool + res_map + bytes(body)
