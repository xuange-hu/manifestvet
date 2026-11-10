"""Reader for Android binary XML (AXML), the format aapt compiles
``AndroidManifest.xml`` into.

Everything here is stdlib + ``struct``.  The point of writing it by hand rather
than shelling out to ``aapt2 dump xmltree`` is *provenance*: every element keeps
the byte offset of its ``ResXMLTree_node`` and the source line aapt recorded, so
each finding can point back at the exact bytes that produced it.  A wrapper
around aapt can only ever say "the manifest contains X".

Layout references: ``frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h``.
Chunk types used by a manifest:

    0x0003 RES_XML_TYPE          file header
    0x0001 RES_STRING_POOL_TYPE  attribute/element names and string values
    0x0180 RES_XML_RESOURCE_MAP  parallel array: string index -> attr resource id
    0x0100 RES_XML_START_NAMESPACE_TYPE
    0x0101 RES_XML_END_NAMESPACE_TYPE
    0x0102 RES_XML_START_ELEMENT_TYPE
    0x0103 RES_XML_END_ELEMENT_TYPE
    0x0104 RES_XML_CDATA_TYPE

The awkward part: in a compiled manifest, ``android:exported`` is not stored as
the string "exported".  The attribute's name field is an index into the string
pool that usually points at the empty string, and the real name has to be
recovered through the resource map (a 32-bit ``android.R.attr`` id).  That is
why :mod:`manifestvet.attrnames` exists and why ``unresolved`` attrs are
surfaced in the report instead of being silently dropped -- a packer that strips
the resource map would otherwise turn every rule into a no-op.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

from .attrnames import ANDROID_NS, attr_name, detect_resource_map_shift

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

UTF8_FLAG = 0x0100
NO_INDEX = 0xFFFFFFFF

# Res_value.dataType
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")


class AxmlError(ValueError):
    """Raised when the bytes are not a well-formed AXML document."""


@dataclass(frozen=True)
class Attribute:
    """One compiled attribute.

    ``name`` is the resolved local name (``exported``) when the resource id maps
    into :data:`manifestvet.attrnames.ATTR_IDS`, otherwise ``0x01010010``-style
    hex so the caller can still see *something* stable.
    """

    name: str
    namespace: str
    value: object
    raw: str
    data_type: int
    res_id: int
    line: int
    offset: int

    @property
    def resolved(self) -> bool:
        """True when a usable local name came out, not a hex fallback.

        Framework attributes are keyed by resource id, so ``0x0101xxxx`` means
        the id was missing from the table.  Attributes in no namespace (``package``)
        and app-defined namespaces carry their own name and are always fine.
        """
        if self.namespace == ANDROID_NS:
            return bool(self.name) and not self.name.startswith("0x")
        return bool(self.name)

    def __str__(self) -> str:  # pragma: no cover - debug helper
        return f"{self.name}={self.value!r}@{self.offset:#x}"


@dataclass
class Element:
    """A ``ResXMLTree`` start-element node plus the children that follow it."""

    name: str
    namespace: str
    attributes: list[Attribute] = field(default_factory=list)
    children: list[Element] = field(default_factory=list)
    text: str = ""
    line: int = 0
    offset: int = 0
    end_offset: int = 0

    # -- attribute access -------------------------------------------------
    def get(self, name: str, default: object = None) -> object:
        """Raw value of ``android:<name>`` (or an un-namespaced attr)."""
        for attr in self.attributes:
            if attr.name == name:
                return attr.value
        return default

    def get_attr(self, name: str) -> Attribute | None:
        for attr in self.attributes:
            if attr.name == name:
                return attr
        return None

    def has(self, name: str) -> bool:
        return self.get_attr(name) is not None

    def bget(self, name: str) -> bool | None:
        """Boolean attribute: ``None`` when absent, else the coerced value."""
        value = self.get(name)
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        return str(value).lower() in {"true", "1"}

    def sget(self, name: str, default: str = "") -> str:
        """String attribute, with booleans/integers rendered the way XML would."""
        value = self.get(name)
        if value is None:
            return default
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    def find_all(self, name: str) -> list[Element]:
        return [c for c in self.children if c.name == name]

    def find(self, name: str) -> Element | None:
        for child in self.children:
            if child.name == name:
                return child
        return None

    def walk(self) -> Iterator[Element]:
        yield self
        for child in self.children:
            yield from child.walk()

    def android_attrs(self) -> dict[str, object]:
        return {a.name: a.value for a in self.attributes if a.namespace == ANDROID_NS}


def _u16(data: bytes, offset: int) -> int:
    return _U16.unpack_from(data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return _U32.unpack_from(data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def looks_like_axml(data: bytes) -> bool:
    """Cheap sniff: AXML files always start with the RES_XML_TYPE chunk header."""
    return len(data) >= 8 and _u16(data, 0) == RES_XML_TYPE


class StringPool:
    """``ResStringPool`` reader.  Handles both UTF-8 and UTF-16 pools.

    aapt emits UTF-8 for manifests, but ``RES_STRING_POOL`` payloads in
    ``resources.arsc`` are frequently UTF-16, and third-party packers mix them,
    so both paths are exercised (see ``tests/test_axml.py``).
    """

    def __init__(self, data: bytes, offset: int, size: int) -> None:
        if size < 28:
            raise AxmlError(f"string pool chunk too small at {offset:#x}")
        self.data = data
        string_count = _u32(data, offset + 8)
        self.flags = _u32(data, offset + 16)
        strings_start = _u32(data, offset + 20)
        self.utf8 = bool(self.flags & UTF8_FLAG)
        self.offsets = [_u32(data, offset + 28 + 4 * i) for i in range(string_count)]
        self._base = offset + strings_start
        self.strings: list[str] = [self._read(o) for o in self.offsets]

    def _read(self, rel: int) -> str:
        base = self._base + rel
        data = self.data
        try:
            if self.utf8:
                # Modified UTF-8: u16 utf16-length (high bit = long form),
                # then u8 byte-length (high bit = long form), then the bytes.
                char_len = _u16(data, base)
                base += 2
                if char_len & 0x8000:
                    char_len = ((char_len & 0x7FFF) << 16) | _u16(data, base)
                    base += 2
                byte_len = data[base]
                base += 1
                if byte_len & 0x80:
                    byte_len = ((byte_len & 0x7F) << 8) | data[base]
                    base += 1
                return data[base : base + byte_len].decode("utf-8", "replace")
            char_len = _u16(data, base)
            base += 2
            if char_len & 0x8000:
                char_len = ((char_len & 0x7FFF) << 16) | _u16(data, base)
                base += 2
            return data[base : base + 2 * char_len].decode("utf-16-le", "replace")
        except (IndexError, struct.error):  # truncated pool: keep going
            return ""

    def __len__(self) -> int:
        return len(self.strings)

    def get(self, index: int) -> str:
        if index == NO_INDEX or index < 0 or index >= len(self.strings):
            return ""
        return self.strings[index]


@dataclass
class Document:
    """Parsed manifest: element tree + provenance for the whole file."""

    root: Element
    pool: StringPool | None
    resource_ids: list[int]
    size: int
    shift: int
    unresolved: list[Attribute] = field(default_factory=list)

    def walk(self) -> Iterator[Element]:
        return self.root.walk()

    @property
    def element_count(self) -> int:
        return sum(1 for _ in self.walk())


def _decode_value(data: bytes, data_type: int, data_value: int, pool: StringPool) -> object:
    if data_type == TYPE_STRING:
        return pool.get(data_value)
    if data_type == TYPE_INT_BOOLEAN:
        return data_value != 0
    if data_type == TYPE_INT_DEC:
        # Res_value.data is an unsigned u32; TYPE_INT_DEC values are signed.
        return struct.unpack("<i", struct.pack("<I", data_value))[0]
    if data_type == TYPE_INT_HEX:
        return data_value
    if data_type == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", data_value))[0]
    if data_type == TYPE_REFERENCE:
        return "@null" if data_value == 0 else f"@0x{data_value:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{data_value:08x}"
    if data_type == TYPE_NULL:
        return None
    return data_value


def parse(data: bytes) -> Document:
    """Parse a compiled ``AndroidManifest.xml`` into a :class:`Document`."""
    if not looks_like_axml(data):
        raise AxmlError(
            "not a binary XML document (expected RES_XML_TYPE 0x0003); "
            "if this is a plain-text manifest, run aapt2/AAPT to compile it or "
            "use --text for source-tree manifests"
        )
    file_size = _u32(data, 4)
    header_size = _u16(data, 2)
    if file_size > len(data):
        # Truncated / spliced files: parse what is there rather than refusing.
        file_size = len(data)
    pos = header_size if header_size >= 8 else 8

    pool: StringPool | None = None
    resource_ids: list[int] = []
    root: Element | None = None
    stack: list[Element] = []
    shift = 1

    while pos + 8 <= file_size:
        chunk_type = _u16(data, pos)
        chunk_header = _u16(data, pos + 2)
        chunk_size = _u32(data, pos + 4)
        if chunk_size < 8 or pos + chunk_size > len(data):
            break  # corrupted tail; keep the tree we already have

        if chunk_type == RES_STRING_POOL_TYPE:
            pool = StringPool(data, pos, chunk_size)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            count = (chunk_size - chunk_header) // 4
            resource_ids = [_u32(data, pos + chunk_header + 4 * i) for i in range(count)]
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            if pool is None:
                raise AxmlError("start-element chunk before string pool")
            if not resource_ids:
                shift = 1
            elif resource_ids and not root:
                # Only needed once: the shift is a property of the file.
                shift = detect_resource_map_shift(pool.strings, resource_ids)
            root, element = _read_element(data, pos, pool, resource_ids, shift, stack, root)
            stack.append(element)
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop().end_offset = pos
        elif chunk_type == RES_XML_CDATA_TYPE and stack and chunk_size >= 16:
            text_index = _u32(data, pos + chunk_header + 4)
            stack[-1].text += pool.get(text_index) if pool else ""
        # Namespace chunks carry no information the rules need; skip them.
        pos += chunk_size

    if root is None:
        raise AxmlError("no start-element chunk found; file is empty or truncated")

    doc = Document(
        root=root,
        pool=pool,
        resource_ids=resource_ids,
        size=file_size,
        shift=shift,
    )
    doc.unresolved = [a for e in doc.walk() for a in e.attributes if not a.resolved]
    return doc


def _read_element(
    data: bytes,
    pos: int,
    pool: StringPool,
    resource_ids: list[int],
    shift: int,
    stack: list[Element],
    root: Element | None,
) -> tuple[Element, Element]:
    """Decode one RES_XML_START_ELEMENT_TYPE chunk and attach it to its parent."""
    line = _u32(data, pos + 8)
    # Layout: ResXMLTree_node { header, lineNumber, comment } is 16 bytes,
    # then ResXMLTree_attrExt { ns, name, attributeStart, attributeSize,
    # attributeCount, idIndex, classIndex, styleIndex } begins.
    body = pos + 16
    ns_index = _u32(data, body)
    name_index = _u32(data, body + 4)
    name = pool.get(name_index)
    namespace = pool.get(ns_index)

    attr_start = _u16(data, body + 8)
    attr_size = _u16(data, body + 10)
    attr_count = _u16(data, body + 12)
    if attr_size < 20:
        attr_size = 20  # some packers shrink it; the fields we read are fixed

    element = Element(name=name, namespace=namespace, line=line, offset=pos)
    attr_base = body + attr_start
    for i in range(attr_count):
        base = attr_base + i * attr_size
        if base + 20 > len(data):
            break
        a_ns = _u32(data, base)
        a_name = _u32(data, base + 4)
        a_raw = _u32(data, base + 8)
        a_type = data[base + 15]
        a_data = _u32(data, base + 16)
        attr_ns = pool.get(a_ns)
        local, res_id = _attribute_name(pool, resource_ids, shift, a_name, attr_ns)
        element.attributes.append(
            Attribute(
                name=local,
                namespace=attr_ns,
                value=_decode_value(b"", a_type, a_data, pool),
                raw=pool.get(a_raw) if a_raw != NO_INDEX else "",
                data_type=a_type,
                res_id=res_id,
                line=line,
                offset=base,
            )
        )

    if stack:
        stack[-1].children.append(element)
    return (root or element), element


def _attribute_name(
    pool: StringPool, resource_ids: list[int], shift: int, name_index: int, namespace: str
) -> tuple[str, int]:
    """Resolve an attribute's local name and (if any) its ``android.R.attr`` id.

    Two conventions exist in the wild for indexing the resource map; the offset
    is detected per file in :func:`parse`.  When the id is not in the table we
    keep the hex form so downstream rules can at least tell attributes apart.
    """
    res_id = 0
    if resource_ids:
        idx = name_index - shift
        if 0 <= idx < len(resource_ids):
            res_id = resource_ids[idx]
    if namespace == ANDROID_NS and res_id:
        return attr_name(res_id), res_id
    fallback = pool.get(name_index)
    if fallback:
        return fallback, res_id
    return (f"0x{res_id:08x}" if res_id else ""), res_id
