"""Parse a *source* ``AndroidManifest.xml`` (plain XML) into the same tree.

Two thirds of the manifests a developer wants audited are not compiled: they sit
in ``app/src/main/AndroidManifest.xml`` inside a checkout, and CI sees the source
tree long before it ever sees an APK.  Refusing to audit them would push the scan
to after the build, which is the wrong end of the pipeline.

``xml.etree`` is not used here for one reason: it throws line numbers away.
expat exposes ``CurrentLineNumber`` *and* ``CurrentByteIndex`` at every callback,
which is exactly the provenance the compiled path gets from
``ResXMLTree_node`` -- so both inputs produce findings that point at a byte.
"""

from __future__ import annotations

from xml.parsers import expat

from .axml import Attribute, AxmlError, Document, Element


class _Adapter:
    def __init__(self) -> None:
        self.root: Element | None = None
        self.stack: list[Element] = []
        self.count = 0

    def start(self, name: str, attrs: dict[str, str]) -> None:
        uri, local = _split(name)
        element = Element(
            name=local,
            namespace=uri,
            line=self.parser.CurrentLineNumber,
            offset=max(self.parser.CurrentByteIndex, 0),
        )
        self.count += 1
        for key, value in attrs.items():
            a_uri, a_local = _split(key)
            element.attributes.append(
                Attribute(
                    name=a_local,
                    namespace=a_uri,
                    value=value,
                    raw=value,
                    data_type=0x03,
                    res_id=0,
                    line=element.line,
                    offset=element.offset,
                )
            )
        if self.stack:
            self.stack[-1].children.append(element)
        else:
            self.root = element
        self.stack.append(element)

    def end(self, name: str) -> None:
        element = self.stack.pop()
        element.end_offset = max(self.parser.CurrentByteIndex, 0)


def _split(name: str) -> tuple[str, str]:
    if "|" in name:
        uri, local = name.split("|", 1)
        return uri, local
    return "", name


def parse(data: bytes) -> Document:
    """Parse plain XML text into a :class:`manifestvet.axml.Document`."""
    if not data.strip():
        raise AxmlError("empty manifest")
    adapter = _Adapter()
    parser = expat.ParserCreate(namespace_separator="|")
    parser.buffer_text = True
    adapter.parser = parser
    parser.StartElementHandler = adapter.start
    parser.EndElementHandler = adapter.end
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise AxmlError(f"malformed XML: {exc}") from exc
    if adapter.root is None:
        raise AxmlError("no root element")
    doc = Document(
        root=adapter.root,
        pool=None,
        resource_ids=[],
        size=len(data),
        shift=0,
    )
    doc.unresolved = []
    return doc


def is_text_manifest(data: bytes) -> bool:
    """True when the bytes look like XML text rather than a compiled chunk."""
    head = data.lstrip()[:64]
    return head.startswith(b"<") or head.lstrip(b"\xef\xbb\xbf").startswith(b"<")
