# AXML, from bytes up

A compiled `AndroidManifest.xml` is not XML. It is a chunked binary format
(`RES_XML_TYPE`, magic `0x0003`) produced by aapt/aapt2, and every tool that wants to
read it has to solve four problems. This note documents how this repo solves them and
what actually goes wrong, because the failure modes are silent: a misread attribute
name does not raise, it just makes a rule stop firing.

## 1. The chunk walk

```
offset 0 : u16 type=0x0003  u16 headerSize=8  u32 fileSize
then, back to back:
  0x0001 RES_STRING_POOL_TYPE
  0x0180 RES_XML_RESOURCE_MAP_TYPE
  0x0100 START_NAMESPACE
  0x0102 START_ELEMENT   (attributes live here)
  0x0103 END_ELEMENT
  0x0101 END_NAMESPACE
```

Every chunk starts with `{u16 type, u16 headerSize, u32 size}` and `size` includes the
8-byte header. Walking is `pos += size`, and the only defensive move that matters is
refusing to advance on `size < 8` or past the end of the buffer — truncated APKs are
common enough that `manifestvet` keeps the elements it has already read instead of
failing the whole file.

## 2. `ResXMLTree_attrExt` — the off-by-eight that eats every attribute

The element chunk is:

```
0x00  u16 type          0x02  u16 headerSize (16)
0x04  u32 size          0x08  u32 lineNumber
0x0C  u32 comment
0x10  u32 ns            <- ResXMLTree_attrExt starts here
0x14  u32 name
0x18  u16 attributeStart
0x1A  u16 attributeSize
0x1C  u16 attributeCount
0x1E  u16 idIndex  0x20 classIndex  0x22 styleIndex
0x24  attributes...
```

`attributeStart` is **relative to the start of `attrExt`** (offset `0x10`), not to the
start of the chunk. Read it from `0x10` and you get `ns`'s low half as the start offset
and `name`'s low half as the size — which yields `attributeCount = 0` on most files. The
symptom is spectacular: the tree parses, every element is there, and *no element has a
single attribute*. `tests/test_axml.py::test_root_and_children` would still pass; only a
test that asserts an attribute value catches it.

Each attribute is 20 bytes:

```
u32 ns   u32 name   u32 rawValue
u16 size(=8)  u8 res0  u8 dataType  u32 data
```

## 3. Attribute names are gone — the resource map is all that is left

`android:exported` is stored as:

- `name` = string-pool index that points at the **empty string** (aapt strips it),
- `ns` = index of `http://schemas.android.com/apk/res/android`,
- and the real identity comes from `RES_XML_RESOURCE_MAP`, a parallel array of 32-bit
  `android.R.attr` ids.

So `0x01010010` → `exported`, using a table. Those ids are public ABI — aapt2 will not
renumber them — which is why a table is the same answer every tool uses, and why
`attrnames.py` does not need to parse a 2 MB `resources.arsc`.

### The alignment problem

The resource map is indexed **relative to the string pool**, and two alignments exist:

| producer | pool[0] | map[i] belongs to |
|---|---|---|
| aapt2 (modern) | first attribute name | `strings[i]` (shift 0) |
| older aapt / some repackers | `""` | `strings[i+1]` (shift 1) |

Counting "ids the table knows" cannot distinguish them — the arrays are dense, so both
alignments score ~equal, and a wrong pick renames **every attribute to its neighbour**.
The discriminator that actually works is agreement between the two sources already in the
file: *the pool string at index `i` and the table name for `map[i-shift]` must be the same
word*. aapt2 gives ~24 agreements at shift 0 and ~0 at shift 1. That is
`detect_resource_map_shift`, and it is unit-tested against both layouts.

## 4. `Res_value`: four types, one of which is signed

```
TYPE_STRING    0x03  data = string index
TYPE_INT_DEC   0x10  data = signed int32 (stored unsigned)
TYPE_INT_BOOLEAN 0x12  data != 0
TYPE_REFERENCE 0x01  data = resource id, rendered as @0x7f0c0001
```

`debuggable="true"` arrives as `TYPE_INT_BOOLEAN` with `data = 0xFFFFFFFF`, not as the
string `"true"`. A reader that decodes everything as a string reports
`debuggable="4294967295"`, and every boolean rule silently inverts or dies. `bget()`
coerces both representations so a source-tree manifest (`"true"`) and a compiled one
(`0xFFFFFFFF`) behave identically — and `tests/test_axmlwrite.py` asserts the two paths
produce the same findings.

## What this buys you

The offsets are not decoration. `manifestvet attrs app.apk` prints each element and
attribute with its byte offset and resource id, so a finding can be checked against the
file rather than trusted:

```
0x00108c L20   <application>
           0x0010b0 theme='@0x7f0e0110'  id=0x01010000
           0x0010c4 label='@0x7f0d001e'  id=0x01010001
           0x0010d8 icon='@0x7f0c0000'  id=0x01010002
           0x0010ec name='com.pickword.ime.PickWordApp'  id=0x01010003
           0x001100 debuggable=True  id=0x0101000f
```

`--format sarif` maps those offsets back to the line aapt recorded, which is what GitHub
code scanning shows inline on the diff.

## References

- `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h` — the structs above.
- `ResStringPool` uses modified UTF-8: `u16` UTF-16 length (high bit = long form), then
  `u8` byte length (high bit = long form), then the bytes. A 3-character CJK string is 3
  UTF-16 units and 9 bytes; confusing the two truncates labels and authorities.
