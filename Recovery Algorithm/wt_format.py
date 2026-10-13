"""
WiredTiger on-disk format primitives.

Role in the larger flow:
    Shared library for the recovery tool. Ports the parts of WiredTiger 11.x
    needed to walk a .wt file end to end: parse the page header, recursively
    walk the B-tree, decode every cell (including prefix-compressed keys and
    cells carrying a validity window), and decompress pages.

Source:
    intpack_inline.h       -- vunpack_uint
    cell.h, cell_inline.h  -- WT_CELL descriptor + __wt_cell_unpack_safe
    block/block_addr.c     -- addr cookie format
    btmem.h                -- WT_PAGE_HEADER + WT_BLOCK_HEADER (40B on disk)

Key subtleties (each one caused a bug in an earlier pass; verified against
the WiredTiger 11.x source):

* The vuint range 0xE0-0xEF stores the byte-count in the low nibble (count
  = b0 & 0x0F), not the value.
* Long-form KEY, KEY_PFX, and VALUE cells with no 64V and no SECOND_DESC
  encode (length - 64). Forgetting the +64 truncates every metadata value
  to about a third of its real length.
* The SECOND_DESC bit (0x08) on a cell descriptor means a second descriptor
  byte follows, which is a bitmask of which validity-window vuints come
  next; you must skip those before reading the length vuint.
* Row-leaf keys can be prefix-compressed (KEY_PFX or KEY_SHORT_PFX). The
  prefix byte counts how many bytes to copy from the previous key; the
  full key is prev_key[:prefix] + cell_data. Walkers must thread state.
* Addr cookies stored inside cells use `(offset/alloc) - 1` for the offset
  (-1 bias), `size/alloc` for the size, and a plain vuint for the checksum.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

import snappy

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALLOC_SIZE_DEFAULT = 4096

PAGE_TYPE_NAMES = {
    0: "INVALID", 1: "BLOCK_MANAGER", 2: "COL_FIX", 3: "COL_INT",
    4: "COL_VAR", 5: "OVFL", 6: "ROW_INT", 7: "ROW_LEAF",
}
PAGE_TYPE_ROW_INT = 6
PAGE_TYPE_ROW_LEAF = 7

PAGE_FLAG_COMPRESSED = 0x01
PAGE_FLAG_ENCRYPTED = 0x08

_HDR_FMT = "<QQIIBBBBII4s"
HDR_SIZE = struct.calcsize(_HDR_FMT)  # 40
assert HDR_SIZE == 40

# Cell descriptor bits (cell.h)
WT_CELL_KEY_SHORT = 1        # short = 0b01
WT_CELL_KEY_SHORT_PFX = 2    # short = 0b10
WT_CELL_VALUE_SHORT = 3      # short = 0b11
WT_CELL_SHORT_MASK = 0x03
WT_CELL_SHORT_SHIFT = 2
WT_CELL_SHORT_MAX = 63

WT_CELL_64V = 0x04
WT_CELL_SECOND_DESC = 0x08
WT_CELL_TYPE_MASK = 0xF0
WT_CELL_SIZE_ADJUST = 64    # +/- 64 on long-form KEY/KEY_PFX/plain VALUE

# Long-form cell types
WT_CELL_ADDR_DEL = 0x00
WT_CELL_ADDR_INT = 0x10
WT_CELL_ADDR_LEAF = 0x20
WT_CELL_ADDR_LEAF_NO = 0x30
WT_CELL_DEL = 0x40
WT_CELL_KEY = 0x50
WT_CELL_KEY_OVFL = 0x60
WT_CELL_KEY_PFX = 0x70
WT_CELL_VALUE = 0x80
WT_CELL_VALUE_COPY = 0x90
WT_CELL_VALUE_OVFL = 0xA0
WT_CELL_VALUE_OVFL_RM = 0xB0
WT_CELL_KEY_OVFL_RM = 0xC0
WT_CELL_ADDR_DEL_VISIBLE_ALL = 0xD0

# Secondary descriptor flag bits (cell.h)
WT_CELL_PREPARE = 0x01
WT_CELL_TS_DURABLE_START = 0x02
WT_CELL_TS_DURABLE_STOP = 0x04
WT_CELL_TS_START = 0x08
WT_CELL_TS_STOP = 0x10
WT_CELL_TXN_START = 0x20
WT_CELL_TXN_STOP = 0x40


# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------
@dataclass
class PageHeader:
    offset: int
    recno: int
    write_gen: int
    mem_size: int
    entries: int
    type: int
    flags: int
    version: int
    disk_size: int
    checksum: int

    @property
    def type_name(self) -> str:
        return PAGE_TYPE_NAMES.get(self.type, f"0x{self.type:02x}")

    @property
    def compressed(self) -> bool:
        return bool(self.flags & PAGE_FLAG_COMPRESSED)


def parse_page_header(buf: bytes, offset: int) -> PageHeader:
    rec, wgen, mem, ent, ptype, pflg, _u, ver, dsize, csum, _b = struct.unpack_from(
        _HDR_FMT, buf, offset
    )
    return PageHeader(offset, rec, wgen, mem, ent, ptype, pflg, ver, dsize, csum)


def header_looks_valid(h: PageHeader, file_size: int, alloc: int) -> bool:
    if h.type == 0 or h.type > 11:
        return False
    if h.disk_size == 0 or h.disk_size % alloc != 0:
        return False
    if h.offset + h.disk_size > file_size:
        return False
    if h.entries > 1_000_000:
        return False
    return True


# ---------------------------------------------------------------------------
# Variable-length integer (positive only)
# ---------------------------------------------------------------------------
POS_1BYTE_MAX = 0x3F                      # 63
POS_2BYTE_MAX = (1 << 13) + POS_1BYTE_MAX # 8255


def vunpack_uint(buf: bytes, pos: int) -> tuple[int, int]:
    """Return (value, next_pos). Raises ValueError on a non-positive marker."""
    b0 = buf[pos]
    if 0x80 <= b0 <= 0xBF:                              # 1-byte
        return (b0 & 0x3F), pos + 1
    if 0xC0 <= b0 <= 0xDF:                              # 2-byte
        return (((b0 & 0x1F) << 8) | buf[pos + 1]) + (POS_1BYTE_MAX + 1), pos + 2
    if 0xE0 <= b0 <= 0xEF:                              # multi (1..15 bytes)
        n = b0 & 0x0F
        val = int.from_bytes(buf[pos + 1 : pos + 1 + n], "big")
        return val + (POS_2BYTE_MAX + 1), pos + 1 + n
    raise ValueError(f"non-positive vuint marker 0x{b0:02x} at pos {pos}")


# ---------------------------------------------------------------------------
# Addr cookie inside a cell
# ---------------------------------------------------------------------------
@dataclass
class AddrCookie:
    offset: int
    size: int
    checksum: int


def unpack_addr_cookie(buf: bytes, alloc: int) -> AddrCookie:
    o, p = vunpack_uint(buf, 0)
    s, p = vunpack_uint(buf, p)
    c, _ = vunpack_uint(buf, p)
    if o == 0 and s == 0 and c == 0:
        raise ValueError("zero addr cookie (no address)")
    return AddrCookie(offset=(o + 1) * alloc, size=s * alloc, checksum=c)


# ---------------------------------------------------------------------------
# Cell unpacker -- proper port of __wt_cell_unpack_safe
# ---------------------------------------------------------------------------
@dataclass
class Cell:
    """Output of unpack_cell.

    `raw` is the cell's storage form (KEY_SHORT / KEY_PFX / VALUE / ADDR_LEAF / ...).
    `kind` is the high-level kind ("KEY", "VALUE", "ADDR", "DEL"). The
    walker uses `kind` to pair keys with values on a leaf page.
    """
    raw: int
    kind: str
    data: bytes | None
    prefix: int               # for KEY cells; 0 if no prefix compression
    next_pos: int


_VALIDITY_FIELDS = (
    WT_CELL_TS_START, WT_CELL_TXN_START, WT_CELL_TS_DURABLE_START,
    WT_CELL_TS_STOP, WT_CELL_TXN_STOP, WT_CELL_TS_DURABLE_STOP,
)


def _skip_validity_window(buf: bytes, pos: int, flags: int) -> int:
    """Skip the variable-length validity window encoded after the secondary
    descriptor byte. Each enabled flag bit consumes one vuint."""
    for bit in _VALIDITY_FIELDS:
        if flags & bit:
            _v, pos = vunpack_uint(buf, pos)
    return pos


_KEY_RAWS = (WT_CELL_KEY, WT_CELL_KEY_PFX, WT_CELL_KEY_OVFL, WT_CELL_KEY_OVFL_RM)
_VALUE_RAWS = (
    WT_CELL_VALUE, WT_CELL_VALUE_COPY, WT_CELL_VALUE_OVFL, WT_CELL_VALUE_OVFL_RM
)
_ADDR_RAWS = (
    WT_CELL_ADDR_DEL, WT_CELL_ADDR_DEL_VISIBLE_ALL,
    WT_CELL_ADDR_INT, WT_CELL_ADDR_LEAF, WT_CELL_ADDR_LEAF_NO,
)


def _kind(raw: int) -> str:
    if raw in (WT_CELL_KEY_SHORT, WT_CELL_KEY_SHORT_PFX) or raw in _KEY_RAWS:
        return "KEY"
    if raw == WT_CELL_VALUE_SHORT or raw in _VALUE_RAWS:
        return "VALUE"
    if raw in _ADDR_RAWS:
        return "ADDR"
    if raw == WT_CELL_DEL:
        return "DEL"
    return "?"


def unpack_cell(buf: bytes, pos: int) -> Cell:
    """Decode a single WT_CELL at `buf[pos:]`. Mirrors __wt_cell_unpack_safe."""
    if pos >= len(buf):
        return Cell(raw=-1, kind="?", data=None, prefix=0, next_pos=pos)
    desc = buf[pos]
    short = desc & WT_CELL_SHORT_MASK

    # --- short forms ---------------------------------------------------------
    if short == WT_CELL_KEY_SHORT:
        ln = desc >> WT_CELL_SHORT_SHIFT
        return Cell(WT_CELL_KEY_SHORT, "KEY",
                    buf[pos + 1 : pos + 1 + ln], 0, pos + 1 + ln)
    if short == WT_CELL_KEY_SHORT_PFX:
        ln = desc >> WT_CELL_SHORT_SHIFT
        prefix = buf[pos + 1]
        return Cell(WT_CELL_KEY_SHORT_PFX, "KEY",
                    buf[pos + 2 : pos + 2 + ln], prefix, pos + 2 + ln)
    if short == WT_CELL_VALUE_SHORT:
        ln = desc >> WT_CELL_SHORT_SHIFT
        return Cell(WT_CELL_VALUE_SHORT, "VALUE",
                    buf[pos + 1 : pos + 1 + ln], 0, pos + 1 + ln)

    # --- long form -----------------------------------------------------------
    raw = desc & WT_CELL_TYPE_MASK
    p = pos + 1
    prefix = 0

    # KEY_PFX in long form: 1 prefix byte immediately after the descriptor.
    if raw == WT_CELL_KEY_PFX:
        prefix = buf[p]
        p += 1

    # SECOND_DESC: secondary descriptor byte + variable window of vuints.
    has_validity = bool(desc & WT_CELL_SECOND_DESC)
    if has_validity:
        try:
            flags = buf[p]
            p += 1
            p = _skip_validity_window(buf, p, flags)
        except (IndexError, ValueError):
            return Cell(raw, _kind(raw), None, prefix, pos + 1)

    # ADDR_DEL with fast-truncate info: txnid + 2 timestamps (or prepare info).
    # We don't need this metadata for recovery -- just skip it.
    if raw == WT_CELL_ADDR_DEL:
        try:
            for _ in range(3):  # txnid + start_ts + durable_ts
                _v, p = vunpack_uint(buf, p)
        except (IndexError, ValueError):
            return Cell(raw, _kind(raw), None, prefix, pos + 1)

    # 64V (RLE / record number) prepended to length.
    if desc & WT_CELL_64V:
        try:
            _v64, p = vunpack_uint(buf, p)
        except (IndexError, ValueError):
            return Cell(raw, _kind(raw), None, prefix, pos + 1)

    # WT_CELL_DEL: no length, no data.
    if raw == WT_CELL_DEL:
        return Cell(raw, "DEL", None, 0, p)

    # WT_CELL_VALUE_COPY: an offset vuint (back-reference), no data.
    if raw == WT_CELL_VALUE_COPY:
        try:
            _off, p = vunpack_uint(buf, p)
        except (IndexError, ValueError):
            return Cell(raw, "VALUE", None, 0, pos + 1)
        return Cell(raw, "VALUE", None, 0, p)

    # Everything else has [length-vuint][data].
    try:
        length, p = vunpack_uint(buf, p)
    except (IndexError, ValueError):
        return Cell(raw, _kind(raw), None, prefix, pos + 1)

    # SIZE_ADJUST applies to long-form KEY, KEY_PFX, and VALUE with no
    # 64V and no SECOND_DESC. NOT to ADDR_*, NOT to overflow cells.
    if raw == WT_CELL_KEY or raw == WT_CELL_KEY_PFX:
        length += WT_CELL_SIZE_ADJUST
    elif raw == WT_CELL_VALUE and not (desc & WT_CELL_64V) and not has_validity:
        length += WT_CELL_SIZE_ADJUST

    if length > len(buf) - p:
        return Cell(raw, _kind(raw), None, prefix, pos + 1)
    return Cell(raw, _kind(raw), bytes(buf[p : p + length]), prefix, p + length)


# ---------------------------------------------------------------------------
# Cell walker that threads state (previous key for prefix decompression)
# ---------------------------------------------------------------------------
@dataclass
class KVEntry:
    """One key+value pair (or key+addr pair on an internal page) reconstructed
    from a page payload."""
    key: bytes                          # fully decompressed
    value: bytes | None                 # None if the cell was missing/del
    value_raw: int = 0                  # raw cell type of the value cell
    addr: AddrCookie | None = None      # for internal pages
    is_overflow: bool = False


def walk_kv_page(payload: bytes, page_type: int, alloc: int = ALLOC_SIZE_DEFAULT
                 ) -> Iterator[KVEntry]:
    """Walk a ROW_LEAF or ROW_INT page payload, yielding KVEntry per pair.

    For a ROW_LEAF the entries are (key, value); value may be absent if the
    cell sequence has two KEY cells in a row.
    For a ROW_INT the entries are (key, addr_cookie).
    Tracks the previous key so KEY_PFX / KEY_SHORT_PFX cells can be
    decompressed.
    """
    pos = 0
    n = len(payload)
    prev_key = b""
    while pos < n:
        kc = unpack_cell(payload, pos)
        if kc.next_pos <= pos or kc.kind != "KEY":
            return
        pos = kc.next_pos
        key_bytes = kc.data or b""
        key = prev_key[: kc.prefix] + key_bytes if kc.prefix else key_bytes
        prev_key = key
        key_overflow = kc.raw in (WT_CELL_KEY_OVFL, WT_CELL_KEY_OVFL_RM)
        if pos >= n:
            yield KVEntry(key=key, value=None, is_overflow=key_overflow)
            return
        # Peek next cell: if it's also a KEY, this entry has no value.
        peek_desc = payload[pos]
        peek_short = peek_desc & WT_CELL_SHORT_MASK
        peek_is_key = (
            peek_short in (WT_CELL_KEY_SHORT, WT_CELL_KEY_SHORT_PFX)
            or (peek_short == 0 and (peek_desc & WT_CELL_TYPE_MASK) in _KEY_RAWS)
        )
        if peek_is_key:
            yield KVEntry(key=key, value=None, is_overflow=key_overflow)
            continue
        vc = unpack_cell(payload, pos)
        if vc.next_pos <= pos:
            yield KVEntry(key=key, value=None, is_overflow=key_overflow)
            return
        pos = vc.next_pos
        addr = None
        if vc.kind == "ADDR" and vc.data is not None:
            try:
                addr = unpack_addr_cookie(vc.data, alloc)
            except (ValueError, IndexError):
                addr = None
        yield KVEntry(
            key=key,
            value=vc.data if vc.kind == "VALUE" else None,
            value_raw=vc.raw,
            addr=addr,
            is_overflow=key_overflow or vc.raw in (
                WT_CELL_VALUE_OVFL, WT_CELL_VALUE_OVFL_RM),
        )


# ---------------------------------------------------------------------------
# Page decompression
# ---------------------------------------------------------------------------
# WT compresses with WT_BLOCK_COMPRESS_SKIP = 64. On a compressed page:
#   bytes 0..39       : WT_PAGE_HEADER + WT_BLOCK_HEADER
#   bytes 40..63      : 24 bytes of cell data, stored RAW (this is the
#                       "skip" region; WT compresses for alignment reasons
#                       starting at offset 64)
#   bytes 64..71      : LE u64 holding the *compressed* snappy stream length
#                       (NOT the uncompressed length, despite what some
#                       earlier WT docs suggest -- ext/compressors/snappy
#                       stores `snaplen` here)
#   bytes 72..72+snaplen : snappy stream (decompresses to mem_size - 64 bytes)
#
# Final payload (cells start at byte 40 logically) =
#   raw[40..63]  ++  snappy.decompress(raw[72..72+snaplen])
#
# If COMPRESSED flag is not set, payload is just bytes 40..disk_size.
WT_BLOCK_COMPRESS_SKIP = 64
WT_SNAPPY_PREFIX = 8


def page_payload(file_bytes: bytes, h: PageHeader) -> bytes:
    raw = file_bytes[h.offset + HDR_SIZE : h.offset + h.disk_size]
    if not h.compressed:
        return raw
    pre = file_bytes[h.offset + HDR_SIZE : h.offset + WT_BLOCK_COMPRESS_SKIP]
    skip_off = WT_BLOCK_COMPRESS_SKIP - HDR_SIZE
    rest = raw[skip_off:]
    if len(rest) < WT_SNAPPY_PREFIX:
        return raw
    snaplen = struct.unpack_from("<Q", rest, 0)[0]
    if snaplen == 0 or snaplen > len(rest) - WT_SNAPPY_PREFIX:
        return raw
    try:
        decompressed = snappy.decompress(
            rest[WT_SNAPPY_PREFIX : WT_SNAPPY_PREFIX + snaplen]
        )
    except Exception:
        return raw
    return pre + decompressed


# ---------------------------------------------------------------------------
# B-tree walk + linear scan
# ---------------------------------------------------------------------------
def extract_normal_pages(
    file_bytes: bytes,
    root_offset: int,
    alloc: int,
    visited: set[int] | None = None,
) -> list[PageHeader]:
    """Recursive walk from `root_offset` via the real addr cookies in internal
    pages. Returns all reachable ROW_LEAF headers."""
    if visited is None:
        visited = set()
    if root_offset in visited:
        return []
    visited.add(root_offset)
    if root_offset + HDR_SIZE > len(file_bytes):
        return []
    h = parse_page_header(file_bytes, root_offset)
    if not header_looks_valid(h, len(file_bytes), alloc):
        return []
    if h.type == PAGE_TYPE_ROW_LEAF:
        return [h]
    if h.type != PAGE_TYPE_ROW_INT:
        return []
    payload = page_payload(file_bytes, h)
    leaves: list[PageHeader] = []
    for entry in walk_kv_page(payload, h.type, alloc):
        if entry.addr is None:
            continue
        if 0 < entry.addr.offset < len(file_bytes):
            leaves.extend(
                extract_normal_pages(file_bytes, entry.addr.offset, alloc, visited)
            )
    return leaves


def scan_all_pages(file_bytes: bytes, alloc: int) -> list[PageHeader]:
    """Linear scan after the 0x1000 block descriptor; same loop as the paper's
    ExtractDelPage but returns every valid page regardless of type."""
    out: list[PageHeader] = []
    off = alloc
    end = len(file_bytes)
    while off + HDR_SIZE <= end:
        h = parse_page_header(file_bytes, off)
        if header_looks_valid(h, end, alloc):
            out.append(h)
            off += h.disk_size
        else:
            off += 0x10
    return out


def extract_orphan_leaves(
    file_bytes: bytes,
    live_leaves: list[PageHeader],
    alloc: int,
) -> list[PageHeader]:
    """ROW_LEAF pages found by linear scan that are NOT reachable from the
    B-tree root -- these are the candidate carriers of deleted/superseded data."""
    live = {p.offset for p in live_leaves}
    return [p for p in scan_all_pages(file_bytes, alloc)
            if p.type == PAGE_TYPE_ROW_LEAF and p.offset not in live]


# ---------------------------------------------------------------------------
# Raw dump: print EVERYTHING physically in the file, page by page, cell by cell
# ---------------------------------------------------------------------------
def dump_all_pages(
    file_bytes: bytes,
    alloc: int = ALLOC_SIZE_DEFAULT,
    max_value: int = 200,
) -> None:
    """Print every page from the linear scan and every cell on each page.

    A plain, physical dump of what is on disk -- no B-tree walk, no live/orphan
    classification. Just scan the whole file and print what each page holds.
    """
    pages = scan_all_pages(file_bytes, alloc)
    print(f"== {len(file_bytes)} bytes | alloc={alloc} | {len(pages)} pages ==")
    for i, h in enumerate(pages):
        comp = " compressed" if h.compressed else ""
        if h.type not in (PAGE_TYPE_ROW_LEAF, PAGE_TYPE_ROW_INT):
            continue
        print(
            f"\n[{i}] off=0x{h.offset:x} type={h.type_name} size={h.disk_size} "
            f"write_gen={h.write_gen} entries={h.entries}{comp}"
        )
        # if h.type not in (PAGE_TYPE_ROW_LEAF, PAGE_TYPE_ROW_INT):
        #     continue
        payload = page_payload(file_bytes, h)
        for j, e in enumerate(walk_kv_page(payload, h.type, alloc)):
            if h.type == PAGE_TYPE_ROW_INT:
                child = f"0x{e.addr.offset:x}" if e.addr else "?"
                print(f"    cell[{j}] key={e.key[:32]!r} -> child {child}")
                continue
            if e.value is None:
                print(f"    cell[{j}] key={e.key[:32]!r} (no value)")
                continue
            if e.is_overflow:
                print(f"    cell[{j}] key={e.key[:32]!r} OVERFLOW {len(e.value)}B")
                continue
            try:
                import bson
                doc = bson.decode_all(e.value)[0]
            except Exception:
                doc = None
            if doc is not None:
                print(f"    cell[{j}] {repr(doc)[:max_value]}")
            else:
                print(
                    f"    cell[{j}] key={e.key[:32]!r} value={len(e.value)}B "
                    f"{e.value[:32].hex()}"
                )

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python wt_format.py <file.wt> [alloc]")
        raise SystemExit(2)
    _alloc = int(sys.argv[2]) if len(sys.argv) > 2 else ALLOC_SIZE_DEFAULT
    with open(sys.argv[1], "rb") as _f:
        _data = _f.read()
    dump_all_pages(_data, _alloc)
