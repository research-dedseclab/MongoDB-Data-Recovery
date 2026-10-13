"""
WiredTiger.turtle parser.

The turtle file is a small text file (k/v pairs, one per line in pairs) that
WiredTiger writes at every clean shutdown. The entry we care about is
`file:WiredTiger.wt`, whose value is a config string that contains a
`checkpoint=(NAME=(addr="HEX", ...))` clause. That hex blob is the
checkpoint cookie for the metadata table itself.

Cookie layout (from __wt_block_ckpt_pack in src/block/block_ckpt.c):

    byte 0           : WT_BM_CHECKPOINT_VERSION  (currently 1)
    + 4x addr triple : root, alloc, avail, discard
                       each = vuint(offset/alloc - 1)  // -1 bias, see below
                            + vuint(size/alloc)
                            + vuint(checksum)
                       The all-zero triple (0,0,0) is the "no address" sentinel.
    + vuint          : file_size
    + vuint          : ckpt_size

We only need `root` (and the file's allocation_size, which we read from the
same config string).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import wt_format as wt


@dataclass
class CheckpointAddr:
    """One unpacked addr triple from a checkpoint cookie."""
    offset: int      # absolute file offset, 0 if "no address"
    size: int        # bytes
    checksum: int

    @property
    def is_none(self) -> bool:
        return self.offset == 0 and self.size == 0


@dataclass
class CheckpointCookie:
    version: int
    root: CheckpointAddr
    alloc: CheckpointAddr
    avail: CheckpointAddr
    discard: CheckpointAddr
    file_size: int
    ckpt_size: int


def _unpack_addr(buf: bytes, pos: int, alloc: int) -> tuple[CheckpointAddr, int]:
    """Unpack one (offset, size, checksum) triple from a checkpoint cookie.

    Per __wt_block_ckpt_unpack: each addr is three vuints. The (0,0,0)
    triple means 'no address'. Otherwise:
        real_offset = (raw_offset + 1) * alloc_size
        real_size   = raw_size * alloc_size
    """
    o, pos = wt.vunpack_uint(buf, pos)
    s, pos = wt.vunpack_uint(buf, pos)
    c, pos = wt.vunpack_uint(buf, pos)
    if (o, s, c) == (0, 0, 0):
        return CheckpointAddr(0, 0, 0), pos
    return CheckpointAddr(offset=(o + 1) * alloc, size=s * alloc, checksum=c), pos


def unpack_checkpoint_cookie(cookie: bytes, alloc: int) -> CheckpointCookie:
    if not cookie:
        raise ValueError("empty checkpoint cookie")
    version = cookie[0]
    pos = 1
    root, pos = _unpack_addr(cookie, pos, alloc)
    a, pos = _unpack_addr(cookie, pos, alloc)
    av, pos = _unpack_addr(cookie, pos, alloc)
    d, pos = _unpack_addr(cookie, pos, alloc)
    fs, pos = wt.vunpack_uint(cookie, pos)
    cs, pos = wt.vunpack_uint(cookie, pos)
    return CheckpointCookie(version, root, a, av, d, fs, cs)


# ---------------------------------------------------------------------------
# Turtle file parsing
# ---------------------------------------------------------------------------
# Turtle layout: pairs of lines, key then value.
#   file:WiredTiger.wt
#   access_pattern_hint=none,allocation_size=4KB,...,checkpoint=(...)
TURTLE_KEY = "file:WiredTiger.wt"


def parse_turtle(turtle_path: Path) -> dict[str, str]:
    """Return the {key: value} pairs from a turtle file."""
    lines = turtle_path.read_text().splitlines()
    out: dict[str, str] = {}
    i = 0
    while i + 1 < len(lines):
        key = lines[i].strip()
        value = lines[i + 1].strip()
        if key and not key.startswith(("WiredTiger ", "major=", "minor=")):
            out[key] = value
        i += 2
    return out


# ---------------------------------------------------------------------------
# Config string parsing (k=v, possibly nested in parens)
# ---------------------------------------------------------------------------
# WT config strings look like: key=value,key=(sub=val,...),... and we need
# specific sub-paths (e.g. `allocation_size`, `block_compressor`,
# `checkpoint=(NAME=(addr="...",...))`). Implementing a tiny recursive
# parser rather than dragging in a real config grammar.
def _parse_config(s: str) -> dict:
    """Parse a WT config string into a nested dict. Values are str."""
    out: dict[str, str | dict] = {}
    i = 0
    n = len(s)
    while i < n:
        # key
        k_start = i
        while i < n and s[i] not in "=,":
            i += 1
        key = s[k_start:i].strip()
        if not key:
            i += 1
            continue
        if i < n and s[i] == "=":
            i += 1
            # value: either (nested), "quoted", or bare-until-comma
            if i < n and s[i] == "(":
                depth = 1
                v_start = i + 1
                i += 1
                while i < n and depth:
                    if s[i] == "(":
                        depth += 1
                    elif s[i] == ")":
                        depth -= 1
                    if depth:
                        i += 1
                value = s[v_start:i]
                i += 1  # past ')'
                out[key] = _parse_config(value)
            elif i < n and s[i] == '"':
                i += 1
                v_start = i
                while i < n and s[i] != '"':
                    i += 1
                out[key] = s[v_start:i]
                if i < n:
                    i += 1
            else:
                v_start = i
                while i < n and s[i] != ",":
                    i += 1
                out[key] = s[v_start:i].strip()
        else:
            out[key] = ""
        # consume comma
        if i < n and s[i] == ",":
            i += 1
    return out


def parse_alloc_size(value: str | dict) -> int:
    """Parse a `allocation_size=4KB`-style value into bytes."""
    if isinstance(value, dict):
        raise TypeError("alloc value must be scalar")
    v = value.strip()
    if v.endswith("KB"):
        return int(v[:-2]) * 1024
    if v.endswith("MB"):
        return int(v[:-2]) * 1024 * 1024
    return int(v)


def pick_latest_checkpoint(ckpt_block: dict) -> tuple[str, dict]:
    """Given the parsed `checkpoint=(...)` block, pick the entry with the
    highest `order=` and return (name, sub_dict). Avoids string-comparing
    "WiredTigerCheckpoint.9" vs "WiredTigerCheckpoint.10"."""
    best_name = ""
    best_sub: dict = {}
    best_order = -1
    for name, sub in ckpt_block.items():
        if not isinstance(sub, dict):
            continue
        try:
            order = int(sub.get("order", "-1"))
        except (TypeError, ValueError):
            order = -1
        if order > best_order:
            best_order = order
            best_name = name
            best_sub = sub
    return best_name, best_sub


def turtle_metadata_cookie(turtle_path: Path) -> tuple[bytes, int]:
    """Return (checkpoint_cookie_bytes, allocation_size) for WiredTiger.wt."""
    pairs = parse_turtle(turtle_path)
    config = pairs.get(TURTLE_KEY)
    if config is None:
        raise KeyError(f"{TURTLE_KEY} not in turtle file")
    cfg = _parse_config(config)
    alloc = parse_alloc_size(cfg.get("allocation_size", "4KB"))
    ckpt = cfg.get("checkpoint")
    if not isinstance(ckpt, dict):
        raise KeyError("checkpoint clause missing from WiredTiger.wt config")
    _name, sub = pick_latest_checkpoint(ckpt)
    addr_hex = sub.get("addr", "")
    if not addr_hex:
        raise KeyError("checkpoint addr= missing")
    return bytes.fromhex(addr_hex), alloc
