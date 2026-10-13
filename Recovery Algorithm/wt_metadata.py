"""
WiredTiger metadata table reader.

Role in the larger flow:
    `WiredTiger.wt` is itself a row-store table whose entries are
    (uri_string, config_string) pairs. For every other table in the database,
    its checkpoint cookie, allocation_size, block_compressor, etc. live in
    this table. To recover anything from `collection-*.wt` we first need
    that config so we can find the table's root page.

Output: dict[uri -> config_string], plus a small typed helper for fields
the recovery driver cares about (root cookie, alloc, compressor).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import wt_format as wt
import wt_turtle as wtt


@dataclass
class FileMetadata:
    """Subset of a WiredTiger metadata entry we use during recovery."""
    uri: str                       # e.g. 'file:collection-0-12047439198281220888.wt'
    allocation_size: int
    block_compressor: str          # 'snappy', '' etc.
    root_offset: int               # 0 = no root (empty checkpoint)
    root_size: int
    file_size: int


# ---------------------------------------------------------------------------
def read_metadata_table(wt_file_path: Path, root_offset: int, alloc: int, ) -> dict[str, str]:
    """Walk the WiredTiger.wt B-tree and return {key_string: value_string}.
    Both keys and values in the metadata table are stored as C-strings
    (NUL-terminated). We strip the trailing NUL for cleanliness.
    """
    data = wt_file_path.read_bytes()
    leaves = wt.extract_normal_pages(data, root_offset, alloc)
    out: dict[str, str] = {}
    for h in leaves:
        payload = wt.page_payload(data, h)
        for entry in wt.walk_kv_page(payload, h.type, alloc):
            if entry.value is None:
                continue
            key = entry.key.rstrip(b"\x00").decode("utf-8", errors="replace")
            val = entry.value.rstrip(b"\x00").decode("utf-8", errors="replace")
            if key:
                out[key] = val
    return out


# ---------------------------------------------------------------------------
def file_metadata_for(uri: str, config: str, default_alloc: int) -> FileMetadata | None:
    """Parse one metadata-table value into the typed FileMetadata.
    Returns None if there is no checkpoint (table never written)."""
    cfg = wtt._parse_config(config)
    alloc = wtt.parse_alloc_size(cfg.get("allocation_size", str(default_alloc)))
    compressor = cfg.get("block_compressor", "") or ""
    if isinstance(compressor, dict):
        compressor = ""
    ckpt = cfg.get("checkpoint")
    if not isinstance(ckpt, dict) or not ckpt:
        return None
    _name, sub = wtt.pick_latest_checkpoint(ckpt)
    addr_hex = sub.get("addr", "") if isinstance(sub, dict) else ""
    if not addr_hex:
        return None
    cookie = wtt.unpack_checkpoint_cookie(bytes.fromhex(addr_hex), alloc)
    return FileMetadata(
        uri=uri,
        allocation_size=alloc,
        block_compressor=compressor,
        root_offset=cookie.root.offset,
        root_size=cookie.root.size,
        file_size=cookie.file_size,
    )


def collect_file_metadata(metadata_table: dict[str, str], default_alloc: int) -> dict[str, FileMetadata]:
    """Filter the metadata table to `file:` URIs and parse each one."""
    out: dict[str, FileMetadata] = {}
    for uri, config in metadata_table.items():
        if not uri.startswith("file:"):
            continue
        fm = file_metadata_for(uri, config, default_alloc)
        if fm is not None:
            out[uri] = fm
    return out
