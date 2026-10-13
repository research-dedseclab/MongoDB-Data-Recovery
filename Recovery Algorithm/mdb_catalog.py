"""
MongoDB _mdb_catalog.wt reader.

Role in the larger flow:
    `_mdb_catalog.wt` is itself a WiredTiger row-store table. Its values are
    BSON documents that map MongoDB namespaces to the ident strings
    MongoDB uses when naming `collection-*.wt` and `index-*.wt` files.

    For each entry the value BSON looks roughly like:

        {
          "ident": "collection-N-XXXX",
          "ns":    "ecommerce_demo.users",
          "md":    { "ns": "ecommerce_demo.users",
                     "options": {...},
                     "indexes": [ ... ] },
          "idxIdent": { "_id_": "index-K-XXXX", ... }
        }

    We turn the catalog into:
        namespace -> { ident, indexes: { index_name -> ident } }

Caveats:
    * Some catalog entries are for non-collection items (e.g. system tables,
      sizeStorer); they are skipped if they lack `ns`/`md.ns`.
    * If the catalog itself has been tampered with, this map is wrong.
      We deliberately do NOT cross-check against `WiredTiger.wt` here --
      that mismatch IS itself a tamper signal we report from the driver.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import bson

import wt_format as wt


@dataclass
class CollectionEntry:
    namespace: str                                       # e.g. 'db.users'
    ident: str                                           # e.g. 'collection-0-X'
    indexes: dict[str, str] = field(default_factory=dict)
    raw: dict | None = None                              # full catalog BSON


def read_catalog(
    catalog_path: Path,
    root_offset: int,
    alloc: int,
) -> dict[str, CollectionEntry]:
    """Walk the live B-tree of _mdb_catalog.wt and return {namespace -> entry}.

    Only walks reachable (live) leaves -- the deleted-collection case is
    handled separately by the tamper driver via orphan leaves.
    """
    data = catalog_path.read_bytes()
    leaves = wt.extract_normal_pages(data, root_offset, alloc)
    out: dict[str, CollectionEntry] = {}
    for h in leaves:
        payload = wt.page_payload(data, h)
        for entry in wt.walk_kv_page(payload, h.type, alloc):
            if not entry.value:
                continue
            try:
                doc = bson.decode_all(entry.value)[0]
            except Exception:
                continue
            ns = doc.get("ns") or (doc.get("md", {}) or {}).get("ns")
            ident = doc.get("ident")
            if not ns or not ident:
                continue
            ce = CollectionEntry(namespace=ns, ident=ident, raw=doc)
            # print(f"Collection entry:: {ce}")
            idx = doc.get("idxIdent")
            if isinstance(idx, dict):
                ce.indexes = {str(k): str(v) for k, v in idx.items()}
            out[ns] = ce
    return out
