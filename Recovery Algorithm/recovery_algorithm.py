"""
MongoDB tamper-recovery driver 

What it does
------------
1. WiredTiger.turtle  -> checkpoint cookie for WiredTiger.wt + its alloc size.
2. WiredTiger.wt      -> walk that B-tree (using the cookie's root offset),
                         get {uri -> config_string} for every other table.
3. _mdb_catalog.wt    -> walk it using the root from step 2, get the
                         {namespace -> ident} mapping.
4. For each requested namespace:
     a. Look up ident -> file URI -> file path.
     b. Look up the file's own checkpoint cookie + alloc + compressor from
        the metadata read in step 2.
     c. Walk the file's live B-tree from the cookie's root -> live leaves.
     d. Linear-scan the file for ROW_LEAF pages not reachable from live
        -> orphan leaves.
     e. Decode BSON from every cell (live + orphan), group by document _id,
        and classify per _id:
            UNCHANGED        : only the live version exists
            MODIFIED         : live exists AND >=1 different orphan version
                               (candidate tamper / regular update)
            DELETED          : no live version, but orphan version(s) exist
            ORPHAN_ONLY      : no _id but orphan content recoverable
     f. Sort orphan versions by write_gen (descending = most recent first)
        so the timeline reads in reverse chronological order.

The script prints a per-namespace report and exits 0 on success. Records
without an `_id` (rare, mostly metadata fragments) are reported in a
catch-all bucket.

Limitations (called out, not hidden)
------------------------------------
* Overflow values (documents larger than `leaf_page_max`) are stored in
  separate OVFL pages; we currently surface the OVFL pointer cell but do
  not chase it. Large docs in such pages will be missed.
* The recovery window is "what's still on disk". Pages reclaimed and
  rewritten by the WT block manager since the modification are gone. => No carving
* No journal/oplog cross-check yet, so MODIFIED = "prior version
  recoverable" (could be a normal update OR a tamper). Distinguishing
  the two requires comparing against the oplog or an external audit log.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import bson

import wt_format as wt
import wt_turtle as wtt
import wt_metadata as wtm
import mdb_catalog as cat


# ---------------------------------------------------------------------------
# BSON carving (used to extract documents from a leaf page payload)
#
# We carve rather than try to track "this cell is a VALUE for that KEY because
# the KEY was the BSON object key" -- in MongoDB collections, the WT KEY is a
# RecordId (8 bytes) and the WT VALUE is the BSON document itself. So we walk
# cells with the proper unpacker (now that it handles SIZE_ADJUST etc.) and
# decode each VALUE cell's bytes as BSON. We fall back to byte-level carving
# only if cell decoding misses something.
# ---------------------------------------------------------------------------
def cells_to_bson(payload: bytes, alloc: int) -> list[dict]:
    """Decode every VALUE cell on a leaf page as BSON."""
    out: list[dict] = []
    for entry in wt.walk_kv_page(payload, wt.PAGE_TYPE_ROW_LEAF, alloc):
        if not entry.value or entry.is_overflow:
            continue
        try:
            out.append(bson.decode_all(entry.value)[0])
        except Exception:
            pass
    return out


def carve_bson(buf: bytes) -> list[dict]:
    """Byte-level BSON sweep, used only as a fallback for cells we couldn't
    pair (e.g. truncated leaves)."""
    out: list[dict] = []
    i, n = 0, len(buf)
    while i + 5 <= n:
        size = struct.unpack_from("<i", buf, i)[0]
        if 5 <= size <= n - i and buf[i + size - 1] == 0:
            try:
                out.append(bson.decode_all(buf[i : i + size])[0])
                i += size
                continue
            except Exception:
                pass
        i += 1
    return out


# ---------------------------------------------------------------------------
# Per-_id timeline
# ---------------------------------------------------------------------------
@dataclass
class DocVersion:
    doc: dict
    leaf_offset: int
    write_gen: int
    source: str   # "live" or "orphan"


@dataclass
class IdTimeline:
    _id: object
    status: str # MODIFIED|DELETED|UNCHANGED|ORPHAN_ONLY
    live: list[DocVersion] = field(default_factory=list)
    prior: list[DocVersion] = field(default_factory=list)


def _content_key(doc: dict) -> str:
    return json.dumps(doc, default=str, sort_keys=True)

def _extract_bson_union(payload: bytes, alloc: int) -> list[dict]:
    """Extract BSON via both cell decode and byte carving, then deduplicate.

    This keeps the existing decode path intact while also picking up BSON that
    can exist in slack/truncated regions.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for d in cells_to_bson(payload, alloc):
        k = _content_key(d)
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    for d in carve_bson(payload):
        k = _content_key(d)
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out

def parse_history_store(
    hs_path: Path,
    hs_fm: wtm.FileMetadata,
) -> tuple[dict[str, list[DocVersion]], dict]:
    """Best-effort History Store parser.

    WiredTigerHS.wt stores historical update values. For MongoDB document
    tables, old BSON can often be recovered here even after orphan pages are
    reclaimed in the main collection file."""
    data = hs_path.read_bytes()
    live_leaves = wt.extract_normal_pages(data, hs_fm.root_offset, hs_fm.allocation_size)
    orphan_leaves = wt.extract_orphan_leaves(data, live_leaves, hs_fm.allocation_size)

    live_page_cells: dict[int, int] = {}
    orphan_page_cells: dict[int, int] = {}

    by_id: dict[str, list[DocVersion]] = defaultdict(list)

    for h in live_leaves:
        payload = wt.page_payload(data, h)
        cells = list(wt.walk_kv_page(payload, wt.PAGE_TYPE_ROW_LEAF, hs_fm.allocation_size))
        live_page_cells[h.offset] = len(cells)
        docs = _extract_bson_union(payload, hs_fm.allocation_size)
        for d in docs:
            if "_id" not in d:
                continue
            key = f"id:{_content_key({'_id': d['_id']})}"
            by_id[key].append(DocVersion(d, h.offset, h.write_gen, "history"))

    for h in orphan_leaves:
        payload = wt.page_payload(data, h)
        cells = list(wt.walk_kv_page(payload, wt.PAGE_TYPE_ROW_LEAF, hs_fm.allocation_size))
        orphan_page_cells[h.offset] = len(cells)
        docs = _extract_bson_union(payload, hs_fm.allocation_size)
        for d in docs:
            if "_id" not in d:
                continue
            key = f"id:{_content_key({'_id': d['_id']})}"
            by_id[key].append(DocVersion(d, h.offset, h.write_gen, "history"))

    # Deduplicate per _id by full document content and sort newest first.
    for key, vs in by_id.items():
        uniq: list[DocVersion] = []
        seen: set[str] = set()
        for v in sorted(vs, key=lambda x: x.write_gen, reverse=True):
            ck = _content_key(v.doc)
            if ck in seen:
                continue
            seen.add(ck)
            uniq.append(v)
        by_id[key] = uniq

    meta = {
        "file": str(hs_path),
        "alloc": hs_fm.allocation_size,
        "root_offset": hs_fm.root_offset,
        "block_compressor": hs_fm.block_compressor,
        "live_leaves": [f"0x{p.offset:x}" for p in live_leaves],
        "orphan_leaves": [f"0x{p.offset:x}" for p in orphan_leaves],
        "live_page_cells": live_page_cells,
        "orphan_page_cells": orphan_page_cells,
        "ids_with_history": len(by_id),
    }
    return by_id, meta


def merge_history_into_timelines(
    timelines: list[IdTimeline],
    hs_by_id: dict[str, list[DocVersion]],
) -> tuple[list[IdTimeline], dict]:
    """Append History Store versions to existing timelines without replacing
    live/orphan classification logic."""
    merged = 0
    touched_ids = 0
    for t in timelines:
        if t._id == "<no _id>":
            continue
        key = f"id:{_content_key({'_id': t._id})}"
        hs_versions = hs_by_id.get(key, [])
        if not hs_versions:
            continue

        existing = {_content_key(v.doc) for v in (t.live + t.prior)}
        added = 0
        for hv in hs_versions:
            ck = _content_key(hv.doc)
            if ck in existing:
                continue
            existing.add(ck)
            t.prior.append(hv)
            added += 1

        if added:
            touched_ids += 1
            merged += added
            if t.status == "UNCHANGED":
                t.status = "MODIFIED"

    return timelines, {
        "history_versions_added": merged,
        "history_ids_touched": touched_ids,
    }

# ---------------------------------------------------------------------------
# Per-file recovery (called once per requested namespace)
# ---------------------------------------------------------------------------
def recover_file(
    path: Path, fm: wtm.FileMetadata, dump: bool = False
) -> tuple[list[IdTimeline], dict]:
    data = path.read_bytes()
    if dump:
        # Plain dump of everything in the file. alloc comes from the metadata
        # table, so the caller only needs a namespace -- no file path required.
        wt.dump_all_pages(data, fm.allocation_size)
    live_leaves = wt.extract_normal_pages(data, fm.root_offset, fm.allocation_size)
    orphan_leaves = wt.extract_orphan_leaves(data, live_leaves, fm.allocation_size)

    live_page_cells: dict[int, int] = {}
    orphan_page_cells: dict[int, int] = {}

    versions: list[DocVersion] = []
    for h in live_leaves:
        payload = wt.page_payload(data, h)
        cells = list(wt.walk_kv_page(payload, wt.PAGE_TYPE_ROW_LEAF, fm.allocation_size))
        # live_page_cells = len(cells)
        live_page_cells[h.offset] = len(cells)
        docs = cells_to_bson(payload, fm.allocation_size) or carve_bson(payload)
        for d in docs:
            versions.append(DocVersion(d, h.offset, h.write_gen, "live"))
    for h in orphan_leaves:
        payload = wt.page_payload(data, h)
        cells = list(wt.walk_kv_page(payload, wt.PAGE_TYPE_ROW_LEAF, fm.allocation_size))
        # orphan_page_cells = len(cells)
        orphan_page_cells[h.offset] = len(cells)
        docs = cells_to_bson(payload, fm.allocation_size) or carve_bson(payload)
        for d in docs:
            # print(d)
            versions.append(DocVersion(d, h.offset, h.write_gen, "orphan"))

    # group by _id (use content-hash for docs without _id so they don't collide)
    by_id: dict[str, list[DocVersion]] = defaultdict(list)
    for v in versions:
        if "_id" in v.doc:
            key = f"id:{_content_key({'_id': v.doc['_id']})}"
        else:
            key = f"noid:{_content_key(v.doc)}"
        by_id[key].append(v)

    timelines: list[IdTimeline] = []
    for _k, vs in by_id.items():
        live = [v for v in vs if v.source == "live"]
        orphan = [v for v in vs if v.source == "orphan"]
        live_content = {_content_key(v.doc) for v in live}
        prior_unique: list[DocVersion] = []
        seen: set[str] = set()
        for v in sorted(orphan, key=lambda x: x.write_gen, reverse=True):
            c = _content_key(v.doc)
            if c in live_content or c in seen:
                continue
            seen.add(c)
            prior_unique.append(v)
        first = (live + orphan)[0]
        _id_val = first.doc.get("_id", "<no _id>")
        if not live:
            status = "DELETED" if prior_unique else "ORPHAN_ONLY"
        elif prior_unique:
            status = "MODIFIED"
        else:
            status = "UNCHANGED"
        timelines.append(IdTimeline(_id=_id_val, status=status,
                                    live=live, prior=prior_unique))

    meta = {
        "file": str(path),
        "alloc": fm.allocation_size,
        "root_offset": fm.root_offset,
        "block_compressor": fm.block_compressor,
        "live_leaves": [f"0x{p.offset:x}" for p in live_leaves],
        "orphan_leaves": [f"0x{p.offset:x}" for p in orphan_leaves],
        "live_page_cells": live_page_cells,
        "orphan_page_cells": orphan_page_cells
    }
    return timelines, meta


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def _ns_to_file_path(dbpath: Path, ident: str) -> Path:
    """MongoDB stores `collection-N-XXXX` as `dbpath/collection-N-XXXX.wt`."""
    return dbpath / f"{ident}.wt"


def _print_namespace_report(ns: str, ident: str,
                            timelines: list[IdTimeline], meta: dict) -> None:
    counts: dict[str, int] = defaultdict(int)
    for t in timelines:
        counts[t.status] += 1
    print(f"\n===== {ns}  ({ident}) =====")
    print(f"  file: {meta['file']}")
    print(f"  alloc=0x{meta['alloc']:x}  root=0x{meta['root_offset']:x}  "
          f"compressor='{meta['block_compressor']}'")
    print(f"  live leaves:   {meta['live_leaves']}")
    print(f"  orphan leaves: {meta['orphan_leaves']}")
    print(f"  summary: {dict(counts)}")
    
    print(f"\n  LIVE LEAF PAGES (reachable from root):")
    if meta['live_leaves']:
        live_pc = meta.get('live_page_cells', {})
        for leaf_off_str in meta['live_leaves']:
            leaf_off = int(leaf_off_str, 16)
            cell_count = live_pc.get(leaf_off, '?')
            print(f"    {leaf_off_str}: {cell_count} cells")
    else:
        print(f"    (none)")
    
    print(f"\n  ORPHAN LEAF PAGES (not reachable from root):")
    if meta['orphan_leaves']:
        orphan_pc = meta.get('orphan_page_cells', {})
        for leaf_off_str in meta['orphan_leaves']:
            leaf_off = int(leaf_off_str, 16)
            cell_count = orphan_pc.get(leaf_off, '?')
            print(f"    {leaf_off_str}: {cell_count} cells")
    else:
        print(f"    (none - no recoverable orphan data)")

    for t in timelines:
        if t.status == "UNCHANGED":
            continue
        print(f"\n  [{t.status}] _id = {t._id}")
        for v in t.live:
            print(f"    LIVE   (leaf 0x{v.leaf_offset:x}, wgen={v.write_gen}):")
            print(f"      {json.dumps(v.doc, default=str)}")
        for v in t.prior:
            print(f"    PRIOR  (leaf 0x{v.leaf_offset:x}, wgen={v.write_gen}):")
            print(f"      {json.dumps(v.doc, default=str)}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("dbpath", type=Path, help="MongoDB data directory")
    ap.add_argument("-n", "--namespace", action="append", default=[],
                    metavar="DB.COLL",
                    help="namespace to recover; repeat for multiple. "
                         "Default: every namespace in the catalog.")
    ap.add_argument("--dump", action="store_true",
                    help="print every page and cell of each collection file "
                         "before the summary")
    args = ap.parse_args(argv[1:])

    dbpath: Path = args.dbpath
    if not dbpath.is_dir():
        print(f"error: dbpath not a directory: {dbpath}", file=sys.stderr)
        return 2

    # Step 1: turtle
    turtle = dbpath / "WiredTiger.turtle"
    if not turtle.exists():
        print(f"error: missing {turtle}", file=sys.stderr)
        return 2
    md_cookie_bytes, md_alloc = wtt.turtle_metadata_cookie(turtle)
    md_cookie = wtt.unpack_checkpoint_cookie(md_cookie_bytes, md_alloc)
    print(f"WiredTiger.turtle: alloc={md_alloc} "
          f"WiredTiger.wt root=0x{md_cookie.root.offset:x}")

    # Step 2: WiredTiger.wt -> metadata table
    wt_meta_path = dbpath / "WiredTiger.wt"
    md_table = wtm.read_metadata_table(wt_meta_path, md_cookie.root.offset, md_alloc)
    file_md = wtm.collect_file_metadata(md_table, md_alloc)
    print(f"WiredTiger.wt: {len(md_table)} metadata rows, "
          f"{len(file_md)} file: entries")

    # Step 3: _mdb_catalog.wt -> namespace map
    catalog_uri = "file:_mdb_catalog.wt"
    catalog_fm = file_md.get(catalog_uri)
    if catalog_fm is None:
        print(f"error: catalog '{catalog_uri}' not in metadata table",
              file=sys.stderr)
        return 2
    catalog_path = dbpath / "_mdb_catalog.wt"
    catalog = cat.read_catalog(catalog_path, catalog_fm.root_offset,
                               catalog_fm.allocation_size)
    print(f"_mdb_catalog.wt: {len(catalog)} collections")

    # Optional additive source: WiredTiger history store.
    hs_uri = "file:WiredTigerHS.wt"
    hs_by_id: dict[str, list[DocVersion]] = {}
    hs_merge_default = {"history_versions_added": 0, "history_ids_touched": 0}
    hs_fm = file_md.get(hs_uri)
    if hs_fm is not None:
        hs_path = dbpath / "WiredTigerHS.wt"
        if hs_path.exists():
            hs_by_id, hs_meta = parse_history_store(hs_path, hs_fm)
            print(
                "WiredTigerHS.wt: "
                f"{len(hs_meta['live_leaves'])} live leaves, "
                f"{len(hs_meta['orphan_leaves'])} orphan leaves, "
                f"{hs_meta['ids_with_history']} _id buckets"
            )

    # Step 4: per-namespace recovery
    targets = args.namespace or sorted(catalog.keys())
    print(f"\nrecovering {len(targets)} namespace(s)...")

    rc = 0
    for ns in targets:
        ce = catalog.get(ns)
        if ce is None:
            print(f"\n!!! namespace not in catalog: {ns}")
            rc = 1
            continue
        coll_uri = f"file:{ce.ident}.wt"
        fm = file_md.get(coll_uri)
        if fm is None:
            print(f"\n!!! no metadata for {coll_uri}")
            rc = 1
            continue
        coll_path = _ns_to_file_path(dbpath, ce.ident)
        if not coll_path.exists():
            print(f"\n!!! file missing: {coll_path}")
            rc = 1
            continue
        timelines, meta = recover_file(coll_path, fm, dump=args.dump)
        _print_namespace_report(ns, ce.ident, timelines, meta)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))