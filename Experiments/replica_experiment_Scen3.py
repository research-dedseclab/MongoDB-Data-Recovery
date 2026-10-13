"""
Replica-set recovery experiment (with an intentionally DELAYED secondary).

Shows how deployment affects the recovery window:
  * primary / normal secondary -> recovery is window-limited (orphan pages that
    the next checkpoint overwrites), same as standalone.
  * DELAYED secondary          -> it lags `secondaryDelaySecs` behind, so the
    deleted/modified records are still LIVE there -> recoverable as live data
    for the whole delay window (a much wider, more robust window).

Flow (same workload as standalone Experiment #2, all writes via the primary):
  1. baseline checkpoint on every member (pristine 100k on disk everywhere);
     automatic checkpointing is suppressed so only our captures checkpoint.
  2. for each round (500..5000): on the primary INSERT 500 new docs (the churn
     that drives block reuse), DELETE 500, MODIFY 500; then snapshot AND recover
     every member. The per-round fsyncLock capture is also the checkpoint that
     closes the non-delayed members' windows round by round.
  3. write one per-round results table per member (same shape as standalone
     Experiment #2), so the live nodes' decay and the delayed node's flat line
     can be plotted together.

A truth id counts as recovered if its ORIGINAL value is obtainable from that
member -- either still LIVE (delayed member) or on an ORPHAN page (others).
`*_via_live` shows how many were recovered because the record was still live.

PREREQUISITES (manual, one time):
  * A 3-node WiredTiger replica set rs0 on 27017/27018/27019.
  * Member 3 configured DELAYED, e.g. in mongosh on the primary:
        cfg = rs.conf()
        cfg.members[2].priority = 0
        cfg.members[2].hidden = true
        cfg.members[2].secondaryDelaySecs = 600      // 10 min lag
        rs.reconfig(cfg)
  * Seed via the set (python seed_ex1_ex2.py pointed at the rs URI) and wait
    > secondaryDelaySecs so the delayed member holds the full baseline.
  * secondaryDelaySecs must exceed this run's duration. Per-round capture of
    every member takes several minutes, so set it to >= 900 (15 min).

Run:  python replica_experiment.py
"""

from __future__ import annotations

import csv
import random
import shutil
import sys
import time
from pathlib import Path

from pymongo import MongoClient, errors

import wt_turtle as wtt
import wt_metadata as wtm
import mdb_catalog as cat
from recovery_algorithm import recover_file
from seed_ex1_ex2 import _make_doc          # reuse the baseline doc generator

# --- configuration ---------------------------------------------------------
PRIMARY_URI = "mongodb://localhost:27017,localhost:27018,localhost:27019/?replicaSet=rs0"

# (label, direct-connection URI, that member's --dbpath, is_delayed)
MEMBERS = [
    ("primary",   "mongodb://localhost:27017/?directConnection=true", r"C:\Users\Hardi-Admin\Desktop\Hardi's Work\Thesis\Replicas\r1", False),
    ("secondary", "mongodb://localhost:27018/?directConnection=true", r"C:\Users\Hardi-Admin\Desktop\Hardi's Work\Thesis\Replicas\r2", False),
    ("delayed",   "mongodb://localhost:27019/?directConnection=true", r"C:\Users\Hardi-Admin\Desktop\Hardi's Work\Thesis\Replicas\r3", True),
]

DB_NAME = "TestDB"
COLL = "ex1"

START = 500           # per-round volume (the Experiment #2 workload)
STEP = 500
MAX = 5000            # 10 rounds: cumulative 5000 inserted / deleted / modified
REPL_WAIT = 3         # seconds to let the NON-delayed secondary catch up

CAPTURE_ROOT = r".\replica_images"            # per-member images (overwritten each round)
SEED = 1234

_IGNORE = shutil.ignore_patterns("*.lock", "_tmp", "diagnostic.data")


def _copy2_safe(src, dst, *, follow_symlinks=True):
    try:
        shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
    except OSError as e:
        print(f"    skip locked file: {Path(src).name} ({e.__class__.__name__})")


def _fsync(uri: str) -> None:
    c = MongoClient(uri, serverSelectionTimeoutMS=8000)
    try:
        c.admin.command({"fsync": 1})
    finally:
        c.close()


def _syncdelay(uri: str, secs: int) -> None:
    """Set a member's WiredTiger auto-checkpoint interval (direct connection)."""
    c = MongoClient(uri, serverSelectionTimeoutMS=8000)
    try:
        c.admin.command({"setParameter": 1, "syncdelay": secs})
    finally:
        c.close()


def _capture(uri: str, dbpath: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    c = MongoClient(uri, serverSelectionTimeoutMS=8000)
    try:
        c.admin.command({"fsync": 1, "lock": True})
        try:
            shutil.copytree(dbpath, dest, ignore=_IGNORE, copy_function=_copy2_safe)
        finally:
            c.admin.command({"fsyncUnlock": 1})
    finally:
        c.close()


def _recover(dbpath: Path, ns: str):
    md_bytes, md_alloc = wtt.turtle_metadata_cookie(dbpath / "WiredTiger.turtle")
    md_cookie = wtt.unpack_checkpoint_cookie(md_bytes, md_alloc)
    md_table = wtm.read_metadata_table(dbpath / "WiredTiger.wt",
                                       md_cookie.root.offset, md_alloc)
    file_md = wtm.collect_file_metadata(md_table, md_alloc)
    catalog_fm = file_md["file:_mdb_catalog.wt"]
    catalog = cat.read_catalog(dbpath / "_mdb_catalog.wt",
                               catalog_fm.root_offset, catalog_fm.allocation_size)
    ce = catalog[ns]
    fm = file_md[f"file:{ce.ident}.wt"]
    return recover_file(dbpath / f"{ce.ident}.wt", fm)


def _rate(hit: int, total: int) -> float:
    return round(100.0 * hit / total, 1) if total else 0.0


def _score(timelines, del_ids: set, mod_ids: set):
    """A truth id is recovered if its ORIGINAL (pre-tamper) value is present,
    either live (delayed member) or on an orphan (others). Returns the row
    fields plus the recovered id sets (so the caller can union across members)."""
    live_ids: set = set()
    live_orig: set = set()          # live version has NO 'tampered' field
    any_orig: set = set()           # any version (live or orphan) is original
    for t in timelines:
        for v in t.live:
            rid = v.doc.get("_id")
            live_ids.add(rid)
            if "tampered" not in v.doc:
                live_orig.add(rid)
                any_orig.add(rid)
        for v in t.prior:
            if "tampered" not in v.doc:
                any_orig.add(v.doc.get("_id"))
    rec_del = del_ids & any_orig
    rec_mod = mod_ids & any_orig
    row = {
        "del_recovered": len(rec_del),
        "del_rate_%": _rate(len(rec_del), len(del_ids)),
        "del_via_live": len(del_ids & live_ids),
        "mod_recovered": len(rec_mod),
        "mod_rate_%": _rate(len(rec_mod), len(mod_ids)),
        "mod_via_live": len(mod_ids & live_orig),
    }
    return row, rec_del, rec_mod


def main() -> int:
    rng = random.Random(SEED)
    ns = f"{DB_NAME}.{COLL}"
    try:
        client = MongoClient(PRIMARY_URI, serverSelectionTimeoutMS=8000)
        client.admin.command("ping")
    except errors.PyMongoError as e:
        print(f"error: cannot reach replica set at {PRIMARY_URI}: {e}", file=sys.stderr)
        return 1

    coll = client[DB_NAME][COLL]
    ids = [d["_id"] for d in coll.find({}, {"_id": 1})]
    if len(ids) < 2 * MAX:
        print(f"error: need >= {2 * MAX} docs in {COLL}. Seed via the replica set first.",
              file=sys.stderr)
        return 2
    pool = set(ids)
    next_id = max(ids) + 1

    for _lbl, uri, _dbp, _dl in MEMBERS:      # baseline checkpoint + suppress auto
        _fsync(uri)
        _syncdelay(uri, 3600)
    print("baseline checkpoint on all members; auto checkpoint suppressed")

    member_rows = {label: [] for (label, *_rest) in MEMBERS}
    del_ids: set = set()
    mod_ids: set = set()
    round_no = 0
    try:
        for _ in range(START, MAX + 1, STEP):   # Experiment #2 workload on the primary
            round_no += 1
            coll.insert_many([_make_doc(next_id + j, rng) for j in range(STEP)],
                             ordered=False)       # inserts = block-reuse churn
            next_id += STEP
            picks = rng.sample(sorted(pool), 2 * STEP)
            d_ids, m_ids = picks[:STEP], picks[STEP:]
            pool.difference_update(picks)
            coll.delete_many({"_id": {"$in": d_ids}})
            coll.update_many({"_id": {"$in": m_ids}},
                             {"$set": {"tampered": True, "round": round_no}})
            del_ids.update(d_ids)
            mod_ids.update(m_ids)

            time.sleep(REPL_WAIT)               # let the normal secondary apply

            # snapshot + recover EVERY member this round. The fsyncLock capture
            # is ALSO the per-round checkpoint that closes the non-delayed windows.
            for label, uri, dbpath, delayed in MEMBERS:
                dest = Path(CAPTURE_ROOT) / label          # overwritten each round
                _capture(uri, dbpath, dest)
                t0 = time.perf_counter()
                timelines, meta = _recover(dest, ns)
                rec_sec = time.perf_counter() - t0
                srow, _rd, _rm = _score(timelines, del_ids, mod_ids)
                row = {"round": round_no,
                       "cum_deleted": len(del_ids),
                       "cum_modified": len(mod_ids)}
                row.update(srow)
                row["orphan_leaves"] = len(meta.get("orphan_leaves", []))
                row["recover_sec"] = round(rec_sec, 3)
                member_rows[label].append(row)
            print(f"round {round_no}: ins/del/mod {STEP} each + captured & scored "
                  f"{len(MEMBERS)} members  (cum del={len(del_ids)}, mod={len(mod_ids)})")
    finally:
        for _lbl, uri, _dbp, _dl in MEMBERS:    # restore default checkpointing
            _syncdelay(uri, 60)
        client.close()

    # one CSV per member, each shaped like the standalone Experiment #2 results
    for label, mrows in member_rows.items():
        out = rf".\replica_results_{label}.csv"
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(mrows[0].keys()))
            w.writeheader()
            w.writerows(mrows)
        print(f"wrote {out}")

    # combined view: MODIFY recovery rate per round per member (the divergence)
    labels = [l for (l, *_r) in MEMBERS]
    print("\nmodify recovery rate % per round "
          "(live nodes decay; delayed stays flat):")
    hdr = ["round", "cum_mod"] + labels
    print(" | ".join(f"{h:>12}" for h in hdr))
    print("-" * (15 * len(hdr)))
    for i in range(len(member_rows[labels[0]])):
        base = member_rows[labels[0]][i]
        cells = [base["round"], base["cum_modified"]] + \
                [member_rows[l][i]["mod_rate_%"] for l in labels]
        print(" | ".join(f"{str(c):>12}" for c in cells))
    print("\nnote: del_rate_% is inflated on replica sets (retained delete "
          "tombstones read as live); use mod_rate_% as the reliable metric.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
