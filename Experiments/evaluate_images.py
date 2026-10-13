"""
Evaluate recovery over the images produced by exp1 / exp2.

For each captured image (a static dbpath copy that carries a truth.json), run
the recovery tool on TestDB.ex1 and record, per checkpoint:

    deleted / modified        cumulative deleted / modified so far (from truth)
    recovered_deleted/_mod    cumulative originals recovered from orphan pages
    live                      live documents still in the tree
    del_rate_% / mod_rate_%   cumulative recovered / cumulative expected
    batch_del_% / batch_mod_% of docs changed since the PREVIOUS checkpoint,
                              how many were recovered (the "fresh" 1-checkpoint
                              window -- expect ~100%)

Writes a CSV (opens directly in Excel) and prints the same table, then a TOTAL:
the single final snapshot rate (last row) vs. the union across every checkpoint
(what you'd recover if you captured an image at every checkpoint). Run AFTER
the experiment script.

Usage:  python evaluate_images.py [scenario] [exp]
        scenario = 1..4 (default 3)     exp = exp1 | exp2 (default exp1)
"""

from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

import wt_turtle as wtt
import wt_metadata as wtm
import mdb_catalog as cat
from recovery_algorithm import recover_file

# --- configuration ---------------------------------------------------------
SCENARIO = int(sys.argv[1]) if len(sys.argv) > 1 else 3   # 1,2,3,4 (CLI arg or default)
EXP = sys.argv[2] if len(sys.argv) > 2 else "exp1"        # "exp1" or "exp2"

# Read the SAME capture root the experiment wrote to, so the two never disagree
# even if you point CAPTURE_ROOT at a custom folder.
if EXP == "exp2":
    from exp2_insert_delete_modify import CAPTURE_ROOT
else:
    from exp1_delete_modify import CAPTURE_ROOT

IMAGES_ROOT = str(Path(CAPTURE_ROOT) / f"scenario{SCENARIO}")
OUT_CSV = rf"C:\Users\Hardi-Admin\Desktop\Hardi's Work\Thesis\Experiments\MongoDB Tamper Lab\exp1_results\{EXP}_results_scenario{SCENARIO}.csv"
SUMMARY_CSV = rf"C:\Users\Hardi-Admin\Desktop\Hardi's Work\Thesis\Experiments\MongoDB Tamper Lab\exp1_results\{EXP}_summary_scenario{SCENARIO}.csv"


def _recover(dbpath: Path, ns: str):
    """Replicate the recovery pipeline for one namespace in a static image."""
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


def main() -> int:
    root = Path(IMAGES_ROOT)
    images = sorted(p for p in root.iterdir() if (p / "truth.json").exists()) \
        if root.is_dir() else []
    if not images:
        print(f"no images with truth.json under {root}", file=sys.stderr)
        return 1

    rows: list[dict] = []
    prev_del: set[int] = set()          # previous image's cumulative sets
    prev_mod: set[int] = set()
    union_del: set[int] = set()         # ids recovered in ANY image
    union_mod: set[int] = set()
    all_del: set[int] = set()           # ids ever deleted / modified
    all_mod: set[int] = set()

    for img in images:
        truth = json.loads((img / "truth.json").read_text())
        ns = truth["namespace"]
        del_ids = {int(k) for k in truth["deleted"]}
        mod_ids = {int(k) for k in truth["modified"]}
        try:
            t0 = time.perf_counter()
            timelines, meta = _recover(img, ns)
            rec_sec = time.perf_counter() - t0       # recovery-only time (no snapshot)
        except Exception as e:  # noqa: BLE001
            print(f"  {img.name}: recovery failed: {type(e).__name__}: {e}")
            continue

        rec_del = {t._id for t in timelines
                   if t.status == "DELETED" and t._id in del_ids}
        rec_mod = {t._id for t in timelines
                   if t.status == "MODIFIED" and t._id in mod_ids}
        live = sum(meta.get("live_page_cells", {}).values())
        orphans = len(meta.get("orphan_leaves", []))

        # "fresh" batch = ids changed since the previous checkpoint image
        batch_del = del_ids - prev_del
        batch_mod = mod_ids - prev_mod
        rows.append({
            "image": img.name,
            "deleted": len(del_ids),
            "modified": len(mod_ids),
            "recovered_deleted": len(rec_del),
            "recovered_modified": len(rec_mod),
            "live": live,
            "orphan_leaves": orphans,
            "del_rate_%": _rate(len(rec_del), len(del_ids)),
            "mod_rate_%": _rate(len(rec_mod), len(mod_ids)),
            "batch_del_%": _rate(len(rec_del & batch_del), len(batch_del)),
            "batch_mod_%": _rate(len(rec_mod & batch_mod), len(batch_mod)),
            "recover_sec": round(rec_sec, 3),
        })

        union_del |= rec_del
        union_mod |= rec_mod
        all_del |= del_ids
        all_mod |= mod_ids
        prev_del, prev_mod = del_ids, mod_ids

    if not rows:
        print("no images scored.", file=sys.stderr)
        return 1

    cols = list(rows[0].keys())
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    print(" | ".join(f"{c:>17}" for c in cols))
    print("-" * (20 * len(cols)))
    for r in rows:
        print(" | ".join(f"{str(r[c]):>17}" for c in cols))

    # summary: mean (paper Table-1 style) + single final snapshot + union
    ud, um, td, tm = len(union_del), len(union_mod), len(all_del), len(all_mod)
    total_sec = sum(r["recover_sec"] for r in rows)
    n = len(rows)
    mean_del = round(sum(r["del_rate_%"] for r in rows) / n, 1)
    mean_mod = round(sum(r["mod_rate_%"] for r in rows) / n, 1)
    mean_overall = round(sum(_rate(r["recovered_deleted"] + r["recovered_modified"],
                                   r["deleted"] + r["modified"]) for r in rows) / n, 1)

    print(f"\nMEAN over {n} checkpoint(s) (paper Table-1 style): "
          f"del {mean_del}%  mod {mean_mod}%  overall {mean_overall}%")
    print(f"final single snapshot (last row): "
          f"del {rows[-1]['del_rate_%']}%  mod {rows[-1]['mod_rate_%']}%")
    print(f"union across {n} checkpoint(s): "
          f"del {_rate(ud, td)}%  mod {_rate(um, tm)}%  "
          f"overall {_rate(ud + um, td + tm)}%")
    print(f"recovery time: total {total_sec:.2f}s, avg {total_sec / n:.3f}s per image")

    summary = {
        "scenario": SCENARIO,
        "checkpoints": n,
        "mean_del_%": mean_del,
        "mean_mod_%": mean_mod,
        "mean_overall_%": mean_overall,
        "final_del_%": rows[-1]["del_rate_%"],
        "final_mod_%": rows[-1]["mod_rate_%"],
        "union_del_%": _rate(ud, td),
        "union_mod_%": _rate(um, tm),
        "union_overall_%": _rate(ud + um, td + tm),
        "total_recover_s": round(total_sec, 2),
        "avg_recover_s": round(total_sec / n, 3),
    }
    with open(SUMMARY_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary.keys()))
        w.writeheader()
        w.writerow(summary)

    print(f"\nwrote {OUT_CSV} and {SUMMARY_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
