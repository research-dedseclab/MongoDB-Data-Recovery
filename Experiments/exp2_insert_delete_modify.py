"""
Experiment #2 -- incremental insert + delete + modify with controlled checkpoints.

The distinguishing feature vs. Experiment #1 is the INSERT: new writes create allocation 
demand that lets the block manager reuse freed (orphan) blocks sooner, so the recovery 
window is even shorter than delete-only. 

Each round: insert STEP new docs, delete STEP existing docs, modify STEP existing
docs. Cumulative counts grow by STEP each round (500..5000). Delete and modify
targets come from the seeded baseline (disjoint) for clean ground truth; inserts
use fresh _ids above the baseline max.

Checkpoint behaviour (single SCENARIO knob), identical to Experiment #1:

    1  ONE checkpoint AFTER all operations    (auto off) -> a single image at end
    2  default auto checkpointing (60s)        (auto on)  -> a single image at end
    3  checkpoint after EACH round             (auto off) -> an image every round
    4  checkpoint every SPARSE_K rounds        (auto off) -> an image every K rounds

Each capture: fsyncLock -> copy dbpath -> fsyncUnlock, plus a truth.json.
A baseline checkpoint is forced at the start (pristine data on disk first).

Run with an optional scenario number:  python exp2_insert_delete_modify.py 3
"""

from __future__ import annotations

import json
import random
import shutil
import sys
import time
from pathlib import Path

from pymongo import MongoClient, errors

from seed_ex1_ex2 import _make_doc          # reuse the baseline doc generator

# --- configuration ---------------------------------------------------------
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "TestDB"
COLL = "ex1"

START = 500
STEP = 500
MAX = 5000                       # cumulative 500,1000,...,5000

SCENARIO = int(sys.argv[1]) if len(sys.argv) > 1 else 3   # 1,2,3,4 (CLI arg or default)
SPARSE_K = 3                     # scenario 4: checkpoint every SPARSE_K rounds

DBPATH = r"C:\Program Files\MongoDB\Server\8.3\data"   # server's --dbpath
CAPTURE_ROOT = r".\exp2_images"                        # where images are copied
SEED = 1234

# derived: how checkpoints/captures are scheduled
ROUNDS = len(range(START, MAX + 1, STEP))
DISABLE_AUTO_CHECKPOINT = SCENARIO != 2
CAPTURE_EVERY = {1: ROUNDS, 2: ROUNDS, 3: 1, 4: SPARSE_K}[SCENARIO]
ROUND_DELAY_SEC = 40 if SCENARIO == 2 else 0   # scenario 2: let the 60s auto checkpoint fire


def _syncdelay(client, secs: int) -> None:
    """Set the WiredTiger auto-checkpoint interval (seconds)."""
    client.admin.command({"setParameter": 1, "syncdelay": secs})


# transient / locked files that must NOT go into a recovery image
_IGNORE = shutil.ignore_patterns("*.lock", "_tmp", "diagnostic.data")


def _copy2_safe(src, dst, *, follow_symlinks=True):
    """copy2 that skips any file mongod still has locked (Windows WinError 33)."""
    try:
        shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
    except OSError as e:
        print(f"    skip locked file: {Path(src).name} ({e.__class__.__name__})")


def _capture(client, label: str, deleted: dict, modified: dict) -> None:
    """fsyncLock -> copy dbpath -> fsyncUnlock, then write truth.json."""
    if not (DBPATH and CAPTURE_ROOT):
        client.admin.command({"fsync": 1})                 # checkpoint only
        print(f"    [{label}] checkpoint (no image: set DBPATH/CAPTURE_ROOT)")
        return
    dest = Path(CAPTURE_ROOT) / f"scenario{SCENARIO}" / label
    if dest.exists():
        shutil.rmtree(dest)
    client.admin.command({"fsync": 1, "lock": True})
    try:
        shutil.copytree(DBPATH, dest, ignore=_IGNORE, copy_function=_copy2_safe)
    finally:
        client.admin.command({"fsyncUnlock": 1})
    truth = {
        "namespace": f"{DB_NAME}.{COLL}",
        "deleted": {str(k): v for k, v in deleted.items()},
        "modified": {str(k): v for k, v in modified.items()},
    }
    (dest / "truth.json").write_text(json.dumps(truth, indent=2))
    print(f"    [{label}] checkpoint + image -> {dest}  "
          f"(cum deleted={len(deleted)}, modified={len(modified)})")


def main() -> int:
    rng = random.Random(SEED)
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
    except errors.ServerSelectionTimeoutError as e:
        print(f"error: cannot reach MongoDB at {MONGO_URI}: {e}", file=sys.stderr)
        return 1

    coll = client[DB_NAME][COLL]
    ids = [d["_id"] for d in coll.find({}, {"_id": 1})]
    pool = set(ids)
    if len(pool) < 2 * MAX:
        print(f"error: need >= {2 * MAX} docs in {COLL}, found {len(pool)}. "
              f"Run seed_ex1_ex2.py first.", file=sys.stderr)
        return 2
    next_id = max(ids) + 1                    # fresh ids for inserts

    client.admin.command({"fsync": 1})        # baseline checkpoint: seeded data -> disk
    print("baseline checkpoint written (pristine data now on disk)")

    if DISABLE_AUTO_CHECKPOINT:
        _syncdelay(client, 3_600)             # 1 hour (max allowed) = no auto ckpt mid-run
        print("auto checkpoint suppressed (syncdelay=3600)")

    deleted: dict[int, str] = {}
    modified: dict[int, str] = {}
    round_no = 0
    try:
        for _ in range(START, MAX + 1, STEP):
            round_no += 1

            # insert STEP new docs (fresh ids) -- the exp2 block-reuse pressure
            coll.insert_many([_make_doc(next_id + j, rng) for j in range(STEP)],
                             ordered=False)
            next_id += STEP

            # delete + modify STEP baseline docs each (disjoint per run)
            picks = rng.sample(sorted(pool), 2 * STEP)
            del_ids, mod_ids = picks[:STEP], picks[STEP:]
            pool.difference_update(picks)

            for d in coll.find({"_id": {"$in": del_ids}}, {"data": 1}):
                deleted[d["_id"]] = str(d.get("data", ""))[:24]
            coll.delete_many({"_id": {"$in": del_ids}})

            for d in coll.find({"_id": {"$in": mod_ids}}, {"data": 1}):
                modified[d["_id"]] = str(d.get("data", ""))[:24]   # pre-image
            coll.update_many({"_id": {"$in": mod_ids}},
                             {"$set": {"tampered": True, "round": round_no}})

            print(f"round {round_no}: inserted {STEP}, deleted {len(del_ids)}, "
                  f"modified {len(mod_ids)}  (cum del={len(deleted)}, "
                  f"mod={len(modified)})")

            if ROUND_DELAY_SEC:
                time.sleep(ROUND_DELAY_SEC)

            if round_no % CAPTURE_EVERY == 0:
                _capture(client, f"round{round_no:02d}_del{len(deleted)}",
                         deleted, modified)

        if round_no % CAPTURE_EVERY != 0:                  # capture final state
            _capture(client, f"round{round_no:02d}_del{len(deleted)}",
                     deleted, modified)
    finally:
        if DISABLE_AUTO_CHECKPOINT:
            _syncdelay(client, 60)                         # restore default
            print("auto checkpoint restored (syncdelay=60)")
        client.close()

    print("experiment #2 complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
