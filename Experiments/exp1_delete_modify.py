"""
Experiment #1 -- incremental delete + modify with controlled checkpoints.

Each round deletes STEP docs and modifies STEP docs from TestDB.ex1. The
cumulative counts grow by STEP each round (500, 1000, ... up to MAX). Delete/modify 
targets are disjoint so each _id is touched at most once (clean ground truth).

Checkpoint behaviour is chosen with a single SCENARIO knob, so you can study how
checkpoint frequency affects the recovery window:

    1  ONE checkpoint AFTER all operations    (auto off) -> a single image at end
    2  default auto checkpointing (60s)        (auto on)  -> a single image at end
    3  checkpoint after EACH 500 del+mod round (auto off) -> an image every round
    4  checkpoint every SPARSE_K rounds        (auto off) -> an image every K rounds

Each capture: fsyncLock -> copy the server dbpath -> fsyncUnlock, plus a
truth.json (namespace/deleted/modified) so the recovery tool can be scored.
The capture's fsyncLock IS the checkpoint, so scenarios 1/3/4 place checkpoints
exactly where the image is taken; scenario 2 leaves WiredTiger's 60s timer on.

A baseline checkpoint is forced at the start so the pristine 100k docs reach
disk BEFORE any delete/modify -- otherwise the original pages never become
orphans and nothing is recoverable. (This is separate from the scenario's
operation checkpoints; scenario 1 still means "no checkpoint between ops".)

Run with an optional scenario number:  python exp1_delete_modify.py 3
This script only performs operations, checkpoints, and image capture.
"""

from __future__ import annotations

import json
import random
import shutil
import sys
import time
from pathlib import Path

from pymongo import MongoClient, errors

# --- configuration ---------------------------------------------------------
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "TestDB"
COLL = "ex1"

START = 500
STEP = 500
MAX = 5000   # cumulative 500,1000,...,5000

SCENARIO = int(sys.argv[1]) if len(sys.argv) > 1 else 3   # 1,2,3,4 (CLI arg or default)
SPARSE_K = 3                     # scenario 4: checkpoint every SPARSE_K rounds

DBPATH = r"C:\Program Files\MongoDB\Server\8.3\data"   # server's --dbpath
CAPTURE_ROOT = r"C:\Users\Hardi-Admin\Desktop\Hardi's Work\Thesis\Experiments\MongoDB Tamper Lab\exp1_images" # where images are copied
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
    pool = {d["_id"] for d in coll.find({}, {"_id": 1})}
    if len(pool) < 2 * MAX:
        print(f"error: need >= {2 * MAX} docs in {COLL}, found {len(pool)}. "
              f"Run seed_ex1_ex2.py first.", file=sys.stderr)
        return 2

    client.admin.command({"fsync": 1})      # baseline checkpoint: seeded data -> disk
    print("baseline checkpoint written (pristine data now on disk)")

    if DISABLE_AUTO_CHECKPOINT:
        _syncdelay(client, 3_600)           # 1 hour (max allowed) = no auto ckpt mid-run
        print("auto checkpoint suppressed (syncdelay=3600)")

    deleted: dict[int, str] = {}
    modified: dict[int, str] = {}
    round_no = 0
    try:
        for _ in range(START, MAX + 1, STEP):
            round_no += 1
            picks = rng.sample(sorted(pool), 2 * STEP)     # disjoint per run
            del_ids, mod_ids = picks[:STEP], picks[STEP:]
            pool.difference_update(picks)

            for d in coll.find({"_id": {"$in": del_ids}}, {"data": 1}):
                deleted[d["_id"]] = str(d.get("data", ""))[:24]
            coll.delete_many({"_id": {"$in": del_ids}})

            for d in coll.find({"_id": {"$in": mod_ids}}, {"data": 1}):
                modified[d["_id"]] = str(d.get("data", ""))[:24]   # pre-image
            coll.update_many({"_id": {"$in": mod_ids}},
                             {"$set": {"tampered": True, "round": round_no}})

            print(f"round {round_no}: deleted {len(del_ids)}, modified "
                  f"{len(mod_ids)}  (cum del={len(deleted)}, mod={len(modified)})")

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

    print("experiment #1 complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
