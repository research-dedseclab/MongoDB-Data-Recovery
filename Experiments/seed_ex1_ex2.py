"""
Seed script -- MongoDB recovery experiments.

Reproduces the base experimental dataset 
        Database : TestDB   (standalone mongod, WiredTiger)
        ex1      : 100,000 documents
        ex2      :   1,000 documents
        each document holds a random string; the total document size
        varies from 100 to 4096 bytes.
This script ONLY seeds the database. It performs NO deletes, no
insert+delete cycles, no drops of ex2, no checkpoint and no recovery --
those belong to the Experiment #1 / #2 scripts you run afterwards.
"""

from __future__ import annotations

import base64
import os
import random
import sys

import bson
from pymongo import MongoClient, errors

# --- configuration ----------------------
# MONGO_URI = "mongodb://localhost:27017"
MONGO_URI = "mongodb://localhost:27017, localhost:27018, localhost:27019/?replicaSet=rs0"
DB_NAME = "TestDB"

EX1_COUNT = 100_000
EX2_COUNT = 1_000

MIN_SIZE = 100      # smallest document, bytes 
MAX_SIZE = 4096     # largest document, bytes 
BATCH = 1_000       # documents per insert_many
SIZE_SEED = 1234    # reproducible size distribution


def _rand_str(n: int) -> str:
    """Fast, unique, high-entropy ASCII string of exactly n characters.
    One char == one byte in a BSON string, so this is what sets doc size."""
    raw = base64.b64encode(os.urandom((n * 3) // 4 + 3)).decode("ascii")
    return raw[:n]


def _make_doc(_id: int, rng: random.Random) -> dict:
    """A document whose total BSON size is a random value in
    [MIN_SIZE, MAX_SIZE], per the paper's 100-4096 byte range."""
    target = rng.randint(MIN_SIZE, MAX_SIZE)
    overhead = len(bson.encode({"_id": _id, "data": ""}))
    return {"_id": _id, "data": _rand_str(max(1, target - overhead))}


def _seed(coll, count: int, rng: random.Random) -> int:
    inserted = 0
    batch: list[dict] = []
    for i in range(1, count + 1):
        batch.append(_make_doc(i, rng))
        if len(batch) >= BATCH:
            coll.insert_many(batch, ordered=False)
            inserted += len(batch)
            batch.clear()
            if inserted % 10_000 == 0:
                print(f"    {coll.name}: {inserted:,}/{count:,}")
    if batch:
        coll.insert_many(batch, ordered=False)
        inserted += len(batch)
    return inserted


def main() -> int:
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
    except errors.ServerSelectionTimeoutError as e:
        print(f"error: cannot reach MongoDB at {MONGO_URI}: {e}", file=sys.stderr)
        return 1

    db = client[DB_NAME]
    rng = random.Random(SIZE_SEED)

    print(f"seeding '{DB_NAME}' on {MONGO_URI}")

    # fresh baseline so re-runs start clean
    db["ex1"].drop()
    db["ex2"].drop()

    print(f"  ex1: inserting {EX1_COUNT:,} documents ...")
    n1 = _seed(db["ex1"], EX1_COUNT, rng)
    print(f"  ex2: inserting {EX2_COUNT:,} documents ...")
    n2 = _seed(db["ex2"], EX2_COUNT, rng)

    print(f"done: ex1={n1:,} docs, ex2={n2:,} docs")
    print("note: seeding does NOT checkpoint. Force a checkpoint (or cleanly "
          "stop mongod) before capturing the .wt image.")
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
