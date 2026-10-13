"""
Driver: run all four Experiment #1 scenarios end to end, hands-off.

For each scenario it:
  1. re-seeds the pristine 100k/1k baseline   (seed_ex1_ex2.py)
  2. runs that scenario                        (exp1_delete_modify.py <s>)
  3. scores the images into a CSV              (evaluate_images.py <s>)

Run from the project folder:  python run_exp1_all.py

Notes:
  * Each scenario re-inserts 100k docs, so this is thorough but not fast.
  * Images use disk (~4-5 GB across all four scenarios) under exp1_images\\.
  * Edit SCENARIOS below to run only a subset.
"""

import subprocess
import sys

SCENARIOS = [1, 2, 3, 4]
PY = sys.executable          # reuse the interpreter that launched this script


def run(*args: str) -> None:
    print(f"\n=== {' '.join(args)} ===", flush=True)
    if subprocess.run([PY, *args]).returncode != 0:
        raise SystemExit(f"failed: {' '.join(args)}")


def main() -> None:
    for s in SCENARIOS:
        run("seed_ex1_ex2.py")
        run("exp1_delete_modify.py", str(s))
        run("evaluate_images.py", str(s))
    print("\nall scenarios done -> exp1_results_scenario{1,2,3,4}.csv")


if __name__ == "__main__":
    main()
