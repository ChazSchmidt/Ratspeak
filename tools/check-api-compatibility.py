#!/usr/bin/env python3
"""Reject unreviewed changes from the Rust API compatibility floor."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "api" / "stability.json"


def fail(message: str) -> None:
    print(f"api compatibility: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_show(commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        fail(f"cannot read compatibility floor {commit}:{path}")
    return result.stdout


def load_floor_ledger(commit: str) -> dict[str, object]:
    for path in ("api/stability.json", "api-stability.json"):
        result = subprocess.run(
            ["git", "show", f"{commit}:{path}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    fail(f"cannot read API ledger at compatibility floor {commit}")


def main() -> None:
    metadata = subprocess.run(
        [sys.executable, "tools/check-api-baseline.py", "--metadata-only"], cwd=ROOT
    )
    if metadata.returncode != 0:
        fail("snapshot metadata or review is invalid")
    ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    floor = ledger.get("compatibilityFloor", {}).get("evidenceCommit")
    if not isinstance(floor, str):
        fail("api/stability.json has no compatibility-floor commit")
    floor_ledger = load_floor_ledger(floor)
    floor_snapshots = {
        package["name"]: package["snapshot"] for package in floor_ledger["packages"]
    }
    current_names = {package["name"] for package in ledger["packages"]}
    removed_packages = sorted(set(floor_snapshots) - current_names)
    if removed_packages:
        fail(f"packages removed from the compatibility floor: {removed_packages}")
    total_added = 0
    total_removed = 0
    packages_with_removals: list[dict[str, object]] = []
    for package in ledger["packages"]:
        path = package["snapshot"]
        floor_path = floor_snapshots.get(package["name"])
        if isinstance(floor_path, str):
            before = set(git_show(floor, floor_path).splitlines())
        elif package.get("tier") == "application-internal" and package.get(
            "compatibility"
        ) == "reviewed-snapshot":
            # A newly reviewed application-internal crate has no earlier API
            # to preserve. Count every current item as additive while keeping
            # removals of previously recorded packages fail-closed above.
            before = set()
        else:
            fail(f"{package['name']} is absent from the compatibility floor")
        after = set((ROOT / path).read_text(encoding="utf-8").splitlines())
        added = sorted(after - before)
        removed = sorted(before - after)
        total_added += len(added)
        total_removed += len(removed)
        if removed:
            packages_with_removals.append(package)
        print(f"{package['name']}: +{len(added)} -{len(removed)}")
        if removed:
            for line in removed:
                print(f"- {line}", file=sys.stderr)
    review = ledger["snapshotSource"]["review"]
    if review["publicApiDiff"] != {
        "added": total_added,
        "removed": total_removed,
    }:
        fail("snapshot review does not match the measured API diff")
    for package in packages_with_removals:
        if package.get("tier") != "application-internal" or package.get(
            "compatibility"
        ) != "reviewed-snapshot":
            fail(
                f"{package['name']} removes API outside the reviewed "
                "application-internal tier"
            )
    if total_removed:
        print(
            "api compatibility: explicitly reviewed application-internal change "
            f"(+{total_added}, -{total_removed})"
        )
    else:
        print(f"api compatibility: additive-only (+{total_added}, -0)")


if __name__ == "__main__":
    main()
