#!/usr/bin/env python3
"""Fetch the locked repositories and seed checked Buildroot download entries."""
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "sources.lock.json").read_text())


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


for name in ("firmware", "builder"):
    source = LOCK[name]
    revision = source["commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit(f"Invalid revision for {name}")
    destination = ROOT / name
    destination.mkdir()
    run("git", "init", "--quiet", cwd=destination)
    run("git", "remote", "add", "origin", source["url"], cwd=destination)
    run("git", "fetch", "--no-tags", "--depth=1", "origin", revision, cwd=destination)
    run("git", "checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=destination)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=destination, text=True).strip()
    if head != revision:
        raise SystemExit(f"Source commit mismatch: {name}")

for source in LOCK["downloads"]:
    dest = Path(os.environ["BR2_DL_DIR"]) / source["path"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    try:
        run("curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
            "--connect-timeout", "15", "--max-time", "300", "--output", str(partial), source["url"])
        if hashlib.sha256(partial.read_bytes()).hexdigest() != source["sha256"]:
            raise SystemExit(f"Upstream artifact changed: {source['path']}")
        partial.replace(dest)
    finally:
        partial.unlink(missing_ok=True)
