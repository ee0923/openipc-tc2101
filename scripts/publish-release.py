#!/usr/bin/env python3
"""Publish one verified TC2101 firmware artifact to its upstream source release."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
BUILD_LABEL = re.compile(r"TC2101 build ([1-9][0-9]*)/([1-9][0-9]*) \(([1-9][0-9]*), ([0-9a-f]{40})\)")


def gh(*args, data=None):
    return subprocess.check_output(
        ["gh", *args], text=True, input=json.dumps(data) if data is not None else None
    )


def api(path, method="GET", data=None):
    args = ["api", "--method", method, f"repos/{os.environ['GITHUB_REPOSITORY']}/{path}"]
    raw = gh(*args, *(("--input", "-") if data is not None else ()), data=data)
    return json.loads(raw) if raw.strip() else None


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validated_files(dist, soc, lock, env):
    if soc not in {"ssc335", "ssc337"} or dist.is_symlink():
        raise ValueError("Expected one TC2101 model")
    archive = dist / f"openipc-tc2101-{soc}-nor-lite.tgz"
    sums, info = dist / "SHA256SUMS", dist / "manifest.json"
    files = (archive, sums, info)
    if set(dist.iterdir()) != set(files) or any(
        item.is_symlink() or not item.is_file() or item.stat().st_size == 0 for item in files
    ):
        raise ValueError("Invalid firmware artifact contents")
    if sums.read_text() != f"{sha(archive)}  {archive.name}\n":
        raise ValueError("Firmware archive does not match SHA256SUMS")
    manifest = json.loads(info.read_text())
    expected = {"soc": soc, "flash_bytes": 0x1000000, "source_lock": lock,
                "build_revision": env["GITHUB_SHA"], "run_id": env["GITHUB_RUN_ID"],
                "run_attempt": env["TC2101_ARTIFACT_ATTEMPT"]}
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise ValueError("Firmware manifest does not match the requested model and build")
    return files


def verify_asset(asset, file, digest):
    if (asset["state"] != "uploaded" or asset["size"] != file.stat().st_size
            or asset.get("digest") != f"sha256:{digest}"):
        raise ValueError(f"Published firmware failed server verification: {asset['name']}")


def releases():
    repo = os.environ["GITHUB_REPOSITORY"]
    pages = gh("api", "--paginate", "--slurp", f"repos/{repo}/releases?per_page=100")
    return [release for page in json.loads(pages) for release in page]


def publish(dist, soc, lock, env):
    repo = env["GITHUB_REPOSITORY"]
    if repo != env.get("GH_REPO") or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Expected the current Actions repository")
    upstream = lock["firmware"]["commit"]
    if not SOURCE_SHA.fullmatch(upstream) or not SOURCE_SHA.fullmatch(env["GITHUB_SHA"]):
        raise ValueError("Expected locked upstream and build commits")
    run_number, run_attempt, run_id = (env[k] for k in ("GITHUB_RUN_NUMBER", "TC2101_ARTIFACT_ATTEMPT", "GITHUB_RUN_ID"))
    label = f"TC2101 build {run_number}/{run_attempt} ({run_id}, {env['GITHUB_SHA']})"
    if not BUILD_LABEL.fullmatch(label):
        raise ValueError("Invalid Actions run identity")
    files = validated_files(dist, soc, lock, env)

    tag = f"openipc-{upstream}"
    marker = f"<!-- tc2101-upstream:{upstream} -->"
    body = (f"Unofficial H3C TC2101 OpenIPC Lite firmware based on "
            f"[OpenIPC firmware `{upstream[:12]}`](https://github.com/OpenIPC/firmware/commit/{upstream}).\n\n"
            "SSC335 and SSC337 are uploaded as their builds pass verification. Match the SoC and "
            "16 MiB NOR layout before flashing. Each ZIP includes the firmware, SHA256SUMS and "
            "its build and partition manifest. Hardware boot of these builds has not been verified.\n\n"
            + marker)
    matches = [r for r in releases() if r["tag_name"] == tag]
    if len(matches) > 1:
        raise ValueError("Multiple releases already use the upstream tag")
    if matches:
        release = matches[0]
        if marker not in (release.get("body") or "") or release.get("immutable"):
            raise ValueError("Existing release is unrecognized or immutable")
    else:
        # A published release must never start out empty.
        release = api("releases", "POST", {"tag_name": tag, "target_commitish": env["GITHUB_SHA"],
                      "name": f"TC2101 OpenIPC {upstream[:12]}", "body": body, "draft": True})
    rid = release["id"]
    canonical = f"openipc-tc2101-{soc}-nor-lite.zip"
    existing = next((a for a in release["assets"] if a["name"] == canonical), None)
    if existing:
        previous = BUILD_LABEL.fullmatch(existing.get("label") or "")
        if not previous:
            raise ValueError("Refusing to replace an asset without TC2101 build provenance")
        if tuple(map(int, previous.group(1, 2))) > (int(run_number), int(run_attempt)):
            raise ValueError("A newer build has already published this model")

    stage_prefix = f"tc2101-staging-{soc}-"
    stage_name = f"{stage_prefix}{run_id}-{run_attempt}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / stage_name
        with zipfile.ZipFile(stage, "w") as bundle:
            for file in files:
                bundle.write(file, file.name)
        digest = sha(stage)
        if existing and existing.get("label") == label and existing.get("digest") == f"sha256:{digest}":
            verify_asset(existing, stage, digest)
        else:
            gh("release", "upload", tag, str(stage), "--clobber", "--repo", repo)
            uploaded = next(a for a in api(f"releases/{rid}")["assets"] if a["name"] == stage_name)
            verify_asset(uploaded, stage, digest)
            # Verify the replacement before removing the previous asset for this model.
            if existing:
                api(f"releases/assets/{existing['id']}", "DELETE")
            api(f"releases/assets/{uploaded['id']}", "PATCH", {"name": canonical, "label": label})
        if release["draft"]:
            api(f"releases/{rid}", "PATCH", {"draft": False})
        final = api(f"releases/{rid}")
        asset = next(a for a in final["assets"] if a["name"] == canonical)
        if final["draft"] or final["tag_name"] != tag or asset.get("label") != label:
            raise ValueError("Release or artifact identity differs after publication")
        verify_asset(asset, stage, digest)
    for asset in final["assets"]:
        if re.fullmatch(re.escape(stage_prefix) + r"[1-9][0-9]*-[1-9][0-9]*\.zip", asset["name"]):
            api(f"releases/assets/{asset['id']}", "DELETE")
    print(f"Published {soc}: https://github.com/{repo}/releases/tag/{tag} ({digest})")


if __name__ == "__main__":
    publish(ROOT / "dist", os.environ["TC2101_SOC"],
            json.loads((ROOT / "sources.lock.json").read_text()), os.environ)
