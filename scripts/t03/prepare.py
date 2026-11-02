#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Prepare the pinned macOS arm64 tools and public upstream checkout for T03.

No wallet, registration, live deployment or upstream cleanup is run here.
Requires Python 3.9+, git and an existing rustup executable.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / ".local"
LOCK = json.loads((ROOT / "config/t03-tools.macos-arm64.json").read_text())


def run(command, **kwargs):
    subprocess.run(command, check=True, **kwargs)


def tools():
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise SystemExit("This tool lock covers macOS arm64 only; do not substitute binaries.")
    root = LOCAL / "tools"
    (root / "downloads").mkdir(parents=True, exist_ok=True)
    (root / "bin").mkdir(exist_ok=True)
    for item in LOCK["tools"]:
        archive = root / "downloads" / item["url"].rsplit("/", 1)[1]
        if not archive.exists():
            request = urllib.request.Request(item["url"], headers={"User-Agent": "local-baseline-reproduction"})
            with urllib.request.urlopen(request, timeout=120) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("Download checksum mismatch: " + item["name"])
            archive.write_bytes(data)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Cached checksum mismatch: " + item["name"])
        destination = root / item["name"]
        destination.mkdir(exist_ok=True)
        if item.get("archiveType") == "zip":
            with zipfile.ZipFile(archive) as bundle:
                for member in bundle.infolist():
                    if not (destination / member.filename).resolve().is_relative_to(destination):
                        raise ValueError("Unsafe zip path")
                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError("Unexpected zip symbolic link")
                bundle.extractall(destination)
            for relative in item["links"].values():
                (destination / relative).chmod(0o755)
        elif item["archive"]:
            with tarfile.open(archive) as bundle:
                for member in bundle.getmembers():
                    target = (destination / member.name).resolve()
                    if not target.is_relative_to(destination):
                        raise ValueError("Unsafe archive path")
                    if member.issym() or member.islnk():
                        base = target.parent if member.issym() else destination
                        if not (base / member.linkname).resolve().is_relative_to(destination):
                            raise ValueError("Unsafe archive link")
                bundle.extractall(destination)
        else:
            executable = destination / next(iter(item["links"].values()))
            executable.write_bytes(archive.read_bytes())
            executable.chmod(0o755)
        for name, relative in item["links"].items():
            link = root / "bin" / name
            target = destination / relative
            if link.is_symlink():
                link.unlink()
            elif link.exists():
                # Earlier local preparation may have installed this binary directly.
                # Never replace an unrelated tool or follow a path outside .local.
                if hashlib.sha256(link.read_bytes()).digest() != hashlib.sha256(target.read_bytes()).digest():
                    raise ValueError("Unexpected existing local tool: " + name)
                link.unlink()
            link.symlink_to(os.path.relpath(target, link.parent))
        print("Verified " + item["name"] + " " + item["version"], flush=True)

    rustup = shutil.which("rustup")
    if not rustup:
        raise SystemExit("rustup is required; install it before preparing this baseline.")
    cargo_bin = LOCAL / "cargo/bin"
    cargo_bin.mkdir(parents=True, exist_ok=True)
    local_rustup = cargo_bin / "rustup"
    if Path(rustup).resolve() != local_rustup.resolve():
        shutil.copy2(rustup, local_rustup)
    for name in ("cargo", "rustc", "rustdoc", "cargo-fmt", "rustfmt", "cargo-clippy", "clippy-driver"):
        link = cargo_bin / name
        if not link.exists():
            link.symlink_to("rustup")
    env = dict(os.environ, CARGO_HOME=str(LOCAL / "cargo"), RUSTUP_HOME=str(LOCAL / "rustup"))
    run([str(local_rustup), "toolchain", "install", LOCK["rustToolchain"], "--profile", "minimal",
         "--target", ",".join(LOCK["rustTargets"])], env=env)


def source():
    upstream = LOCAL / "upstream/interfold"
    upstream.parent.mkdir(parents=True, exist_ok=True)
    if not upstream.exists():
        run(["git", "clone", "--filter=blob:none", "--no-checkout", LOCK["sourceRepository"], str(upstream)])
        run(["git", "checkout", "--detach", LOCK["sourceRevision"]], cwd=upstream)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=upstream, text=True).strip()
    if revision != LOCK["sourceRevision"]:
        raise ValueError("Upstream revision differs; existing checkout was not reset")
    print("Verified upstream " + revision)
    patch = ROOT / "patches/t03-local.patch"
    reverse = subprocess.run(["git", "apply", "--reverse", "--check", str(patch)], cwd=upstream,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if reverse.returncode:
        run(["git", "apply", "--check", str(patch)], cwd=upstream)
        run(["git", "apply", str(patch)], cwd=upstream)
    print("Verified T03 local patch")


if __name__ == "__main__":
    tools()
    source()
