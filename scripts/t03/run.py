#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Run the isolated T03 synthetic baseline. Start from scripts/t03/env.sh in bash.

All mutable state and logs are ignored. Only processes started here are stopped.
The headless SDK exercises the ballot path; this is not a browser usability test.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / ".local/upstream/interfold"
CRISP = UPSTREAM / "examples/CRISP"
RUN = ROOT / ".local/runs" / ("t03-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
CHILDREN = []
HANDLES = []
PHASES = {}


def available_ports():
    for port in (8545, 4000, 13151, 13415, 8080, 50501, 50502, 50503, 50504, 50505):
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", port))
    for port in range(9201, 9206):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind(("127.0.0.1", port))


def start(name, command, cwd=CRISP):
    print("Starting " + name, flush=True)
    handle = (RUN / (name + ".log")).open("w")
    HANDLES.append(handle)
    child = subprocess.Popen(command, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
    CHILDREN.append((name, child))
    (RUN / "processes.json").write_text(json.dumps({n: p.pid for n, p in CHILDREN}, indent=2) + "\n")
    return child


def wait_for(name, predicate, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        for service, child in CHILDREN:
            if service in ("anvil", "randomness", "nodes", "program", "server") and child.poll() is not None:
                raise RuntimeError(service + " exited; inspect its ignored log")
        time.sleep(1)
    raise TimeoutError("Timed out waiting for " + name)


def port_open(port):
    with socket.socket() as connection:
        return connection.connect_ex(("127.0.0.1", port)) == 0


def step(name, command, cwd=CRISP, timeout=1800):
    start_at = time.monotonic()
    child = start(name, command, cwd)
    try:
        code = child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        raise TimeoutError(name + " exceeded its limit; inspect its ignored log")
    PHASES[name + "Ms"] = round((time.monotonic() - start_at) * 1000)
    if code:
        raise RuntimeError(name + " failed with exit " + str(code) + "; inspect its ignored log")


def update_server_env():
    path = CRISP / "server/.env"
    values = {
        "CRISP_BIND_ADDR": "127.0.0.1:4000", "E3_DURATION": "7200",
        "RELAY_MAX_INPUTS_PER_SLOT": "0", "RELAY_MAX_INPUTS_PER_ROUND": "0",
        "RUST_LOG": "info",
    }
    lines = path.read_text().splitlines()
    for key, value in values.items():
        lines = [line for line in lines if not line.startswith(key + "=")]
        lines.append(key + "=" + value)
    path.write_text("\n".join(lines) + "\n")


def cleanup():
    # The node script's signal trap stops its own swarm. Other descendants share our groups.
    for _, child in reversed(CHILDREN):
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 10
    for _, child in CHILDREN:
        try:
            child.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)
    for handle in HANDLES:
        handle.close()


def stop(name):
    for service, child in CHILDREN:
        if service == name:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            child.wait(timeout=20)
            return


def main():
    if os.environ.get("T03_ROOT") != str(ROOT):
        raise RuntimeError("Source scripts/t03/env.sh from bash first")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=UPSTREAM, text=True).strip() != "4ace535c1ff4d7897ec958a943cb45c55dc298a7":
        raise RuntimeError("Wrong upstream source")
    subprocess.run(["git", "apply", "--reverse", "--check", str(ROOT / "patches/t03-local.patch")], cwd=UPSTREAM, check=True)
    available_ports()
    RUN.mkdir(parents=True)
    print("Ignored run directory: " + str(RUN), flush=True)
    chains = json.loads(subprocess.check_output(["yq", "-o=json", ".chains", "interfold.config.yaml"], cwd=CRISP, text=True))
    enabled = [chain for chain in chains if chain.get("enabled", True)]
    if len(enabled) != 1 or enabled[0]["name"] != "localhost" or enabled[0]["rpc_url"] not in ("ws://localhost:8545", "ws://127.0.0.1:8545"):
        raise RuntimeError("Only the isolated localhost chain may be enabled")
    # Preserve owned old state rather than invoke the upstream broad cleanup script.
    for path in (CRISP / ".interfold/data", CRISP / ".interfold/config", CRISP / "server/database"):
        if path.exists():
            path.rename(RUN / ("prior-" + path.parent.name.lstrip(".") + "-" + path.name))
    ready = CRISP / ".interfold/ready"
    if ready.exists():
        ready.unlink()
    start("anvil", ["anvil", "--host", "127.0.0.1", "--chain-id", "31337", "--block-time", "1", "--silent"])
    wait_for("local chain", lambda: port_open(8545))
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
    with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8545", data=body, headers={"Content-Type": "application/json"}), timeout=10) as response:
        if json.load(response)["result"] != "0x7a69":
            raise RuntimeError("Refuse a nonlocal chain")
    start("randomness", ["node", "scripts/anvil-randomness.mjs"])
    step("deploy", ["bash", "scripts/crisp_deploy.sh"])
    update_server_env()
    start("nodes", ["bash", "scripts/dev_cipher.sh", str(ready)])
    wait_for("registered local nodes", ready.is_file, 900)
    start("program", [str(CRISP / "target/debug/e3-support-scripts-dev")])
    wait_for("loopback development program", lambda: port_open(13151))
    start("server", [str(CRISP / "target/debug/server")], CRISP / "server")
    wait_for("CRISP server", lambda: port_open(4000))
    step("request", [str(CRISP / "target/debug/cli"), "init", "--balance-threshold", "1"], CRISP / "server")
    last = (RUN / "request.log").read_text().strip().splitlines()[-1]
    if not last.isdecimal():
        raise RuntimeError("CLI did not return a round ID")
    e3_id = last
    key_started = time.monotonic()

    def key_ready():
        result = subprocess.run([str(CRISP / "target/debug/cli"), "check-e3-ready", "--e3id", e3_id], cwd=CRISP / "server", capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip().splitlines()[-1:] == ["true"]

    wait_for("authenticated committee key", key_ready, 600)
    PHASES["requestToKeyObservedMs"] = round((time.monotonic() - key_started) * 1000)
    step("ballots", ["pnpm", "exec", "tsx", str(ROOT / "scripts/t03/ballots.mts"), "round", e3_id, str(RUN / "baseline.json")], UPSTREAM, timeout=3600)
    baseline = json.loads((RUN / "baseline.json").read_text())
    baseline["lifecycleMeasurements"] = PHASES
    baseline["patchSha256"] = hashlib.sha256((ROOT / "patches/t03-local.patch").read_bytes()).hexdigest()
    (RUN / "baseline.json").write_text(json.dumps(baseline, indent=2) + "\n")
    (ROOT / ".local/latest-t03-run").write_text(str(RUN) + "\n")
    print("T03 baseline passed; raw evidence: " + str(RUN), flush=True)
    # Release committee/prover memory before the secure client component check.
    stop("nodes")
    stop("program")
    secure = {"scope": "secure client component; compute, DKG and threshold-decryption proofs are separate"}
    try:
        step("secure-sdk-build", ["pnpm", "--filter", "@crisp-e3/sdk", "build:prod"], UPSTREAM, timeout=3600)
        step("secure-client", ["pnpm", "exec", "tsx", str(ROOT / "scripts/t03/ballots.mts"), "secure-client", e3_id, str(RUN / "secure-client.json")], UPSTREAM, timeout=1800)
        secure["status"] = "passed"
    except (RuntimeError, TimeoutError) as error:
        secure["status"] = "blocked"
        secure["reason"] = str(error)
        print("Secure client attempt did not pass; inspect the ignored phase log.", flush=True)
    (RUN / "secure-attempt.json").write_text(json.dumps(secure, indent=2) + "\n")
    (RUN / "lifecycle.json").write_text(json.dumps(PHASES, indent=2) + "\n")


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    finally:
        cleanup()
