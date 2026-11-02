#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Install only pinned Node, pnpm and Anvil locally. No Rust, SDK build or proving setup."""
import hashlib
import json
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tarfile
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def prepare():
    system = (platform.system(), platform.machine())
    if system == ('Darwin', 'arm64'):
        source = json.loads((ROOT / 'config/t03-tools.macos-arm64.json').read_text())
        tools = {x['name']: x for x in source['tools']}
    elif system == ('Linux', 'x86_64'):
        tools = json.loads((ROOT / 'scripts/t08/round/tools.json').read_text())
    else:
        raise ValueError('Supported verification hosts: macOS arm64 and Linux x86_64')
    local = ROOT / '.local/public-verifier-tools'
    downloads = local / 'downloads'
    binary = local / 'bin'
    downloads.mkdir(parents=True, exist_ok=True)
    binary.mkdir(exist_ok=True)
    for name in ['node', 'pnpm', 'foundry']:
        item = tools[name]
        archive = downloads / item['url'].rsplit('/', 1)[-1]
        old = ROOT / '.local/tools/downloads' / archive.name
        if old.is_file() and sha(old) == item['sha256']:
            archive = old
        if not archive.exists():
            partial = archive.with_suffix('.partial')
            with urlopen(Request(item['url'], headers={'User-Agent': 'public-round-verification'}), timeout=120) as response, partial.open('wb') as output:
                shutil.copyfileobj(response, output)
            if sha(partial) != item['sha256']:
                raise ValueError('Download checksum differs: ' + name)
            partial.replace(archive)
        if sha(archive) != item['sha256']:
            raise ValueError('Saved tool checksum differs: ' + name)
        with tarfile.open(archive) as tar:
            if name == 'pnpm':
                destination = local / 'pnpm'
                destination.mkdir(exist_ok=True)
                for member in tar.getmembers():
                    if not (destination / member.name).resolve().is_relative_to(destination.resolve()) or not (member.isfile() or member.isdir()):
                        raise ValueError('Unexpected pnpm archive member')
                tar.extractall(destination)
                target = destination / 'package/bin/pnpm.cjs'
                target.chmod(0o755)
                link = binary / 'pnpm'
                if link.is_symlink():
                    link.unlink()
                if link.exists():
                    raise ValueError('Unexpected existing pnpm command')
                link.symlink_to(target)
            else:
                command = 'anvil' if name == 'foundry' else 'node'
                candidates = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == command]
                if len(candidates) != 1:
                    raise ValueError('Expected one executable: ' + command)
                target = binary / command
                with tar.extractfile(candidates[0]) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755)
        print('Verified ' + name, flush=True)
    env = local / 'env.sh'
    env.write_text('export PATH=' + shlex.quote(str(binary)) + ':"$PATH"\n')
    print(subprocess.check_output([str(binary / 'node'), '--version'], text=True).strip())
    print(subprocess.check_output([str(binary / 'anvil'), '--version'], text=True).splitlines()[0])
    print('Next: source ' + str(env) + '; pnpm install --frozen-lockfile --ignore-scripts')


if __name__ == '__main__':
    prepare()
