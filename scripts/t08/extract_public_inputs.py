#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Extract only the checksum-checked public computation input stream, never a proof or witness."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def extract(archive, destination):
    if destination.exists():
        raise ValueError('Destination exists; preserve it')
    selected = None
    manifest_path = archive.parent / 'round-evidence-manifest.json'
    manifest_bytes = manifest_path.read_bytes()
    sums = (archive.parent / 'SHA256SUMS.txt').read_text().splitlines()
    expected = [line.split()[0] for line in sums if line.split()[-1].lstrip('*') == manifest_path.name]
    if len(expected) != 1 or hashlib.sha256(manifest_bytes).hexdigest() != expected[0]:
        raise ValueError('Public evidence manifest checksum differs')
    manifest = json.loads(manifest_bytes)
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            if member.name.endswith('/input.bin') and member.name.startswith('.state/compute/'):
                if selected is not None or not member.isfile() or member.size > 16 * 1024 * 1024:
                    raise ValueError('Unexpected public input member')
                selected = (member.name, stream.extractfile(member).read())
                break
    if selected is None or manifest is None:
        raise ValueError('Missing input or checksum manifest')
    name, data = selected
    item = manifest['files'][name]
    if item['bytes'] != len(data) or item['sha256'] != hashlib.sha256(data).hexdigest():
        raise ValueError('Input checksum differs')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as output:
        output.write(data)
    destination.chmod(0o600)
    print(json.dumps({'file': str(destination), 'bytes': len(data), 'sha256': item['sha256']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    extract(args.archive, args.destination)
