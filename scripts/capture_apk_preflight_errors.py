#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Capture complete original APK output-budget counts and error precedence.

Every refusal is produced by the frozen real Provider and Service, followed by
the original error projector. Owned ZIP constructors and public signing blocks
supply inputs; no native result is fed into the reference. No APK executes.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import time
import zipfile
import zlib


FROZEN_PACKAGE = '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def inputs(repo):
    q = module(repo / 'scripts/qualify_apk_observations.py', 'apk_owned_inputs')
    source = repo / 'tests/fixtures/rea_apk_signature'
    encoded = json.loads((source / 'service-error-bytes-r1.json').read_text())
    row = next(x for x in encoded['cases'] if x['name'] == 'declared-frozen-output-digest-1')
    compressed = bytes.fromhex(row['data'])
    assert sha(compressed) == row['compressed_sha256']
    big = zlib.decompress(compressed)
    assert len(big) == row['bytes'] and sha(big) == row['sha256']
    rotated = (source / 'rotation-v31.apk').read_bytes()
    assert sha(rotated) == '5127923e25443cfe023ec6ca2acdb6c188b1502665f244a2584a899d2885ee09'
    big_pairs = q.block_pairs(big)
    assert all(ident not in (q.V3, q.V31) for ident, _ in big_pairs)
    later_pairs = [(ident, data) for ident, data in q.block_pairs(rotated) if ident in (q.V3, q.V31)]
    assert {ident for ident, _ in later_pairs} == {q.V3, q.V31}
    output = {
        'oversized-v2-plus-v3-and-v31': q.rebuild(big, big_pairs + later_pairs),
        'oversized-v2-before-malformed-v3': q.rebuild(big, big_pairs + [(q.V3, b'')]),
    }
    # Supplementary characters occupy two JavaScript UTF-16 code units. The
    # metadata stays below the 4096-entry cap and has no paired v1 signers.
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for index in range(4096):
            name = 'META-INF/' + str(index).zfill(4) + '\U00010000' * 180 + '.SF'
            archive.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), b'')
    names = stream.getvalue()
    output['oversized-v1-utf16-name-array'] = names
    output['oversized-v1-names-before-malformed-v3'] = q.rebuild(names, [(q.V3, b'')])
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--rea-install', type=Path, required=True)
    parser.add_argument('--rea-tarball', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    package = args.rea_tarball.read_bytes()
    assert sha(package) == FROZEN_PACKAGE
    checked = 0
    with tarfile.open(fileobj=io.BytesIO(package), mode='r:gz') as archive:
        for member in archive:
            if member.isfile():
                assert member.name.startswith('package/') and '..' not in Path(member.name).parts
                assert (args.rea_install / member.name.removeprefix('package/')).read_bytes() == archive.extractfile(member).read()
                checked += 1
    fixtures = args.out / 'fixtures'
    fixtures.mkdir()
    (args.out / 'cases').mkdir()
    owned = inputs(args.repo)
    manifest = []
    compressed_inputs = []
    for name, data in owned.items():
        path = fixtures / (name + '.apk')
        path.write_bytes(data)
        path.chmod(0o400)
        manifest.append(dict(name=name, path=str(path), bytes=len(data), sha256=sha(data),
                             expected_tag=None, source='Owned constructor in capture_apk_preflight_errors.py'))
        packed = zlib.compress(data, 9)
        compressed_inputs.append(dict(name=name, bytes=len(data), sha256=sha(data), encoding='zlib-hex',
                                      compressed_bytes=len(packed), compressed_sha256=sha(packed), data=packed.hex()))
    request = dict(root=str(args.rea_install), out=str(args.out), cases=manifest)
    stdin = json.dumps(request, separators=(',', ':')).encode()
    (args.out / 'request.json').write_bytes(stdin)
    reference = module(args.repo / 'scripts/capture_apk_service_errors.py', 'apk_original_error_runner')
    (args.out / 'runner.mjs').write_text(reference.NODE)
    argv = ['node', str(args.out / 'runner.mjs')]
    started = time.monotonic()
    result = subprocess.run(argv, input=stdin, capture_output=True, timeout=90, cwd='/', env={})
    (args.out / 'reference.stdout.json').write_bytes(result.stdout)
    (args.out / 'reference.stderr.log').write_bytes(result.stderr)
    receipt = dict(argv=argv, timeout_seconds=90, exit_code=result.returncode, seconds=time.monotonic() - started,
                   stdin_sha256=sha(stdin), stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr))
    (args.out / 'reference.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    reported = json.loads(result.stdout)
    errors = json.loads((args.out / 'errors.json').read_text())
    assert reported['cases'] == len(owned) == len(errors) == 4
    by_name = {row['name']: row for row in errors}
    assert {row['name'] for row in compressed_inputs} == set(by_name)
    for row in compressed_inputs:
        row['reference'] = by_name[row['name']]
    for name in ['oversized-v2-before-malformed-v3', 'oversized-v1-names-before-malformed-v3']:
        assert by_name[name]['typed_error']['_tag'] == 'AnalysisInputError'
    for name in ['oversized-v2-plus-v3-and-v31', 'oversized-v1-utf16-name-array']:
        assert by_name[name]['typed_error']['_tag'] == 'AnalysisResourceConstraintError'
        assert by_name[name]['expected']['details']['resource'] == 'capacity'
    aggregate = dict(format='hepta.apk-preflight-original-errors.v1', frozen_npm_tarball_sha256=FROZEN_PACKAGE,
                     frozen_install_files_checked=checked, oracle_node=reported['node'],
                     oracle_openssl=reported['openssl'], cases=compressed_inputs)
    aggregate_path = args.out / 'preflight-errors-r1.json'
    aggregate_path.write_text(json.dumps(aggregate, indent=2) + '\n')
    summary = dict(passed=True, cases=len(owned), receipt=receipt, frozen_install_files_checked=checked,
                   frozen_npm_tarball_sha256=FROZEN_PACKAGE, fixture_bytes=sum(map(len, owned.values())),
                   compressed_bytes=sum(row['compressed_bytes'] for row in compressed_inputs),
                   aggregate_sha256=sha(aggregate_path.read_bytes()), aggregate_bytes=aggregate_path.stat().st_size,
                   script_sha256=sha(Path(__file__).read_bytes()),
                   helpers={name: sha((args.repo / 'scripts' / name).read_bytes()) for name in
                            ['qualify_apk_observations.py', 'capture_apk_service_errors.py']},
                   scope='Four actual original projected refusals. Native producer and runtime qualification are separate.')
    (args.out / 'qualification.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
