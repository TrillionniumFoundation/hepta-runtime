# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Data-only regression controls for completed fixture transport."""
from pathlib import Path
import copy, json, os, shutil, tempfile
import lifecycle_fixtures as fixtures
from lifecycle_inputs import pin
from lifecycle_success_projection import capture_tree, SORTED

DOMAINS = ('preflight', 'success', 'pending')
NAMES = ('live-byte-change', 'copied-retired-capture', 'snapshot-byte-change',
         'verifier-source-change', 'process-owner-change', 'raw-stream-change',
         'missing-retirement', 'reappeared-fixture', 'unreaped-owner')
EXPECTED = [dict(domain=domain, name=name, passed=True)
            for domain in DOMAINS for name in NAMES]


def rejected(call):
    try:
        call()
    except (AssertionError, ValueError, KeyError, FileNotFoundError):
        return
    raise AssertionError('damaged fixture evidence was accepted')


def run():
    results = []
    with tempfile.TemporaryDirectory(prefix='public-fixture-transport-') as temporary:
        for domain in DOMAINS:
            folder = Path(temporary) / domain
            folder.mkdir()
            state = folder / 'final-state'
            state.mkdir(mode=0o700)
            (state / 'payload').write_bytes(b'complete\x00owned\xffbytes')
            os.link(state / 'payload', state / 'alias')
            trees = capture_tree(state, True)
            if domain == 'preflight':
                root = dict(trees.pop('')); root.pop('kind')
                for row in trees.values():
                    row.pop('stable', None)
                final = dict(root_stat=root, full=trees)
            else:
                final = dict(filesystem=trees)
                fence = folder / 'final-fence'; fence.mkdir(mode=0o700)
                (fence / '.owner.lock').write_bytes(b'')
                before = {'fence': capture_tree(fence, True)}
                for name in ('fence-before.json', 'fence-after.json'):
                    (folder / name).write_bytes(SORTED(before))
            (folder / 'eof-filesystem.json').write_bytes(SORTED(final))
            for name, raw in (('input.bin', b'input\n'), ('stdout.bin', b'output\n'), ('stderr', b'')):
                (folder / name).write_bytes(raw)
            process = dict(status='PASS', exit_code=0, reaped=True, pid=os.getpid(), side='native',
                **{name: pin(folder / name) for name in ('input.bin', 'stdout.bin', 'stderr')})
            if domain == 'pending':
                process.update(status='CAPTURED_NOT_QUALIFIED', full_capture=True, qualification=False)
            assert fixtures.admit(folder, domain, process) is False
            original = (state / 'payload').read_bytes()
            (state / 'payload').write_bytes(b'changed')
            rejected(lambda: fixtures.admit(folder, domain, process))
            (state / 'payload').write_bytes(original)
            results.append(dict(domain=domain, name=NAMES[0], passed=True))
            fixtures.retire(folder, domain, process)
            restored = Path(temporary) / (domain + '-restored')
            shutil.copytree(folder, restored)
            for path in folder.iterdir():
                other = restored / path.name
                assert path.stat().st_ino != other.stat().st_ino
                assert pin(path) == pin(other)
            assert fixtures.admit(restored, domain, process, require_retired=True)
            results.append(dict(domain=domain, name=NAMES[1], passed=True))

            def admit():
                return fixtures.admit(restored, domain, process, require_retired=True)

            def damage_file(name, change):
                path = restored / name; saved = path.read_bytes()
                try:
                    path.write_bytes(change(saved)); rejected(admit)
                finally:
                    path.write_bytes(saved)
                assert admit()

            damage_file('eof-filesystem.json', lambda raw: raw + b' ')
            results.append(dict(domain=domain, name=NAMES[2], passed=True))
            def different_source(raw):
                value = json.loads(raw); value['verifier_source']['sha256'] = '0' * 64
                return SORTED(value)
            damage_file(fixtures.RECEIPT, different_source)
            results.append(dict(domain=domain, name=NAMES[3], passed=True))
            owner = copy.deepcopy(process); owner['pid'] += 1
            rejected(lambda: fixtures.admit(restored, domain, owner, require_retired=True))
            results.append(dict(domain=domain, name=NAMES[4], passed=True))
            damage_file('stdout.bin', lambda raw: raw + b'changed\n')
            results.append(dict(domain=domain, name=NAMES[5], passed=True))
            receipt = restored / fixtures.RECEIPT; saved = receipt.read_bytes()
            receipt.unlink(); rejected(admit); receipt.write_bytes(saved)
            results.append(dict(domain=domain, name=NAMES[6], passed=True))
            live = restored / 'final-state'; live.mkdir(); rejected(admit); live.rmdir()
            results.append(dict(domain=domain, name=NAMES[7], passed=True))
            owner = copy.deepcopy(process); owner['reaped'] = False
            rejected(lambda: fixtures.admit(restored, domain, owner, require_retired=True))
            results.append(dict(domain=domain, name=NAMES[8], passed=True))
            assert admit()
    assert results == EXPECTED
    return results


if __name__ == '__main__':
    print(json.dumps(dict(status='PASS', data_controls=len(run()), runtime_processes=0), sort_keys=True))
