"""Real readiness calls against the complete original prepare_at function."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import select
import struct
import subprocess
import sys
import time
import traceback
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_cases import cases, frame
from prepare_fixture import Fixture, setup, mutate
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def exact(process, count):
    raw = bytearray();deadline = time.monotonic() + 15
    while len(raw) < count:
        left = deadline - time.monotonic();assert left > 0
        assert select.select([process.stdout], [], [], left)[0], 'owned reply deadline'
        block = os.read(process.stdout.fileno(), count - len(raw));assert block, ('early EOF', process.poll())
        raw.extend(block)
    return bytes(raw)

def request_bytes(fixture, step):
    if 'request' in step:return bytes.fromhex(step['request'])
    if 'path_hex' in step:return frame(bytes.fromhex(step['path_hex']))
    path = os.fsencode(str(fixture / step['root_relative']))
    return frame(path + bytes.fromhex(step.get('path_suffix', '')))

def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    fixture = Fixture(root, directory);fixture.snapshot()
    for change in row.get('setup', []):mutate(root, change);fixture.snapshot()
    before = fixture.snapshot();started = time.monotonic()
    command = [str(executable)]
    if 'supervisor' in row:
        configuration = directory / 'kernel-config.json';configuration.write_bytes(ENCODE(row['supervisor']))
        command = [sys.executable, '-I', '-B', str(Path(__file__).with_name('prepare_supervisor.py')),
            '--fixture', str(root), '--config', str(configuration), '--log', str(directory / 'kernel.json'),
            '--timeout', '30', '--'] + command
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(os.environ, PATH=''), umask=row.get('umask', 0o077), bufsize=0)
    observations = [];inputs = bytearray();outputs = bytearray();stderr = b'';error = None
    try:
        for step in row['operations']:
            if 'mutation' in step:
                mutate(root, step['mutation']);observations.append(dict(mutation=step['mutation'], filesystem=fixture.snapshot()));continue
            root_name = row.get('root_name', 'root')
            try:existed = (root / root_name / '.request-results-v2-anchor.json').exists()
            except PermissionError:existed = True
            raw = request_bytes(root, step);wire = struct.pack('<Q', len(raw)) + raw;inputs.extend(wire)
            at = 0
            while at < len(wire):
                count = process.stdin.write(wire[at:]);assert count > 0;at += count
            process.stdin.flush();header = exact(process, 4);code = struct.unpack('<I', header)[0]
            assert code in (32, 0xffffffff), code
            body = exact(process, 32) if code == 32 else b'';outputs.extend(header + body)
            filesystem = fixture.snapshot();record = dict(code=code, body_sha256=SHA(body))
            if body:
                magic, diagnostic, errno, success = struct.unpack('<8s3Q', body)
                assert magic == b'HRSPR001' and diagnostic != 255 and success == int(diagnostic == 0)
                record.update(diagnostic=diagnostic, errno=errno, success=success)
                if success and not existed:
                    fixture.verify_created_anchor(root_name, row.get('created_legacy_path'))
                    fixture.verified_created_anchors[-1]['origin'] = row.get('anchor_origin', 'tested_implementation')
            observed = process
            if 'supervisor' in row:
                observed = SimpleNamespace(pid=int((directory / 'kernel.pid').read_text()), poll=process.poll)
            descriptors = fixture.descriptors(observed);assert descriptors == []
            record['no_retained_fixture_descriptors'] = True
            observations.append(dict(response=record, filesystem=filesystem))
        process.stdin.close();process.wait(timeout=15);assert not process.stdout.read()
        stderr = process.stderr.read();assert process.returncode == 0 and not stderr
        if 'supervisor' in row:
            kernel = json.loads((directory / 'kernel.json').read_bytes())
            assert kernel['status'] == 'PASS' and kernel['child_reaped'] and kernel['all_selected_faults_reached']
            assert kernel['exit_code'] == 0 and kernel['semantic_emulation'] is False
    except BaseException as caught:
        error = repr(caught);raise
    finally:
        if process.poll() is None:process.kill();process.wait()
        if process.stdout and not process.stdout.closed:outputs.extend(process.stdout.read())
        if process.stderr and not process.stderr.closed:stderr += process.stderr.read()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:stream.close()
        for name, raw in (('stdin.bin', inputs), ('stdout.bin', outputs), ('stderr.bin', stderr)):(directory / name).write_bytes(raw)
        identities = fixture.finish()
        (directory / 'process.json').write_bytes(ENCODE(dict(command=command, pid=process.pid,
            exit_code=process.returncode, reaped=True, elapsed_seconds=time.monotonic() - started,
            path_environment_empty=True, error=error, stdin_bytes=len(inputs), stdin_sha256=SHA(inputs),
            stdout_bytes=len(outputs), stdout_sha256=SHA(outputs), stderr_bytes=len(stderr), stderr_sha256=SHA(stderr),
            observations=observations, **identities)))
    return dict(before=before, observations=observations), bytes(outputs), identities

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('native', 'oracle', 'output'):parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='hepta.request-storage.prepare-comparison.v1', status='FAIL', cases=[],
        whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False,
        result_storage_closed=False, audit_storage_closed=False, public_request_dispatch_qualified=False,
        initialization_mutex_contention_qualified=False, initialization_mutex_poisoning_qualified=False)
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    started = time.monotonic();save()
    try:
        native, oracle = args.native.resolve(strict=True), args.oracle.resolve(strict=True)
        pins = {str(p): SHA(p.read_bytes()) for p in (native, oracle)}
        definitions = list(cases());assert len({r['name'] for r in definitions}) == len(definitions);verified = 0
        with (out / 'cases.jsonl').open('xb') as corpus:
            for index, definition in enumerate(definitions):
                corpus.write(json.dumps(definition, sort_keys=True).encode() + b'\n');corpus.flush()
                directory = out / f'{index:04d}';directory.mkdir(mode=0o700)
                expected, old, old_pins = run(oracle, definition, directory / 'original')
                actual, new, new_pins = run(native, definition, directory / 'native')
                passed = expected == actual and old == new
                report['cases'].append(dict(index=index, name=definition['name'], passed=passed,
                    output_bytes=len(new), output_sha256=SHA(new),
                    created_anchors_original=old_pins['verified_created_anchors'], created_anchors_native=new_pins['verified_created_anchors']))
                if not passed:
                    (directory / 'mismatch.json').write_bytes(ENCODE(dict(original=expected, native=actual)))
                    raise AssertionError(report['cases'][-1])
                assert len(old_pins['verified_created_anchors']) == len(new_pins['verified_created_anchors'])
                verified += len(new_pins['verified_created_anchors'])
                if index % 8 == 0:save()
        assert pins == {str(p): SHA(p.read_bytes()) for p in (native, oracle)}
        report.update(status='PASS', compared_cases=len(definitions), processes_per_implementation=len(definitions),
            requests_per_implementation=sum('mutation' not in step for row in definitions for step in row['operations']),
            observations_per_implementation=sum(len(row['operations']) for row in definitions),
            complete_response_bytes_equal=True, observed_filesystem_equal_after_verified_identity_and_digest_projection=True,
            every_reply_verified_no_retained_fixture_descriptors=True, actual_created_anchors_per_implementation=verified,
            executable_bytes_unchanged=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:save()
    print(json.dumps({key: value for key, value in report.items() if key != 'cases'}, sort_keys=True))

if __name__ == '__main__':main()
