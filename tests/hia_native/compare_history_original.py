"""Replay every retained history row through the unchanged original Rust owner."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import time

SOURCE_SHA = 'e00f11f708239c1c8b4ee06da7833433ef86427ebd77544fc9b46ce2b6eb44eb'
ORIGINAL_COMMIT = 'a0dcdda1991ec536d5e2d252c006a778993fa566'
OWN = ('native/history.hepta', 'native/history_composition.json',
       'scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
       'scripts/hia_native_history_build.py', 'tests/hia_native/test_history.py',
       'tests/hia_native/history_oracle_source.py', 'tests/hia_native/oracle_history.rs')
REFERENCES = ('native/text_budget.hepta', 'native/composition_packer.hepta',
              'tests/hia_native/view_cache_hex_transport.hepta',
              'scripts/hia_native_composition_build.py', 'scripts/hia_native_scope_qualification.py',
              'scripts/hia_native_entropy_qualification.py', 'src/mcp/fs/core.rs',
              'src/mcp/fs/core_tests.rs', 'src/mcp/fs/text_editing.rs')
COUNTS = {'capacity_refusals': 2, 'frame_refusals': 16,
          'full_input_boundary_bytes': 134217728, 'largest_original_snapshot': 134217657,
          'lifecycle_rows': 28, 'native_elf_processes': 4, 'native_elf_requests': 34,
          'native_image_calls': 6195, 'original_owner_rows': 6167, 'poison_rows': 3,
          'production_total_byte_cap': 67108864, 'reference_rows': 6198, 'state_refusals': 13}
STREAMS = {
    'input.bin.gz': (394117614, '5a8d1857c068a4460166a0aada46dc27ae65db3fd7137971c3374fc402f32042'),
    'native-output.bin.gz': (321300328, '25bfbb643af8e49ecb060dd2c2b2a5baa33a8be6b98f5f06bb524c47ef49f156'),
    'rows.jsonl.gz': (730303, '1f092530dfeff1b76bd8581ac9c25e5f0b1d055b9412ab3e6c61168f64a27a04'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), f'not a regular file: {path}')
    return path


def digest(stream):
    size, value = 0, hashlib.sha256()
    while chunk := stream.read(1 << 20):
        size += len(chunk)
        value.update(chunk)
    return {'bytes': size, 'sha256': value.hexdigest()}


def identity(path):
    with regular(path).open('rb') as stream:
        return digest(stream)


def source_bindings(root, reference):
    pins = {'owner': {p: identity(root / p)['sha256'] for p in OWN},
            'reference': {p: identity(reference / p)['sha256'] for p in REFERENCES}}
    require(pins['owner']['native/history.hepta'] == SOURCE_SHA, 'HIA source changed')
    proof = json.loads((root / 'native/history_composition.json').read_bytes())
    require(proof['source_sha256'] == SOURCE_SHA and
            proof['original_runtime_commit'] == ORIGINAL_COMMIT, 'original owner pin changed')
    require(set(proof['original_sources']) == set(REFERENCES[-3:]), 'original source set changed')
    for name, recorded in proof['original_sources'].items():
        raw = regular(reference / name).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(recorded == {'blob': blob, 'sha256': hashlib.sha256(raw).hexdigest()},
                f'original source identity changed: {name}')
    spec = importlib.util.spec_from_file_location('history_oracle_source', root / OWN[-2])
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    require((root / OWN[-1]).read_bytes() == generator.oracle_source(reference).encode(),
            'Rust oracle no longer embeds the unchanged original owner')
    return pins


def checked_corpus(root, reference, folder):
    corpus = json.loads(regular(folder / 'native-corpus.json').read_bytes())
    require(corpus['schema'] == 'hepta.runtime.history-native-corpus.v1', 'wrong corpus schema')
    report = corpus['report']
    require(report['status'] == 'PASS' and type(report['groups']) is int and
            report['groups'] == 7, 'native suite was incomplete')
    require(report['counts'] == COUNTS and all(type(v) is int for v in report['counts'].values()),
            'native domain changed')
    require(report['source_pins_unchanged'] is True and
            report['source_pins'] == source_bindings(root, reference), 'native source pins changed')
    require(report['original_rust_executions'] == 0 and
            type(report['original_rust_executions']) is int and
            report['production_activated'] is False and report['whole_runtime_replaced'] is False,
            'native report overstates its scope')
    require(set(corpus['streams']) == set(STREAMS), 'corpus stream set changed')
    for name, (size, sha) in STREAMS.items():
        recorded = corpus['streams'][name]
        require(recorded['raw_bytes'] == size and recorded['raw_sha256'] == sha,
                f'original domain changed: {name}')
        require(identity(folder / name) == {'bytes': recorded['gzip_bytes'],
                'sha256': recorded['gzip_sha256']}, f'compressed stream changed: {name}')
        with gzip.open(folder / name, 'rb') as stream:
            require(digest(stream) == {'bytes': size, 'sha256': sha}, f'truncated corpus: {name}')
    return corpus


def compare(root, reference, folder, output, *, rustc=None, binary=None):
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = {'schema': 'hepta.runtime.history-original-comparison.v1', 'status': 'FAIL',
              'production_activated': False, 'whole_runtime_replaced': False,
              'full_runtime_semantics': False, 'original_runtime_commit': ORIGINAL_COMMIT}
    try:
        corpus = checked_corpus(root, reference, folder)
        before = source_bindings(root, reference)
        corpus_before = {name: identity(folder / name) for name in (*STREAMS, 'native-corpus.json')}
        result.update(source_pins=before, counts=COUNTS, corpus=corpus_before,
                      comparator=identity(Path(__file__)))
        if binary is None:
            require(rustc is not None, 'an explicit pinned rustc or already compiled binary is required')
            version = subprocess.run([str(rustc), '--version'], check=True, capture_output=True,
                                     timeout=30).stdout.decode().strip()
            binary = output / 'original-history.elf'
            command = [str(rustc), '--edition=2021', '-O', '-C', 'overflow-checks=off',
                       str(root / OWN[-1]), '-o', str(binary)]
            compile_started = time.monotonic()
            with (output / 'compile.stdout').open('xb') as out, (output / 'compile.stderr').open('xb') as err:
                process = subprocess.run(command, stdout=out, stderr=err, timeout=180)
            result['compile'] = {'command': command, 'rustc_version': version,
                                 'exit_code': process.returncode,
                                 'seconds': time.monotonic() - compile_started,
                                 'stdout': identity(output / 'compile.stdout'),
                                 'stderr': identity(output / 'compile.stderr')}
            require(process.returncode == 0, 'original Rust compilation failed')
        else:
            result['compile'] = {'compiled_by_qualification_recipe': True, 'binary': str(binary)}
        executable_before = identity(binary)
        result['executable'] = executable_before
        with gzip.open(folder / 'input.bin.gz', 'rb') as src, (output / 'input.bin').open('xb') as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        require(identity(output / 'input.bin') == {'bytes': STREAMS['input.bin.gz'][0],
                'sha256': STREAMS['input.bin.gz'][1]}, 'replay input changed')
        replay_started = time.monotonic()
        with (output / 'input.bin').open('rb') as inp, (output / 'original-output.bin').open('xb') as out, \
                (output / 'original.stderr').open('xb') as err:
            process = subprocess.run([str(binary)], stdin=inp, stdout=out, stderr=err, timeout=180)
        result['replay'] = {'exit_code': process.returncode, 'seconds': time.monotonic() - replay_started,
                            'stdout': identity(output / 'original-output.bin'),
                            'stderr': identity(output / 'original.stderr')}
        require(process.returncode == 0, 'original Rust replay failed')
        summary = json.loads((output / 'original.stderr').read_bytes())
        require(summary == {'status': 'PASS', 'original_history_rows': 6198,
                            'original_history_operations': 6167, 'lifecycle_rows': 28, 'poison_rows': 3},
                'original Rust did not consume every row')
        require(all(type(summary[k]) is int for k in summary if k != 'status'), 'noninteger Rust counts')
        result['original_summary'] = summary
        compared = 0
        with gzip.open(folder / 'native-output.bin.gz', 'rb') as expected, \
                (output / 'original-output.bin').open('rb') as actual:
            while chunk := expected.read(1 << 20):
                require(actual.read(len(chunk)) == chunk, f'original output differs near byte {compared}')
                compared += len(chunk)
            require(actual.read(1) == b'', 'original output has trailing bytes')
        require(compared == STREAMS['native-output.bin.gz'][0], 'comparison was truncated')
        with (output / 'original-output.bin').open('rb') as src, \
                (output / 'original-output.bin.gz').open('xb') as dst:
            with gzip.GzipFile(fileobj=dst, mode='wb', compresslevel=1, mtime=0) as compressed:
                shutil.copyfileobj(src, compressed, 1 << 20)
        result['retained_original_output'] = identity(output / 'original-output.bin.gz')
        require(source_bindings(root, reference) == before, 'sources changed during original replay')
        require({name: identity(folder / name) for name in corpus_before} == corpus_before,
                'corpus changed during original replay')
        require(identity(binary) == executable_before, 'original executable changed during replay')
        result.update(status='PASS', output_bytes_compared=compared, source_pins_unchanged=True,
                      corpus_unchanged=True, executable_unchanged=True)
        (output / 'input.bin').unlink()
        (output / 'original-output.bin').unlink()
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    result['seconds'] = time.monotonic() - started
    (output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--reference-root', required=True, type=Path)
    parser.add_argument('--corpus', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    owner = parser.add_mutually_exclusive_group(required=True)
    owner.add_argument('--rustc', type=Path)
    owner.add_argument('--binary', type=Path)
    args = parser.parse_args()
    result = compare(args.root.resolve(), args.reference_root.resolve(), args.corpus.resolve(),
                     args.output.resolve(), rustc=args.rustc, binary=args.binary)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
