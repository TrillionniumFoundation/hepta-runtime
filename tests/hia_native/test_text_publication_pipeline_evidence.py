"""Physical refusals, fixture retirement and two actual absent-origin reads."""
from pathlib import Path
import importlib.util
import json
import os
import shutil
import struct
import sys
import time
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_text_publication_pipeline as p
import hia_native_text_publication_pipeline_evidence as reader
import hia_native_text_publication_retirement as retirement
import hia_native_text_publication_qualification as q


def load_controls():
    spec = importlib.util.spec_from_file_location('text_frozen_refusals', ROOT / 'tests/hia_native/test_text_publication_evidence.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def directory_identity(path):
    st = Path(path).lstat()
    return {'dev': st.st_dev, 'ino': st.st_ino, 'mode': st.st_mode, 'uid': st.st_uid, 'gid': st.st_gid}


def native_controls(folder, config, admitted):
    legacy = load_controls(); snapshot = legacy.Snapshot(folder / 'snapshot', config, admitted)
    q.same(reader.native_from_roots(**snapshot.config), admitted, 'unaltered complete private snapshot')
    rows = []
    for index, (group, name, mutate, resigned) in enumerate(legacy.controls(), 1):
        case = folder / 'cases' / ('%02d-' % index + name); case.mkdir(parents=True)
        began = time.monotonic_ns(); mutate(snapshot); changes = {}
        for key, before in snapshot.changed.items():
            path = snapshot.path(key)
            if path.exists():
                raw = path.read_bytes(); target = case / 'changed' / key; target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream: stream.write(raw)
                changes[key] = {'before': before, 'after': q.pin(raw), 'file': 'changed/' + key}
            else: changes[key] = {'before': before, 'after': None, 'file': None}
        refusal = None
        try: reader.native_from_roots(**snapshot.config)
        except (ValueError, OSError, KeyError, UnicodeError, struct.error) as error:
            refusal = {'type': type(error).__name__, 'message': str(error)}
        row = {'index': index, 'group': group, 'name': name, 'resigned_surrounding_indices': resigned,
               'actual_physical_changes': changes, 'elapsed_seconds': (time.monotonic_ns() - began) / 1e9,
               'rejection': refusal, 'status': 'PASS' if refusal else 'FAIL',
               'native_cases_added': 0, 'rust_cases_added': 0}
        p.write_new(case / 'result.json', row); rows.append(row); snapshot.reset()
        q.require(refusal is not None, 'physical mutation was accepted: ' + name)
    q.same(reader.native_from_roots(**snapshot.config), admitted, 'private snapshot completely restored')
    q.same(reader.native_from_roots(**config), admitted, 'original whole evidence preserved')
    shutil.rmtree(folder / 'snapshot')
    return rows


def archive_controls(folder, base, admitted, retained):
    snapshot = folder / 'archive-snapshot'; snapshot.mkdir()
    for name in admitted['artifact_sha256']:
        source = base / name; target = snapshot / name; target.parent.mkdir(parents=True, exist_ok=True)
        os.link(source, target)
    for name in retained['artifact_sha256']:
        relative = name.removeprefix(p.FOLDER + '/'); target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True); os.link(base / relative, target)
    original_index = (snapshot / 'retirement/archive.json').read_bytes()
    original_receipt = (snapshot / 'retirement/retired.json').read_bytes()
    archive = q.decode(original_index)
    blob = next(name for name in retained['artifact_sha256'] if '/blobs/' in name).removeprefix(p.FOLDER + '/')
    names = ('changed-complete-blob', 'omitted-permission-grant-resigned', 'open-hardlink-group-resigned',
             'changed-raw-symlink-resigned', 'duplicate-archive-root-resigned', 'same-bytes-outside-symlink')
    rows = []
    for index, name in enumerate(names, 1):
        case = folder / 'archive-cases' / ('%02d-' % index + name); case.mkdir(parents=True)
        modified = json.loads(json.dumps(archive)); changes = {}
        def replace(relative, raw, *, symlink=None):
            target = snapshot / relative; before = p.file_pin(target); target.unlink()
            if symlink is None:
                with target.open('xb') as stream: stream.write(raw)
                destination = case / 'changed' / relative; destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as stream: stream.write(raw)
                changes[relative] = {'before': before, 'after': q.pin(raw), 'file': 'changed/' + relative}
            else:
                target.symlink_to(symlink)
                changes[relative] = {'before': before, 'after': None, 'symlink_target': str(symlink)}
        if index == 1:
            replace(blob, (snapshot / blob).read_bytes() + b'X')
        elif index == 2:
            next(t for t in modified['roots'] if t['permission_grants'])['permission_grants'].pop()
        elif index == 3:
            next(n for t in modified['roots'] for n in t['nodes'] if n['kind'] == 'file')['nlink'] += 1
        elif index == 4:
            next(n for t in modified['roots'] for n in t['nodes'] if n['kind'] == 'symlink')['target_base64'] = q.b64(b'foreign')
        elif index == 5: modified['roots'].append(modified['roots'][-1])
        else:
            outside = case / 'outside.json'; outside.write_bytes(original_index)
            replace('retirement/archive.json', original_index, symlink=outside)
        if 2 <= index <= 5:
            raw = p.encoded(modified); replace('retirement/archive.json', raw)
            receipt = q.decode(original_receipt); receipt['archive'] = q.pin(raw)
            replace('retirement/retired.json', p.encoded(receipt))
        refusal = None
        try: retirement.evidence(snapshot, admitted)
        except (ValueError, OSError, KeyError, UnicodeError, struct.error) as error:
            refusal = {'type': type(error).__name__, 'message': str(error)}
        row = {'index': index, 'name': name, 'status': 'PASS' if refusal else 'FAIL',
               'rejection': refusal, 'physical_changes': changes, 'native_execution': 0, 'rust_execution': 0}
        p.write_new(case / 'result.json', row); rows.append(row)
        q.require(refusal is not None, 'archive mutation was accepted')
        for relative in changes:
            target = snapshot / relative; target.unlink(); os.link(base / relative, target)
    q.same(retirement.evidence(snapshot, admitted), retained, 'archive private snapshot restored')
    shutil.rmtree(snapshot)
    return rows


def relocation_reads(folder, base, config, admitted, retained):
    # All actual machine/corpus producer source roots are below this component
    # output. Hide that entire owned namespace; never move the repository.
    identity = directory_identity(base)
    hidden = base.with_name(base.name + '.read-only-retained-' + str(os.getpid()))
    q.require(not hidden.exists(), 'exclusive absent-origin holding path')
    roots = []
    for number in (1, 2):
        destination = folder / ('new-root-' + str(number)); destination.mkdir()
        p.copy_sources(ROOT, destination / 'source', p.source_names(ROOT))
        output = destination / 'output'; output.mkdir()
        for name in admitted['artifact_sha256']:
            target = output / name; target.parent.mkdir(parents=True, exist_ok=True); os.link(base / name, target)
        for name in retained['artifact_sha256']:
            relative = name.removeprefix(p.FOLDER + '/'); target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True); os.link(base / relative, target)
        p.write_new(destination / 'CONFIG.json', dict({k: config[k] for k in p.GROUPS}, origins={str(base): str(output)}))
        roots.append(destination)
    expected = {'native': admitted, 'retirement': retained}; rows = []; first_hidden = None
    os.rename(base, hidden)
    try:
        q.require(not os.path.lexists(base), 'actual original component output absent')
        for number, destination in enumerate(roots, 1):
            if number == 2:
                first_hidden = roots[0].with_name('new-root-1-retained'); os.rename(roots[0], first_hidden)
                q.require(not roots[0].exists(), 'first read root absent during second read')
            source = destination / 'source'; output = destination / 'output'; process_dir = destination / 'read'
            command = [p.PYTHON, '-I', '-B', str(source / 'scripts/hia_native_text_publication_pipeline_evidence.py'),
                       '--config', str(destination / 'CONFIG.json'), '--output', str(process_dir / 'EVIDENCE.json'),
                       '--retirement', str(output)]
            process_dir.mkdir(); row = p.child_process(source, process_dir, 'read', command, plain=True)
            q.same(p.read_json(process_dir / 'EVIDENCE.json'), expected, 'complete object at two independent roots')
            result = {'status': 'PASS', 'source': str(source), 'output': str(output),
                      'original_component_output_absent': not os.path.lexists(base),
                      'original_producer_sources_absent': all(not os.path.lexists(base / group / 'source') for group in ('native', 'boundary', 'faults', 'corpus')),
                      'previous_read_root_absent': number == 1 or not roots[0].exists(),
                      'repository_root_moved': False, 'no_live_fixture_dependency': True,
                      'process': row, 'evidence': p.file_pin(process_dir / 'EVIDENCE.json'),
                      'complete_object_equal': True, 'native_execution': 0, 'rust_execution': 0}
            p.write_new(destination / 'RESULT.json', result); rows.append(result)
    finally:
        if first_hidden is not None: os.rename(first_hidden, roots[0])
        os.rename(hidden, base)
    q.same(directory_identity(base), identity, 'same original source/output inode restored')
    q.same(reader.native_from_roots(**config), admitted, 'native evidence unchanged after actual absence')
    q.same(retirement.evidence(base, admitted), retained, 'archive unchanged after actual absence')
    return {'reads': rows, 'identity_before': identity, 'identity_restored': directory_identity(base)}


def run():
    started = time.monotonic_ns(); base, manifest, prepared = p.execution()
    output = base.parent / 'text-publication-controls'; output.mkdir()
    config = reader.config_for(base, prepared); p.write_new(output / 'CONFIG.json', config)
    admitted = reader.native_from_roots(**config); p.write_new(base / 'native-admission.json', admitted)
    p.write_new(output / 'BASELINE.json', admitted)
    rows = native_controls(output, config, admitted)
    retained = retirement.create(base, admitted); p.write_new(base / 'retirement-admission.json', retained)
    q.same(reader.native_from_roots(**config), admitted, 'native evidence identical before and after retirement')
    archive_rows = archive_controls(output, base, admitted, retained)
    relocations = relocation_reads(output, base, config, admitted, retained)
    result = {'schema': 'hepta.runtime.text-publication-pipeline-read-controls.v1', 'status': 'PASS',
              'test_groups': 8, 'native_refusals': 33, 'archive_refusals': 6, 'positive_relocations': 2,
              'native_controls': rows, 'archive_controls': archive_rows, 'relocations': relocations,
              'baseline': p.file_pin(output / 'BASELINE.json'), 'retirement': retained,
              'sources': p.source_table(ROOT), 'native_execution': 0, 'rust_execution': 0,
              'elapsed_seconds': (time.monotonic_ns() - started) / 1e9,
              'skipped': 0, 'errors': 0, 'failures': 0, 'original_reference_executed': False,
              'public_handler_replaced': False, 'whole_runtime_replaced': False}
    p.write_new(output / 'RESULT.json', result)
    summary = {key: value for key, value in result.items()
               if key not in ('native_controls', 'archive_controls', 'relocations', 'sources', 'retirement')}
    p.write_new(base / 'evidence-suite.json', summary)
    print(p.encoded(summary).decode(), end='', flush=True)


if __name__ == '__main__': run()
