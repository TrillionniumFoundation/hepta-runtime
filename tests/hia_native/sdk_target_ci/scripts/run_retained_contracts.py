"""Build and compare the retained G1/G2/G3/G4 components in this CI invocation."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def run_retained(output, hepta, buildroot, compile_one, steps):
    output = Path(output)
    pins = json.loads((output / 'source-pins/retained-modules.json').read_bytes())
    g4 = output / pins['g4']['root']
    g3 = output / pins['g3']['root']
    g2 = g3 / 'joined-g2'
    report = {'schema': 'hepta.sdk-retained-fresh-source-ci.v1', 'status': 'RUNNING',
              'fresh_source_builds': True, 'existing_binary_inputs': False,
              'full_sdk_qualified': False, 'full_async_runtime_qualified': False,
              'native_task_registry_qualified': False, 'native_future_cancellation_qualified': False,
              'fresh_cold_qualified': False, 'production_activated': False, 'old_path_removed': False}
    report_path = output / 'evidence/retained-contracts-summary.json'
    put(report_path, report)
    try:
        groups = {}
        for group, stage in [('g4', g4), ('g3', g3)]:
            rows = {}
            for name, pin in pins[group]['members'].items():
                source = stage / pin['source']
                assert sha(source.read_bytes()) == pin['source_sha256'], (group, name)
                path = compile_one('retained-' + group + '-' + name, source, pin['buffer_profile'])
                metadata = json.loads(path.read_bytes())
                assert metadata['source_sha256'] == pin['source_sha256'], (group, name)
                assert metadata['image_sha256'] == pin['image_sha256'], (group, name)
                assert metadata['buffer_profile'] == pin['buffer_profile'], (group, name)
                rows[name] = {'path': os.path.relpath(path, stage), 'sha256': sha(path.read_bytes()),
                              'source': pin['source'], 'source_sha256': pin['source_sha256'],
                              'image_sha256': pin['image_sha256'], 'buffer_profile': pin['buffer_profile']}
            groups[group] = rows
            put(stage / 'evidence/hia-modules.json', {
                'schema': 'hepta.sdk-retained-source-rebuilt-modules.v1', 'members': rows,
                'existing_binary_inputs': False, 'fresh_cold_qualified': False})
        joined = {}
        for name in ('message', 'connection', 'fixture'):
            row = groups['g3'][name]
            joined[name] = dict(row, path=os.path.relpath((g3 / row['path']).resolve(), g2))
        put(g2 / 'evidence/hia-modules.json', {
            'schema': 'hepta.sdk-joined-source-rebuilt-modules.v1', 'members': joined,
            'existing_binary_inputs': False, 'fresh_cold_qualified': False})
        # Reuse only the bootstrap built from source earlier in this invocation.
        # This separate build root avoids compiler-module name collisions.
        packroot = g3 / 'hia-build-g4'
        packroot.mkdir()
        shutil.copytree(Path(buildroot) / 'bootstrap', packroot / 'bootstrap')
        command = [sys.executable, g3 / 'scripts/build_connection_fixture.py',
                   '--hepta', hepta, '--runtime', g3, '--build-root', packroot,
                   '--name', 'g4-transport']
        for name, row in groups['g3'].items():
            command += ['--' + name + '-manifest', (g3 / row['path']).resolve()]
        steps.run('retained-four-image-pack', command, cwd=g3, timeout=600)
        packed_path = packroot / 'g4-transport-elf/manifest.json'
        packed = json.loads(packed_path.read_bytes())
        for field, expected in pins['g3']['packed_fixture'].items():
            assert packed[field] == expected, field
        assert sha((packed_path.parent / packed['executable']).read_bytes()) == packed['elf_sha256']
        invocations = [
            ('retained-g4-response', g4, 'scripts/qualify_response.py', 'source-response', []),
            ('retained-g1-g3-transport', g3, 'scripts/qualify_g3.py', 'source-transport',
             ['--fixture-manifest', 'hia-build-g4/g4-transport-elf/manifest.json']),
            ('retained-g2-connection', g2, 'scripts/qualify_normal.py', 'source-connection', []),
            ('retained-g4-cache', g4, 'scripts/qualify_cache_sessions.py', 'source-cache', []),
        ]
        results = {}
        for label, stage, script, run_name, extra in invocations:
            steps.run(label, [sys.executable, stage / script, '--run-name', run_name, *extra],
                      cwd=stage, timeout=600)
            result = json.loads((stage / 'evidence' / run_name / 'summary.json').read_bytes())
            assert result['status'] == 'PASS', label
            results[label] = result
        g4_result = results['retained-g4-response']
        g3_result = results['retained-g1-g3-transport']
        g2_result = results['retained-g2-connection']
        cache_result = results['retained-g4-cache']
        assert g4_result['counts']['response_cases'] == 215
        assert g4_result['counts']['typed_emitter_cases'] == 119
        assert g3_result['counts']['model_native_calls'] == 197
        assert g3_result['counts']['elf_transport_cases'] == 25
        assert g3_result['counts']['codec_eof_reference_cases'] == 4
        assert g3_result['counts']['native_shutdown_calls'] == 12
        assert g2_result['counts']['sessions'] == 67
        assert cache_result['sessions'] == 3 and cache_result['matched_response_lines'] == 15
        report.update(status='PASS', retained_g1_g2_g3_g4_domains_reexecuted=True,
                      packed_elf_sha256=packed['elf_sha256'],
                      g4_counts=g4_result['counts'], g3_counts=g3_result['counts'],
                      g2_counts=g2_result['counts'], cache_sessions=cache_result['sessions'],
                      cache_response_lines=cache_result['matched_response_lines'],
                      original_response_transport_connection_executables_rebuilt=True)
    except BaseException:
        import traceback
        report.update(status='FAIL', failure=traceback.format_exc())
        raise
    finally:
        put(report_path, report)
    return report
