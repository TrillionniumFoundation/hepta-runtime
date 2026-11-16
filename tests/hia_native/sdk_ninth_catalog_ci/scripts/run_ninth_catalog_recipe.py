#!/usr/bin/env python3
"""Fresh CI-only TextEditor metadata and nine-item native catalog qualification."""
from pathlib import Path
import argparse
import contextlib
import hashlib
import json
import os
import shutil
import struct
import sys
import time
import traceback

sys.dont_write_bytecode = True


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def frame(magic, operation, raw):
    return magic + struct.pack('<QQ', operation, len(raw)) + raw


def public_frame(operation, argument, raw=b''):
    return b'HRMCD002' + struct.pack('<QQ', operation, argument) + raw


def non_list_cases():
    cases = [('operation2-' + str(arg), public_frame(2, arg)) for arg in range(1, 5)]
    cases += [('operation3-' + str(arg), public_frame(3, arg)) for arg in range(1, 4)]
    cases += [('operation5-' + str(arg), public_frame(5, arg)) for arg in range(2)]
    cases += [('operation6-' + str(arg), public_frame(6, arg)) for arg in range(1, 9)]
    version = b'"2025-11-25"'
    cases.append(('operation4-version', public_frame(4, len(version), version)))
    assert len(cases) == 18
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--hepta', type=Path)
    parser.add_argument('--rust-bin', type=Path)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    sys.path.insert(0, str(source / 'scripts'))
    from source_check import verify
    source_report = verify(source)
    if args.check_only:
        print(json.dumps(source_report, sort_keys=True))
        return
    assert os.environ.get('CI') == 'true', 'Rust and HIA execution for this recipe is authorized only in CI'
    assert args.output is not None and args.hepta is not None and args.rust_bin is not None
    output = args.output.resolve()
    assert not output.exists() and not output.is_relative_to(source)
    shutil.copytree(source, output)
    (output / 'evidence').mkdir()
    sys.path.insert(0, str(output / 'scripts'))
    from exact_rust_build import build_exact_oracle
    started = time.monotonic()
    report = {'schema': 'hepta.g5.ninth-catalog-ci-qualification.v2', 'status': 'RUNNING',
              'source_manifest_sha256': sha((source / 'source-manifest.json').read_bytes()),
              'current_original_target_commit': 'd3d75c30719db966b004756f610007a7c723729e',
              'actual_macro_metadata': False, 'ninth_schema_generated': False,
              'original_tool_handler_executed': False, 'native_catalog_compiled': False,
              'native_catalog_metadata_boundary_qualified': False,
              'public_route_registered': False, 'public_text_editor_body_qualified': False,
              'existing_binary_inputs': False, 'historical_3_4_evidence_promoted': False,
              'fresh_development_fixed_point': False, 'fresh_cold_qualified': False,
              'full_sdk_qualified': False, 'full_async_runtime_qualified': False,
              'native_task_registry_qualified': False, 'native_future_cancellation_qualified': False,
              'full_136_route_qualified': False, 'production_activated': False, 'old_path_removed': False}

    def save():
        put(output / 'evidence/recipe-summary.json', report)

    save()
    try:
        deps = json.loads((output / 'ci/dependencies.json').read_bytes())
        binary, receipt, records = build_exact_oracle(output, 'oracle',
            'g5-target-text-editor-catalog-oracle', args.rust_bin)
        # Preserve the freshly built executable even if the metadata assertion
        # fails before the first successful observation can be recorded.
        receipt.update(current_original_target_commit=deps['original_target']['commit'],
            original_metadata_execution_attempted=True, original_handler_executed=False)
        put(output / 'evidence/oracle-build.json', receipt)
        metadata_input = (output / 'cases/metadata.jsonl').read_bytes()
        metadata_raw = records.run('original-metadata', [binary], stdin=metadata_input, timeout=60)
        (output / 'evidence/oracle-metadata.jsonl').write_bytes(metadata_raw)
        metadata_rows = [json.loads(line) for line in metadata_raw.splitlines()]
        assert len(metadata_rows) == 1
        metadata = metadata_rows[0]
        assert metadata['actual_macro_metadata'] is True and metadata['handler_executed'] is False
        tool = metadata['tool']
        assert tool['name'] == 'text_editor' and tool['title'] == 'Text Editor'
        assert json.loads(metadata['tool_wire']) == tool
        assert metadata['schema'] == tool['inputSchema']
        assert set(tool['inputSchema']['required']) == {'command', 'path'}
        put(output / 'evidence/text-editor-declaration.json', tool)
        receipt.update(actual_target_sdk_executed=True,
            current_original_target_commit=deps['original_target']['commit'],
            cases_sha256=sha(metadata_input), observations_sha256=sha(metadata_raw),
            actual_original_tool_macro_executed=True, original_handler_executed=False)
        put(output / 'evidence/oracle-build.json', receipt)
        report.update(actual_macro_metadata=True, ninth_schema_generated=True,
            original_oracle_binary_sha256=receipt['binary_sha256'],
            declaration_sha256=sha((output / 'evidence/text-editor-declaration.json').read_bytes()))
        save()
        tools = json.loads((output / 'cases/public-eight-tools.json').read_bytes())
        assert len(tools) == 8 and all(row['name'] != 'text_editor' for row in tools)
        tools.append(tool)
        raw_catalog = encode({'tools': tools})
        cases = [{'mode': 'catalog', 'type': 'tools', 'policy': policy,
                  'label': 'public-nine-tools-policy' + str(policy), 'wire': raw_catalog.decode()}
                 for policy in range(3)]
        cases_raw = b''.join(encode(case) + b'\n' for case in cases)
        (output / 'evidence/catalog-cases.jsonl').write_bytes(cases_raw)
        observed_raw = records.run('original-nine-tool-catalog', [binary], stdin=cases_raw, timeout=60)
        (output / 'evidence/oracle-nine-tool-catalog.jsonl').write_bytes(observed_raw)
        observations = [json.loads(line) for line in observed_raw.splitlines()]
        assert len(observations) == 3
        receipt['catalog_cases_sha256'] = sha(cases_raw)
        receipt['catalog_observations_sha256'] = sha(observed_raw)
        put(output / 'evidence/oracle-build.json', receipt)
        from hia_native_build import NativeBuild
        from hia_native_loader import NativeModule
        builder = NativeBuild(args.hepta, output / 'native-build')
        builder.bootstrap()
        assert builder.compiler_sha256 == deps['compiler']['generation_sha256']
        report['fresh_development_fixed_point'] = True
        module_rows = {}
        for spec in deps['native_modules']:
            path = builder.compile(spec['name'], output / spec['path'],
                                   standalone=None, buffer_profile=spec['buffer_profile'])
            metadata_native = json.loads(path.read_bytes())
            assert metadata_native['source_sha256'] == spec['source_sha256']
            assert metadata_native['image_sha256'] == spec['expected_image_sha256']
            module_rows[spec['name']] = {'manifest': str(path.relative_to(output)),
                'manifest_sha256': sha(path.read_bytes()), **metadata_native}
        put(output / 'evidence/hia-modules.json', module_rows)
        save()
        events = []
        def event(owner, label, incoming, outgoing):
            events.append({'owner': owner, 'label': label,
                'input_hex': incoming.hex(), 'output_hex': outgoing.hex()})
            with (output / 'evidence/native-events.jsonl').open('a') as handle:
                handle.write(json.dumps(events[-1], sort_keys=True, separators=(',', ':')) + '\n')

        native_wires = {}
        with contextlib.ExitStack() as stack:
            modules = {name: stack.enter_context(NativeModule(output / row['manifest'],
                       manifest_sha256=row['manifest_sha256'])) for name, row in module_rows.items()}
            serde = stack.enter_context(modules['serde'].session(output_capacity=1 << 20, workspace_capacity=32 << 20))
            catalog = stack.enter_context(modules['catalog'].session(output_capacity=1 << 20, workspace_capacity=96 << 20))
            for case, ref in zip(cases, observations, strict=True):
                assert case['label'] == ref['label'] and case['policy'] == ref['policy']
                assert ref['original_text_editor_metadata_used'] is True and ref['handler_executed'] is False
                incoming = frame(b'HSJVAL01', 1, case['wire'].encode())
                canonical = serde(incoming)
                event('serde', case['label'], incoming, canonical)
                assert canonical == ref['canonical_input'].encode(), case['label']
                incoming = frame(b'HRRSP001', 4 | (case['policy'] << 8), canonical)
                raw = catalog(incoming)
                event('catalog', case['label'], incoming, raw)
                assert raw[:8] == b'HRRPO001' and len(raw) >= 64
                assert struct.unpack('<7Q', raw[8:64]) == (4, 0, 64, len(raw) - 64, case['policy'], 0, 0)
                assert raw[64:] == ref['wire'].encode(), case['label']
                native_wires[case['policy']] = raw[64:]
                if case['policy'] in (1, 2):
                    suffix = b',"result":' + raw[64:] + b'}'
                    (output / ('evidence/public-nine-tools-policy' + str(case['policy']) + '.suffix.bin')).write_bytes(suffix)
            put(output / 'evidence/catalog-comparison.json', {
                'status': 'PASS', 'ordinary_policy_cases': 3, 'actual_macro_metadata': True,
                'actual_original_sdk_executed': True, 'native_catalog_executed': True,
                'cases_sha256': sha(cases_raw), 'oracle_observations_sha256': sha(observed_raw),
                'original_handler_executed': False, 'public_route_registered': False})
            from author_ninth_catalog import author
            generated, composition = author(output, args.hepta)
            ninth_path = builder.compile('runtime_mcp_catalog_ninth', generated,
                                          standalone=None, buffer_profile='history.v1')
            ninth_row = json.loads(ninth_path.read_bytes())
            assert ninth_row['source_sha256'] == composition['source_sha256']
            module_rows['ninth_catalog'] = {'manifest': str(ninth_path.relative_to(output)),
                'manifest_sha256': sha(ninth_path.read_bytes()), **ninth_row}
            put(output / 'evidence/hia-modules.json', module_rows)
            ninth = stack.enter_context(NativeModule(ninth_path, manifest_sha256=sha(ninth_path.read_bytes())))
            report['native_catalog_compiled'] = True
            save()
            def invoke_public(name, module, label, wire):
                code, raw, _ = module.invoke_raw(wire, output_capacity=1 << 20, workspace_capacity=65536)
                assert code == 32 and raw[:8] == b'HRCATR02', (name, label, code)
                status, length, reserved = struct.unpack_from('<3Q', raw, 8)
                assert status == reserved == 0 and length <= len(raw) - 32
                result = raw[:32 + length]
                event(name, label, wire, result)
                return result
            for mode in range(2):
                wire = public_frame(1, mode)
                old = invoke_public('baseline_catalog', modules['baseline_catalog'], 'list-' + str(mode), wire)
                new = invoke_public('ninth_catalog', ninth, 'list-' + str(mode), wire)
                expected_suffix = b',"result":' + native_wires[mode + 1] + b'}'
                assert new[32:] == expected_suffix
                old_result = json.loads(b'{"id":0' + old[32:])['result']
                new_result = json.loads(b'{"id":0' + new[32:])['result']
                old_tools = old_result.pop('tools')
                new_tools = new_result.pop('tools')
                assert len(old_tools) == 8 and len(new_tools) == 9
                assert new_tools[:8] == old_tools
                assert new_tools[-1] == tool
                assert old_result == new_result
            for label, wire in non_list_cases():
                old = invoke_public('baseline_catalog', modules['baseline_catalog'], label, wire)
                new = invoke_public('ninth_catalog', ninth, label, wire)
                assert new == old, label
        assert len(events) == 46
        composition['native_execution_qualified'] = True
        composition['ordinary_native_domain'] = {'list_modes': 2, 'retained_non_list_operations': 18}
        composition['native_module_manifest'] = module_rows['ninth_catalog']['manifest']
        composition['native_image_sha256'] = module_rows['ninth_catalog']['image_sha256']
        composition['public_route_registered'] = False
        put(output / 'generated/native/runtime_mcp_catalog_ninth_composition.json', composition)
        report.update(status='PASS', native_catalog_metadata_boundary_qualified=True,
            ordinary_typed_policy_cases=3, catalog_list_modes=2,
            retained_non_list_operations=18, native_invocations=len(events),
            native_modules=module_rows, native_events_sha256=sha((output / 'evidence/native-events.jsonl').read_bytes()),
            generated_catalog_source_sha256=composition['source_sha256'],
            generated_catalog_image_sha256=module_rows['ninth_catalog']['image_sha256'],
            source_tree_unchanged=verify(source) == source_report)
    except BaseException:
        report.update(status='FAIL', failure=traceback.format_exc())
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        save()
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
