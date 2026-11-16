# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual artifact transport fixtures; no native/Rust semantic execution claim."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_artifact_bundle as b


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + '\n')


class ArtifactBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-artifact-bundle-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / 'full'
        self.output.mkdir(mode=0o750)
        self.head, self.invocation = 'a' * 40, '12345-1'
        self.artifacts = self.root / 'artifacts'; self.artifacts.mkdir()
        (self.output / 'build').mkdir(mode=0o750)
        (self.output / 'build/native.elf').write_bytes(b'\x7fELF\0complete native image\xff')
        (self.output / 'build/native.elf').chmod(0o751)
        (self.output / 'empty-native').mkdir(mode=0o710)
        baseline = {'source_sha256': {'fixture': 'b' * 64},
            'description': 'transport-only fixture, no semantic qualification'}
        save(self.output / b.r.NATIVE_REPORT, baseline)
        files, directories = b.p.inventory(self.output)
        native = {'schema': 'hepta.runtime.original-native.v1',
            'context': {'invocation': self.invocation, 'checkout_head': self.head},
            'files': files, 'directories': directories,
            'groups': {key: list(value) for key, value in b.r.groups().items()}}
        save(self.output / b.r.NATIVE_SEAL, native)
        self.native_sha = b.p.digest(self.output / b.r.NATIVE_SEAL)
        native_root = self.artifacts / b.source_name(self.head, self.invocation, 'native')
        shutil.copytree(self.output, native_root)
        save(native_root / 'result.json', baseline)
        self.shards = {}
        for group in b.r.groups():
            path = self.output / (group + '/all-original-bytes.gz')
            path.parent.mkdir(); path.write_bytes((group + ': complete original stdout\n').encode() + b'\0\xff')
            path.chmod(0o640)
            (self.output / group / 'empty-corpus').mkdir(mode=0o710)
            folder = self.output / 'original-qualification-shards' / group
            save(folder / b.r.SHARD_REPORT, {'group': group, 'fixture_only': True})
            seal = {'schema': 'hepta.runtime.original-shard.v1',
                'binding': b.r.shard_binding(group, self.native_sha, self.invocation),
                'files': {path.relative_to(self.output).as_posix(): b.identity(path)},
                'directories': [group, group + '/empty-corpus'],
                'report_sha256': b.p.digest(folder / b.r.SHARD_REPORT)}
            save(folder / b.r.SHARD_SEAL, seal)
            self.shards[group] = b.p.digest(folder / b.r.SHARD_SEAL)
            artifact = self.artifacts / b.source_name(self.head, self.invocation, group)
            shutil.copytree(folder, artifact)
            target = artifact / 'data' / path.relative_to(self.output)
            target.parent.mkdir(parents=True); shutil.copyfile(path, target)
        report = {**baseline, 'status': 'PASS', 'phase': 'complete',
            'native_components_status': 'PASS', 'rust_comparison_status': 'PASS',
            'production_activated': False, 'whole_runtime_replaced': False, 'old_stack_removal_qualified': False,
            'original_rust_comparisons': {key: {'fixture_only': True} for keys in b.r.groups().values() for key in keys},
            'original_qualification_pipeline': {'schema': 'hepta.runtime.original-pipeline.v1',
                'invocation': self.invocation, 'native_sha256': self.native_sha, 'shards': self.shards,
                'recipes': [key for keys in b.r.groups().values() for key in keys]}, 'checks': []}
        for name in b.r.CONTROLS:
            stdout, stderr = b'transport fixture output\n', b''
            (self.output / (name + '.stdout')).write_bytes(stdout)
            (self.output / (name + '.stderr')).write_bytes(stderr)
            report['checks'].append({'name': name, 'command': ['fixture-only-control', name],
                'phase': 'original_rust_comparison', 'timeout_seconds': 180, 'elapsed_seconds': 0.1,
                'exit_code': 0, 'timed_out': False, 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
                'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()})
        save(self.output / 'result.json', report)
        save(self.output / 'regex-evidence-controls.json', {'schema': 'hepta.runtime.regex-evidence-controls.v1',
            'status': 'PASS', 'negative_control_count': 14, 'negative_controls': list(range(14)),
            'actual_baseline_admissions': 6, 'source_and_artifacts_restored': True,
            'actual_process_report_sha256': b.p.digest(self.output / 'result.json')})
        self.bundle = self.root / 'bundle'

    def export(self):
        return b.export(self.output, self.bundle, self.head, self.invocation, self.native_sha, self.shards)

    def restore(self, digest):
        return b.restore(self.bundle, self.artifacts, self.root / 'restored', digest)

    def pending(self):
        report = b.p.read_json(self.output / 'result.json')
        report.update(status=b.r.COLLECTED_STATUS, phase=b.r.COLLECTED_PHASE,
            rust_comparison_status='PARTIAL', checks=[], original_collection_assembly_elapsed_seconds=0.1)
        save(self.output / 'result.json', report)
        (self.output / 'regex-evidence-controls.json').unlink()
        for name in b.r.CONTROLS:
            (self.output / (name + '.stdout')).unlink()
            (self.output / (name + '.stderr')).unlink()

    def controlled(self):
        report = b.p.read_json(self.output / 'result.json')
        report.update(status=b.r.CONTROLLED_STATUS, phase=b.r.CONTROLLED_PHASE,
            rust_comparison_status='PARTIAL', original_collection_assembly_elapsed_seconds=0.1,
            original_collection_controls_elapsed_seconds=0.2)
        for name in b.r.CONTROLS:
            report[name.replace('-', '_')] = {'transport_fixture_only': True}
        save(self.output / 'result.json', report)
        (self.output / 'regex-evidence-controls.json').unlink()

    def test_completed_controls_transport_remains_nonpass_and_requires_its_own_stage(self):
        self.controlled()
        for kwargs in ({}, {'collection': True}):
            with self.assertRaisesRegex(ValueError, 'exact collection stage'):
                b.export(self.output, self.bundle, self.head, self.invocation,
                    self.native_sha, self.shards, **kwargs)
        result = b.export(self.output, self.bundle, self.head, self.invocation,
            self.native_sha, self.shards, controls=True)
        self.assertEqual(result['status'], 'CONTROLS_BUNDLE_EXPORTED')
        self.assertEqual(result['semantic_checks_executed'], 0)
        for kwargs in ({}, {'collection': True}):
            with self.assertRaisesRegex(ValueError, 'qualification stage differs'):
                b.restore(self.bundle, self.artifacts, self.root / 'restored', result['sha256'], **kwargs)
        self.assertFalse((self.root / 'restored').exists())
        restored = b.restore(self.bundle, self.artifacts, self.root / 'restored', result['sha256'], controls=True)
        self.assertEqual(restored['status'], 'CONTROLS_BUNDLE_RESTORED')
        self.assertEqual(b.p.inventory(self.output), b.p.inventory(self.root / 'restored'))
        report = b.p.read_json(self.root / 'restored/result.json')
        self.assertEqual((report['status'], report['rust_comparison_status']), (b.r.CONTROLLED_STATUS, 'PARTIAL'))

    def test_controlled_transport_cannot_accept_final_pass_or_missing_actual_control(self):
        with self.assertRaisesRegex(ValueError, 'exact collection stage'):
            b.export(self.output, self.bundle, self.head, self.invocation,
                self.native_sha, self.shards, controls=True)
        result = self.export()
        with self.assertRaisesRegex(ValueError, 'qualification stage differs'):
            b.restore(self.bundle, self.artifacts, self.root / 'restored', result['sha256'], controls=True)
        shutil.rmtree(self.bundle)
        self.controlled()
        original = b.p.read_json(self.output / 'result.json')
        changes = [lambda x: x['checks'].pop(),
            lambda x: x['checks'].append(copy.deepcopy(x['checks'][-1])),
            lambda x: x['checks'][-1].__setitem__('timed_out', True),
            lambda x: x['checks'][-1].__setitem__('exit_code', 1),
            lambda x: x['checks'][-1].__setitem__('timeout_seconds', 179),
            lambda x: x.pop(b.r.CONTROLS[-1].replace('-', '_'))]
        for change in changes:
            report = copy.deepcopy(original); change(report); save(self.output / 'result.json', report)
            with self.assertRaises(ValueError):
                b.export(self.output, self.bundle, self.head, self.invocation,
                    self.native_sha, self.shards, controls=True)
            self.assertFalse(self.bundle.exists())

    def test_controlled_stage_cannot_import_regex_or_use_ambiguous_transport_flags(self):
        self.controlled()
        save(self.output / 'regex-evidence-controls.json', {'status': 'PASS'})
        with self.assertRaisesRegex(ValueError, 'cannot import final qualification controls'):
            b.export(self.output, self.bundle, self.head, self.invocation,
                self.native_sha, self.shards, controls=True)
        with self.assertRaisesRegex(ValueError, 'stage must be unambiguous'):
            b.export(self.output, self.bundle, self.head, self.invocation,
                self.native_sha, self.shards, collection=True, controls=True)
        with self.assertRaisesRegex(ValueError, 'stage must be unambiguous'):
            b.restore(self.bundle, self.artifacts, self.root / 'restored', 'a' * 64,
                collection=True, controls=True)

    def test_even_rehashed_controlled_payload_cannot_restore_a_premature_pass_report(self):
        self.controlled()
        b.export(self.output, self.bundle, self.head, self.invocation,
            self.native_sha, self.shards, controls=True)
        path = self.bundle / 'data/result.json'
        report = b.p.read_json(path)
        report.update(status='PASS', phase='complete', rust_comparison_status='PASS')
        save(path, report)
        manifest = b.p.read_json(self.bundle / b.MANIFEST)
        old = manifest['files']['result.json']['bytes']
        manifest['files']['result.json'].update(b.identity(path))
        manifest['full_evidence_bytes'] += path.stat().st_size - old
        save(self.bundle / b.MANIFEST, manifest)
        with self.assertRaisesRegex(ValueError, 'another qualification stage before restoration'):
            b.restore(self.bundle, self.artifacts, self.root / 'restored',
                b.p.digest(self.bundle / b.MANIFEST), controls=True)
        self.assertFalse((self.root / 'restored').exists())

    def test_nonpass_collection_preserves_all_bytes_without_claiming_complete_qualification(self):
        self.pending()
        with self.assertRaisesRegex(ValueError, 'exact collection stage'):
            self.export()
        result = b.export(self.output, self.bundle, self.head, self.invocation,
                          self.native_sha, self.shards, collection=True)
        self.assertEqual(result['status'], 'COLLECTION_BUNDLE_EXPORTED')
        self.assertEqual(result['semantic_checks_executed'], 0)
        with self.assertRaisesRegex(ValueError, 'qualification stage differs'):
            self.restore(result['sha256'])
        self.assertFalse((self.root / 'restored').exists())
        restored = b.restore(self.bundle, self.artifacts, self.root / 'restored',
                             result['sha256'], collection=True)
        self.assertEqual(restored['status'], 'COLLECTION_BUNDLE_RESTORED')
        self.assertEqual(b.p.inventory(self.output), b.p.inventory(self.root / 'restored'))
        self.assertEqual(b.p.read_json(self.root / 'restored/result.json')['status'], b.r.COLLECTED_STATUS)

    def test_complete_report_cannot_be_exported_or_restored_as_pending_collection(self):
        with self.assertRaisesRegex(ValueError, 'exact collection stage'):
            b.export(self.output, self.bundle, self.head, self.invocation,
                     self.native_sha, self.shards, collection=True)
        result = self.export()
        with self.assertRaisesRegex(ValueError, 'qualification stage differs'):
            b.restore(self.bundle, self.artifacts, self.root / 'restored', result['sha256'], collection=True)
        self.assertFalse((self.root / 'restored').exists())

    def test_pending_report_cannot_import_control_results(self):
        self.pending()
        report = b.p.read_json(self.output / 'result.json')
        report['checks'].append({'name': b.r.CONTROLS[0]})
        save(self.output / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'pending collection cannot import'):
            b.export(self.output, self.bundle, self.head, self.invocation,
                     self.native_sha, self.shards, collection=True)
        self.assertFalse(self.bundle.exists())

    def test_exact_full_byte_mode_and_empty_directory_reconstruction(self):
        result = self.export()
        self.assertEqual(result['status'], 'BUNDLE_EXPORTED')
        self.assertGreater(result['complete_files'], result['payload_files'])
        self.assertGreater(result['bytes_referenced_in_retained_artifacts'], 0)
        self.assertFalse((self.bundle / 'data/build/native.elf').exists())
        self.assertEqual(self.restore(result['sha256'])['status'], 'BUNDLE_RESTORED')
        self.assertEqual(b.p.inventory(self.output), b.p.inventory(self.root / 'restored'))
        for name in ['.', *b.p.inventory(self.output)[1]]:
            self.assertEqual(stat.S_IMODE((self.output / name).stat().st_mode),
                stat.S_IMODE((self.root / 'restored' / name).stat().st_mode))

    def test_zip_mode_loss_is_restored_from_the_complete_hashed_index(self):
        result = self.export()
        for root in (self.artifacts, self.bundle / 'data'):
            for path in root.rglob('*'):
                if path.is_file(): path.chmod(0o644)
        self.restore(result['sha256'])
        self.assertEqual(b.p.inventory(self.output), b.p.inventory(self.root / 'restored'))

    def test_export_refuses_missing_duplicate_or_cross_invocation_sources(self):
        original = dict(self.shards)
        for changed in ({key: value for key, value in original.items() if key != 'audit'},
                        {**original, 'unknown': 'a' * 64}, {**original, 'audit': 'f' * 64}):
            self.shards = changed
            with self.assertRaises(ValueError): self.export()
        self.shards = original
        self.invocation = '12345-2'
        with self.assertRaises(ValueError): self.export()
        self.assertFalse(self.bundle.exists())

    def test_modified_native_original_and_control_bytes_are_refused(self):
        for name in ('build/native.elf', 'audit/all-original-bytes.gz', b.r.CONTROLS[0] + '.stdout'):
            path = self.output / name; raw = path.read_bytes(); path.write_bytes(raw + b'altered')
            with self.subTest(name=name), self.assertRaises(ValueError): self.export()
            path.write_bytes(raw)
        self.export()

    def test_restore_requires_external_manifest_sha_and_all_retained_artifacts(self):
        result = self.export()
        with self.assertRaises(ValueError): self.restore('f' * 64)
        group = self.artifacts / b.source_name(self.head, self.invocation, 'audit')
        group.rename(self.root / 'held')
        with self.assertRaises(ValueError): self.restore(result['sha256'])
        self.assertFalse((self.root / 'restored').exists())

    def test_restore_rejects_tampered_sources_and_extra_payload_before_writing(self):
        result = self.export()
        for path in (self.artifacts / b.source_name(self.head, self.invocation, 'native') / 'build/native.elf',
                     self.bundle / 'data/result.json'):
            raw = path.read_bytes(); path.write_bytes(raw + b'changed')
            with self.assertRaises(ValueError): self.restore(result['sha256'])
            path.write_bytes(raw)
        (self.bundle / 'data/unrecorded').write_bytes(b'not admitted')
        with self.assertRaises(ValueError): self.restore(result['sha256'])
        self.assertFalse((self.root / 'restored').exists())

    def test_manifest_refuses_traversal_unknown_origin_special_modes_and_wrong_totals(self):
        self.export()
        original = b.p.read_json(self.bundle / b.MANIFEST)
        changes = [lambda x: x['files'].__setitem__('../escape', x['files']['result.json']),
            lambda x: x['files']['result.json'].__setitem__('origin', 'unknown'),
            lambda x: x['files']['result.json'].__setitem__('mode', 0o4755),
            lambda x: x['directories'].__setitem__('bad', 0o2755),
            lambda x: x.__setitem__('full_evidence_bytes', x['full_evidence_bytes'] - 1),
            lambda x: x['sources']['audit'].__setitem__('artifact', 'other-run'),
            lambda x: x['directories'].pop('build')]
        for change in changes:
            value = copy.deepcopy(original); change(value)
            with self.assertRaises(ValueError): b.validate_manifest(value)

    def test_symlink_and_existing_destination_are_refused(self):
        result = self.export()
        path = self.bundle / 'data/result.json'; raw = path.read_bytes(); path.unlink()
        target = self.root / 'outside'; target.write_bytes(raw); path.symlink_to(target)
        with self.assertRaises(ValueError): self.restore(result['sha256'])
        path.unlink(); path.write_bytes(raw)
        (self.root / 'restored').mkdir()
        with self.assertRaises(ValueError): self.restore(result['sha256'])
        with self.assertRaises(ValueError): self.export()

    def test_even_rehashed_index_cannot_omit_a_sealed_source_member(self):
        self.export()
        path = self.bundle / b.MANIFEST
        value = b.p.read_json(path)
        removed = value['files'].pop('build/native.elf')
        value['full_evidence_bytes'] -= removed['bytes']
        value['bytes_referenced_in_retained_artifacts'] -= removed['bytes']
        save(path, value)
        with self.assertRaisesRegex(ValueError, 'omits or remaps'):
            self.restore(b.p.digest(path))
        self.assertFalse((self.root / 'restored').exists())

    def test_workflow_exports_only_after_all_admissions_and_keeps_all_input_artifacts(self):
        text = (ROOT / '.github/workflows/hia-runtime-native.yml').read_text()
        last = text.split('\n  qualify:\n', 1)[1]
        controls = text.split('\n  original_controls:\n', 1)[1].split('\n  qualify:\n', 1)[0]
        self.assertIn('hia_native_artifact_bundle.py export-controls', controls)
        self.assertIn('controls_sha256: ${{ steps.bundle.outputs.sha256 }}', controls)
        self.assertNotIn('id: regex', controls)
        self.assertIn('hia_native_rust_pipeline.py finalize', last)
        self.assertIn('--controls-sha256 "${{ needs.original_controls.outputs.controls_sha256 }}"', last)
        self.assertLess(last.index('id: regex'), last.index('id: bundle'))
        self.assertIn('path: ${{ runner.temp }}/hia-aggregate-bundle/', last)
        self.assertIn('--github-output "$GITHUB_OUTPUT"', last)
        for group in b.r.groups():
            self.assertIn('--shard-sha256 "' + group + '=${{ needs.original_' + group + '.outputs.sha256 }}"', last)
        self.assertIn('timeout-minutes: 15', last)
        self.assertIn('name: hia-native-complete-', text)
        self.assertIn('name: hia-original-shard-', (ROOT / '.github/workflows/hia-runtime-original-shard.yml').read_text())


if __name__ == '__main__':
    unittest.main()
