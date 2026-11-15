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
