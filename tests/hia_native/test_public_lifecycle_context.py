# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Check the three actual original-evidence owner shapes and invalid identities."""
from pathlib import Path
import copy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_public_lifecycle_qualification import verify_original_native_context

class OriginalNativeContext(unittest.TestCase):
    def setUp(self):
        self.binding = {'invocation': '123-4', 'context': {
            'mode': 'ci-original-pipeline', 'invocation': '123-4',
            'native_seal_sha256': 'a' * 64}}
        self.shard = {'original_shard': {'group': 'public', 'invocation': '123-4',
            'native_sha256': 'a' * 64}, 'started_at': 'different-start'}
        self.aggregate = {'original_qualification_pipeline': {
            'schema': 'hepta.runtime.original-pipeline.v1',
            'invocation': '123-4', 'native_sha256': 'a' * 64,
            'shards': {'public': 'b' * 64}, 'recipes': ['public-lifecycle']},
            'started_at': 'different-start'}

    def test_shard_owner(self):
        verify_original_native_context(self.binding, self.shard)

    def test_collected_owner_uses_workflow_invocation(self):
        verify_original_native_context(self.binding, self.aggregate)

    def test_owned_component(self):
        binding = {'invocation': 'aggregate:fixed-start', 'context': {
            'mode': 'owned-component-validation', 'invocation': 'aggregate:fixed-start'}}
        verify_original_native_context(binding, {'started_at': 'fixed-start'})
        for field in ('invocation', 'context'):
            changed = copy.deepcopy(binding)
            if field == 'invocation':
                changed[field] = 'aggregate:other-start'
            else:
                changed[field]['invocation'] = 'aggregate:other-start'
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_original_native_context(changed, {'started_at': 'fixed-start'})

    def test_workflow_binding_cannot_fall_back_to_owned(self):
        with self.assertRaises(ValueError):
            verify_original_native_context(self.binding, {'started_at': '123-4'})

    def test_ambiguous_workflow_owners_rejected_even_when_equal(self):
        report = copy.deepcopy(self.aggregate)
        report.update(self.shard)
        with self.assertRaises(ValueError):
            verify_original_native_context(self.binding, report)

    def test_each_workflow_identity_is_required(self):
        for source in (self.shard, self.aggregate):
            for field in ('mode', 'invocation', 'native_seal_sha256'):
                changed = copy.deepcopy(self.binding)
                changed['context'][field] = 'another-value'
                with self.subTest(source=source, field=field), self.assertRaises(ValueError):
                    verify_original_native_context(changed, source)
            changed = copy.deepcopy(self.binding)
            changed['invocation'] = 'other-run'
            with self.assertRaises(ValueError):
                verify_original_native_context(changed, source)

    def test_wrong_collected_schema_rejected(self):
        changed = copy.deepcopy(self.aggregate)
        changed['original_qualification_pipeline']['schema'] = 'unqualified'
        with self.assertRaises(ValueError):
            verify_original_native_context(self.binding, changed)

    def test_owned_binding_cannot_claim_workflow(self):
        binding = {'invocation': '123-4', 'context': {
            'mode': 'owned-component-validation', 'invocation': '123-4',
            'native_seal_sha256': 'a' * 64}}
        for report in (self.shard, self.aggregate):
            with self.assertRaises(ValueError):
                verify_original_native_context(binding, report)

if __name__ == '__main__':
    unittest.main()
