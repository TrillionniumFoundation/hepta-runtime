#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline cross-evidence consistency for the v4 ChatGPT model-origin tool ledger.

This verifies accounting and pinning, not that GitHub CI originated a ChatGPT
call. New model-origin actions must have an independent, explicit receipt.
"""
import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
QUAL = ROOT/'docs/qualification'

def load(path):
    return json.loads(path.read_text())

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class ModelOriginLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load(ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json')
        cls.before_path = QUAL/'dc-parity-v4-model-origin-tool-ledger-20261013.json'
        cls.delta_path = QUAL/'dc-parity-v4-model-origin-seven-new-20261013.json'
        cls.final_path = QUAL/'dc-parity-v4-model-origin-tool-ledger-v2-20261013.json'
        cls.before = load(cls.before_path)
        cls.delta = load(cls.delta_path)
        cls.final = load(cls.final_path)

    def test_exact_approved_catalog_and_annotation_partition(self):
        tools = self.catalog['tools']
        self.assertEqual(self.catalog['tool_count'], 50)
        self.assertEqual(self.catalog['catalog_sha256'], '63742708c287e8468d73f27ba85ecc6585afd4adcd76d06b618456730cfaf8ad')
        self.assertEqual(len(tools), 50)
        readonly = {t['name'] for t in tools if t['annotations']['readOnlyHint']}
        mutating = {t['name'] for t in tools if not t['annotations']['readOnlyHint']}
        self.assertEqual(len(readonly), 19)
        self.assertEqual(len(mutating), 31)
        self.assertEqual(set(self.final['model_positive_nonreadonly_tools']) |
                         set(self.final['model_unverified_nonreadonly_tools']), mutating)
        self.assertFalse(set(self.final['model_positive_nonreadonly_tools']) & readonly)

    def test_no_name_promoted_without_independent_receipt(self):
        old_positive = set(self.before['model_positive_nonreadonly_tools'])
        old_unknown = set(self.before['model_unverified_nonreadonly_tools'])
        new_positive = set(self.delta['new_positive_tool_names'])
        self.assertEqual((len(old_positive), len(old_unknown)), (22, 9))
        self.assertEqual(len(new_positive), 7)
        self.assertTrue(new_positive <= old_unknown)
        self.assertEqual(set(self.final['model_positive_nonreadonly_tools']), old_positive | new_positive)
        self.assertEqual(set(self.final['model_unverified_nonreadonly_tools']), old_unknown-new_positive)
        self.assertEqual((self.final['model_origin_successful_tool_names'],
                          self.final['model_origin_not_verified_tool_names']), (29, 2))
        self.assertEqual(self.final['previous_ledger_sha256'], sha(self.before_path))
        self.assertEqual(self.final['delta_evidence_sha256'], sha(self.delta_path))

    def test_high_risk_unverified_tools_are_not_silently_promoted(self):
        self.assertEqual(self.final['model_unverified_nonreadonly_tools'],
                         ['privileged_action', 'process_checkpoint'])
        self.assertFalse(self.delta['checkpoint_inspect_probe']['not_counted_as_positive'] is False)
        self.assertEqual(self.delta['checkpoint_inspect_probe']['native_job_final_state'], 'cancelled')
        self.assertFalse(self.delta['checkpoint_inspect_probe']['no_dump_restore_resume_or_existing_process_modified'] is False)
        self.assertEqual(self.delta['privileged_action_policy']['host_actions_advertised'], 0)
        self.assertTrue(self.delta['limits']['action_annotations_modified'] is False)
        self.assertTrue(self.delta['limits']['public_gateway_deployed'] is False)

    def test_scope_does_not_misrepresent_bounded_success(self):
        self.assertIn('No cryptographic ChatGPT-origin attestation', self.delta['origin'])
        self.assertTrue(self.delta['checks']['pdf_security']['unsigned_incremental_revision'])
        self.assertFalse(self.delta['checks']['binary_patch_inode']['atomic_visibility'])
        self.assertTrue(self.delta['checks']['stream_handoff']['cooperating_dc_owner'])
        self.assertTrue(self.delta['checks']['stream_handoff']['other_sessions_untouched'])
        self.assertEqual([x['total'] for x in self.delta['checks']['stream_handoff']['events']], [0,17,22])
        self.assertTrue(self.delta['checks']['sudo_start']['no_privileged_write'])

if __name__=='__main__':
    unittest.main(verbosity=2)
