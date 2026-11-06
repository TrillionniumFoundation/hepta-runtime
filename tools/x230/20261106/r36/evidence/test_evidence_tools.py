#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Local failure/containment fixtures only; no X230 paths, workload or credential reads."""
import base64
from contextlib import redirect_stdout
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import evidence_policy as policy
import pack_r36_evidence as pack
from scan_evidence import scan
import verify_r36_evidence as verify


class EvidenceTests(unittest.TestCase):
    def test_encoded_secret_findings_never_include_the_matched_body(self):
        token = b'gh' + b'p_' + b'A' * 36
        forms = [token, token.hex().encode(), base64.b64encode(token),
                 json.dumps({'bytes_hex': base64.b64encode(token).hex()}).encode(),
                 gzip.compress(json.dumps({'value': token.decode()}).encode())]
        escaped = b'"' + b''.join(('\\u%04x' % byte).encode() for byte in token) + b'"'
        shallow = base64.b64encode(escaped)
        deep = base64.b64encode(gzip.compress(shallow))
        forms.append(json.dumps({'a': shallow.decode(), 'b': deep.decode()}).encode())
        for body in forms:
            with self.subTest(bytes=len(body)):
                findings = scan(body, 'fixture')
                self.assertTrue(any('github-token' in item['pattern'] for item in findings))
                self.assertTrue(all(set(item) == {'path', 'pattern'} for item in findings))
                self.assertNotIn(token.decode(), json.dumps(findings))

    def test_pem_is_found_in_raw_escaped_and_encoded_forms_without_marker_false_positive(self):
        header = b'-----BEGIN ' + b'PRIVATE KEY-----'
        key = header + b'\n' + b'A' * 64 + b'\n'
        traditional = (b'-----BEGIN ' + b'RSA PRIVATE KEY-----\n'
                       + b'Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,' + b'A' * 32
                       + b'\n\n' + b'A' * 64 + b'\n')
        for value in (key, traditional):
            inner = json.dumps({'value': value.decode()})
            rpc = json.dumps({'content': [{'type': 'text', 'text': inner}]}).encode()
            jsonl = rpc + b'\n' + rpc + b'\n'
            for body in (value, json.dumps({'value': value.decode()}).encode(), base64.b64encode(value), value.hex().encode(), jsonl):
                self.assertTrue(any('private-key-pem' in row['pattern'] for row in scan(body, 'fixture')))
        self.assertEqual(scan(b'PRIVATE_MARKERS = (b"' + header + b'",)', 'source-fixture'), [])

    def test_private_and_target_directories_are_never_traversed(self):
        helper = policy.load_helper()
        here = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(dir=here) as temporary:
            root = Path(temporary)
            for name in ('.ssh', 'profile', 'target-build', 'qualification-01'):
                (root / name).mkdir()
                (root / name / 'sentinel').write_bytes(b'not a real credential')
            original = policy.os.scandir

            def guarded(path):
                self.assertNotIn(Path(path).name, ('.ssh', 'profile', 'target-build'))
                return original(path)

            with patch.object(policy, 'SCOPES', {'r36': root, 'recovery': root / 'absent'}), patch.object(policy.os, 'scandir', guarded):
                value = policy.inventory(helper, root / 'evidence-export-01')
            for name in ('.ssh', 'profile', 'target-build'):
                self.assertIsNotNone(value['entries']['r36/' + name]['reason'])
                self.assertNotIn('r36/' + name + '/sentinel', value['entries'])
            self.assertIn('r36/qualification-01/sentinel', value['entries'])

    def test_absence_failed_reports_and_unreadable_outputs_are_not_promoted(self):
        scopes = {'r36': {'directories': {'r36/qualification-01': {}}, 'entries': ['r36/campaign-01']},
                  'recovery': {'present': False}}
        reports = {'r36/qualification-01/report.json': b'{"qualified": false}'}
        observations = policy.stage_observations(scopes, reports.get)
        self.assertIs(observations['qualification']['reported_flag'], False)
        self.assertEqual(observations['observation']['state'], 'metadata_only_output_unresolved')
        self.assertEqual(observations['lifecycle']['state'], 'not_executed_no_output_observed')
        self.assertIsNone(observations['cancel_recovery']['reported_flag'])

    def test_holder_copy_binding_rejects_changed_bytes_and_unplanned_paths(self):
        relative = 'observation-holder-01/receipt.json'
        member = 'r36/holder-inputs-01/' + relative
        body = b'{"passed": false}'
        pin = {'original_path': str(policy.HOLDER_ROOT / relative), 'bytes': len(body),
               'sha256': hashlib.sha256(body).hexdigest()}
        manifest = {'schema': 'hepta-r36-observed-holder-copies/v1', 'observed': True, 'files': {relative: pin}}
        payloads = {member: dict(pin), 'r36/holder-inputs-01/manifest.json': {}}
        getter = lambda name: json.dumps(manifest).encode()
        self.assertEqual(policy.holder_bindings(payloads, {}, getter)['state'], 'observed_copies_bound')
        payloads[member]['sha256'] = '0' * 64
        with self.assertRaises(RuntimeError):
            policy.holder_bindings(payloads, {}, getter)
        payloads[member]['sha256'] = pin['sha256']
        pin['original_path'] = str(policy.HOLDER_ROOT / 'unplanned/receipt.json')
        with self.assertRaises(RuntimeError):
            policy.holder_bindings(payloads, {}, getter)

    def test_archive_roundtrip_preserves_failure_and_refuses_tampering(self):
        here = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(dir=here) as temporary:
            base = Path(temporary)
            root, recovery = base / 'r36', base / 'absent-recovery'
            root.mkdir()
            deployed = root / 'evidence-tools-01'
            deployed.mkdir()
            for name in policy.TOOL_FILES:
                shutil.copyfile(here / name, deployed / name)
            qualification = root / 'qualification-01'
            qualification.mkdir()
            (qualification / 'report.json').write_text('{"qualified":false}\n')
            (qualification / 'stderr').write_text('synthetic failed test\n')
            (qualification / 'case-log.gz').write_bytes(gzip.compress(b'synthetic case output\n'))
            (qualification / 'test-executable').write_bytes(b'\x7fELF' + b'synthetic omitted body')
            for name in ('.ssh', 'target-build'):
                (root / name).mkdir()
                (root / name / 'not-read').write_text('synthetic body\n')
            out = root / 'evidence-export-01'
            with patch.object(policy, 'ROOT', root), patch.object(policy, 'CANARY', recovery), \
                    patch.object(policy, 'SCOPES', {'r36': root, 'recovery': recovery}), redirect_stdout(io.StringIO()):
                self.assertEqual(pack.capture(out), 0)
                report = out / 'export-report.json'
                pin = hashlib.sha256(report.read_bytes()).hexdigest()
                result = base / 'verification.json'
                argv = ['verify', '--archive', str(out / 'r36-evidence-01.tar.xz'), '--report', str(report),
                        '--report-sha256', pin, '--out', str(result)]
                with patch.object(sys, 'argv', argv):
                    self.assertEqual(verify.main(), 0)
                value = json.loads(result.read_bytes())
                self.assertIs(value['original_stage_observations']['qualification']['reported_flag'], False)
                self.assertIs(value['candidate_adopted'], False)
                self.assertEqual(value['omission_count'], 3)
                self.assertEqual(value['original_stage_observations']['lifecycle']['state'], 'not_executed_no_output_observed')
                archive = out / 'r36-evidence-01.tar.xz'
                with archive.open('ab') as stream:
                    stream.write(b'trailing corruption')
                argv[-1] = str(base / 'must-not-pass.json')
                with patch.object(sys, 'argv', argv), self.assertRaises(RuntimeError):
                    verify.main()
                self.assertFalse(Path(argv[-1]).exists())
if __name__ == '__main__':
    unittest.main()
