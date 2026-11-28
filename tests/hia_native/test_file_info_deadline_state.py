#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""HIA deadline continuation state with synthetic guard acknowledgements.

This is not a wall-clock or blocked-syscall test. The native guard's actual
process ownership, cancellation and timing must be qualified separately.
"""
import errno, hashlib, json, os, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_file_info_io_state import InfoIoStateTests, Fixture, request, EFFECT, COUNTS


class DeadlineStateTests(unittest.TestCase):
    setUpClass = classmethod(InfoIoStateTests.setUpClass.__func__)
    tearDownClass = classmethod(InfoIoStateTests.tearDownClass.__func__)
    fixture = InfoIoStateTests.fixture

    def test_start_failures_preserve_parent_root_and_recover(self):
        for error, status in [(errno.ETIMEDOUT, 15), (errno.ENOMEM, 19),
                              (errno.EMFILE, 19), (errno.ENOSYS, 19), (errno.EIO, 19)]:
            fixture = self.fixture(fault=lambda _, event: error if event['action'] == 10 else 0)
            root = fixture.get(72)
            before_sha = COUNTS['native_sha_calls']
            before_call = fixture.get(2184)
            result = fixture.info()
            self.assertEqual((result['status'], result['error']), (status, error))
            self.assertEqual([event['action'] for event in fixture.events], [10])
            self.assertEqual(fixture.get(72), root)
            self.assertEqual(fixture.get(2184), before_call)
            self.assertEqual(COUNTS['native_sha_calls'], before_sha)
            self.assertEqual((fixture.get(16), fixture.get(2192)), (0, 0))
            fixture.fault = None
            self.assertEqual(fixture.info()['sha256'], hashlib.sha256(b'abc').digest())
            self.assertEqual(fixture.events[-1]['action'], 12)
            self.assertEqual((fixture.get(16), fixture.get(2192)), (0, 0))

    def test_finish_failure_discards_prepared_result_and_recovers(self):
        fixture = self.fixture(fault=lambda _, event: errno.EIO if event['action'] == 12 else 0)
        result = fixture.info()
        self.assertEqual((result['status'], result['error']), (19, errno.EIO))
        self.assertEqual(sum(event['action'] == 12 for event in fixture.events), 1)
        self.assertEqual((fixture.get(16), fixture.get(2192)), (0, 0))
        fixture.fault = None
        self.assertEqual(fixture.info()['status'], 0)

    def test_invalid_start_acknowledgements_refuse(self):
        for position in (320, 336, 344, 352):
            fixture = Fixture(self.members[3], self.members[2])
            raw = request()
            self.assertEqual(fixture.native(raw), EFFECT)
            self.assertEqual(fixture.get(16), 55)
            fixture.effect()
            prior = fixture.get(position)
            fixture.put(position, prior + 1)
            self.assertEqual(fixture.native(raw), 0xffffffff)
            fixture.put(position, prior)
            self.assertEqual(fixture.info()['status'], 0)
            fixture.close()


if __name__ == '__main__':
    outcome = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DeadlineStateTests))
    if not outcome.wasSuccessful():
        raise SystemExit(1)
    proof = dict(schema='hepta.runtime.native-info-deadline-state-test.v1', status='pass', counts=COUNTS,
                 io_source_sha256=DeadlineStateTests.members[3].metadata['source_sha256'],
                 io_manifest_sha256=hashlib.sha256(DeadlineStateTests.owner_manifest.read_bytes()).hexdigest(),
                 guard='synthetic acknowledgements; no real wall-clock deadline claim')
    if os.environ.get('HIA_INFO_DEADLINE_STATE_RESULT'):
        Path(os.environ['HIA_INFO_DEADLINE_STATE_RESULT']).write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(proof, sort_keys=True))
