"""Actual scope ELF, fixed entropy syscalls and complete original Rust scope.

Every credential, binding and payload in this file is a synthetic test fixture.
The supervisor controls only its own directly forked child. Ordinary random
bytes are never compared for equality; deterministic injected completions are.
"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import os
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('HIA_REFERENCE_RUNTIME', HERE.parents[1]))
SOURCE_ROOT = Path(os.environ.get('HIA_SCOPE_OS_SOURCE_ROOT', HERE.parents[1]))
sys.path.insert(0,str(HERE))
from scope_os_support import inspect_scope_os
INVALID, CAPACITY, INPUT, PAYLOAD, BINDING, ENTROPY, NONCE, INTEGRITY, KEY, STATE = range(0xffffffff, 0xfffffff5, -1)
TOKEN = b'synthetic-verified-scope-token-0123456789'
FIELDS = [b'1' * 64, b'2' * 64, b'binary_read', b'3' * 64, b'4' * 64, b'5' * 64]
PAYLOAD_BYTES = b'owned native scope payload\0\xff\xe4\xb8\xad'
ORIGINAL_SHA = 'a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633'
COUNTS = Counter()
CASES = []


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def request(op, tail=b''):
    return b'HRSCOPE1' + struct.pack('<2Q', op, 0) + tail


def record(op, payload=b'', *, fields=FIELDS, kind=1, timestamp=(1 << 120) + 69):
    return (b'HRREC001' + struct.pack('<11Q', op, 0, kind, timestamp & ((1 << 64) - 1),
                                    timestamp >> 64, *map(len, fields)) + b''.join(fields) + payload)


class Session:
    def __init__(self, suite, mode, label, original=False):
        self.suite, self.mode, self.original = suite, mode, original
        self.log = suite.directory / (label + ('-rust' if original else '-native') + '.json')
        binary = suite.reference if original else suite.binary
        command = [sys.executable, '-I', '-B', str(HERE / 'scope_os_supervisor.py'),
                   '--mode', mode, '--log', str(self.log), '--', str(binary)]
        if not original:
            command += ['--local-read-profile', '/']
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, start_new_session=True)
        self.pending = bytearray()
        self.rows = []
        self.finished = False

    def response(self):
        deadline = time.monotonic() + 15
        while b'\n' not in self.pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'owned scope response exceeded the 15-second test deadline'
            if not select.select([self.process.stdout], [], [], remaining)[0]:
                raise AssertionError('owned scope did not publish a response')
            raw = os.read(self.process.stdout.fileno(), 65536)
            if not raw:
                assert not self.pending, 'partial code/hex response was published'
                return None
            self.pending.extend(raw)
            assert len(self.pending) <= 16 << 20
        line, _, rest = self.pending.partition(b'\n')
        self.pending[:] = rest
        assert len(line) >= 9 and line[8:9] == b':' and line[:8] == line[:8].lower()
        code, output = int(line[:8], 16), bytes.fromhex(line[9:].decode('ascii'))
        assert len(output) == (0 if code >= 0xffff0000 else code)
        return code, output

    def call(self, wire, expected=None):
        self.process.stdin.write(wire.hex().encode('ascii') + b'\n')
        self.process.stdin.flush()
        result = self.response()
        if result is None:
            self.process.stdin.close();self.process.stdin=None
            out,err=self.process.communicate(timeout=15)
            raise AssertionError('scope unexpectedly terminated: '+err.decode(errors='replace'))
        code, output = result
        if expected is not None:
            assert code == expected, (self.mode, code, expected)
        self.rows.append({'input_sha256':digest(wire), 'input_bytes':len(wire), 'operation':struct.unpack_from('<Q', wire, 8)[0],
                          'code':code, 'output_sha256':digest(output), 'output_bytes':len(output)})
        return output

    def finish(self, exit_code=0):
        assert not self.finished
        self.finished = True
        if self.process.stdin is not None:
            self.process.stdin.close()
            self.process.stdin = None
        try:
            out, err = self.process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.communicate()
            raise AssertionError('owned scope process group exceeded the 15-second cleanup deadline')
        assert self.process.returncode == exit_code, (self.mode, self.process.returncode, err.decode(errors='replace'))
        assert not out and not self.pending, 'unexpected unaccounted scope output'
        trace = json.loads(self.log.read_bytes())
        assert trace['owned_child_reaped'] is True
        order=trace['entropy_event_order']
        for domain,field in [('system_entropy','events'),('original_standard_library','original_auxiliary_entropy')]:
            assert [item['index'] for item in order if item['domain']==domain] == list(range(len(trace[field])))
        assert len(order)==len(trace['events'])+len(trace['original_auxiliary_entropy'])
        assert all(item['domain'] in ('system_entropy','original_standard_library') for item in order)
        expected = self.suite.reference_sha if self.original else self.suite.binary_sha
        assert trace['executable_sha256'] == expected
        owner = None
        if self.original:
            owner = json.loads(err)
            assert owner['status'] == 'PASS' and owner['actual_system_entropy'] is True
            assert owner['fixture_entropy_owner_used'] is False
            assert owner['requests'] == len(self.rows)
            assert owner['refusals'] == sum(row['code'] >= 0xffff0000 for row in self.rows)
            assert trace['native_cleanup'] is None and not trace['native_idle_snapshots']
            assert len(trace['original_auxiliary_entropy']) == 1
            assert trace['original_startup_entropy'] == [{'kind':'process_runtime_startup','requested':8,'flags':1,
                'completion':'kernel','before_input':True,'getrandom_index':0}]
            assert all(row['symbol']=='syscall' for row in trace['original_system_rng_callsites'])
            assert trace['original_getrandom_syscalls'] == len(trace['original_system_rng_callsites']) + 2
            COUNTS['original_standard_library_seed_calls'] += len(trace['original_auxiliary_entropy'])
            COUNTS['original_process_startup_rng_calls'] += 1
            COUNTS['original_getrandom_syscalls'] += trace['original_getrandom_syscalls']
        else:
            assert err == b'', err.decode(errors='replace')
            assert not trace['original_auxiliary_entropy'] and not trace['original_system_rng_callsites']
            assert not trace['original_startup_entropy'] and trace['original_getrandom_syscalls'] == 0
            cleanup = trace['native_cleanup']
            assert cleanup['private_workspaces_zero'] is True and cleanup['transport_output_zero'] is True
            assert cleanup['private_entropy_descriptors_retired'] is True and cleanup['module_count'] == 8
            assert cleanup['exit_code'] == exit_code
            snapshots = trace['native_idle_snapshots']
            assert snapshots and all(row['scope_transient_zero'] and row['entropy_transient_zero'] for row in snapshots)
            sequences = [row['entropy_sequence'] for row in snapshots]
            assert sequences == sorted(sequences), 'ordinary scope operations reset the entropy sequence'
            for row in snapshots:
                if row['scope_state'] != 2:
                    assert row['private_keys_zero'] is True
        prefix = 'original_' if self.original else 'native_'
        COUNTS[prefix+'processes'] += 1
        COUNTS[prefix+'responses'] += len(self.rows)
        COUNTS[prefix+'refusals'] += sum(row['code'] >= 0xffff0000 for row in self.rows)
        COUNTS[prefix+'kernel_completions'] += sum(e['completion'] == 'kernel' for e in trace['events'])
        COUNTS[prefix+'injected_completions'] += sum(e['completion'] != 'kernel' for e in trace['events'])
        if owner:
            for key, value in owner.items():
                if key.startswith('original_') and type(value) is int:
                    COUNTS[key] += value
        return {'mode':self.mode, 'rows':self.rows, 'trace':trace, 'original_owner':owner, 'exit_code':exit_code}

    def abort(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
        self.process.communicate()


def normalized_events(trace, *, original):
    events = trace['events']
    data = [row for row in events if row['kind'] == 'read_urandom']
    closes = [index for index, row in enumerate(events) if row['kind'] == 'close_urandom']
    if original:
        assert not closes
    elif data:
        assert closes == [len(events)-1], 'cached entropy fd was not retained until process cleanup'
    else:
        assert not closes
    return [{k:v for k,v in row.items() if k != 'device_fd'} for row in events if row['kind'] != 'close_urandom']


class ScopeOsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_SCOPE_OS_MANIFEST'])
        cls.artifact = inspect_scope_os(cls.manifest,SOURCE_ROOT)
        cls.metadata = json.loads(cls.manifest.read_bytes())
        cls.binary = (cls.manifest.parent / cls.metadata['executable']).resolve(strict=True)
        cls.binary_sha = digest(cls.binary.read_bytes())
        assert cls.binary_sha == cls.metadata['executable_sha256']
        assert cls.metadata['compiler_commit'] == 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
        reference = os.environ.get('HIA_SCOPE_OS_REFERENCE_BINARY')
        cls.reference = Path(reference).resolve(strict=True) if reference else None
        cls.reference_sha = digest(cls.reference.read_bytes()) if cls.reference else None
        if reference:
            assert cls.reference_sha == os.environ['HIA_SCOPE_OS_REFERENCE_SHA256']
        assert digest((ROOT/'src/mcp/runtime/operation_crypto.rs').read_bytes()) == ORIGINAL_SHA
        cls.temporary = tempfile.TemporaryDirectory(prefix='hepta-owned-scope-os-')
        cls.directory = Path(cls.temporary.name)
        cls.sources = {str(path.relative_to(HERE)):digest(path.read_bytes()) for path in
                       [HERE/'test_scope_os.py', HERE/'scope_os_supervisor.py', HERE/'scope_os_support.py', HERE/'io_fault_supervisor.py',
                        HERE/'oracle_scope_os.rs', *(HERE/'scope_os_oracle').glob('*')]
                       if path.is_file()}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_pair(self, mode, label, action, *, exact=False):
        sessions = [Session(self, mode, label)]
        if self.reference:
            sessions.append(Session(self, mode, label, original=True))
        reports = []
        try:
            for session in sessions:
                action(session)
                reports.append(session.finish())
        finally:
            for session in sessions:
                session.abort()
        native = reports[0]
        case = {'label':label, 'comparison':'deterministic-completions' if exact else 'semantic-results-and-system-entropy-trace',
                'native':native, 'original':reports[1] if len(reports)==2 else None}
        CASES.append(case)
        if len(reports) == 2:
            original = reports[1]
            self.assertEqual(normalized_events(native['trace'], original=False),
                             normalized_events(original['trace'], original=True))
            self.assertEqual([(r['operation'],r['code'],r['output_bytes']) for r in native['rows']],
                             [(r['operation'],r['code'],r['output_bytes']) for r in original['rows']])
            if exact:
                self.assertEqual(native['rows'], original['rows'])
                COUNTS['deterministic_byte_compared_responses'] += len(native['rows'])
            COUNTS['original_compared_process_pairs'] += 1
        else:
            normalized_events(native['trace'], original=False)
        return native

    def exercise(self, session, *, stdio=False, release=True):
        session.call(request(2) if stdio else request(1,TOKEN), 0)
        for op in (3,4,5):
            value = session.call(request(op,b'canonical synthetic context'),64)
            self.assertTrue(all(c in b'0123456789abcdef' for c in value))
        packet = session.call(request(6,record(4,PAYLOAD_BYTES)),len(PAYLOAD_BYTES)+84)
        self.assertEqual(packet[:8],b'HEPTAOP1')
        opened = session.call(request(7,record(3,packet)),len(PAYLOAD_BYTES))
        self.assertEqual(opened,PAYLOAD_BYTES)
        corrupt = bytearray(packet);corrupt[-1] ^= 1
        session.call(request(7,record(3,bytes(corrupt))),INTEGRITY)
        if release:
            session.call(request(9),0)

    def test_real_stdio_and_normal_random_roundtrip(self):
        for mode in ('observe','probe_enosys','probe_eperm'):
            result = self.run_pair(mode,'stdio-'+mode,lambda s:self.exercise(s,stdio=True))
            events = result['trace']['events']
            self.assertEqual([e['requested'] for e in events if e['kind'] in ('getrandom','read_urandom')],[32,32,32,32,12])
            self.assertEqual(sum(e['kind']=='probe' for e in events),1)
            released = [r for r in result['trace']['native_idle_snapshots'] if r['scope_state']==3]
            self.assertTrue(released and released[-1]['entropy_sequence'] > 0)
            self.assertEqual(released[-1]['entropy_cached_fd'],int(mode!='observe'))

    def test_real_nonce_cross_open_between_owners(self):
        sessions=[Session(self,'observe','cross')]
        if self.reference:sessions.append(Session(self,'observe','cross',original=True))
        try:
            for s in sessions:s.call(request(1,TOKEN),0)
            packets=[s.call(request(6,record(4,PAYLOAD_BYTES)),len(PAYLOAD_BYTES)+84) for s in sessions]
            # Compare authenticated plaintext across the owners. Nonces and
            # ciphertext are deliberately not asserted equal or unequal.
            for index,s in enumerate(sessions):
                self.assertEqual(s.call(request(7,record(3,packets[(index+1)%len(sessions)])),len(PAYLOAD_BYTES)),PAYLOAD_BYTES)
                s.call(request(9),0)
            reports=[s.finish() for s in sessions]
            if self.reference:
                self.assertEqual(normalized_events(reports[0]['trace'],original=False),normalized_events(reports[1]['trace'],original=True))
                COUNTS['actual_cross_owner_opens'] += 2
                COUNTS['original_compared_process_pairs'] += 1
            else:
                normalized_events(reports[0]['trace'],original=False)
            CASES.append({'label':'cross-open-real-nonces','comparison':'cross-owner-authenticated-plaintext' if self.reference else 'native-authenticated-roundtrip',
                          'native':reports[0],'original':reports[1] if self.reference else None})
        finally:
            for s in sessions:s.abort()

    def test_deterministic_partial_completions_and_stdio_order(self):
        for mode in ('constant','fallback_constant','partial','fallback_partial'):
            self.run_pair(mode,'synthetic-'+mode,lambda s:self.exercise(s,stdio=True),exact=True)

    def test_each_stdio_fill_failure_clears_and_retries(self):
        for fail in range(1,5):
            def action(s):
                s.call(request(2),ENTROPY)
                s.call(request(3,b'not active'),STATE)
                self.exercise(s,stdio=True)
            self.run_pair('stdio_fail_'+str(fail),'stdio-failure-'+str(fail),action,exact=True)

    def test_preflight_precedes_entropy_and_data_errors_keep_backend(self):
        fields=list(FIELDS);fields[0]=b'A'*64
        for mode in ('eio','enosys','eagain','zero'):
            def action(s):
                s.call(request(1,TOKEN),0)
                s.call(request(6,record(4,b'x',fields=fields)),BINDING)
                s.call(request(6,record(4,b'x'*(1048576+1),fields=fields)),PAYLOAD)
                s.call(request(6,record(4,b'x')),ENTROPY)
                s.call(request(6,record(4,b'x')),ENTROPY)
                s.call(request(9),0)
            report=self.run_pair(mode,'data-error-'+mode,action,exact=True)
            self.assertEqual([e['requested'] for e in report['trace']['events'] if e['kind']=='getrandom'],[12,12])

    def test_fallback_recovery_and_partial_error_cache(self):
        for mode in ('fallback_open_error','fallback_poll_error','fallback_urandom_open_error',
                     'fallback_read_error','partial_error','fallback_partial_error'):
            def action(s):
                s.call(request(1,TOKEN),0)
                s.call(request(6,record(4,b'x')),ENTROPY)
                packet=s.call(request(6,record(4,PAYLOAD_BYTES)),len(PAYLOAD_BYTES)+84)
                self.assertEqual(s.call(request(7,record(3,packet)),len(PAYLOAD_BYTES)),PAYLOAD_BYTES)
                s.call(request(9),0)
            self.run_pair(mode,'recovery-'+mode,action)

    def test_probe_outcomes_and_interruptions(self):
        for mode in ('probe_eintr','probe_eio','probe_eagain','eintr','fallback_eintr'):
            self.run_pair(mode,'retry-'+mode,self.exercise)

    def test_clone_lifetime_shared_nonce_accounting_and_cached_entropy(self):
        for mode in ('constant','fallback_constant'):
            def action(s):
                s.call(request(1,TOKEN),0)
                s.call(request(8),0)
                packet=s.call(request(6,record(4,PAYLOAD_BYTES)),len(PAYLOAD_BYTES)+84)
                s.call(request(9),0)
                s.call(request(6,record(4,PAYLOAD_BYTES)),NONCE)
                fields=list(FIELDS);fields[5]=b'6'*64
                s.call(request(6,record(4,PAYLOAD_BYTES,fields=fields)),len(PAYLOAD_BYTES)+84)
                self.assertEqual(s.call(request(7,record(3,packet)),len(PAYLOAD_BYTES)),PAYLOAD_BYTES)
                s.call(request(9),0)
                s.call(request(3,b'retired'),STATE)
            self.run_pair(mode,'clone-'+mode,action,exact=True)

    def test_eof_destroys_active_private_keys(self):
        for mode in ('observe','probe_enosys'):
            report=self.run_pair(mode,'active-eof-'+mode,lambda s:self.exercise(s,stdio=True,release=False))
            snapshots=report['trace']['native_idle_snapshots']
            self.assertEqual(snapshots[-1]['scope_state'],2)
            self.assertFalse(snapshots[-1]['private_keys_zero'])

    def test_impossible_kernel_results_poison_and_clean_native_only(self):
        for mode in ('bad_errno','fallback_bad_errno'):
            s=Session(self,mode,'native-contract-'+mode)
            try:
                s.call(request(1,TOKEN),0)
                wire=request(6,record(4,PAYLOAD_BYTES))
                s.process.stdin.write(wire.hex().encode()+b'\n');s.process.stdin.flush()
                self.assertIsNone(s.response())
                result=s.finish(2)
                COUNTS['native_contract_requests_without_response'] += 1
                CASES.append({'label':'native-contract-'+mode,'comparison':'native-only-impossible-kernel-contract',
                              'pending_request_sha256':digest(wire),'native':result,'original':None})
            finally:s.abort()
        for mode in ('oversized','fallback_oversized'):
            s=Session(self,mode,'native-contract-'+mode)
            try:
                s.call(request(1,TOKEN),0)
                s.call(request(6,record(4,PAYLOAD_BYTES)),ENTROPY)
                s.call(request(3,b'still active'),64)
                s.call(request(9),0)
                result=s.finish()
                COUNTS['native_impossible_count_refusals'] += 1
                CASES.append({'label':'native-contract-'+mode,'comparison':'native-only-impossible-kernel-contract',
                              'native':result,'original':None})
            finally:s.abort()

    def test_transport_failure_retires_cached_entropy_fd(self):
        for broken in (False,True):
            s=Session(self,'probe_enosys','broken-output' if broken else 'malformed-hex')
            try:
                s.call(request(2),0)
                if broken:
                    s.process.stdout.close();s.process.stdout=None
                    raw=request(3,b'will fail while publishing')
                    s.process.stdin.write(raw.hex().encode()+b'\n');s.process.stdin.flush()
                    result=s.finish(74)
                else:
                    s.process.stdin.write(b'0\n');s.process.stdin.flush()
                    self.assertIsNone(s.response())
                    result=s.finish(2)
                COUNTS['native_transport_requests_without_response'] += 1
                CASES.append({'label':'broken-output' if broken else 'malformed-hex','comparison':'native-only-transport',
                              'native':result,'original':None})
            finally:s.abort()


if __name__=='__main__':
    result=unittest.main(exit=False,verbosity=2)
    complete=(result.result.wasSuccessful() and result.result.testsRun==11 and not result.result.skipped
              and not result.result.expectedFailures and not result.result.unexpectedSuccesses)
    expected={'native_contract_requests_without_response':2,'native_impossible_count_refusals':2,
              'native_injected_completions':371,'native_kernel_completions':148,'native_processes':37,
              'native_refusals':54,'native_responses':238,'native_transport_requests_without_response':2}
    if getattr(ScopeOsTests,'reference',None):
        expected.update(actual_cross_owner_opens=2,deterministic_byte_compared_responses=114,
                        original_clones=2,original_compared_process_pairs=31,original_idempotency_bindings=18,
                        original_injected_completions=363,original_kernel_completions=106,original_last_releases=29,
                        original_opens=45,original_policy_bindings=18,original_processes=31,original_refusals=52,
                        original_releases=31,original_request_bindings=18,original_responses=226,original_seals=53,
                        original_standard_library_seed_calls=31,original_stdio_constructors=17,original_verified_constructors=18)
        expected.update(original_process_startup_rng_calls=31,original_getrandom_syscalls=298)
    complete=complete and dict(COUNTS)==expected
    sources=getattr(ScopeOsTests,'sources',{})
    unchanged=all(digest((HERE/name).read_bytes())==value for name,value in sources.items())
    report={'schema':'hepta.runtime.scope-os-test.v1','status':'PASS' if complete and unchanged else 'FAIL',
            'expected_counts':expected,'original_reference_status':'PASS' if complete and getattr(ScopeOsTests,'reference',None) else 'PENDING' if not getattr(ScopeOsTests,'reference',None) else 'FAIL',
            'tests_run':result.result.testsRun,'failures':len(result.result.failures),'errors':len(result.result.errors),
            'skipped':len(result.result.skipped),'counts':dict(COUNTS),'cases':CASES,
            'source_sha256':sources,'source_unchanged':unchanged,'original_source_sha256':ORIGINAL_SHA,
            'artifact':getattr(ScopeOsTests,'artifact',None),
            'native_executable_sha256':getattr(ScopeOsTests,'binary_sha',None),
            'original_executable_sha256':getattr(ScopeOsTests,'reference_sha',None),
            'normal_random_bytes_equality_claimed':False,'production_activated':False,
            'concurrent_shared_capability_qualified':False,
            'cleanup_difference':'Native explicitly closes its cached urandom fd and wipes declared private regions; original process exit releases its static cache.'}
    target=os.environ.get('HIA_SCOPE_OS_RESULT')
    if target:
        path=Path(target);assert not path.exists();path.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))
    raise SystemExit(0 if report['status']=='PASS' else 1)
