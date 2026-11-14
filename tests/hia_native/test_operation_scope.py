"""Actual private HIA scope continuations, lifetime and independent references.

The deterministic entropy child and credentials are synthetic test fixtures.
This suite does not authenticate bearers or prove concurrent capabilities.
"""
from pathlib import Path
from collections import Counter
import ctypes
import gzip
import hashlib
import hmac
import json
import os
import random
import struct
import subprocess
import sys
import unittest

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SOURCE_ROOT = Path(os.environ.get('HIA_SCOPE_SOURCE_ROOT', Path(__file__).resolve().parents[2]))
ROOT = Path(os.environ.get('HIA_REFERENCE_RUNTIME', SOURCE_ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule

INVALID, CAPACITY, INPUT, PAYLOAD, BINDING, ENTROPY, NONCE, INTEGRITY, KEY, STATE = range(0xffffffff, 0xfffffff5, -1)
FATAL, CALL = 0xffffffe8, 0xffffffe0
WORK = 3 << 20
PREFIX = b'hepta-runtime/native-operation/'
TOKEN = b'synthetic-verified-scope-token-0123456789'
FIELDS = [b'1' * 64, b'2' * 64, b'binary_read', b'3' * 64, b'4' * 64, b'5' * 64]
ORIGINAL_SHA = 'a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633'
COUNTS = Counter()
CORPUS = []
NATIVE_ROWS = []
FAULT_SESSIONS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def request(op, tail=b''):
    return b'HRSCOPE1' + struct.pack('<2Q', op, 0) + tail


def binding(op, payload=b'', *, fields=FIELDS, kind=1, timestamp=(1 << 120) + 69):
    return (b'HRREC001' + struct.pack('<11Q', op, 0, kind, timestamp & ((1 << 64) - 1),
                                    timestamp >> 64, *map(len, fields)) + b''.join(fields) + payload)


def entropy_control(seed=7, fail=0, mode=0, partial=0, *, stats=False):
    return b'HRTESTE1' + struct.pack('<5Q', 2 if stats else 1,
                                    0 if stats else seed, 0 if stats else fail,
                                    0 if stats else mode, 0 if stats else partial)


def entropy_bytes(seed, call, size, mode=0):
    base = seed + (call * 37 if mode == 0 else 0)
    return bytes((base + i * 19) & 255 for i in range(size))


def keys(token=TOKEN):
    prk = hmac.digest(PREFIX + b'crypto/extract/v1', token, 'sha256')
    domains = [b'result-aead/v1', b'request-binding/v1', b'idempotency-binding/v1', b'private-policy-binding/v1']
    return [hmac.digest(prk, PREFIX + label + b'\x01', 'sha256') for label in domains]


def private_binding(key, op, raw):
    domain = PREFIX + {3:b'request-binding/v1', 4:b'idempotency-binding/v1', 5:b'private-policy-binding/v1'}[op]
    return hmac.digest(key, len(domain).to_bytes(4, 'big') + domain + len(raw).to_bytes(8, 'big') + raw, 'sha256').hex().encode()


def sealed(key, nonce, payload, *, fields=FIELDS, kind=1, timestamp=(1 << 120) + 69):
    values = [PREFIX + b'result-aad/v1', b'HEPTAOP1', b'chacha20_poly1305',
              b'serialized-native-sdk-result-family/v1', *fields,
              b'native_result' if kind == 1 else b'native_error']
    aad = b''.join(len(v).to_bytes(4, 'big') + v for v in values) + timestamp.to_bytes(16, 'big')
    prk = hmac.digest(PREFIX + b'record-key/extract/v1', key, 'sha256')
    record_key = hmac.digest(prk, PREFIX + b'record-key/expand/v1' + fields[0] + fields[5] + b'\x01', 'sha256')
    inner = b'HOPIN001' + len(payload).to_bytes(8, 'big') + hashlib.sha256(payload).digest() + payload
    return b'HEPTAOP1' + nonce + ChaCha20Poly1305(record_key).encrypt(nonce, inner, aad)


class Harness:
    """Generic bounded child transport; every domain owner is native HIA."""
    def __init__(self, modules, profile):
        self.modules, self.profile = modules, profile
        self.work = {}
        self.trace = []
        self.retired = False
        self.replayable = True
        COUNTS['direct_sessions'] += 1
        self.session = COUNTS['direct_sessions']
        for row in profile:
            if row['id'] == 0:
                continue
            count = row['workspace_capacity']
            buf = ctypes.create_string_buffer(count + 16)
            ctypes.memset(ctypes.addressof(buf) + count, 0x6b, 16)
            self.work[row['id']] = (buf, count)

    def get(self, module, at):
        return struct.unpack('<Q', ctypes.string_at(ctypes.addressof(self.work[module][0]) + at, 8))[0]

    def put(self, module, at, value):
        ctypes.memmove(ctypes.addressof(self.work[module][0]) + at, struct.pack('<Q', value), 8)

    def bytes(self, module):
        buf, count = self.work[module]
        return ctypes.string_at(buf, count)

    def enter(self, module, source, size, output, capacity, *, active=(), fault=None):
        assert module not in active and len(active) < 8
        row = self.profile[module]
        assert size <= row['input_capacity'] and capacity <= row['output_capacity']
        buf, count = self.work[module]
        address = ctypes.addressof(buf)
        before = ctypes.string_at(source, size)
        b = count - 256
        if row['flags'] == 1:
            self.put(module, b + 120, 3)
            self.put(module, b + 128, module)
            self.put(module, b + 136, len(active) + 1)
        for _ in range(32):
            code = self.modules[module]._entry(ctypes.c_void_p(source), size, ctypes.c_void_p(output), capacity, buf, count)
            COUNTS['native_entries_' + str(module)] += 1
            assert ctypes.string_at(source, size) == before, 'child mutated its borrowed input'
            assert ctypes.string_at(address + count, 16) == b'\x6b' * 16
            if code != CALL:
                assert code >= 0xffff0000 or code <= capacity
                return code
            assert row['flags'] == 1
            values = struct.unpack('<14Q', ctypes.string_at(address + b, 112))
            magic, sequence, target, region, start, length, outregion, outat, outcap, reserved, result, ack, done, denied = values
            assert magic == int.from_bytes(b'HIACAL01', 'little') and sequence > 0
            assert row['call_mask'] & (1 << target) and target not in (*active, module)
            assert region in (0, 2) and outregion == 2 and reserved == result == ack == done == denied == 0
            input_base, input_bound = (source, size) if region == 0 else (address, b)
            assert start <= input_bound - length and outat <= b - outcap
            inp, dest = input_base + start, address + outat
            assert not length or not outcap or inp + length <= dest or dest + outcap <= inp
            phase = self.get(module, 160 if module == 6 else 0)
            returned = self.enter(target, inp, length, dest, outcap, active=(*active, module), fault=fault)
            event = {'caller':module, 'phase':phase, 'target':target, 'input_bytes':length, 'output_capacity':outcap, 'code':returned}
            self.trace.append(event)
            self.put(module, b + 80, returned)
            self.put(module, b + 88, sequence)
            self.put(module, b + 96, 1)
            self.put(module, b + 104, 0)
            if fault is not None:
                fault(self, event, b)
                event['fixture_completion_words'] = list(struct.unpack('<14Q', ctypes.string_at(address + b, 112)))
        raise AssertionError('private scope continuation failed to terminate')

    def invoke(self, wire, *, target=6, capacity=2 << 20, fault=None, fault_reason=None, export=True):
        assert not self.retired
        assert (fault is None) == (fault_reason is None)
        if fault is not None and self.replayable:
            # A changed child completion has no original Rust equivalent.
            # Exclude the complete session, including earlier constructor rows
            # and later release rows, so replay never receives a partial state
            # history with hidden entropy or nonce mutations.
            self.replayable = False
            FAULT_SESSIONS[self.session] = fault_reason
            prior = len(CORPUS)
            CORPUS[:] = [row for row in CORPUS if row['session'] != self.session]
            COUNTS['fault_sessions_excluded_from_rust'] += 1
            COUNTS['fault_session_prefix_rows_excluded'] += prior - len(CORPUS)
        source = ctypes.create_string_buffer(wire + b'\x7c' * 16)
        output = ctypes.create_string_buffer(capacity + 16)
        ctypes.memset(output, 0xa5, capacity + 16)
        trace_start = len(self.trace)
        code = self.enter(target, ctypes.addressof(source), len(wire), ctypes.addressof(output), capacity, fault=fault)
        size = 0 if code >= 0xffff0000 else code
        result = ctypes.string_at(output, size)
        assert source.raw == wire + b'\x7c' * 16 + b'\0'
        assert ctypes.string_at(ctypes.addressof(output) + size, capacity + 16 - size) == b'\xa5' * (capacity + 16 - size)
        COUNTS['direct_requests_' + str(target)] += 1
        if target == 6:
            private = self.bytes(6)
            assert private[160:WORK - 256] == bytes(WORK - 416), 'scope temporary secret-bearing bytes remain'
            if self.get(6, 0) in (0, 3, 4):
                assert private[8:WORK - 256] == bytes(WORK - 264)
            if code == FATAL:
                self.retired = True
        row = {'session':self.session, 'target':target, 'input_hex':wire.hex(), 'code':code,
               'output_hex':result.hex(), 'scope_state':self.get(6, 0), 'scope_references':self.get(6, 8),
               'entropy_calls':self.get(7, 40), 'nonce_count':self.get(5, 2056)}
        NATIVE_ROWS.append({**row, 'native_ordinal':len(NATIVE_ROWS), 'output_capacity':capacity,
                            'export_requested':export, 'injected_fault_reason':fault_reason,
                            'child_events':self.trace[trace_start:]})
        if export and self.replayable:
            CORPUS.append(row)
        return code, result

    def close(self):
        if not self.retired:
            while self.get(6, 0) == 2:
                assert self.invoke(request(9), capacity=0) == (0, b'')
        if self.get(6, 0) in (0, 3, 4):
            assert self.bytes(6)[8:WORK - 256] == bytes(WORK - 264)
        if self.get(6, 0) == 3:
            assert self.bytes(5) == bytes(1576960)
            assert self.bytes(2) == bytes(2048)
            assert self.bytes(4) == bytes(512)
            assert self.bytes(1)[:WORK-256] == bytes(WORK-256)


class ScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_SCOPE_MANIFEST'])
        cls.meta = json.loads(cls.manifest.read_bytes())
        cls.proof = json.loads((SOURCE_ROOT / 'native/operation_scope_composition.json').read_bytes())
        assert cls.meta['profile'] == [{k:v for k,v in item.items() if k != 'source'} for item in cls.proof['members']]
        assert cls.meta['compiler_commit'] == cls.proof['compiler_commit']
        assert cls.meta['compiler_sha256'] == cls.proof['compiler_sha256']
        assert sha((ROOT / 'src/mcp/runtime/operation_crypto.rs').read_bytes()) == ORIGINAL_SHA
        for name, digest in cls.proof['dependency_provenance'].items():
            assert sha((ROOT / name).read_bytes()) == digest
        assert sha((ROOT / 'native/composition_packer.hepta').read_bytes()) == cls.proof['packer_source_sha256']
        assert cls.meta['packer']['source_sha256'] == cls.proof['packer_source_sha256']
        cls.modules = {}
        for index, item in enumerate(cls.proof['members']):
            source = (SOURCE_ROOT if index in (0, 6, 7) else ROOT) / item['source']
            assert sha(source.read_bytes()) == item['source_sha256']
            row = cls.meta['members'][index]
            path = cls.manifest.parent / row['manifest']
            assert sha(path.read_bytes()) == row['manifest_sha256']
            assert row['source_sha256'] == item['source_sha256']
            cls.modules[index] = NativeModule(path, manifest_sha256=sha(path.read_bytes()))
        cls.exe = cls.manifest.parent / cls.meta['executable']
        assert sha(cls.exe.read_bytes()) == cls.meta['executable_sha256']
        names = ['oracle_operation_scope.rs', 'scope_oracle/Cargo.toml', 'scope_oracle/Cargo.lock',
                 'scope_oracle/build.rs', 'scope_oracle/original_access.rs']
        cls.oracle_sources = {name:sha((Path(__file__).parent/name).read_bytes()) for name in names}

    @classmethod
    def tearDownClass(cls):
        for module in cls.modules.values():
            module.close()
        if os.environ.get('HIA_SCOPE_CORPUS_DIR'):
            names = ['oracle_operation_scope.rs', 'scope_oracle/Cargo.toml', 'scope_oracle/Cargo.lock',
                     'scope_oracle/build.rs', 'scope_oracle/original_access.rs']
            oracle_sources = {name:sha((Path(__file__).parent / name).read_bytes()) for name in names}
            assert oracle_sources == cls.oracle_sources, 'original reference sources changed during native execution'
            folder = Path(os.environ['HIA_SCOPE_CORPUS_DIR'])
            folder.mkdir(parents=True, exist_ok=False)
            fault_rows = [row for row in NATIVE_ROWS if row['session'] in FAULT_SESSIONS]
            capacity_rows = [row for row in NATIVE_ROWS
                             if row['session'] not in FAULT_SESSIONS and not row['export_requested']]
            assert all(row['code'] == CAPACITY for row in capacity_rows)
            assert len(CORPUS) + len(fault_rows) + len(capacity_rows) == len(NATIVE_ROWS)
            assert len(NATIVE_ROWS) == sum(COUNTS[f'direct_requests_{target}'] for target in (5, 6, 7))
            assert {row['session'] for row in CORPUS}.isdisjoint(FAULT_SESSIONS)
            excluded = []
            for session, reason in sorted(FAULT_SESSIONS.items()):
                rows = [row for row in fault_rows if row['session'] == session]
                excluded.append({'session':session, 'reason':reason, 'native_rows':len(rows),
                                 'injected_rows':sum(row['injected_fault_reason'] is not None for row in rows),
                                 'first_native_ordinal':rows[0]['native_ordinal'],
                                 'last_native_ordinal':rows[-1]['native_ordinal']})
            def controls(name, rows):
                data = b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n' for row in rows)
                encoded = gzip.compress(data, mtime=0)
                (folder / name).write_bytes(encoded)
                return {'file':name, 'native_rows':len(rows), 'raw_bytes':len(data),
                        'raw_sha256':sha(data), 'gzip_bytes':len(encoded), 'gzip_sha256':sha(encoded)}
            retained_controls = {
                'selection_policy':'entire session selected when a named child-result fault is installed, before observing the result',
                'excluded_sessions':excluded, 'total_direct_native_rows':len(NATIVE_ROWS),
                'fault_histories':controls('scope_fault_sessions.jsonl.gz', fault_rows),
                'capacity_controls':controls('scope_capacity_controls.jsonl.gz', capacity_rows)}
            raw = b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n' for row in CORPUS)
            packed = gzip.compress(raw, mtime=0)
            (folder / 'scope_cases.jsonl.gz').write_bytes(packed)
            metadata = {'schema':'hepta.runtime.native-operation-scope-corpus.v1', 'counts':dict(COUNTS),
                        'source_sha256':cls.proof['source_sha256'], 'image_sha256':cls.meta['members'][6]['image_sha256'],
                        'manifest_sha256':sha(cls.manifest.read_bytes()), 'composition_sha256':sha((SOURCE_ROOT/'native/operation_scope_composition.json').read_bytes()),
                        'test_sha256':sha(Path(__file__).read_bytes()), 'builder_sha256':sha((SOURCE_ROOT/'scripts/hia_native_scope_build.py').read_bytes()),
                        'original_source_sha256':ORIGINAL_SHA, 'oracle_sources_sha256':oracle_sources,
                        'native_controls':retained_controls,
                        'python_reference':{'distribution':'cryptography','version':cryptography.__version__},
                        'native_output_sha256':sha(''.join(f"{r['code']}:{r['output_hex']}\n" for r in CORPUS).encode()),
                        'corpus':{'file':'scope_cases.jsonl.gz','cases':len(CORPUS),'raw_bytes':len(raw),
                                  'raw_sha256':sha(raw),'gzip_sha256':sha(packed)}}
            (folder/'native-corpus.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
        print(json.dumps({'native_scope_counts':dict(COUNTS)},sort_keys=True))

    def setUp(self):
        self.h = Harness(self.modules, self.meta['profile'])
        self.assertEqual(self.h.invoke(entropy_control(),target=7,capacity=128),(0,b''))

    def tearDown(self):
        self.h.close()

    def fresh(self, *, seed=7, fail=0, mode=0, partial=0):
        self.h.close()
        self.h = Harness(self.modules, self.meta['profile'])
        self.assertEqual(self.h.invoke(entropy_control(seed,fail,mode,partial),target=7,capacity=128),(0,b''))
        return self.h

    def ok(self, wire, expected=b'', **kw):
        self.assertEqual(self.h.invoke(wire,**kw),(len(expected),expected))

    def refuse(self, wire, code, **kw):
        self.assertEqual(self.h.invoke(wire,**kw),(code,b''))

    def test_token_keys_bindings_and_shared_serial_lifetime(self):
        self.ok(request(1,TOKEN),capacity=0)
        self.assertEqual(self.h.bytes(6)[32:160],b''.join(keys()))
        self.assertEqual(self.h.get(7,40),0)
        self.assertEqual([(r['phase'],r['target']) for r in self.h.trace if r['caller']==6],[(1,2),(3,5)])
        for _ in range(3):
            self.ok(request(8),capacity=0)
        self.assertEqual(self.h.get(6,8),4)
        for op in (3,4,5):
            raw=b'private context: \0\xff'+bytes([op])
            self.ok(request(op,raw),private_binding(keys()[op-2],op,raw),capacity=64)
            COUNTS['binding_reference_cases']+=1
        self.ok(request(9),capacity=0)
        self.assertEqual(self.h.get(6,8),3)
        self.ok(request(3,b'still alive'),private_binding(keys()[1],3,b'still alive'),capacity=64)
        COUNTS['binding_reference_cases']+=1
        self.h.close()
        self.assertEqual(self.h.bytes(5),bytes(1576960))
        self.refuse(request(3,b'closed'),STATE)
        self.refuse(request(1,TOKEN),STATE)

    def test_seal_open_and_exact_order(self):
        self.ok(request(1,TOKEN),capacity=0)
        payload=b'private output\0with arbitrary\xffbytes'
        expected=sealed(keys()[0],entropy_bytes(7,1,12),payload)
        self.h.trace.clear()
        self.ok(request(6,binding(4,payload)),expected)
        self.assertEqual([(r['phase'],r['target']) for r in self.h.trace if r['caller']==6],[(5,1),(6,7),(7,5),(8,1)])
        COUNTS['seal_reference_cases']+=1
        self.assertEqual(self.h.get(5,2056),1)
        self.h.trace.clear()
        self.ok(request(7,binding(3,expected)),payload)
        self.assertEqual([(r['phase'],r['target']) for r in self.h.trace if r['caller']==6],[(9,1)])
        self.assertEqual(self.h.get(7,40),1)
        self.assertEqual(self.h.get(5,2056),1)
        COUNTS['open_reference_cases']+=1


    def test_stdio_four_fills_failure_cleanup_and_retry(self):
        for failed in (1,2,3,4):
            self.fresh(seed=19,fail=failed,partial=17)
            self.refuse(request(2),ENTROPY,capacity=0)
            self.assertEqual(self.h.get(7,40),failed)
            self.assertEqual(self.h.get(7,48),failed*32)
            self.assertEqual(self.h.get(5,2048),0)
            self.assertEqual([e['output_capacity'] for e in self.h.trace if e['target']==7],[32]*failed)
            COUNTS['stdio_failure_reference_cases']+=1
            self.ok(request(2),capacity=0)
            expected=[entropy_bytes(19,failed+i,32) for i in range(1,5)]
            self.assertEqual(self.h.bytes(6)[32:160],b''.join(expected))
            self.assertEqual(self.h.get(7,40),failed+4)
            self.assertEqual(self.h.get(5,2048),int.from_bytes(b'HNSTATE1','little'))
            for op in (3,4,5):
                payload=b'ordered private stdio key '+bytes([op])
                self.ok(request(op,payload),private_binding(expected[op-2],op,payload),capacity=64)
                COUNTS['binding_reference_cases']+=1
            COUNTS['stdio_success_reference_cases']+=1
        self.fresh(seed=51,fail=5,partial=7)
        self.ok(request(2),capacity=0)
        expected=[entropy_bytes(51,i,32) for i in range(1,5)]
        self.refuse(request(6,binding(4,b'private result')),ENTROPY)
        self.assertEqual(self.h.bytes(6)[32:160],b''.join(expected))
        self.assertEqual(self.h.get(5,2056),0)
        output=sealed(expected[0],entropy_bytes(51,6,12),b'private result')
        self.ok(request(6,binding(4,b'private result')),output)
        COUNTS['seal_reference_cases']+=1
        COUNTS['entropy_failure_reference_cases']+=1

    def test_token_admission_and_binding_limits(self):
        bad=[b'',b'x',b'x'*31,b'x'*4097]
        bad += [b'x'*15+bytes([n])+b'x'*16 for n in list(range(33))+list(range(127,256))]
        for token in bad:
            self.refuse(request(1,token),INPUT,capacity=0)
            self.assertEqual(self.h.get(7,40),0)
            self.assertEqual(self.h.get(5,2048),0)
            COUNTS['invalid_token_reference_cases']+=1
        for size in (32,33,64,127,4095,4096):
            self.fresh()
            token=bytes(33+(i*17)%94 for i in range(size))
            self.ok(request(1,token),capacity=0)
            self.assertEqual(self.h.bytes(6)[32:160],b''.join(keys(token)))
            COUNTS['verified_constructor_reference_cases']+=1
            for op in (3,4,5):
                self.refuse(request(op),INPUT)
                self.refuse(request(op,b'x'*(129 if op==4 else 1048577)),INPUT)
                data=bytes(range(128)) if op==4 else b'\x00\xffcanonical'+bytes([size&255])
                self.ok(request(op,data),private_binding(keys(token)[op-2],op,data),capacity=64)
                COUNTS['binding_reference_cases']+=1
                COUNTS['invalid_binding_input_reference_cases']+=2
        for op in (3,5):
            data=(b'private-context-\xff\x00'*70000)[:1048576]
            self.ok(request(op,data),private_binding(keys(token)[op-2],op,data),capacity=64)
            COUNTS['binding_reference_cases']+=1

    def test_preflight_precedes_entropy_and_reservation(self):
        self.ok(request(1,TOKEN),capacity=0)
        badfields=list(FIELDS);badfields[2]=b'Bad_tool'
        self.refuse(request(6,binding(4,b'x'*1048577,fields=badfields)),PAYLOAD)
        self.refuse(request(6,binding(4,b'x',fields=badfields)),BINDING,capacity=0)
        self.refuse(request(6,binding(4,b'x')),CAPACITY,capacity=84,export=False)
        self.assertEqual(self.h.get(7,40),0)
        self.assertEqual(self.h.get(5,2056),0)
        self.assertFalse(any(e['target'] in (5,7) for e in self.h.trace if e['phase'] in (5,6,7,8)))
        packet=sealed(keys()[0],bytes(range(12)),b'never reserved')
        self.refuse(request(7,binding(3,b'bad',fields=badfields)),INTEGRITY)
        self.refuse(request(7,binding(3,packet,fields=badfields)),BINDING,capacity=0)
        self.refuse(request(7,binding(3,packet)),CAPACITY,capacity=0,export=False)
        self.ok(request(7,binding(3,packet)),b'never reserved')
        self.assertEqual(self.h.get(7,40),0)
        self.assertEqual(self.h.get(5,2056),0)
        COUNTS['preflight_reference_refusals']+=4
        COUNTS['capacity_refusals']+=2
        COUNTS['open_reference_cases']+=1


    def test_shared_nonce_rejection_and_distinct_namespaces(self):
        self.fresh(seed=23,mode=1)
        self.ok(request(1,TOKEN),capacity=0)
        self.ok(request(8),capacity=0)
        nonce=entropy_bytes(23,1,12,mode=1)
        packet=sealed(keys()[0],nonce,b'first clone')
        self.ok(request(6,binding(4,b'first clone')),packet)
        self.refuse(request(6,binding(4,b'second clone')),NONCE)
        self.ok(request(9),capacity=0)
        self.refuse(request(6,binding(4,b'after another clone was released')),NONCE)
        owner=list(FIELDS);owner[1]=b'6'*64
        self.refuse(request(6,binding(4,b'changed AAD owner',fields=owner)),NONCE)
        for index in (0,5):
            fields=list(FIELDS);fields[index]=b'a'*64
            expected=sealed(keys()[0],nonce,b'new namespace',fields=fields)
            self.ok(request(6,binding(4,b'new namespace',fields=fields)),expected)
            COUNTS['seal_reference_cases']+=1
        self.ok(request(7,binding(3,packet)),b'first clone')
        self.assertEqual(self.h.get(5,2056),3)
        COUNTS['seal_reference_cases']+=1
        COUNTS['open_reference_cases']+=1
        COUNTS['duplicate_nonce_reference_cases']+=3

    def test_record_boundaries_kinds_u128_and_authentication(self):
        self.ok(request(1,TOKEN),capacity=0)
        rng=random.Random(0x5c0fe)
        sizes=[0,1,15,16,17,63,64,65,255,1024,16384,1048576]
        sizes += [rng.randrange(0,2049) for _ in range(40)]
        stamps=[0,(1<<64)-1,1<<64,1<<127,(1<<128)-1]
        for index,size in enumerate(sizes):
            fields=list(FIELDS)
            fields[0]=hashlib.sha256(str(index).encode()).hexdigest().encode()
            if index==1:
                fields[2]=b'a'+b'9_'*63+b'z'
            payload=rng.randbytes(size)
            kind=1+index%2;stamp=stamps[index%len(stamps)]
            nonce=entropy_bytes(7,index+1,12)
            expected=sealed(keys()[0],nonce,payload,fields=fields,kind=kind,timestamp=stamp)
            sealwire=request(6,binding(4,payload,fields=fields,kind=kind,timestamp=stamp))
            self.ok(sealwire,expected,capacity=len(expected))
            self.ok(request(7,binding(3,expected,fields=fields,kind=kind,timestamp=stamp)),payload,capacity=len(payload))
            COUNTS['seal_reference_cases']+=1
            COUNTS['open_reference_cases']+=1
            COUNTS['exact_capacity_successes']+=2
            if index<4:
                for at in (0,8,20,len(expected)-1):
                    changed=bytearray(expected);changed[at]^=1
                    self.refuse(request(7,binding(3,changed,fields=fields,kind=kind,timestamp=stamp)),INTEGRITY)
                    COUNTS['authentication_reference_refusals']+=1
        self.assertEqual(self.h.get(5,2056),len(sizes))
        self.assertEqual(self.h.get(7,40),len(sizes))

    def test_budget_exhaustion_consumes_entropy_before_refusing(self):
        self.ok(request(1,TOKEN),capacity=0)
        for index in range(16384):
            frame=b'HRNONC01'+struct.pack('<2Q',2,0)+FIELDS[0]+FIELDS[5]+index.to_bytes(12,'little')
            self.assertEqual(self.h.invoke(frame,target=5,capacity=0),(0,b''))
        COUNTS['nonce_budget_setup_reservations']+=16384
        self.h.trace.clear()
        self.refuse(request(6,binding(4,b'budget exhausted')),NONCE)
        self.assertEqual(self.h.get(7,40),1)
        self.assertEqual(self.h.get(5,2056),16384)
        self.assertEqual([(e['phase'],e['target']) for e in self.h.trace if e['caller']==6],[(5,1),(6,7),(7,5)])
        COUNTS['nonce_budget_reference_refusals']+=1


    def test_malformed_frames_and_admission_do_not_mutate_capability(self):
        self.ok(request(1,TOKEN),capacity=0)
        before=self.h.bytes(6)[:160]
        samples=[request(3,b'x')[:n] for n in range(24)]
        samples += [request(0),request(10),request(2,b'x'),request(8,b'x'),request(9,b'x')]
        for at in range(8):
            raw=bytearray(request(3,b'x'));raw[at]^=1;samples.append(bytes(raw))
        for bit in range(64):
            raw=bytearray(request(3,b'x'));struct.pack_into('<Q',raw,16,1<<bit);samples.append(bytes(raw))
        samples += [request(6,binding(4,b'x')[:n]) for n in (0,1,8,16,24,48,95)]
        raw=bytearray(request(6,binding(4,b'x')));struct.pack_into('<Q',raw,72,(1<<64)-1);samples.append(bytes(raw))
        for wire in samples:
            self.refuse(wire,INVALID)
            self.assertEqual(self.h.bytes(6)[:160],before)
        self.refuse(request(1,TOKEN),STATE)
        self.refuse(request(2),STATE)
        self.refuse(request(3,b'valid'),CAPACITY,capacity=63,export=False)
        self.assertEqual(self.h.get(7,40),0)
        self.assertEqual(self.h.get(5,2056),0)
        COUNTS['malformed_frame_refusals']+=len(samples)
        COUNTS['capacity_refusals']+=1

    def test_child_contract_refusals_clear_keys_and_retire_bundle(self):
        def prepare(phase):
            self.fresh()
            if phase not in (1,2,3):
                self.ok(request(1,TOKEN),capacity=0)
            if phase==2:
                return request(2)
            if phase in (1,3):
                return request(1,TOKEN)
            if phase==4:
                return request(3,b'private binding')
            if phase==9:
                packet=sealed(keys()[0],bytes(range(12)),b'private output')
                return request(7,binding(3,packet))
            if phase==10:
                return request(9)
            return request(6,binding(4,b'private output'))
        for phase in range(1,11):
            wire=prepare(phase)
            fired=[]
            def fault(h,event,b):
                if event['caller']==6 and event['phase']==phase and not fired:
                    h.put(6,b+80,1 if event['code']==0 else event['code']-1)
                    fired.append(True)
            self.refuse(wire,FATAL,fault=fault,
                        fault_reason=f'phase {phase}: replace the child result length',export=False)
            self.assertEqual(fired,[True])
            self.assertEqual(self.h.bytes(6)[8:WORK-256],bytes(WORK-264))
            if phase in (7,8):
                self.assertEqual(self.h.get(5,2056),1)
            COUNTS['child_contract_refusals']+=1
        for offset in (0,8,16,24,32,40,48,56,64,72,88,96,104):
            wire=prepare(4)
            def fault(h,event,b):
                if event['caller']==6:
                    h.put(6,b+offset,h.get(6,b+offset)^1)
            self.refuse(wire,FATAL,fault=fault,
                        fault_reason=f'phase 4: corrupt call-footer word at byte {offset}',export=False)
            COUNTS['child_contract_refusals']+=1
        wire=prepare(4)
        def dirty(h,event,b):
            if event['caller']==6:
                h.put(6,b+80,(1<<32)|64)
        self.refuse(wire,FATAL,fault=dirty,
                    fault_reason='phase 4: child result has nonzero bits above u32',export=False)
        COUNTS['child_contract_refusals']+=1

    def test_consumed_nonce_is_not_refunded_after_record_refusal(self):
        self.fresh(mode=1)
        self.ok(request(1,TOKEN),capacity=0)
        def refused_record(h,event,b):
            if event['caller']==6 and event['phase']==8:
                h.put(6,b+80,0xfffffffb)
        self.refuse(request(6,binding(4,b'private output')),INTEGRITY,fault=refused_record,
                    fault_reason='phase 8: replace record seal completion after nonce reservation',export=False)
        self.assertEqual(self.h.get(5,2056),1)
        self.assertEqual(self.h.get(6,0),2)
        self.refuse(request(6,binding(4,b'no automatic nonce refund')),NONCE,export=False)
        COUNTS['post_reservation_refusal_controls']+=2


    def test_actual_persistent_elf_capability_and_lifecycle(self):
        payload=b'actual ELF private output\0\xff'
        packet=sealed(keys()[0],entropy_bytes(7,1,12,1),payload)
        cases=[(entropy_control(mode=1),0,b''),(request(1,TOKEN),0,b''),
               (request(8),0,b''),(request(3,b'private'),64,private_binding(keys()[1],3,b'private')),
               (request(6,binding(4,payload)),len(packet),packet),
               (request(7,binding(3,packet)),len(payload),payload),
               (request(6,binding(4,b'clone duplicate')),NONCE,b''),
               (request(9),0,b''),(request(7,binding(3,packet)),len(payload),payload),
               (request(9),0,b''),(request(3,b'closed'),STATE,b''),(request(1,TOKEN),STATE,b''),
               (entropy_control(stats=True),32,struct.pack('<4Q',2,24,0,12))]
        expected_keys=[entropy_bytes(41,n,32) for n in range(4,8)]
        nonce=entropy_bytes(41,8,12)
        encrypted=sealed(expected_keys[0],nonce,payload)
        retry=[(entropy_control(41,3,partial=17),0,b''),(request(2),ENTROPY,b''),(request(2),0,b''),
               (request(4,b'private idempotency'),64,private_binding(expected_keys[2],4,b'private idempotency')),
               (request(6,binding(4,payload)),len(encrypted),encrypted),
               (request(7,binding(3,encrypted)),len(payload),payload),(request(9),0,b''),
               (entropy_control(stats=True),32,struct.pack('<4Q',8,236,1,12))]
        refusal=[(request(3,b'no capability'),STATE,b''),
                 (b'HRKDF001'+bytes(48),INVALID,b''),
                 (b'HRNONC01'+struct.pack('<2Q',3,0),INVALID,b''),
                 (binding(1),INVALID,b'')]
        for trace in (cases,retry,refusal):
            stdin=b''.join(w.hex().encode()+b'\n' for w,_,_ in trace)
            expected=b''.join(f'{c:08x}:'.encode()+o.hex().encode()+b'\n' for _,c,o in trace)
            result=subprocess.run([str(self.exe),'--local-read-profile','/scope-fixture'],
                                  input=stdin,capture_output=True,env={'PATH':'','LC_ALL':'C'},timeout=30)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected,b''))
            COUNTS['actual_elf_processes']+=1
            COUNTS['actual_elf_requests']+=len(trace)
            COUNTS['actual_elf_responses']+=len(trace)
        # A real HIA child returns a short successful length. The scope must
        # retire and the root must stop without emitting a partial scope reply.
        wire=entropy_control(mode=2).hex().encode()+b'\n'+request(2).hex().encode()+b'\n'
        result=subprocess.run([str(self.exe),'--local-read-profile','/scope-fixture'],
                              input=wire,capture_output=True,env={'PATH':'','LC_ALL':'C'},timeout=30)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'00000000:\n',b''))
        COUNTS['actual_elf_processes']+=1
        COUNTS['actual_elf_requests']+=2
        COUNTS['actual_elf_responses']+=1
        COUNTS['actual_elf_fatal_contract_controls']+=1


if __name__ == '__main__':
    unittest.main(verbosity=2)
