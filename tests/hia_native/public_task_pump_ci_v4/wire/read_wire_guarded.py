"""Preload and guard the immutable serial1394 wire and complete journal readers.

This is a new wrapper around the five byte-preserved observer files. Graph
admission belongs to ci/read_build.py and must run in the caller's same guard.
No verification function in this module writes a report or launches a process.
"""
from __future__ import annotations
import codecs
import gzip
import importlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent


def prepare(port_package):
    """Call before the fixed guard; this performs only source reads/imports."""
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / 'reference'))
    wire = importlib.import_module('read_wire')
    journal = importlib.import_module('read_public_journal')
    guard = importlib.import_module('read_only_guard')
    controls = importlib.import_module('public_reader_controls')
    observer_controls = importlib.import_module('observer_process_controls')
    assert Path(wire.__file__).resolve(strict=True) == ROOT / 'read_wire.py'
    assert Path(journal.__file__).resolve(strict=True) == ROOT / 'read_public_journal.py'
    assert Path(guard.__file__).resolve(strict=True) == ROOT / 'reference/read_only_guard.py'
    assert Path(wire.original_reader.__file__).resolve(strict=True) == ROOT / 'reference/verify.py'
    assert Path(controls.__file__).resolve(strict=True) == ROOT / 'public_reader_controls.py'
    assert Path(observer_controls.__file__).resolve(strict=True) == ROOT / 'observer_process_controls.py'
    wire.source_pin()
    prepared = journal.prepare(port_package)
    # Warm library decoding and the exact source-owned corpus imports. The
    # unchanged reader regenerates and compares all 1,394 inputs again inside
    # the guard; this is not a cached replacement for its input validation.
    for encoding in ('utf-8', 'utf-8-sig', 'ascii'):
        codecs.lookup(encoding)
    assert gzip.decompress(gzip.compress(b'', mtime=0)) == b''
    assert tomllib.loads('owned = true')['owned'] is True
    assert sum(1 for _ in wire.rows()) == 1394
    return {'wire': wire, 'journal': journal, 'guard': guard, 'prepared_journal': prepared,
            'controls': controls, 'observer_controls': observer_controls}


def verify(capture, original_run, *, expected_binary, prepared):
    wire = prepared['wire'].verify(Path(capture), Path(original_run), expected_binary=expected_binary)
    journal = prepared['journal'].verify(Path(capture), wire, prepared=prepared['prepared_journal'])
    assert journal['records'] == wire['records'] == 1394
    return {'status': 'COMPLETE_SERIAL1394_WIRE_AND_WORKER_EVIDENCE_PASS',
            'wire': wire, 'journal': journal,
            'requires_same_guard_fresh_graph_admission': True,
            'native_or_rust_executions': 0, 'reader_writes': 0,
            'full_sdk_qualified': False, 'async_pending_registry_qualified': False,
            'cross_session_pool_qualified': False, 'whole_runtime_replaced': False}


def guarded(operation, *, roots, prepared):
    """Guard the caller's complete graph + wire + journal join, not a summary."""
    roots = list(dict.fromkeys(Path(root).resolve(strict=True) for root in roots))
    assert ROOT in roots or any(ROOT.is_relative_to(root) for root in roots)
    port = prepared['prepared_journal']['root']
    assert port in roots or any(port.is_relative_to(root) for root in roots)
    result = prepared['guard'].guarded(operation, roots=roots, foreign_path=Path('/dev/null'))
    assert result['before'] == result['after'] and len(result['probes']) == 11
    assert result['native_or_rust_executions'] == result['reader_writes'] == 0
    return result
