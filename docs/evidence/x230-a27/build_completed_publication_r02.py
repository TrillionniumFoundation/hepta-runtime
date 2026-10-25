#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create complete public views of fixed, already completed A27 evidence.

No workload, remote operation, original-archive publication, or input mutation.
The three imported sanitizer modules are checked against their frozen hashes.
"""
from collections import Counter
import gzip
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'a27-completed-publication-r02'
DEPENDENCIES = {
    'build_x230_a26_series_evidence_r02': ('a26-series-tools', '610b7c95dfa46b25e677b29095f0b813c1074aefef4f8a101910b95b2978748f'),
    'build_x230_evidence': ('a25-evidence-tools', 'd868f8aab6db0b8d35fd38116241355660758a1e4b336b64cda3f7b945ffa4fb'),
    'build_x230_six_running_evidence': ('a25-evidence-tools', 'e079b19be97815bb8c4a41891fa995e40e1e353425b7e909bb814a65a3359c52'),
}
INPUTS = {
    'owner-path/run-r02': ('a27-owner-actual-evidence-r02/a27-observation-probe-run-r02/run.json', 'c38f7190bf2f040cb20fa8999f377228cbb35957cea589c1c96d282fe3c99174'),
    'owner-path/build-r02': ('a27-owner-actual-evidence-r02/a27-observation-probe-build-r02/build.json', 'acbed08436eec71a6f6aa2615dcad2038f0bc9cc3d66d0eb25e31034804aed70'),
    'owner-path/environment-r02': ('a27-owner-actual-evidence-r02/a27-observation-probe-environment-r02.json', '779d326816b537e4f85df467f5b896c16e2878de9b988955878f08f7b2269bf1'),
    'owner-path/failed-prepare-r01': ('a27-observation-probe/evidence-build-r01/build.json', 'b795a967940fcea0e0585e7a113f9a4f6a2be54f46092dbb9cfb1afc8e54776d'),
    'resources/report-r01': ('a27-resources/evidence-native-r01/report.json', '9c6033a96683c6379b1addd90a9c0952c86d271156c554508d39ecbd71caec7e'),
    'resources/errors-r01': ('a27-resources/evidence-native-r01/errors.jsonl', 'c992edea62fef05a2378da1f49501cccbc62da30ef7712ce99a096d69d95e6fb'),
}
ARCHIVE = 'a27-owner-actual-evidence-r02.tar.gz'
ARCHIVE_SHA = 'c4e0e67b1bddcaba3bc59238c19056783f7304b085d96a18adee99d1969558d9'
COUNTER_PATHS = {
    ('resources', 'timeline', 0, 'readable_fields', 'identity'),
    ('final_resources', 'timeline', 0, 'readable_fields', 'identity'),
}
EXTRA_IDENTITY_KEYS = {'device', 'inode', 'st_dev', 'st_ino', 'st_uid', 'st_gid'}


def need(value, message):
    if not value:
        raise ValueError(message)


def receipt(name, raw):
    return {'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def at(value, path):
    for key in path:
        value = value[key]
    return value


def main():
    need(len(sys.argv) == 1 and not os.path.lexists(OUT), 'fresh fixed output required')
    sys.dont_write_bytecode = True
    dependencies = {}
    for name, (directory, expected) in DEPENDENCIES.items():
        path = ROOT / directory / (name + '.py')
        need(path == path.resolve(), 'indirect sanitizer dependency')
        raw = path.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == expected, 'frozen sanitizer changed')
        dependencies[name] = raw
    sys.path[:0] = [str(ROOT / 'a26-series-tools'), str(ROOT / 'a25-evidence-tools')]
    module = importlib.import_module('build_x230_a26_series_evidence_r02')
    for name, (directory, _) in DEPENDENCIES.items():
        need(Path(sys.modules[name].__file__).resolve() == ROOT / directory / (name + '.py'),
             'unexpected imported sanitizer')
    source = Path(__file__).read_bytes()
    raw_inputs, input_receipts, values = {}, {}, {}
    for label, (relative, expected) in INPUTS.items():
        bound, raw = module.read_file(ROOT / relative)
        need(not bound['retention_limit_exceeded'] and bound['sha256'] == expected, 'original evidence differs')
        raw_inputs[label], input_receipts[label] = raw, bound
        values[label] = ([module.decode(line) for line in raw.splitlines()]
                         if relative.endswith('.jsonl') else module.decode(raw))
    archive, _ = module.read_file(ROOT / ARCHIVE, 0)
    need(archive['sha256'] == ARCHIVE_SHA and archive['bytes'] == 433589, 'original archive differs')
    archive.pop('retention_limit_exceeded')
    archive.update(file=ARCHIVE, published=False, contents_copied_to_publication=False)

    # /proc/loadavg stores a final numeric process identity inside a string.
    # Discover those exact identity tokens through the unchanged PID policy.
    environment = values['owner-path/environment-r02']
    pid_seeds = []
    for key in ('loadavg_before', 'loadavg_after'):
        fields = environment[key].split()
        need(len(fields) == 5 and fields[-1].isdigit(), 'loadavg schema differs')
        pid_seeds.append({'pid': int(fields[-1])})
    sanitizer = module.CompleteSanitizer({'documents': values, 'identity_discovery_seeds': pid_seeds})
    # crate@version strings trigger the original generic user-name discovery.
    # Preserve all colliding dependency entries with unique opaque key receipts
    # before applying the unchanged sanitizer; never merge their values.
    transform_inputs = dict(values)
    build = dict(values['owner-path/build-r02'])
    key_groups = Counter(sanitizer.string(key) for key in build['dependencies'])
    key_aliases, key_receipts, renamed = {}, [], {}
    for key, value in build['dependencies'].items():
        if key_groups[sanitizer.string(key)] > 1:
            original_key = sanitizer.opaque_receipt(key)
            public_key = '<opaque-key:' + original_key['canonical_value_sha256'] + '>'
            need(sanitizer.string(public_key) == public_key, 'opaque key marker changed')
            key_aliases[key] = public_key
            key_receipts.append({'document': 'owner-path/build-r02', 'path': ['dependencies'],
                                 'original_key': original_key, 'public_key': public_key})
        else:
            public_key = key
        need(public_key not in renamed, 'opaque dependency key collision')
        renamed[public_key] = value
    build['dependencies'] = renamed
    transform_inputs['owner-path/build-r02'] = build
    public = {label: sanitizer(value) for label, value in transform_inputs.items()}

    def identity_metadata_key(key):
        lower = key.lower()
        return lower == 'stamp' or lower.endswith('_stamp') or lower in EXTRA_IDENTITY_KEYS

    identity_adaptations, identity_inside_opaque_parents = [], []
    def count_identity_metadata(value):
        if isinstance(value, dict):
            return sum((1 if identity_metadata_key(key) else 0) + count_identity_metadata(item)
                       for key, item in value.items())
        if isinstance(value, list):
            return sum(count_identity_metadata(item) for item in value)
        return 0

    def mask_metadata(original, target, label, path=()):
        if isinstance(original, dict):
            for key, value in original.items():
                pk = (key_aliases[key] if label == 'owner-path/build-r02'
                      and path == ('dependencies',) and key in key_aliases else sanitizer.string(key))
                lower = key.lower()
                if identity_metadata_key(key):
                    replacement = sanitizer.opaque_receipt(value)
                    target[pk] = replacement
                    identity_adaptations.append({'document': label, 'path': list(path + (pk,)),
                                                 'original_value_receipt': replacement,
                                                 'policy': 'file/process identity metadata; existing opaque_receipt'})
                elif (lower not in sanitizer.private_keys and lower not in sanitizer.opaque_keys
                      and 'base64' not in lower and not lower.endswith('_hex')):
                    mask_metadata(value, target[pk], label, path + (pk,))
                else:
                    hidden = count_identity_metadata(value)
                    if hidden:
                        identity_inside_opaque_parents.append({
                            'document': label, 'path': list(path + (pk,)),
                            'identity_metadata_fields_inside': hidden,
                            'original_parent_receipt': sanitizer.opaque_receipt(value),
                            'policy': 'already hidden by unchanged generic opaque-parent policy'})
        elif isinstance(original, list):
            for index, (value, item) in enumerate(zip(original, target)):
                mask_metadata(value, item, label, path + (index,))
    for label, value in values.items():
        mask_metadata(value, public[label], label)
    need(len(identity_adaptations) == 1711 and
         sum(item['identity_metadata_fields_inside'] for item in identity_inside_opaque_parents) == 10,
         'complete identity metadata inventory changed')

    # The sole exception to generic private-key classification: these exact
    # numeric sampler counters describe coverage, not a process identity.
    exceptions = []
    for path in sorted(COUNTER_PATHS):
        value = at(values['resources/report-r01'], path)
        need(type(value) is int and value >= 0, 'readable identity counter is not numeric')
        at(public['resources/report-r01'], path[:-1])[path[-1]] = value
        exceptions.append({'document': 'resources/report-r01', 'path': list(path), 'value': value,
                           'reason': 'numeric readable-field coverage counter; not a process identity'})
    # Compiler argv rows use a plural container in this evidence schema.
    commands = values['owner-path/build-r02']['commands']
    need(set(commands) == {'A', 'B'} and all(isinstance(v, list) and v for v in commands.values()),
         'compiler command inventory differs')
    for key, command in commands.items():
        public['owner-path/build-r02']['commands'][key] = sanitizer({'argv': command})['argv']

    structure, opaque = {}, []
    def public_key(label, path, key):
        if label == 'owner-path/build-r02' and path == ('dependencies',) and key in key_aliases:
            return key_aliases[key]
        return sanitizer.string(key)

    def walk(original, transformed, label, path, counts):
        counter = label == 'resources/report-r01' and path in COUNTER_PATHS
        compiler_argv = label == 'owner-path/build-r02' and len(path) == 2 and path[0] == 'commands'
        if compiler_argv:
            need(transformed == sanitizer.opaque_receipt(original), 'compiler argv receipt differs')
            opaque.append({'document': label, 'path': list(path), 'policy': 'existing opaque argv receipt'})
            counts['opaque_subtrees_replaced'] += 1
        elif counter:
            need(type(original) is type(transformed) is int and original == transformed, 'counter exception changed')
            counts['numeric_counter_exceptions_preserved'] += 1
        elif isinstance(original, dict):
            need(isinstance(transformed, dict) and len(original) == len(transformed)
                 and {public_key(label, path, k) for k in original} == set(transformed), 'dictionary shape changed')
            counts['dictionary_keys_retained'] += len(original)
            for key, value in original.items():
                pk, lower = public_key(label, path, key), key.lower()
                child_path = path + (pk,)
                if label == 'resources/report-r01' and child_path in COUNTER_PATHS:
                    walk(value, transformed[pk], label, child_path, counts)
                elif (identity_metadata_key(key) or lower in sanitizer.private_keys or lower in sanitizer.opaque_keys
                      or 'base64' in lower or lower.endswith('_hex')):
                    need(transformed[pk] == sanitizer.opaque_receipt(value), 'opaque receipt differs')
                    if not identity_metadata_key(key):
                        opaque.append({'document': label, 'path': list(child_path),
                                       'policy': 'unchanged CompleteSanitizer field policy'})
                    counts['opaque_subtrees_replaced'] += 1
                else:
                    walk(value, transformed[pk], label, child_path, counts)
        elif isinstance(original, list):
            need(isinstance(transformed, list) and len(original) == len(transformed), 'list rows changed')
            counts['list_rows_retained'] += len(original)
            for index, (a, b) in enumerate(zip(original, transformed)):
                walk(a, b, label, path + (index,), counts)
        elif isinstance(original, str):
            need(transformed == sanitizer.string(original), 'string changed outside frozen policy')
            counts['strings_verified'] += 1
        else:
            need(type(original) is type(transformed) and original == transformed, 'metric or flag changed')
            counts['numeric_boolean_null_values_unchanged'] += 1
    for label, value in values.items():
        counts = Counter()
        walk(value, public[label], label, (), counts)
        structure[label] = dict(counts)

    run = values['owner-path/run-r02']
    need(len(run['cells']) == 32 and sum(len(c['record']['rows']) for c in run['cells']) == 2176
         and len(run['semantics']) == 2, 'complete owner evidence count differs')
    def row_counts(value):
        rows = [row for cell in value['cells'] for row in cell['record']['rows']]
        return {'cells': len(value['cells']), 'rows': len(rows),
                'row_passed': sum(row.get('passed') is True for row in rows),
                'row_failed_or_not_passed': sum(row.get('passed') is not True for row in rows),
                'semantics': len(value['semantics']),
                'semantics_passed': sum(s['record'].get('passed') is True for s in value['semantics']),
                'cell_returncodes': [cell['returncode'] for cell in value['cells']],
                'cell_record_passed_flags': [cell['record']['passed'] for cell in value['cells']]}
    need(row_counts(run) == row_counts(public['owner-path/run-r02']), 'owner result counts changed')
    errors = values['resources/errors-r01']
    need(len(errors) == 5 and [row['sequence'] for row in errors] == list(range(5)), 'five original errors differ')
    final = values['resources/report-r01']['final_resources']
    need(final['error_count'] == final['error_log_rows_written'] == 5
         and final['error_log_bytes'] == len(raw_inputs['resources/errors-r01'])
         and final['error_log_sha256'] == INPUTS['resources/errors-r01'][1]
         and final['error_log_complete'] is True, 'native error log binding differs')
    need(values['owner-path/failed-prepare-r01']['prepared'] is False
         and values['owner-path/failed-prepare-r01']['compiled'] is False
         and values['owner-path/failed-prepare-r01']['error'] is not None, 'first failed preparation lost')

    outputs, bindings = {}, {}
    for label, value in public.items():
        jsonl = label == 'resources/errors-r01'
        raw = b''.join(module.canonical(row) for row in value) if jsonl else module.canonical(value)
        name = label + '.complete.sanitized.' + ('jsonl' if jsonl else 'json')
        info = {'original': receipt(INPUTS[label][0], raw_inputs[label]),
                'complete_public_content_bytes': len(raw), 'complete_public_content_sha256': module.sha(raw)}
        if len(raw) > 65536:
            compressed, check = module.compressed(value)
            need(not jsonl and gzip.decompress(compressed) == raw, 'complete gzip roundtrip differs')
            name, raw = name + '.gz', compressed
            info['gzip_mtime'] = 0
        outputs[name] = raw
        info['public'] = receipt(name, raw)
        bindings[label] = info
    identity_inventory = {'explicit_adaptations': identity_adaptations,
                          'already_inside_opaque_parents': identity_inside_opaque_parents}
    inventory_raw, inventory_plain = module.compressed(identity_inventory)
    inventory_name = 'identity-adaptations.complete.sanitized.json.gz'
    need(module.decode(gzip.decompress(inventory_raw)) == identity_inventory,
         'identity inventory gzip roundtrip differs')
    outputs[inventory_name] = inventory_raw
    notes = '''# Completed A27 evidence: publication scope

These views preserve the actual owner-path run, successful r02 build,
environment sample, first failed preparation, and native sampler report and
five error JSONL rows. No new experiment or qualification was run here.
All 32 owner cells, 2,176 individual rows, and both semantic checks remain.
Every nonidentity metric, boolean, error outcome, and timestamp remains exact.
Gzip files decompress to the complete canonical sanitized document; no row
filtering, success filtering, or summary-only replacement is applied.

The frozen A26 CompleteSanitizer implementation and both original imports
remain unchanged. Process identities, private paths, credentials and opaque
argv fields use its existing policies. The final PID token in each loadavg
string is supplied as an identity discovery seed; its other fields remain.
The receipt also binds each complete original loadavg string. All 1,721
file/process metadata tuples under stamp or *_stamp are covered: 1,711 receive
the same existing opaque receipt, and ten are already inside an opaque parent
under the unchanged generic policy. Device/inode aliases use the same
explicit schema policy; separate byte counts, hashes and workload metrics
remain. A compressed complete inventory binds every adapted metadata field.
The only exception to generic private-key classification is the exact numeric
`readable_fields.identity` coverage counter in the sampler's two timeline
snapshots. Those counters remain integers. No actual process identity uses
that exception. The receipt lists the two exact paths and original values.

Compiler commands stored under the plural commands container receive the
existing opaque argv receipt, preserving each A/B key. Error JSONL rows keep
their sequence, errno, type, stage, time and truncation flag; only their private
identity fields and private text are sanitized. Original error-log hashes in
the native report continue to refer to original bytes. The publication receipt
separately binds the sanitized log, so it does not silently rewrite history.

The generic sanitizer discovers crate names in crate@version strings as user
names. Where that would collapse several dependency keys to the same marker,
each key is first represented by its full canonical opaque-key hash. The
receipt binds every such key mapping; all distinct dependency values remain.
This preserves the original redaction instead of exposing a name or merging
entries. It is not an exception that permits an identity value to remain raw.

The original actual-evidence archive is hashed but not copied or published.
Source-only frozen probe bundles are separate artifacts. Publication integrity
does not establish a performance win, runtime adoption, complete process
coverage, atomic resource measurements, or a wider recovery guarantee.

The earlier public-view r01 package is retained privately and must not be
published: its generic policy left raw file identity tuples. This fresh r02
corrects publication only, without repeating any experiment or changing raw
evidence. The earlier dependency-key collision refusal happened before any
publication write; the logged schema adaptation preserved every value.
'''
    outputs['PUBLICATION_NOTES.md'] = notes.encode()
    outputs['build_completed_publication_r02.py'] = source
    text_public = '\n'.join(module.canonical(value).decode() for value in public.values())
    need(module.common.Sanitizer.private_path.search(text_public) is None, 'private path remains')
    need(re.search(r'/proc/[0-9]+(?:/|\b)', text_public) is None, 'raw proc PID remains')
    for key in ('loadavg_before', 'loadavg_after'):
        original_fields, public_fields = environment[key].split(), public['owner-path/environment-r02'][key].split()
        need(original_fields[:4] == public_fields[:4] and public_fields[-1] == '<pid>', 'loadavg metrics or PID handling differs')
    def no_raw_metadata(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if identity_metadata_key(key):
                    need(isinstance(item, dict) and item.get('redacted') is True
                         and module.HEX256.fullmatch(item.get('canonical_value_sha256', '')),
                         'raw identity tuple or named identity field remains')
                no_raw_metadata(item)
        elif isinstance(value, list):
            for item in value:
                no_raw_metadata(item)
    for value in public.values():
        no_raw_metadata(value)
    for a, b in zip(errors, public['resources/errors-r01']):
        need(b['pid'] == sanitizer.opaque_receipt(a['pid'])
             and b['birth_ticks'] == sanitizer.opaque_receipt(a['birth_ticks']), 'raw process identity remains')
    for label, (relative, _) in INPUTS.items():
        current, fresh = module.read_file(ROOT / relative)
        need(current == input_receipts[label] and fresh == raw_inputs[label], 'raw input changed')
    for name, (directory, _) in DEPENDENCIES.items():
        need((ROOT / directory / (name + '.py')).read_bytes() == dependencies[name], 'sanitizer changed')
    need(Path(__file__).read_bytes() == source, 'transform source changed')
    manifest = {
        'schema': 'hepta-a27-completed-evidence-publication/v2', 'publication_integrity_passed': True,
        'new_workload_run': False, 'remote_calls': False, 'raw_inputs_modified': False,
        'sanitizer_implementation_modified': False,
        'sanitizer_dependencies': [receipt(name + '.py', raw) for name, raw in dependencies.items()],
        'transform_source': receipt('build_completed_publication_r02.py', source),
        'original_archive': archive, 'document_bindings': bindings,
        'preservation_checks': structure, 'owner_counts': row_counts(run),
        'native_error_rows_retained': 5, 'first_failed_preparation_retained': True,
        'schema_context_numeric_identity_exceptions': exceptions,
        'dependency_key_collision_receipts': key_receipts,
        'identity_metadata_adaptations': {
            'count': len(identity_adaptations),
            'already_inside_opaque_parent_count': 10,
            'complete_original_identity_metadata_field_count': 1721,
            'counts_by_document': dict(Counter(item['document'] for item in identity_adaptations)),
            'policy': 'stamp, *_stamp and device/inode aliases use unchanged opaque_receipt; separate byte/hash metrics retained',
            'complete_inventory': {**receipt(inventory_name, inventory_raw), **inventory_plain}},
        'loadavg_identity_adaptations': [
            {'document': 'owner-path/environment-r02', 'path': [key],
             'original_complete_string': sanitizer.opaque_receipt(environment[key]),
             'public_value': public['owner-path/environment-r02'][key],
             'first_four_fields_preserved': True, 'last_PID_replaced': True}
            for key in ('loadavg_before', 'loadavg_after')],
        'publication_history': {
            'initial_collision_refusal_before_any_publication_write': True,
            'dependency_key_disambiguation_preserved_all_values': True,
            'prior_r01_retained_unpublished': True,
            'prior_package_manifest_sha256': 'ef502f470f0ad19b2105c45060c864dac8e96c180f822e6b5f09e0e6d060de68',
            'fresh_r02_corrects_only_identity_publication': True,
            'workload_repeated_for_publication': False},
        'loadavg_final_PID_discovery_seed_receipts': [sanitizer.opaque_receipt(row['pid']) for row in pid_seeds],
        'opaque_context_inventory': opaque,
        'public_artifacts': [receipt(name, raw) for name, raw in outputs.items()],
    }
    outputs['publication-receipt.json'] = module.canonical(manifest)
    outputs['package-manifest.json'] = module.canonical({
        'schema': 'hepta-a27-completed-publication-package/v2',
        'publication_complete': True, 'prior_r01_must_not_be_published': True,
        'complete_document_integrity_rechecked': True, 'source_archive_published': False,
        'original_archive_sha256': ARCHIVE_SHA, 'owner_cells': 32, 'owner_rows': 2176,
        'owner_semantics': 2, 'resource_error_rows': 5, 'identity_metadata_adaptations': 1711,
        'identity_fields_already_inside_opaque_parents': 10,
        'numeric_coverage_counter_exceptions': 2, 'collision_dependency_keys': 7,
        'files': [receipt(name, raw) for name, raw in outputs.items()]})
    OUT.mkdir(mode=0o700)
    (OUT / 'owner-path').mkdir(mode=0o700)
    (OUT / 'resources').mkdir(mode=0o700)
    for name, raw in outputs.items():
        module.create_only(OUT / name, raw)
        need((OUT / name).read_bytes() == raw, 'public output verification failed')
    for path in (OUT / 'owner-path', OUT / 'resources', OUT):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print(json.dumps({'publication_integrity_passed': True,
                      'files': [receipt(name, raw) for name, raw in outputs.items()]}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
