#!/usr/bin/env node
// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Real frozen parser differential. Fixtures are synthetic validation inputs;
// this does not execute target programs or establish public MCP qualification.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';

const options = {};
for (let i = 2; i < process.argv.length; i += 2) {
  assert(process.argv[i].startsWith('--') && process.argv[i + 1]);
  options[process.argv[i].slice(2)] = path.resolve(process.argv[i + 1]);
}
for (const key of ['reference', 'native-driver', 'source', 'output']) assert(options[key], `--${key} required`);
const root = options.output;
fs.mkdirSync(root, { mode: 0o700 });
const sha = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const pinned = {
  'dist/domain/process/processCaptureParsing.js': 'edd70deac24dc4bde890d9144a08f34921463d635e3b9229153f393266de9dfd',
  'dist/domain/process/processCapture.js': '62ef469b39127f357cde393d950cee53b68f75053595e8f2956fd1b8bf16045b',
  'dist/domain/process/processCaptureValidation.js': '8d565d73cb739b790f6c1c74088cf7ca62758a03acd16545e8c0d27034092c5f',
  'dist/domain/process/processCaptureCoverage.js': 'd7697b0f99bd0e0a1d7ab1cf2ac30022cc7b44de5674b35dd980437638d357b6',
  'dist/domain/process/processScenario.js': 'e221649e79630f1766c5cbbdee961d7210375cb62b6304417ad900763c6e2d09',
  'dist/domain/validationFailure.js': 'f0de8883244cb41e21a787ea42d2b3338309388de4d2e56d3db2751bfb4eb00e',
};
for (const [name, expected] of Object.entries(pinned)) assert.equal(sha(path.join(options.reference, name)), expected, name);
assert.equal(JSON.parse(fs.readFileSync(path.join(options.reference, 'package.json'))).version, '6.8.0');
const selected = [process.execPath, path.resolve(process.argv[1]), options['native-driver'],
  path.join(options.reference, 'package.json'), path.join(options.reference, 'dist/domain/jsonValue.js'),
  ...Object.keys(pinned).map(p => path.join(options.reference, p)),
  ...['rea_evidence.rs', 'rea_evidence_stream.rs', 'rea_evidence_source.rs',
    'rea_evidence_source_process.rs', 'rea_evidence_source_process_schema.rs',
    'rea_evidence_source_process_coverage.rs', 'rea_evidence_source_process_semantics.rs',
    'rea_evidence_source_process_tests.rs'].map(p => path.join(options.source, 'src/mcp', p))];
const snapshot = () => Object.fromEntries(selected.map(file => [file, sha(file)]));
const before = snapshot();
const { safeParseProcessCapture } = await import(pathToFileURL(path.join(options.reference, 'dist/domain/process/processCaptureParsing.js')));
const { digestProcessCommitment } = await import(pathToFileURL(path.join(options.reference, 'dist/domain/process/processScenario.js')));
const { describeValidationFailure } = await import(pathToFileURL(path.join(options.reference, 'dist/domain/validationFailure.js')));
const clone = value => structuredClone(value);
const retention = () => ({ budget_bytes: 0, observed_bytes: 0, retained_bytes: 0, observed_frames: 0, retained_frames: 0 });
const coverage = () => ({ files_limit: 0, depth_limit: 0, enumeration_truncated: false, enumeration_reasons: [],
  enumeration_omissions: [], hash_budget_bytes: 0, hashed_bytes: 0, hash_omissions: [] });
function recommit(value) {
  value.manifest.full_scenario_sha256 = digestProcessCommitment(value.manifest.scenario);
  value.manifest.comparison_contract_sha256 = digestProcessCommitment(value.manifest.comparison_contract);
  value.manifest.normalization_sha256 = digestProcessCommitment(value.normalization);
  return value;
}
function minimal() {
  return recommit({ manifest: { rea_version: '6.8.0', provider_version: 'synthetic-validation-input', platform: 'linux',
    architecture: 'x86_64', pty_backend: 'node-pty', started_at: '2026-01-01T00:00:00Z', completed_at: '2026-01-01T00:00:00Z',
    scenario: { executable_sha256: null }, comparison_contract: {}, selected_executable_sha256: null, executable_sha256: null,
    executable_identity: { state: 'path_metadata_unchanged', reason: null } },
    normalization: { paths: false, pids: false, ports: false, time_bucket_ms: 1, patterns: [] },
    frames: [], rendered_frames: [], interaction_events: [], exit: { code: 0, signal: null, reason: 'exited' },
    settlement: { state: 'quiesced', elapsed_ms: 0, cleanup_outcome: 'not_required' }, process_samples: [],
    filesystem_checkpoints: ['before', 'after_settlement'].map(name => ({ name, at_ms: 0, files: [], effects: [], truncated: false })),
    event_journal: [], files_before: [], files_after: [], filesystem_effects: [], truncated: false,
    truncation_details: { raw_terminal: retention(), rendered_terminal: retention(), filesystem_before: coverage(), filesystem_after: coverage(),
      process: { sample_limit: 0, sampling_partial: false, retained_samples: 0, sample_limit_reached: false, sampling_failures: 0,
        first_sampling_failure: null, coverage: 'sampled' } }, limitations: [], residual_unknowns: [],
    cleanup: { owned_process_group: 'verified', temporary_root: 'removed' } });
}
function populated() {
  const value = minimal();
  value.manifest.selected_executable_sha256 = value.manifest.executable_sha256 = value.manifest.scenario.executable_sha256 = '1'.repeat(64);
  value.manifest.scenario.limits = { output_bytes: 1024 };
  value.manifest.scenario['\u{1f680}'] = { '\ue000': 1e-7, '\u{10000}': 1e21 };
  value.normalization.patterns = [{ pattern: 'literal', replacement: 'replacement' }];
  value.frames = [{ sequence: 0, at_ms: 1, data: 'hé🚀', raw_data: '\u001b[31mraw' }, { sequence: 1, at_ms: 2, data: 'next' }];
  value.rendered_frames = [{ sequence: 0, at_ms: 1, columns: 80, rows: 24, cursor_x: 3, cursor_y: 0,
    active_buffer: 'normal', lines: ['hé🚀'], serialized_state: 'state' }];
  value.interaction_events = ['input', 'resize', 'signal'].map((type, i) => ({ sequence: i, scheduled_at_ms: i,
    dispatched_at_ms: i + 3, type, data: 'synthetic', outcome: ['dispatched', 'target_exited', 'failed'][i] }));
  value.process_samples = [{ at_ms: 2, pid: 123, parent_pid: 1, command: 'synthetic-only', process_group_id: 123, session_id: 123 }];
  const file = { path: 'hashed', mode: 420, size: 3, type: 'file', sha256: '2'.repeat(64), symlink_target: null };
  const unknown = { ...file, path: 'unhashed', size: 4, sha256: null };
  const link = { path: 'link', mode: 511, size: 3, type: 'symlink', sha256: null, symlink_target: 'owned' };
  const dir = { path: 'directory', mode: 448, size: 0, type: 'directory', sha256: null, symlink_target: null };
  const other = { ...dir, path: 'other', type: 'other' };
  value.files_before = [file, unknown, link, dir, other]; value.files_after = clone(value.files_before);
  value.filesystem_effects = [
    { path: 'created', status: 'created', before: null, after: file },
    { path: 'deleted', status: 'deleted', before: file, after: null },
    { path: 'modified', status: 'modified', before: file, after: file },
    { path: 'unchanged', status: 'unchanged', before: file, after: file },
    { path: 'unknown', status: 'unknown', before: null, after: null, reason: 'not observed' },
  ];
  value.truncated = true;
  for (let i = 0; i < 2; i++) {
    const field = i ? 'filesystem_after' : 'filesystem_before';
    value.truncation_details[field] = { files_limit: 5, depth_limit: 4, enumeration_truncated: true,
      enumeration_reasons: ['symlink_not_followed'], enumeration_omissions: [{ path: 'link', reason: 'symlink_not_followed', system_code: null }],
      unobserved_subtrees: [{ path: 'link', reason: 'symlink_not_followed' }, { path: 'own', reason: 'observer_owned' }],
      hash_budget_bytes: 3, hashed_bytes: 3, hash_omissions: [{ path: 'unhashed', size_bytes: 4, remaining_budget_bytes: 0,
        reason: 'file_bytes_budget', system_code: null }] };
    value.filesystem_checkpoints[i].at_ms = i + 1;
    value.filesystem_checkpoints[i].files = clone(value.files_before);
    value.filesystem_checkpoints[i].effects = clone(value.filesystem_effects);
    value.filesystem_checkpoints[i].truncated = true;
  }
  const rawBytes = value.frames.reduce((n, f) => n + Buffer.byteLength(f.raw_data ?? f.data), 0);
  value.truncation_details.raw_terminal = { budget_bytes: rawBytes, observed_bytes: rawBytes, retained_bytes: rawBytes,
    observed_frames: 2, retained_frames: 2, unknown_size_frames: 0, normalization_over_budget_frames: 0 };
  const renderedBytes = Buffer.byteLength('hé🚀') + Buffer.byteLength('state');
  value.truncation_details.rendered_terminal = { budget_bytes: renderedBytes, observed_bytes: renderedBytes, retained_bytes: renderedBytes,
    observed_frames: 1, retained_frames: 1, unknown_size_frames: 0, normalization_over_budget_frames: 0 };
  value.truncation_details.normalized_terminal = { budget_bytes: 1024, retained_bytes: value.frames.reduce((n, f) => n + Buffer.byteLength(f.data), 0), omitted_frames: 0 };
  value.truncation_details.process = { sample_limit: 1, sampling_partial: false, retained_samples: 1, sample_limit_reached: false,
    sampling_failures: 0, first_sampling_failure: null, coverage: 'sampled' };
  value.residual_unknowns = ['terminal', 'interaction', 'exit', 'process', 'filesystem', 'cleanup', 'network', 'environment'].map(scope => ({ scope, reason: 'synthetic' }));
  value.cleanup.unverified_processes = [{ pid: 456, reason: 'synthetic metadata' }];
  value.limitations = ['Synthetic schema fixture; no process or filesystem observation is asserted.'];
  for (const collection of ['frames', 'rendered_frames', 'interaction_events', 'lifecycle', 'process_samples', 'filesystem_checkpoints']) {
    for (let index = 0; index < (collection === 'lifecycle' ? 2 : value[collection].length); index++)
      value.event_journal.push({ capture_order: value.event_journal.length, collection, index });
  }
  return recommit(value);
}
const base = minimal(); const rich = populated();
for (const value of [base, rich]) {
  const parsed = safeParseProcessCapture(value); assert(parsed.success, parsed.success ? '' : describeValidationFailure(parsed.error));
}
const casesPath = path.join(root, 'cases.jsonl');
const fd = fs.openSync(casesPath, 'wx', 0o600);
let total = 0; let accepted = 0; const labels = new Set();
function keyOrder(value, location = [], orders = {}) {
  if (value !== null && typeof value === 'object') {
    if (!Array.isArray(value)) orders[JSON.stringify(location)] = Object.keys(value);
    for (const [key, item] of Object.entries(value)) keyOrder(item, [...location, Array.isArray(value) ? Number(key) : key], orders);
  }
  return orders;
}
function emit(label, value) {
  assert(!labels.has(label), label); labels.add(label);
  const parsed = safeParseProcessCapture(value);
  const expected = parsed.success ? { success: true } : { success: false, description: describeValidationFailure(parsed.error) };
  fs.writeSync(fd, JSON.stringify({ label, input: value, orders: keyOrder(value), expected }) + '\n');
  total++; accepted += Number(parsed.success);
}
function mutate(label, change, source = rich, commit = false) { const value = clone(source); change(value); emit(label, commit ? recommit(value) : value); }
emit('valid:minimal', base); emit('valid:populated', rich);
function paths(value, parent = [], output = []) {
  output.push(parent);
  if (value !== null && typeof value === 'object')
    for (const [key, child] of Object.entries(value)) paths(child, [...parent, Array.isArray(value) ? Number(key) : key], output);
  return output;
}
const replacements = [null, true, 0, -1, 0.5, '', 'unknown', [], {}, 9007199254740992, -9007199254740992];
for (const address of paths(rich)) {
  for (let index = 0; index < replacements.length; index++) {
    let value = clone(rich);
    if (address.length === 0) value = clone(replacements[index]);
    else { let parent = value; for (const key of address.slice(0, -1)) parent = parent[key]; parent[address.at(-1)] = clone(replacements[index]); }
    emit(`shape:${JSON.stringify(address)}:replace:${index}`, value);
  }
  if (address.length && typeof address.at(-1) === 'string') {
    const value = clone(rich); let parent = value; for (const key of address.slice(0, -1)) parent = parent[key]; delete parent[address.at(-1)];
    emit(`shape:${JSON.stringify(address)}:missing`, value);
  }
}
for (const date of ['0000-02-29T00:00Z', '1600-02-29T00:00Z', '1900-02-29T00:00Z', '2000-02-29T00:00Z',
  '2024-02-29T23:59:59.001Z', '2026-01-01T00:00Z', '2026-01-01T00:00:00.1Z', '9999-12-31T23:59:59Z',
  '2026-01-01T24:00Z', '2026-01-01T00:60Z', '2026-01-01T00:00:60Z', '2026-01-01T00:00:00.Z',
  '2026-01-01T00:00+00:00', '2026-01-01T00:00z', '2026-01-01T00:00Z\n', '2026-01-01T00:00Z\r',
  '2026-01-01T00:00Z\u2028', '2026-1-01T00:00Z', '+2026-01-01T00:00Z', '10000-01-01T00:00Z'])
  mutate(`date:${JSON.stringify(date)}`, value => { value.manifest.started_at = date; }, base);
for (const field of ['manifest', 'normalization', 'cleanup', 'exit', 'settlement', 'truncation_details'])
  mutate(`unknown:${field}`, value => { value[field].z = 1; value[field].a = 2; }, base);
mutate('unknown:root-prototype', value => { Object.defineProperty(value, '__proto__', { value: 'own-key', enumerable: true }); }, base);
mutate('unknown:strict-object-blocks-semantic-refinement', value => { value.manifest.extra = true; value.manifest.normalization_sha256 = '0'.repeat(64); }, base);
mutate('type:abort-blocks-semantic-refinement', value => { value.frames = null; value.manifest.normalization_sha256 = '0'.repeat(64); }, base);
for (const field of ['manifest', 'normalization', 'cleanup', 'truncation_details'])
  for (const key of ['__proto__', 'constructor', 'toString'])
    mutate(`unknown:${field}:${key}`, value => { Object.defineProperty(value[field], key, { value: 'own-key', enumerable: true }); }, base);
mutate('unknown:pattern-stripped', value => { value.normalization.patterns[0].z = 1; value.normalization.patterns[0].a = 2; });
mutate('record:prototype-skipped', value => { Object.defineProperty(value.manifest.scenario, '__proto__', { value: ['ignored'], enumerable: true }); }, base);
mutate('record:prototype-affects-raw-commitment', value => { Object.defineProperty(value.manifest.scenario, '__proto__', { value: ['ignored'], enumerable: true }); }, base, true);
mutate('record:undefined-is-not-null', value => { delete value.manifest.scenario.executable_sha256; }, base, true);
mutate('identity:unknown-valid', value => { value.manifest.executable_identity = { state: 'unknown', reason: 'unobserved' }; value.manifest.executable_sha256 = null; });
mutate('identity:changed-path-reason', value => { value.manifest.executable_identity.reason = ''; });
mutate('identity:unknown-without-reason', value => { value.manifest.executable_identity.state = 'unknown'; });
for (const field of ['full_scenario_sha256', 'comparison_contract_sha256', 'normalization_sha256'])
  mutate(`commitment:${field}`, value => { value.manifest[field] = '0'.repeat(64); }, base);
for (const collection of ['frames', 'rendered_frames', 'interaction_events'])
  mutate(`sequence:${collection}`, value => { value[collection][0].sequence = 5; });
for (const collection of ['frames', 'rendered_frames', 'process_samples'])
  mutate(`ordering:${collection}`, value => { const item = clone(value[collection][0]); item.at_ms = 0; if ('sequence' in item) item.sequence = value[collection].length; value[collection].push(item); });
mutate('ordering:dispatch', value => { value.interaction_events[1].dispatched_at_ms = 0; });
mutate('ordering:checkpoint', value => { value.filesystem_checkpoints[1].at_ms = 0; });
mutate('journal:duplicate', value => { value.event_journal[1].collection = value.event_journal[0].collection; value.event_journal[1].index = value.event_journal[0].index; });
mutate('journal:out-of-range', value => { value.event_journal[0].index = 100; });
mutate('journal:noncontiguous', value => { value.event_journal[0].capture_order = 1; });
mutate('journal:incomplete', value => { value.event_journal.pop(); });
mutate('journal:empty-allowed', value => { value.event_journal = []; });
mutate('lifecycle:missing-checkpoint', value => { value.filesystem_checkpoints.pop(); });
mutate('lifecycle:wrong-checkpoint-order', value => { value.filesystem_checkpoints.reverse(); });
mutate('lifecycle:unpropagated-truncation', value => { value.truncated = false; });
for (const state of ['alive_at_deadline', 'unverifiable']) {
  mutate(`settlement:${state}:cleaned`, value => { value.settlement = { state, elapsed_ms: 1, cleanup_outcome: 'cleaned' }; }, base);
  mutate(`settlement:${state}:failed`, value => { value.settlement = { state, elapsed_ms: 1, cleanup_outcome: 'failed' }; }, base);
}
const finalized = clone(base);
finalized.manifest.scenario.finalization_ms = finalized.manifest.comparison_contract.finalization_ms = 10;
finalized.exit = { code: null, signal: null, reason: 'timeout', finalization: { requested_ms: 10, elapsed_ms: 12, exit_code: 0,
  signals: [{ signal: 'SIGTERM', sent_at_ms: 0, delivery: 'signaled' }] } };
recommit(finalized); emit('finalization:valid-term', finalized);
const finalCases = {
  'missing': value => { delete value.exit.finalization; },
  'normal-exit': value => { value.exit.reason = 'exited'; },
  'starts-kill': value => { value.exit.finalization.signals[0].signal = 'SIGKILL'; },
  'two-kills': value => { value.exit.finalization.signals.push({ signal: 'SIGKILL', sent_at_ms: 10, delivery: 'gone' }, { signal: 'SIGKILL', sent_at_ms: 11, delivery: 'gone' }); },
  'nonfinal-kill': value => { value.exit.finalization.signals.push({ signal: 'SIGKILL', sent_at_ms: 10, delivery: 'gone' }, { signal: 'SIGTERM', sent_at_ms: 11, delivery: 'gone' }); },
  'decreasing-times': value => { value.exit.finalization.signals[0].sent_at_ms = 2; value.exit.finalization.signals.push({ signal: 'SIGTERM', sent_at_ms: 1, delivery: 'gone' }); },
  'two-terms': value => { value.exit.finalization.signals.push({ signal: 'SIGTERM', sent_at_ms: 1, delivery: 'gone' }); },
  'early-kill': value => { value.exit.finalization.signals.push({ signal: 'SIGKILL', sent_at_ms: 9, delivery: 'gone' }); },
  'null-elapsed': value => { value.exit.finalization.elapsed_ms = null; },
  'code-plus-signal': value => { value.exit.signal = 9; },
  'elapsed-before-attempt': value => { value.exit.finalization.signals[0].sent_at_ms = 13; },
  'interval-mismatch': value => { value.exit.finalization.requested_ms = 11; },
  'reason-with-delivery': value => { value.exit.finalization.signals[0].reason = 'unsupported'; },
  'unverified-delivery': value => { Object.assign(value.exit.finalization.signals[0], { delivery: 'unverified', reason: 'unsupported' }); },
  'empty-signals': value => { value.exit.finalization.signals = []; },
  'negative-requested': value => { value.exit.finalization.requested_ms = -1; },
  'unsafe-requested-positive': value => { value.exit.finalization.requested_ms = 9007199254740992; },
  'unsafe-requested-negative': value => { value.exit.finalization.requested_ms = -9007199254740992; },
  'negative-elapsed': value => { value.exit.finalization.elapsed_ms = -1; },
  'normal-code-at-deadline': value => { value.exit.code = 0; },
};
for (const [label, mutateFn] of Object.entries(finalCases)) mutate(`finalization:${label}`, mutateFn, finalized);
mutate('finalization:manifest-disagreement', value => { value.manifest.comparison_contract.finalization_ms = 11; }, finalized, true);
mutate('finalization:null-vs-missing', value => { value.manifest.scenario.finalization_ms = null; }, base, true);
mutate('finalization:equal-object-is-not-identical', value => { value.manifest.scenario.finalization_ms = {}; value.manifest.comparison_contract.finalization_ms = {}; }, base, true);
for (const field of ['retained_samples', 'sampling_failures', 'sample_limit', 'sampling_partial', 'sample_limit_reached', 'first_sampling_failure'])
  mutate(`process-coverage:${field}`, value => { value.truncation_details.process[field] = typeof value.truncation_details.process[field] === 'boolean' ? true : field === 'first_sampling_failure' ? 'failure' : 2; });
for (const field of ['budget_bytes', 'observed_bytes', 'retained_bytes', 'observed_frames', 'retained_frames', 'unknown_size_frames', 'normalization_over_budget_frames'])
  for (const collection of ['raw_terminal', 'rendered_terminal']) mutate(`byte-coverage:${collection}:${field}`, value => { value.truncation_details[collection][field] += 1; });
for (const field of ['budget_bytes', 'retained_bytes', 'omitted_frames']) mutate(`normalized-coverage:${field}`, value => { value.truncation_details.normalized_terminal[field] += 1; });
for (const invalid of [undefined, null, 0, 0.5, 9007199254740992, '1024', {}])
  mutate(`normalized-budget:${JSON.stringify(invalid)}`, value => { if (invalid === undefined) delete value.manifest.scenario.limits; else value.manifest.scenario.limits.output_bytes = invalid; }, rich, true);
for (const collection of ['filesystem_before', 'filesystem_after']) {
  for (const field of ['files_limit', 'hashed_bytes', 'hash_budget_bytes'])
    mutate(`filesystem:${collection}:${field}`, value => { value.truncation_details[collection][field] = 0; });
  for (const field of ['size_bytes', 'remaining_budget_bytes', 'path', 'system_code', 'reason'])
    mutate(`hash-omission:${collection}:${field}`, value => { value.truncation_details[collection].hash_omissions[0][field] = field.endsWith('bytes') ? 99 : field === 'reason' ? 'file_unavailable' : 'missing'; });
  mutate(`hash-omission:${collection}:duplicate`, value => { value.truncation_details[collection].hash_omissions.push(clone(value.truncation_details[collection].hash_omissions[0])); });
  for (const reason of ['identity_changed', 'directory_unavailable', 'entry_unavailable', 'symlink_not_followed'])
    for (const location of ['link', 'directory', 'absent']) for (const code of [null, 'ENOENT'])
      mutate(`enumeration:${collection}:${reason}:${location}:${code}`, value => {
        value.truncation_details[collection].enumeration_reasons = [reason];
        value.truncation_details[collection].enumeration_omissions = [{ path: location, reason, system_code: code }];
      });
  mutate(`enumeration:${collection}:missing-reason`, value => { value.truncation_details[collection].enumeration_reasons = []; });
  mutate(`enumeration:${collection}:duplicate`, value => { value.truncation_details[collection].enumeration_omissions.push(clone(value.truncation_details[collection].enumeration_omissions[0])); });
}
fs.closeSync(fd);
const nativePath = path.join(root, 'native.jsonl');
const input = fs.openSync(casesPath, 'r'); const output = fs.openSync(nativePath, 'wx', 0o600);
const executed = spawnSync(options['native-driver'], [], { stdio: [input, output, 'pipe'], timeout: 120000, maxBuffer: 1048576 });
fs.closeSync(input); fs.closeSync(output);
fs.writeFileSync(path.join(root, 'native.stderr.log'), executed.stderr ?? Buffer.alloc(0));
const reference = createInterface({ input: fs.createReadStream(casesPath), crlfDelay: Infinity });
const native = createInterface({ input: fs.createReadStream(nativePath), crlfDelay: Infinity })[Symbol.asyncIterator]();
let nativeReturned = 0;
const differences = [];
for await (const line of reference) {
  const expected = JSON.parse(line); const next = await native.next();
  const actual = next.done ? undefined : JSON.parse(next.value);
  nativeReturned += Number(!next.done);
  if (!actual || actual.label !== expected.label || JSON.stringify(actual.actual) !== JSON.stringify(expected.expected)) {
    // Compare records independently of the serializer's key ordering.
    if (actual && actual.label === expected.label && actual.actual.success === expected.expected.success &&
      actual.actual.description === expected.expected.description && !actual.actual.native_error) continue;
    differences.push({ label: expected.label, expected: expected.expected, actual: actual?.actual ?? null });
  }
}
for (;;) { const next = await native.next(); if (next.done) break; nativeReturned++; }
const after = snapshot();
const sourceStable = JSON.stringify(before) === JSON.stringify(after);
const summary = { schema: 'hepta.rea.process-capture-parser-differential.v1', scope: 'synthetic-input-structural-and-semantic-validation',
  reference_version: '6.8.0', node: process.version, node_versions: process.versions, before, after, source_stable: sourceStable,
  corpus_sha256: sha(casesPath), native_output_sha256: sha(nativePath), total, reference_accepted: accepted,
  native_returned: nativeReturned, differences: differences.length, native_exit_code: executed.status,
  native_public_mcp: false, complete_process_adapter_qualified: false,
  qualified_finite_corpus: sourceStable && executed.status === 0 && nativeReturned === total && differences.length === 0 };
fs.writeFileSync(path.join(root, 'differences.json'), JSON.stringify(differences, null, 2) + '\n');
fs.writeFileSync(path.join(root, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify({ total, accepted, differences: differences.length, native_exit_code: executed.status,
  qualified_finite_corpus: summary.qualified_finite_corpus, output: root }));
if (!summary.qualified_finite_corpus) process.exitCode = 1;
