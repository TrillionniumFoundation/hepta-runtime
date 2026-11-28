/** Independent local model of the fixed-entry controller. No remote tools exist here. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const candidate = path.join(root, 'candidate');
const sourcePath = path.join(candidate, 'recovery/entry_switch.js');
const source = fs.readFileSync(sourcePath);
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
assert.equal(digest(source), 'e86acaf8ee5cebbdb06ddc7bb8ab420575ec0d69651859a8675de5c7754a7b76');
const host = 'rog';
const task = '/home/qian-qi/ndu-work/ndu-runtime-close-20261120-c2c548b7';
const entry = '/home/qian-qi/.local/bin/hepta-kaggle-account';
const oldRelease = '/home/qian-qi/.local/share/hepta-kaggle/releases/batch-0.1.12-gpuimage-4920';
const newRelease = '/home/qian-qi/.local/share/hepta-kaggle/releases/batch-0.1.13-cache-import-c2c548b7';
const oldLauncher = '/home/qian-qi/.local/share/hepta-kaggle/multiaccount-v7-gpuimage-4920/account_launcher.py';
const newLauncher = '/home/qian-qi/.local/share/hepta-kaggle/multiaccount-cache-import-c2c548b7/account_launcher.py';
const moduleNames = ['kaggle_jobs.py', 'kaggle_create_only.py', 'kaggle_transport.py', 'hepta_kaggle.py', 'tool_contract.py'];
const oldEntry = fs.readFileSync(path.join(candidate, 'recovery/original_account_entry.bin'));
const newEntry = fs.readFileSync(path.join(candidate, 'recovery/proposed_account_entry.bin'));
assert.equal(oldEntry.length, 295);
assert.equal(newEntry.length, 300);
assert.equal(digest(oldEntry), '83cb827b69028c6312ea1560c92d9cbb6c5fd6eb0dbb5597623f98b12a76b5de');
assert.equal(digest(newEntry), 'c60bc1bacac20aec5dce2e3acc18bcc30ee03cd96a686d489bafe6dc0ce16653');
assert.equal(oldEntry.toString().split(oldLauncher).length, 2);
assert.equal(oldEntry.toString().replace(oldLauncher, newLauncher), newEntry.toString());
const authorization = {scope: 'ndu-repair-mastery-20261120-aa42a9-v1', frozen_commit: 'a'.repeat(40)};
const context = vm.createContext({});
new vm.Script(source.toString(), {filename: sourcePath}).runInContext(context, {timeout: 1000});
assert.equal(typeof context.switchOriginalMasteryEntry, 'function');
const controller = context.switchOriginalMasteryEntry;

function fixture(initial = 'old', hook = {}) {
  let serial = 0;
  const files = new Map();
  const calls = [];
  let writeAttempts = 0;
  let mutations = 0;
  function put(name, bytes, mode = 0o600) {
    files.set(name, {bytes: Buffer.from(bytes), mode, version: 'fixture-version-' + (++serial),
      metadata: {uid: 1000, gid: 1000, link_count: 1, acl_sha256: digest(Buffer.alloc(0)), xattr_names: [], xattr_sha256: {}}});
  }
  for (const name of moduleNames) {
    put(oldRelease + '/' + name, fs.readFileSync(path.join(root, 'deployed', name)));
    put(newRelease + '/' + name, fs.readFileSync(path.join(candidate, 'tools/cloud-compute/kaggle', name)));
  }
  const oldLauncherBytes = fs.readFileSync(path.join(root, 'deployed/account_launcher.py'));
  put(oldLauncher, oldLauncherBytes);
  put(newLauncher, oldLauncherBytes.toString().replace(path.basename(oldRelease), path.basename(newRelease)));
  put('/home/qian-qi/.local/bin/hepta-compute', fs.readFileSync(path.join(root, 'deployed/hepta-compute')), 0o700);
  put('/home/qian-qi/.hepta-kaggle-adoption-releases/v5-batch-4920/bootstrap_fixed.py', fs.readFileSync(path.join(root, 'deployed/bootstrap_fixed.py')));
  put('/home/qian-qi/.hepta-kaggle-adoption-releases/v5-batch-4920/hepta_compute_base.py', fs.readFileSync(path.join(root, 'deployed/hepta_compute_base.py')));
  put(task + '/original_account_entry.bin', oldEntry, 0o700);
  put(task + '/proposed_account_entry.bin', newEntry, 0o700);
  put(entry, initial === 'old' ? oldEntry : newEntry, 0o700);
  const untouched = ['/fixture/original_request.json', '/fixture/original_router.sqlite', '/fixture/original_account.lock', '/fixture/new_cache_provenance_receipt.json'];
  for (const p of untouched) put(p, 'RETAINED ORIGINAL EVIDENCE ' + p);
  const originalSentinels = new Map(untouched.map(p => [p, Buffer.from(files.get(p).bytes)]));
  function packet(value) {
    return hook.textEnvelope ? {content: [{type: 'text', text: JSON.stringify(value)}]} : {structuredContent: value};
  }
  function get(p) {
    const v = files.get(p);
    if (!v) throw new Error('FIXTURE_FILE_MISSING: ' + p);
    return v;
  }
  const tools = {
    async mcp__codex_apps__h_file_info(args) {
      assert.equal(args.host, host);
      calls.push({method: 'file_info', path: args.path});
      const v = get(args.path);
      const info = {path: args.path, mode: v.mode, size: v.bytes.length, sha256: digest(v.bytes), version: v.version, metadata: structuredClone(v.metadata)};
      if (hook.info) hook.info(info, {files, mutations});
      return packet(info);
    },
    async mcp__codex_apps__h_binary_read(args) {
      assert.equal(args.host, host);
      calls.push({method: 'binary_read', path: args.path, expected_version: args.expected_version});
      const v = get(args.path);
      assert.equal(args.expected_version, v.version);
      assert.equal(args.offset, 0);
      assert.equal(args.limit, 65536);
      const value = {path: args.path, version: v.version, offset: 0, eof: true, next_offset: v.bytes.length, chunk_sha256: digest(v.bytes), data_base64: v.bytes.toString('base64')};
      if (hook.read) hook.read(value, {files, mutations});
      return packet(value);
    },
    async mcp__codex_apps__h_binary_write(args) {
      assert.equal(args.host, host);
      assert.equal(args.path, entry);
      calls.push({method: 'binary_write', path: args.path, expected_version: args.expected_version});
      writeAttempts++;
      if (hook.beforeWrite) hook.beforeWrite({args, files, put});
      const current = get(args.path);
      if (current.version !== args.expected_version) return {isError: true, content: [{type: 'text', text: 'FIXTURE_VERSION_CONFLICT'}]};
      if (hook.rejectWriteBeforeMutation) return {isError: true, content: [{type: 'text', text: 'FIXTURE_WRITE_REJECTED'}]};
      const bytes = Buffer.from(args.data_base64, 'base64');
      const previous = current;
      put(args.path, bytes, current.mode);
      files.get(args.path).metadata = structuredClone(previous.metadata);
      mutations++;
      if (hook.afterWrite) hook.afterWrite({files, put});
      if (hook.rejectWriteAfterMutation) return {isError: true, content: [{type: 'text', text: 'FIXTURE_AMBIGUOUS_WRITE_RESPONSE'}]};
      return packet({path: args.path, sha256: digest(bytes), version: get(args.path).version});
    }
  };
  return {tools, calls, files, put, get,
    summary() { return {write_attempts: writeAttempts, simulated_mutations: mutations, call_count: calls.length}; },
    assertSentinels() { for (const [p, b] of originalSentinels) assert.deepEqual(get(p).bytes, b); }
  };
}

const start = performance.now();
const cpuStart = process.cpuUsage();
const cases = [];
async function run(name, initial, mode, options = {}) {
  const f = fixture(initial, options.hook);
  if (options.setup) options.setup(f);
  const beforeEntry = Buffer.from(f.get(entry).bytes);
  const j = await controller(f.tools, mode, authorization);
  const stats = f.summary();
  if (options.success) {
    assert.equal(j.ok, true);
    assert.equal(stats.write_attempts, 1);
    assert.equal(stats.simulated_mutations, 1);
    assert.equal(j.state, mode === 'activate' ? 'ENTRY_ACTIVATED_ONLY' : 'ORIGINAL_ENTRY_RESTORED_ONLY');
    assert.deepEqual(f.get(entry).bytes, mode === 'activate' ? newEntry : oldEntry);
  } else {
    assert.equal(j.ok, false);
    assert.equal(stats.write_attempts, options.writeAttempts ?? 0);
    assert.equal(j.state, stats.write_attempts ? 'RECONCILE_EXACT_ENTRY_DO_NOT_RETRY' : 'NO_MUTATION');
    if (!stats.simulated_mutations) assert.deepEqual(f.get(entry).bytes, beforeEntry);
    if (options.error) assert.match(j.error, options.error);
  }
  assert.equal(j.provider_calls, 0);
  assert.equal(j.ledger_or_lock_writes, 0);
  f.assertSentinels();
  assert.equal(f.calls.filter(c => c.method === 'binary_write').length, stats.write_attempts);
  assert.ok(f.calls.filter(c => c.method === 'binary_write').every(c => c.path === entry));
  if (options.check) options.check(f, j);
  cases.push({name, result: 'PASS', mode, observed_state: j.state, observed_error: j.error ?? null, ...stats, trace: f.calls});
}

for (const [name, mode, auth] of [
  ['wrong_scope_rejected_before_tools', 'activate', {scope: 'sunfo-unknown', frozen_commit: 'a'.repeat(40)}],
  ['missing_commit_rejected_before_tools', 'activate', {scope: authorization.scope}],
  ['invalid_mode_rejected_before_tools', 'replace', authorization]
]) {
  const f = fixture();
  await assert.rejects(() => controller(f.tools, mode, auth));
  assert.equal(f.calls.length, 0);
  cases.push({name, result: 'PASS', call_count: 0, write_attempts: 0, simulated_mutations: 0});
}
await run('activate_exact_original', 'old', 'activate', {success: true});
await run('activate_text_result_envelope', 'old', 'activate', {success: true, hook: {textEnvelope: true}});
await run('wrong_old_dependency', 'old', 'activate', {setup: f => f.put(oldRelease + '/kaggle_jobs.py', 'wrong old dependency'), error: /DEPLOYMENT_PREFLIGHT_FAILED/});
await run('wrong_new_dependency', 'old', 'activate', {setup: f => f.put(newRelease + '/kaggle_jobs.py', 'wrong new dependency'), error: /DEPLOYMENT_PREFLIGHT_FAILED/});
await run('original_router_changed', 'old', 'activate', {setup: f => f.put('/home/qian-qi/.hepta-kaggle-adoption-releases/v5-batch-4920/hepta_compute_base.py', 'changed router'), error: /DEPLOYMENT_PREFLIGHT_FAILED/});
await run('entry_wrong_hash', 'old', 'activate', {setup: f => f.put(entry, 'unknown entry', 0o700), error: /EXACT_DEPLOYMENT_IDENTITY_CHANGED/});
await run('entry_wrong_permissions', 'old', 'activate', {setup: f => { f.get(entry).mode = 0o600; }, error: /ENTRY_METADATA_CHANGED/});
await run('entry_wrong_owner', 'old', 'activate', {setup: f => { f.get(entry).metadata.uid = 2000; }, error: /EXACT_DEPLOYMENT_IDENTITY_CHANGED/});
await run('entry_multiple_hardlinks', 'old', 'activate', {setup: f => { f.get(entry).metadata.link_count = 2; }, error: /EXACT_DEPLOYMENT_IDENTITY_CHANGED/});
await run('retained_wrong_hash', 'old', 'activate', {setup: f => f.put(task + '/proposed_account_entry.bin', 'wrong retained bytes', 0o700), error: /EXACT_DEPLOYMENT_IDENTITY_CHANGED/});
await run('retained_version_changed', 'old', 'activate', {hook: {read: b => { b.version = 'other-version'; }}, error: /RETAINED_SWITCH_BYTES_CHANGED/});
await run('retained_incomplete_read', 'old', 'activate', {hook: {read: b => { b.eof = false; }}, error: /RETAINED_SWITCH_BYTES_CHANGED/});
await run('retained_chunk_digest_mismatch', 'old', 'activate', {hook: {read: b => { b.chunk_sha256 = '0'.repeat(64); }}, error: /RETAINED_SWITCH_BYTES_CHANGED/});
await run('concurrent_version_cas_rejected_no_retry', 'old', 'activate', {hook: {beforeWrite: ({files}) => { files.get(entry).version = 'concurrent-version'; }}, writeAttempts: 1, error: /HEPTA_API_ERROR/});
await run('write_rejected_no_retry', 'old', 'activate', {hook: {rejectWriteBeforeMutation: true}, writeAttempts: 1, error: /HEPTA_API_ERROR/});
await run('ambiguous_write_result_reconcile_no_retry', 'old', 'activate', {hook: {rejectWriteAfterMutation: true}, writeAttempts: 1, error: /HEPTA_API_ERROR/});
await run('post_write_wrong_hash_reconcile_no_retry', 'old', 'activate', {hook: {afterWrite: ({put}) => put(entry, 'unexpected published bytes', 0o700)}, writeAttempts: 1, error: /EXACT_DEPLOYMENT_IDENTITY_CHANGED/});
await run('post_write_metadata_changed_reconcile_no_retry', 'old', 'activate', {hook: {afterWrite: ({files}) => { files.get(entry).metadata.gid = 2000; }}, writeAttempts: 1, error: /ENTRY_METADATA_VERIFICATION_FAILED/});
await run('rollback_exact_proposed', 'new', 'rollback', {success: true});
await run('rollback_does_not_require_new_release', 'new', 'rollback', {
  setup: f => { for (const n of moduleNames) f.files.delete(newRelease + '/' + n); f.files.delete(newLauncher); },
  success: true,
  check: f => assert.equal(f.calls.filter(c => c.path.startsWith(newRelease) || c.path === newLauncher).length, 0)
});
await run('rollback_refuses_unrelated_current_entry', 'new', 'rollback', {setup: f => f.put(entry, 'other active wrapper', 0o700), error: /EXACT_DEPLOYMENT_IDENTITY_CHANGED/});

const output = {
  schema: 'independent-entry-switch-model-review-v1',
  status: 'PASS_SCOPED_STATIC_AND_LOCAL_MODEL_REVIEW',
  blocking_findings: [],
  source_sha256: digest(source), reviewer_sha256: digest(fs.readFileSync(fileURLToPath(import.meta.url))),
  meaningful_cases_passed: cases.length,
  model_scope: 'Independent in-memory simulation of documented official file-info, pinned-read, and atomic expected-version write interfaces. Executes the exact candidate controller against fake tools only. Does not verify remote availability or replace a real activation receipt.',
  module_dependency_scope: 'Five staged local modules cover all internal imports. kagglesdk dynamic imports and existing venv behavior reside in unchanged transport; no new SDK dependency introduced.',
  author_tests_used_as_independent_evidence: false,
  remote_calls: 0, production_mutations: 0, candidate_source_edits: 0,
  python_preparation_contract: '/usr/bin/python3.12 -I -B; no -O; runtime owner confirmed fixed argv before freeze',
  actual_activation_or_collection_claim: false,
  body_wall_seconds: (performance.now() - start) / 1000,
  body_cpu_seconds: Object.values(process.cpuUsage(cpuStart)).reduce((a, b) => a + b, 0) / 1000000,
  cases
};
fs.writeFileSync(path.join(here, 'ENTRY_SWITCH_INDEPENDENT_REVIEW.json'), JSON.stringify(output, null, 2) + '\n', {flag: 'wx'});
console.log(JSON.stringify({status: output.status, meaningful_cases_passed: cases.length, remote_calls: 0, production_mutations: 0, body_wall_seconds: output.body_wall_seconds, body_cpu_seconds: output.body_cpu_seconds}));
