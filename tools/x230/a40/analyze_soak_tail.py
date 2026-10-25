#!/usr/bin/env python3
"""Reproduce the frozen A40r02 complete-row soak-tail analysis locally.

This is the complete analysis originally executed as a local Python heredoc.
Only input-layout/output argument parsing has been added. It imports no product
code, runs no product or harness process, and makes no network requests.

Usage (choose an output path that does not already exist):
  python3 analyze_soak_tail.py --workspace-root /abs/workspace \
      --out /abs/new-soak-tail-analysis.json
  python3 analyze_soak_tail.py --repository-root /abs/hepta-runtime \
      --out /abs/new-soak-tail-analysis.json

Fixed paths below intentionally describe that workspace snapshot:
  publish-a40/docs/evidence/x230-a40/{final-evidence.tar.gz,qualification.json}
  runtime-a40r2-source/
  publish-a40/tools/x230/a40/{x230_file_pool_benchmark.py,
                            x230_observation_benchmark.py}
The repository layout instead uses src/, docs/evidence/x230-a40/ and
tools/x230/a40/ directly under --repository-root.

The expected bundle SHA, ELF SHA, member names, counts and source commentary
are deliberately pinned to A40r02. This is an evidence reproducer, not a generic
benchmark analyzer. Use normal Python (not -O): the original evidence checks
use assertions. Output is created exclusively; an existing file is never
overwritten. Source line references describe the qualification-bound snapshot.
"""

from pathlib import Path
import argparse
import collections,hashlib,io,json,math,statistics,tarfile

parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
layout=parser.add_mutually_exclusive_group(required=True)
layout.add_argument('--workspace-root',type=Path)
layout.add_argument('--repository-root',type=Path)
parser.add_argument('--out',type=Path,required=True)
args=parser.parse_args()
if not __debug__:
    parser.error('run without -O; this reproducer retains the original assertion checks')
base=args.repository_root or args.workspace_root
if not base.is_absolute() or not args.out.is_absolute():
    parser.error('the input root and --out must be absolute paths')
evidence=base/('docs/evidence/x230-a40' if args.repository_root else 'publish-a40/docs/evidence/x230-a40')
bundle=evidence/'final-evidence.tar.gz'
qualification=evidence/'qualification.json'
out=args.out
source=base if args.repository_root else base/'runtime-a40r2-source'
source_paths=['src/mcp/runtime/ssh.rs','src/mcp/runtime/binary.rs','src/mcp/runtime/ssh_observation_pool.rs','src/mcp/runtime/ssh_observation_profile.rs','src/mcp/runtime/ssh_observation_validation.rs','src/mcp/server.rs']
harness_dir=base/('tools/x230/a40' if args.repository_root else 'publish-a40/tools/x230/a40')
harness_paths=[harness_dir/'x230_file_pool_benchmark.py',harness_dir/'x230_observation_benchmark.py']
inputs=[bundle,qualification]+[source/p for p in source_paths]+harness_paths
snapshots={}
def digest(b): return hashlib.sha256(b).hexdigest()
def identity(st): return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
def read_stable(p):
 a=p.stat(); b=p.read_bytes(); z=p.stat()
 assert identity(a)==identity(z),(str(p),'changed during read')
 snapshots[p]=(identity(z),digest(b)); return b
raw={p:read_stable(p) for p in inputs}
bundle_bytes=raw[bundle]
assert len(bundle_bytes)==2612169
assert digest(bundle_bytes)=='2fd95f6ab697ddda7d746752e5c3083eb96e2e23d9933a05ebf1093976c8a0e4'
pre='a40-staggered-output-recovery-20261025-r02/file-pool-soak-r01/'
with tarfile.open(fileobj=io.BytesIO(bundle_bytes),mode='r:gz') as t:
 for name in (pre+'report.json',pre+'calls.jsonl'):
  assert sum(m.name==name for m in t.getmembers())==1
  assert t.getmember(name).isreg()
 rb=t.extractfile(pre+'report.json').read(); cb=t.extractfile(pre+'calls.jsonl').read()
r=json.loads(rb); rows=[json.loads(line) for line in cb.splitlines()]
assert digest(cb)==r['calls_sha256']
assert r['complete'] is True and r['binary_unchanged'] is True and r['agent_unchanged'] is True
assert r['order']==['on'] and r['concurrency']==[8] and r['calls_per_cell']==96
assert r['binary_sha256']=='3238c9d4bb2f8dc4dbb86e591ce774bea70c6785c159cf27b70003f00623540c'
assert collections.Counter(x['phase'] for x in rows)=={'warmup':12,'measured':12480,'negative':12}
assert all(x['okay'] is True and x['automatic_retry'] is False for x in rows)
m=[x for x in rows if x['phase']=='measured']
assert all(isinstance(x['elapsed_ms'],(int,float)) and math.isfinite(x['elapsed_ms']) and x['elapsed_ms']>=0 for x in m)
assert all(x['round']==0 and x['mode']=='on' and x['concurrency']==8 for x in m)
hosts=sorted({x['host'] for x in m}); assert len(hosts)==6
assert {x['tool'] for x in m}=={'file_info','binary_read'}
slots=[(x['round'],x['mode'],x['concurrency'],x['iteration'],x['index']) for x in m]
assert len(set(slots))==len(slots)
groups=collections.defaultdict(list)
for row in m: groups[row['iteration']].append(row)
assert sorted(groups)==list(range(130))
def quantile(values,p): return sorted(values)[math.ceil(len(values)*p)-1]
assert len(r['rounds'])==1 and r['rounds'][0]['index']==0 and r['rounds'][0]['mode']=='on'
cells=r['rounds'][0]['cells']; assert len(cells)==130
for cell in cells:
 g=groups[cell['iteration']]; assert len(g)==96 and {x['index'] for x in g}==set(range(96))
 assert collections.Counter((x['host'],x['tool']) for x in g)=={(h,t):8 for h in hosts for t in ('file_info','binary_read')}
 assert cell['concurrency']==8 and cell['calls']==96 and cell['success']==96
 vals=[x['elapsed_ms'] for x in g]
 for key,val in [('p50_ms',statistics.median(vals)),('p95_ms',quantile(vals,.95)),('p99_ms',quantile(vals,.99))]:
  assert math.isclose(cell[key],val,rel_tol=1e-12,abs_tol=1e-9),(cell['iteration'],key)
 assert math.isclose(cell['successful_calls_per_second'],96/cell['seconds'],rel_tol=1e-12)
q=json.loads(raw[qualification]); assert q['qualified'] is True
source_receipts={}
for rel in source_paths:
 b=raw[source/rel]; h=digest(b)
 assert q['source_tested'][rel]==h and q['source_after'][rel]==h
 source_receipts[rel]={'bytes':len(b),'sha256':h,'matches_qualification_source_tested_and_after':True}
assert digest(raw[harness_paths[0]])==r['script_sha256']
values=[x['elapsed_ms'] for x in m]
def tail(threshold):
 subset=[x for x in m if x['elapsed_ms']>=threshold]
 return {'count':len(subset),'percent_of_measured':100*len(subset)/len(m),'by_iteration':dict(sorted(collections.Counter(x['iteration'] for x in subset).items())), 'by_host':dict(sorted(collections.Counter(x['host'] for x in subset).items())), 'by_tool':dict(sorted(collections.Counter(x['tool'] for x in subset).items()))}
tail1=tail(1000); tail5=tail(5000)
assert tail1['count']==33 and tail5['count']==10
assert tail5['by_iteration']=={14:10} and tail5['by_host']=={'pocket4':4,'rog':6}
slow=[{k:x[k] for k in ('iteration','index','host','tool','elapsed_ms','okay','automatic_retry')} for x in sorted(m,key=lambda x:(x['iteration'],x['index'])) if x['elapsed_ms']>=5000]
analysis={
 'schema':'hepta-x230-file-soak-tail-analysis/v1',
 'candidate_label':'A40r02',
 'scope':'Local complete-row reanalysis and static source review only. On-only C8 six-host soak of synthetic completed-job outputs; not a matched off/on soak or a new product test.',
 'provenance':{
  'bundle':{'path':'docs/evidence/x230-a40/final-evidence.tar.gz','bytes':len(bundle_bytes),'sha256':digest(bundle_bytes)},
  'report':{'tar_member':pre+'report.json','bytes':len(rb),'sha256':digest(rb)},
  'calls':{'tar_member':pre+'calls.jsonl','bytes':len(cb),'sha256':digest(cb),'matches_report_calls_sha256':True},
  'qualified_binary_sha256':r['binary_sha256'],
  'qualification_sha256':digest(raw[qualification]),
  'source_files':source_receipts,
  'harness_files':{p.name:{'bytes':len(raw[p]),'sha256':digest(raw[p])} for p in harness_paths}
 },
 'observations':{
  'raw_rows':len(rows),'phase_counts':dict(sorted(collections.Counter(x['phase'] for x in rows).items())),
  'measured_rows':len(m),'measured_successes':sum(x['okay'] is True for x in m),'all_measured_okay':True,
  'all_raw_automatic_retry_false':True,'all_measured_rows_retained':True,
  'round':0,'mode':'on','concurrency':8,'iterations':130,'iteration_range_inclusive':[0,129],'calls_per_iteration':96,
  'measured_by_host':dict(sorted(collections.Counter(x['host'] for x in m).items())),
  'measured_by_tool':dict(sorted(collections.Counter(x['tool'] for x in m).items())),
  'every_iteration_host_tool_cell_has_8_rows':True,'measured_logical_slots_unique':True,
  'all_130_report_cell_counts_success_rates_and_latency_quantiles_match_raw':True,
  'quantile_method':'nearest rank: sorted values[ceil(n*p)-1]; all measured rows included',
  'latency_ms':{'p50':statistics.median(values),'p95':quantile(values,.95),'p99':quantile(values,.99),'max':max(values)},
  'latency_buckets':{'less_than_1000_ms':sum(v<1000 for v in values),'at_least_1000_below_5000_ms':sum(1000<=v<5000 for v in values),'at_least_5000_ms':sum(v>=5000 for v in values),'at_least_30000_ms':sum(v>=30000 for v in values)},
  'at_least_1000_ms':tail1,'at_least_5000_ms':tail5,
  'all_at_least_5000_ms_rows':slow,
  'iteration_14_cell':{k:v for k,v in next(c for c in cells if c['iteration']==14).items() if k!='resources'},
  'latency_measurement':'Client monotonic time starts immediately before controller.rpc and ends after response parsing and content/version validation. It includes write-lock/stdio dispatch and response wait; it excludes ThreadPoolExecutor waiting before call() starts. Rows contain no pool-stage timing or causal trace.',
  'latency_measurement_source':['tools/x230/a40/x230_file_pool_benchmark.py:137-178','tools/x230/a40/x230_file_pool_benchmark.py:258-266','tools/x230/a40/x230_observation_benchmark.py:352-367']
 },
 'source_facts':{
  'file_observation_deadline':{'seconds':30,'starts':'capture(): Instant::now() + duration, before queue admission','preserved_through':['channel admission','pending queue expiry','initial profile validation','per-host capacity and master readiness','global capture capacity','SSH socket/capture','final authority validation'],'sources':['src/mcp/runtime/ssh.rs:181-192','src/mcp/runtime/ssh_observation_pool.rs:267-332','src/mcp/runtime/ssh_observation_pool.rs:1332-1483','src/mcp/runtime/ssh_observation_pool.rs:1606-1695']},
  'capacity':{'total_logical_admission':16,'channel_capacity':8,'global_expensive_preflight_or_capture_budgets':8,'per_host_sessions':2,'masters':8,'validation_workers':2,'admission_when_full':'try_acquire_owned returns error; no fallback or automatic retry','host_waiters':'Initial global preflight permit is released before waiting for a host; capture reacquires global capacity after host/master readiness. No added capacity or reset deadline.','sources':['src/mcp/runtime/ssh_observation_pool.rs:32-42','src/mcp/runtime/ssh_observation_pool.rs:300-332','src/mcp/runtime/ssh_observation_pool.rs:1341-1415','src/mcp/runtime/ssh_observation_validation.rs:12-15,104-129']},
  'suboperation_budgets':{'agent_lookup_seconds':2,'master_start_seconds':12,'bounded_by_original_request_deadline':True,'harness_response_wait_seconds':50,'harness_wait_scope':'queue.Queue.get timeout after write-lock and stdio write/flush; not a product deadline or whole-call hard bound','sources':['src/mcp/runtime/ssh_observation_pool.rs:663-688','src/mcp/runtime/ssh_observation_pool.rs:1192-1199,1324-1329','tools/x230/a40/x230_observation_benchmark.py:352-367']},
  'sync_owner_validation':{'owner_runtime':'dedicated current-thread Tokio runtime','behavior':'A bounded blocking worker performs complete-file validation, then its retained ticket runs a second complete-file rehash plus boundary validation synchronously on the owner thread. Synchronous file read/open/stat/hash work has deadline/cancel checks before and after individual steps; the rehash buffer is 16 KiB.','sources':['src/mcp/runtime/ssh_observation_pool.rs:166-174,639-662','src/mcp/runtime/ssh_observation_profile.rs:19,271-309,779-808','src/mcp/runtime/ssh_observation_validation.rs:49-67,104-147']},
  'timeout_policy':'Queue/capture deadlines and cancellation return errors without fallback/retry. Failed captured children are stopped and reaped. Validation rechecks the original deadline before authority acceptance; an expired result is rejected. Request-scoped agent lookup deadline discards that result without automatically retrying or substituting a credential snapshot.',
  'timeout_policy_sources':['src/mcp/runtime/ssh_observation_pool.rs:267-332,663-688,949-981','src/mcp/runtime/ssh_observation_validation.rs:49-67,122-147'],
  'public_tool_description':'file_info and binary_read descriptions promise no 1-second or 5-second latency bound; direct binary RPC also uses 30 seconds.','public_tool_sources':['src/mcp/server.rs:1686-1722','src/mcp/runtime/binary.rs:143,163-195']
 },
 'interpretation':{
  'observed_30_second_budget_violation':False,
  'budget_conclusion':'The maximum measured whole call is 14.411153833 seconds, below the 30-second file-observation transport budget. These samples therefore do not show a breach of that overall budget. The 1-second and 5-second thresholds classify the observed tail; they are not deadlines promised by these tool paths. Overall elapsed times cannot establish individual agent-lookup or master-start stage durations.',
  'synchronous_wait_risk':'Source-level risk, not a diagnosed cause: the synchronous complete-file verification can occupy the pool owner without yielding. Slow blocking filesystem syscalls cannot be interrupted by its cooperative checks and can delay other pool work or timer processing on that owner. Checks between read chunks and before acceptance prevent stale authority from being accepted once control returns; they do not make blocking I/O preemptible. The outer reply timeout runs in the calling context and can still expire independently of a stalled owner, so this is not proof of unbounded client RPC duration.',
  'tail_cause':'Unknown. No per-stage timing, trace, matched off-mode soak or network/filesystem fault record in these rows identifies why rog and pocket4 clustered at iteration 14. Do not attribute the tail to the static synchronization risk, agent forwarding, master renewal, host saturation, or network conditions from these records alone.',
  'scope_limits':['All successful results and the full long tail remain in the denominator; successful requests are not evidence of uniformly low latency.','One on-only soak does not quantify a regression against an equally long off-mode baseline.','Unique logical harness slots and automatic_retry=false do not establish RPC wire exactly-once delivery.','No claim of a universal 30-second end-to-end hard real-time bound: client dispatch/parsing and synchronous OS operations have separate timing scope.'],
  'follow_up_design_only':'A later investigation can record per-request queue, authority-check, master-wait and capture durations without weakening complete-file, policy or credential validation. No instrumentation or further load was run for this analysis.'
 }
}
for p in inputs:
 a=p.stat(); b=p.read_bytes(); z=p.stat()
 assert identity(a)==identity(z)==snapshots[p][0] and digest(b)==snapshots[p][1],(str(p),'input changed')
analysis['inputs_unchanged_after_analysis']=True
out.parent.mkdir(parents=True,exist_ok=True)
encoded=(json.dumps(analysis,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()
with out.open('xb') as f: f.write(encoded)
assert json.loads(out.read_bytes())==json.loads(encoded)
print(json.dumps({'out':str(out),'bytes':len(encoded),'sha256':digest(encoded),'measured':len(m),'tail_1000':tail1,'tail_5000':tail5,'latency_ms':analysis['observations']['latency_ms'],'inputs_unchanged':True},ensure_ascii=False,indent=2))
