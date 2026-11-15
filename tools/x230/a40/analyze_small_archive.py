#!/usr/bin/env python3
"""Independently recheck the frozen A40r02 small-archive evidence bundle.

This reproduces the complete original offline analysis with CLI input paths.
It is deliberately bound to the recorded A40r02 bundle hash, member paths and
qualified executable digest; it is not a generic benchmark or new fixture.
It performs only local reads and writes one new JSON report, refusing to
replace an existing output. No remote API, subprocess or product is invoked.

Example:
  python3 analyze_small_archive.py --bundle /abs/final-evidence.tar.gz \
    --harness /abs/x230_small_archive_benchmark.py --out /abs/new-analysis.json
"""
from pathlib import Path, PurePosixPath
import argparse, collections, hashlib, json, math, statistics, tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bundle', type=Path, required=True)
parser.add_argument('--harness', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
options = parser.parse_args()
BUNDLE = options.bundle
PREFIX = 'a40-staggered-output-recovery-20261025-r02/small-archive-abba-r01/'
EXPECTED_BUNDLE = '2fd95f6ab697ddda7d746752e5c3083eb96e2e23d9933a05ebf1093976c8a0e4'
EXPECTED_CANDIDATE = '3238c9d4bb2f8dc4dbb86e591ce774bea70c6785c159cf27b70003f00623540c'
OUT = options.out

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def need(ok, message):
    if not ok:
        raise AssertionError(message)

def read_jsonl(data):
    need(data.endswith(b'\n'), 'partial JSONL final line')
    lines = data.splitlines(keepends=True)
    return lines, [json.loads(line) for line in lines]

def stats(rows):
    values = sorted(row['elapsed_ms'] for row in rows)
    return {'calls': len(values), 'mean_ms': statistics.mean(values),
            'p50_ms': statistics.median(values), 'p95_ms': values[math.ceil(.95*len(values))-1],
            'p99_ms': values[math.ceil(.99*len(values))-1], 'max_ms': values[-1]}

def close_numbers(left, right):
    return all(k in right and math.isclose(v, right[k], rel_tol=1e-10, abs_tol=1e-9) for k,v in left.items())

raw_bundle = BUNDLE.read_bytes()
need(len(raw_bundle) == 2612169 and sha(raw_bundle) == EXPECTED_BUNDLE, 'bundle hash/length differs')
with tarfile.open(BUNDLE, 'r:gz') as archive:
    members = {item.name: item for item in archive.getmembers()}
    def read(relative):
        name = PREFIX + relative
        item = members[name]
        need(item.isfile(), 'nonregular evidence member')
        return archive.extractfile(item).read()
    raw_report, raw_calls = read('report.json'), read('calls.jsonl')
    report = json.loads(raw_report)
    _, calls = read_jsonl(raw_calls)
    need(report['schema'] == 'hepta-x230-small-archive-abba/v1', 'schema differs')
    need(report['complete'] is True and report['comparison_valid'] is True, 'report incomplete')
    need(report['inputs_unchanged'] is True and report['script_unchanged'] is True, 'input drift')
    need(report['performance_adoption_claimed'] is False, 'unexpected adoption claim')
    need(report['product_metadata_deadline_modified'] is False and report['automatic_retries'] == 0,
         'deadline/retry contract differs')
    need(report['ssh_or_profile_used'] is False and report['workers'] == 2, 'fixture transport/workers differs')
    need(report['inputs']['B']['sha256'] == EXPECTED_CANDIDATE, 'candidate digest differs')
    need(report['order'] == ['A','B','B','A'] and len(report['rounds']) == 4, 'ABBA order differs')
    need(report['measured_per_round'] == 1024 and report['measured_planned'] == 4096
         and report['measured_attempted'] == 4096 and report['measured_unexecuted'] == 0, 'measurement coverage differs')
    need(report['calls_file']['sha256'] == sha(raw_calls) and report['calls_file']['bytes'] == len(raw_calls), 'calls digest differs')
    harness = options.harness
    need(report['script']['sha256'] == sha(harness.read_bytes()), 'published harness differs')
    for arm in ('A','B'):
        need(report['final_inputs'][arm] == {k:v for k,v in report['inputs'][arm].items() if k != 'path'}, 'final binary metadata differs')
    need(len(calls) == 4424, 'total tool dispatch count differs')
    need(all(row['okay'] is True and row['sent'] is True and row['response_received'] is True
             and row['automatic_retry'] is False and row['write_attempts'] == 1 and row['concurrency'] == 1 for row in calls),
         'failed/unsent/retried/overlapping dispatch')
    rounds = []
    all_seed_ids = set()
    public_scope_values = collections.Counter()
    raw_wire_totals = collections.Counter()
    per_arm = {}
    for index, arm in enumerate(['A','B','B','A']):
        rr = report['rounds'][index]
        directory = f'round-{index}-{arm}/'
        rows = [row for row in calls if row['round'] == index]
        need(len(rows) == 1106 and all(row['arm'] == arm for row in rows), 'round dispatch coverage differs')
        expected_purposes = {'seed':64, 'preflight':5, 'warmup':8, 'measured':1024, 'postflight':5}
        need(dict(collections.Counter(row['purpose'] for row in rows)) == expected_purposes, 'purpose coverage differs')
        journal_rows = rr['seeds'] + rr['validation'] + rr['warmup'] + rr['measured']
        need(sorted(journal_rows,key=lambda row:row['rpc_id']) == rows, 'report/journal rows differ')
        need([row['rpc_id'] for row in rows] == list(range(2,1108)), 'tool RPC IDs not complete unique sequence')
        need(rr['round'] == index and rr['arm'] == arm and rr['complete'] is True and rr['originals_unchanged'] is True,
             'round terminal contract differs')
        expected = json.loads(read(directory+'expected-public-records.json'))
        need(len(expected) == 64 and len({row['request_id'] for row in expected}) == 64, 'public originals coverage differs')
        need(expected == sorted(expected, key=lambda row:(row['accepted_unix_ms'],row['request_id'])), 'record order differs')
        need(all(set(row) == {'request_id','tool_name','state','accepted_unix_ms','elapsed_ms'}
                 and row['tool_name'] == 'host_list' and row['state'] == 'completed' for row in expected), 'public record schema differs')
        seed_ids = {row['native_request_id'] for row in rows if row['purpose'] == 'seed'}
        need(len(seed_ids) == 64 and seed_ids == {row['request_id'] for row in expected}, 'native seeds/public records differ')
        need(not all_seed_ids.intersection(seed_ids), 'native request ID reused across fresh rounds')
        all_seed_ids.update(seed_ids)
        snapshots = [json.loads(read(directory+name)) for name in (
            'originals-after-seed.json','originals-before-measured.json',
            'originals-after-measured.json','originals-after-shutdown.json')]
        need(all(value == snapshots[0] for value in snapshots), 'original maps changed between checkpoints')
        snap = snapshots[0]
        need(snap['logical_records'] == snap['hot_files'] == snap['archive_files'] == 64, 'original-map cardinality differs')
        need(snap['file_map_sha256'] == sha(canonical(snap['files'])), 'complete original-map digest differs')
        need(snap['public_record_projection_sha256'] == sha(canonical(expected)), 'public projection digest differs')
        for kind in ('hot','archive'):
            need(len(snap['files'][kind]) == 64, 'original file-map size differs')
            need({PurePosixPath(path).stem for path in snap['files'][kind]} == seed_ids, 'file-map names differ from native seed IDs')
            need(all(v['bytes'] <= 2048 and len(v['sha256']) == 64 and len(v['identity']) == 8 for v in snap['files'][kind].values()), 'original file receipt differs')
        req_raw, res_raw, err_raw = (read(directory+'controller/'+name) for name in ('requests.jsonl','responses.jsonl','stderr.log'))
        req_lines, req = read_jsonl(req_raw)
        res_lines, res = read_jsonl(res_raw)
        need(len(req) == 1108 and len(res) == 1107, 'native wire cardinality differs')
        need(req[0]['method'] == 'initialize' and req[0]['id'] == 1, 'initialize request differs')
        need(req[1] == {'jsonrpc':'2.0','method':'notifications/initialized','params':{}}, 'initialized notification differs')
        need([item['id'] for item in res] == list(range(1,1108)), 'native response IDs differ')
        need([item['id'] for item in req if 'id' in item] == list(range(1,1108)), 'native request IDs differ')
        need('result' in res[0] and 'error' not in res[0], 'initialize response failed')
        raw_wire_totals.update({'tool_calls':1106,'initialize_rpcs':1,'initialized_notifications':1,
                               'rpc_requests_with_id':1107,'request_lines':1108,'response_lines':1107})
        by_response = {item['id']:(wire,item) for wire,item in zip(res_lines,res)}
        for row in rows:
            req_segment=req_raw[row['request_wire_offset']:row['request_wire_offset']+row['request_wire_bytes']]
            need(sha(req_segment)==row['request_wire_sha256'], 'request wire offset/hash differs')
            request=json.loads(req_segment)
            need(request == {'jsonrpc':'2.0','id':row['rpc_id'],'method':'tools/call',
                             'params':{'name':row['tool'],'arguments':row['arguments']}}, 'exact wire request differs from journal')
            response_segment=res_raw[row['response_wire_offset']:row['response_wire_offset']+row['response_wire_bytes']]
            need(sha(response_segment)==row['response_wire_sha256'], 'response wire offset/hash differs')
            need(response_segment==by_response[row['rpc_id']][0], 'response not bound to original RPC ID')
            response=json.loads(response_segment)
            need(response['jsonrpc']=='2.0' and 'error' not in response, 'native JSON-RPC error')
            result=response['result']
            need(result.get('isError',False) is False, 'native tool error')
            texts=[part['text'] for part in result['content'] if part['type']=='text']
            need(len(texts)==1, 'native text result cardinality differs')
            dto=json.loads(texts[0])
            need(sha(canonical(dto))==row['dto_sha256'], 'DTO hash differs')
            if row['tool']=='host_list':
                meta=result['_meta'];marker=meta['io.hepta.runtime/request-v8'];ack=meta['io.hepta.runtime/retention-v8']
                need(marker['request_id']==row['native_request_id'] and marker['automatic_retry'] is False
                     and marker['delivery_proven'] is False, 'seed native request identity semantics differ')
                need(ack['audit_completion_durable'] is True and ack['result_state']=='stored'
                     and ack['automatic_retry'] is False, 'seed durability/retention ack differs')
                need(dto=={'hosts':[{'name':'fixture','platform':'linux','execution_mode':'isolated',
                     'operator_tools':False,'allow_execute':False,'allow_pty':False,'allow_write':False,'privileged_actions':[]}]},
                     'closed synthetic host_list response differs')
            else:
                scope={k:dto[k] for k in ('ownership_scope','session_scope','authenticated_chatgpt_caller_isolation',
                                        'credential_metadata_resume','cross_session_resume')}
                need(scope == {'ownership_scope':'native_mcp_session_only','session_scope':'native_mcp_session_only',
                    'authenticated_chatgpt_caller_isolation':False,'credential_metadata_resume':False,'cross_session_resume':False},
                    'public owner scope differs')
                public_scope_values.update([row['tool']])
                if row['tool']=='usage_stats':
                    need(dto['schema']=='hepta-private-usage-v1' and dto['total_requests']==64 and dto['completed']==64
                         and dto['failed']==dto['unknown']==dto['active']==0 and dto['tool_counts']=={'host_list':64},
                         'usage counters differ from originals')
                    need(dto['first_accepted_unix_ms']==expected[0]['accepted_unix_ms']
                         and dto['last_accepted_unix_ms']==expected[-1]['accepted_unix_ms'], 'usage original timestamps differ')
                    need(dto['contains_parameters_or_output'] is False and dto['scope']=='same_verified_credential_or_native_session',
                         'usage exposure/scope differs')
                else:
                    args=row['arguments'];need(args['limit']==32, 'page limit differs')
                    page=0 if 'after_id' not in args else 1
                    if page:need(args['after_id']==expected[31]['request_id'], 'page cursor differs')
                    need(dto['requests']==expected[page*32:(page+1)*32]
                         and dto['next_after_id']==(expected[31]['request_id'] if page==0 else None), 'full page differs from originals')
                    need(dto['history_is_live'] is True and dto['automatic_operation_retry'] is False, 'observer retry/live semantics differ')
                    if row['tool']=='request_history':
                        need(dto['retention']=={'global':512,'per_owner':128}, 'public per_owner retention differs')
                    else:
                        need(dto['total']==64 and dto['archive_retention']=='no_automatic_metadata_eviction'
                             and dto['contains_parameters_or_output'] is False, 'archive total/retention differs')
        shutdown=rr['shutdown'];waited=shutdown['waited']
        need(shutdown['method']=='stdin_eof' and shutdown['original_child_reaped'] is True
             and waited['exit_code']==0 and waited['pid']==rr['startup']['pid']
             and not shutdown['errors'] and shutdown['reader_error'] is None and not shutdown['unmatched'], 'original controller shutdown differs')
        need(err_raw==b'', 'controller stderr was not empty')
        for name,data in [('requests.jsonl',req_raw),('responses.jsonl',res_raw),('stderr.log',err_raw)]:
            need(shutdown['files'][name]['sha256']==sha(data) and shutdown['files'][name]['bytes']==len(data), 'shutdown wire-file receipt differs')
        computed={tool:stats([row for row in rows if row['purpose']=='measured' and row['tool']==tool])
                  for tool in ('usage_stats','request_history','request_archive')}
        need(rr['measured_summary']['attempted']==rr['measured_summary']['sent']==rr['measured_summary']['successes']==1024
             and rr['measured_summary']['failures']==0 and rr['measured_summary']['performance_valid'] is True, 'round measurement summary differs')
        for tool,calc in computed.items():
            need(close_numbers(calc, rr['measured_summary']['tools'][tool]), 'round latency statistics differ')
        rounds.append({'round':index,'arm':arm,'tool_dispatches':len(rows),'purpose_counts':expected_purposes,
                       'native_seed_ids_unique':len(seed_ids),'original_snapshot_count':4,'hot_records':64,'archive_records':64,
                       'original_maps_identical':True,'file_map_sha256':snap['file_map_sha256'],
                       'public_projection_sha256':snap['public_record_projection_sha256'],
                       'wire_request_lines':len(req),'wire_response_lines':len(res),'rpc_id_sequence_complete':True,
                       'wire_rows_hash_and_identity_bound':True,'measured_tool_statistics':computed,
                       'original_controller_reaped':True,'shutdown_method':shutdown['method'],'exit_code':waited['exit_code'],
                       'whole_round_waited_cpu_seconds':waited['total_cpu_seconds']})
    measured=[row for row in calls if row['purpose']=='measured']
    need(len(measured)==4096, 'complete measured row count differs')
    descriptions={}
    for tool in ('usage_stats','request_history','request_archive'):
        computed={arm:stats([row for row in measured if row['arm']==arm and row['tool']==tool]) for arm in ('A','B')}
        means={arm:computed[arm]['mean_ms'] for arm in ('A','B')}
        comparison={'baseline_mean_ms':means['A'],'candidate_mean_ms':means['B'],
                    'candidate_mean_change_percent':100*(means['B']/means['A']-1)}
        need(close_numbers(comparison,report['descriptive_comparison'][tool]), 'whole ABBA descriptive comparison differs')
        descriptions[tool]={'per_arm':computed,**comparison}
    result={'schema':'hepta-x230-small-archive-independent-analysis/v1','analysis_complete':True,'consistent':True,'errors':[],
       'inputs':{'bundle_bytes':len(raw_bundle),'bundle_sha256':sha(raw_bundle),
                 'report_member':PREFIX+'report.json','report_sha256':sha(raw_report),
                 'calls_member':PREFIX+'calls.jsonl','calls_bytes':len(raw_calls),'calls_sha256':sha(raw_calls),
                 'candidate_binary_sha256':report['inputs']['B']['sha256'],'baseline_binary_sha256':report['inputs']['A']['sha256'],
                 'harness_sha256':report['script']['sha256']},
       'counts':{'tool_dispatches':len(calls),'by_purpose':dict(collections.Counter(row['purpose'] for row in calls)),
                 'by_tool':dict(collections.Counter(row['tool'] for row in calls)),
                 'native_seed_ids_global_unique':len(all_seed_ids),'wire':dict(raw_wire_totals)},
       'all_dispatched_rows_checked':True,'all_original_wire_ranges_hash_and_rpc_bound':True,'automatic_retries':0,
       'public_metadata_scope':'native_mcp_session_only','history_retention':{'global':512,'per_owner':128},
       'public_scope_checks_by_tool':dict(public_scope_values),'rounds':rounds,'descriptive_latencies':descriptions,
       'scope':'One fixed A/B/B/A block; fresh native owners, 64 records per owner, hot C1 queries; two worker threads; no SSH.',
       'limitations':['Source reports and complete native-wire records were checked locally; no remote original files or original ELF were reread by this analyzer.',
                      'The collector excludes state directories. Original-file hash/stat maps are captured at four checkpoints; equality and their internal map/projection hashes were recomputed, but excluded original full file bytes were not independently reread.',
                      'Initialize RPCs and initialized notifications are counted separately from tools/call dispatch rows.',
                      'Different owner/request IDs and timestamps across rounds are intentional; fixtures are equivalent by count/schema and complete per-round projection, not byte-identical across arms.',
                      'Latency differences are descriptive and cannot be attributed causally to the output-recovery change.',
                      'No cold-start, 65,536-record, C4/concurrent, multi-host, reboot/power-loss, or general exactly-once qualification follows.']}
need(sha(BUNDLE.read_bytes())==EXPECTED_BUNDLE,'bundle changed during analysis')
result['inputs_unchanged']=True
with OUT.open('x') as stream:json.dump(result,stream,indent=2,sort_keys=True);stream.write('\n')
print(json.dumps({'path':str(OUT),'bytes':OUT.stat().st_size,'sha256':sha(OUT.read_bytes()),
                  'consistent':True,'counts':result['counts'],'descriptive_latencies':descriptions},sort_keys=True))
