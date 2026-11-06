import base64,hashlib,json,os,pathlib,stat
ROOT=pathlib.Path('/home/qian/hepta-runtime-optimization-20261106-r34')
SOURCE=ROOT/'source'
payload=None
def read_bound(path,expected=None,maximum=128*1024*1024):
    assert path.is_absolute() and path.resolve(strict=True)==path
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        first=os.fstat(fd)
        assert stat.S_ISREG(first.st_mode) and first.st_nlink==1 and first.st_size<=maximum
        with os.fdopen(os.dup(fd),'rb') as stream: raw=stream.read(maximum+1)
        fields=('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        stamp=lambda s:tuple(getattr(s,k) for k in fields)
        assert len(raw)==first.st_size and stamp(first)==stamp(os.fstat(fd))==stamp(path.lstat())
    finally: os.close(fd)
    identity={'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    if expected:
        assert identity['bytes']==expected['bytes'] and identity['sha256']==expected['sha256'],str(path)
    return identity,raw
assert ROOT.resolve(strict=True)==ROOT and os.getuid()==1000
bound={};docs={}
for name,pin in payload['pins'].items():
    bound[name],raw=read_bound(ROOT/name,pin)
    docs[name]=json.loads(raw)
q=docs['qualification-01/report.json'];p=docs['preparation.json'];m=docs['qualification-01/source-map.json']
s=docs['qualification-01/isolated-tests/summary.json'];a=docs['qualification-01/isolated-tests.audit.json']
assert q['qualified'] and q['finished_utc'] and p['passed'] and p['qualification_returncode']==0
assert p['qualification_report_sha256']==bound['qualification-01/report.json']['sha256']
assert q['source_tested']==q['source_after']==m and len(m)==220
assert q['harness_before']==q['harness_after'] and len(q['harness_after'])==19
assert [r['name'] for r in q['stages']]==['format','fmt-check','harness-tests','clippy','test-build','isolated-tests','audit-isolated-tests','release']
assert all(r['returncode']==0 for r in q['stages'])
counts={k:s[k] for k in ('passed','failed','ignored','selected','retries')}
assert counts=={'passed':1653,'failed':0,'ignored':34,'selected':1687,'retries':0}
assert s['success'] and s['enumeration_errors']==[] and s['source_manifest_sha256']==bound['qualification-01/source-map.json']['sha256']
assert a['success'] and a['errors']==[] and a['executed']==1653
assert all(a[k]==counts[k] for k in ('passed','failed','ignored','selected'))
assert a['input_sha256']['summary.json']==bound['qualification-01/isolated-tests/summary.json']['sha256']
candidate=json.loads(read_bound(ROOT/'candidate/input.json',{'bytes':53074,'sha256':'7336fe6abeca46e5f8ebc05e8a75e292a507aad1575565331a850e7cbb8f9c70'})[1])
baseline=candidate['baseline_compile_inputs']
changed={'src/mcp/runtime/jobs.rs','src/mcp/runtime/ssh.rs','src/mcp/runtime/ssh_direct.rs','src/mcp/runtime/ssh_direct_tests.rs'}
assert set(baseline)==set(m) and {n for n in baseline if baseline[n]!=m[n]}==changed
assert q['source_input']==p['source_before_qualification']==candidate['candidate_compile_inputs']
paths=[SOURCE/n for n in ('Cargo.toml','Cargo.lock','rustfmt.toml')]
for directory in ('src','examples'): paths.extend(x for x in (SOURCE/directory).rglob('*') if x.is_file())
assert {x.relative_to(SOURCE).as_posix() for x in paths}==set(m)
for n,digest in m.items(): assert read_bound(SOURCE/n)[0]['sha256']==digest
for n,digest in q['harness_after'].items(): assert read_bound(SOURCE/'tools/x230/20261028'/n)[0]['sha256']==digest
programs={}
assert set(q['binaries'])=={'hepta-runtime','hepta-runtime-jobctl','native_process_driver'}
for name,item in q['binaries'].items():
    path=pathlib.Path(item['path'])
    assert path.is_relative_to(ROOT/'qualification-01')
    identity,raw=read_bound(path)
    assert identity['sha256']==item['sha256'] and raw.startswith(b'\x7fELF')
    programs[name]=identity
native={f['name']:json.loads(base64.b64decode(f['data_base64'],validate=True)) for f in payload['originals']}
terminal=native['qualification-terminal-status-01.json'];reading=native['qualification-native-read-01.json']
assert terminal['job_id']==reading['job_id']=='1a1aef7882f-fc05-6499'
assert terminal['state']=='succeeded' and terminal['exit_code']==0
assert terminal['output_complete'] and terminal['output_durable'] and terminal['terminal_publication_confirmed']
assert not terminal['automatic_retry'] and not terminal['timed_out'] and not terminal['cancelled']
for stream in ('stdout','stderr'):
    row=reading[stream];raw=bytes.fromhex(row['bytes_hex'])
    assert row['offset']==0 and row['eof'] and row['size']==row['next_offset']==len(raw)
    assert row['text']==raw.decode() and terminal['log_bytes'][stream]['seen']==terminal['log_bytes'][stream]['stored']==len(raw)
    assert terminal['log_synced'][stream] and terminal['log_errors'][stream] is None and not terminal['log_truncated'][stream]
prune=native['cache-prune-native-02.json']
assert prune['job_id']=='1a1aef5957d-fc05-6486' and prune['state']=='succeeded' and prune['exit_code']==0
assert p['cache_transferred_by_rename'] and (ROOT/'target-build').is_dir()
assert not os.path.lexists(pathlib.Path('/home/qian/hepta-runtime-optimization-20261106-r33/target-build'))
assert all(not os.path.lexists(ROOT/f['name']) for f in payload['originals'])
assert not os.path.lexists(ROOT/'qualification-postflight-01.json')
for f in payload['originals']:
    raw=base64.b64decode(f['data_base64'],validate=True)
    assert len(raw)==f['bytes'] and hashlib.sha256(raw).hexdigest()==f['sha256']
    with (ROOT/f['name']).open('xb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
    identity,_=read_bound(ROOT/f['name'],f);bound[f['name']]=identity
for n,digest in m.items(): assert read_bound(SOURCE/n)[0]['sha256']==digest
result={'schema':'hepta-r34-qualified-source-postflight/v1','passed':True,'qualification_job_id':terminal['job_id'],'qualified':True,
'counts':counts,'compiler_input_count':220,'changed_paths_from_r24':sorted(changed),'current_source_matches_qualified_map':True,
'original_harness_count':19,'harness_unchanged':True,'retained_programs':programs,'originals':bound,
'cache_transferred_by_rename':True,'tests_benchmarks_or_original_auditors_reexecuted':False,'candidate_adopted':False,
'current_machine_idle_claimed':False,'production_services_modified':False}
raw=(json.dumps(result,indent=2,sort_keys=True)+'\n').encode()
path=ROOT/'qualification-postflight-01.json'
with path.open('xb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
print(json.dumps({'passed':True,'qualification_job_id':terminal['job_id'],'counts':counts,'retained_programs':programs,
'postflight':{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'installed_originals':{f['name']:bound[f['name']] for f in payload['originals']}},sort_keys=True))
