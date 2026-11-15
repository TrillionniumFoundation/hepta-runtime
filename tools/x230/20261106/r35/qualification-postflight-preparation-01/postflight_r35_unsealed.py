import base64,hashlib,json,os,pathlib,stat
ROOT=pathlib.Path('/home/qian/hepta-runtime-optimization-20261106-r35')
SOURCE=ROOT/'source'
payload=None
assert type(payload) is dict, 'UNSEALED: completed original R35 qualification payload required'
assert payload.get('schema')=='hepta-r35-qualification-postflight-input/v1'
assert type(payload.get('qualification_job_id')) is str
assert type(payload.get('pins')) is dict and set(payload['pins'])=={
    'qualification-01/report.json','preparation.json','qualification-01/source-map.json',
    'qualification-01/isolated-tests/summary.json','qualification-01/isolated-tests.audit.json'}
for pin in payload['pins'].values():
    assert type(pin) is dict and set(pin)=={'bytes','sha256'}
    assert type(pin['bytes']) is int and 0<pin['bytes']<=8*1024*1024
    assert type(pin['sha256']) is str and len(pin['sha256'])==64 and set(pin['sha256'])<=set('0123456789abcdef')
assert type(payload.get('counts')) is dict and set(payload['counts'])=={
    'passed','failed','ignored','selected','retries'}
assert all(type(v) is int and v>=0 for v in payload['counts'].values())
assert payload['counts']['passed']>0 and payload['counts']['failed']==payload['counts']['retries']==0
assert payload['counts']['selected']==payload['counts']['passed']+payload['counts']['ignored']
COPY_PINS={'installation-originals-01/installation-history-01.json': {'bytes': 4327,
                                                            'sha256': 'b3d5a29e35052cb298a133a915a32a3336a7d4e2163b9782cddac0c51a94ecd2'},
 'installation-originals-01/installation-original-read-error-01.txt': {'bytes': 262,
                                                                       'sha256': '3972979a0df708c3dade11d8e37128338852d1ee16b0eb28f0356386bd4d87de'},
 'installation-originals-01/installation-original-start-01.json': {'bytes': 1116,
                                                                   'sha256': 'ce1dce72b66aaa62eaead5e7df7d9370ffceb4a66a4c7970f48cc1b235b63169'},
 'installation-originals-01/installation-original-status-error-01.txt': {'bytes': 262,
                                                                         'sha256': '3972979a0df708c3dade11d8e37128338852d1ee16b0eb28f0356386bd4d87de'},
 'installation-originals-01/installation-reconcile-native-01.json': {'bytes': 729,
                                                                     'sha256': '07097de6aa7d14e78f1e81d254bb8840e00437f22e78664661ed2f8f85377621'},
 'installation-originals-01/installation-reconcile-read-01.json': {'bytes': 1807,
                                                                   'sha256': 'addca379f4ce7b27d36134dfac38e379394c93dd9d742b3efcc967c5936f2f14'},
 'installation-originals-01/installation-reconcile-start-01.json': {'bytes': 994,
                                                                    'sha256': 'dbffd00d11b125d4de2645d3cfbe29ede74a4dfd36181be38e5451725dde4064'},
 'installation-originals-01/installation-reconcile.py': {'bytes': 1168,
                                                         'sha256': '6bf7bd2ce69de20ec1d8456c7bbd3890a8b23a849d1faadb7d7e5d57ff8fa32a'},
 'installation-originals-01/installation-staged-native-02.json': {'bytes': 729,
                                                                  'sha256': 'b211e3c8a2c2789f7b61d8d505cbf79b72c2a1e48650f3653adcb73cf052989a'},
 'installation-originals-01/installation-staged-read-02.json': {'bytes': 1985,
                                                                'sha256': '51a6acbc64b487838ed6a8bb1a18f32e36c26cf9f59909c4d0dfae9cdd29ad4e'},
 'installation-originals-01/installation-staged-start-02.json': {'bytes': 987,
                                                                 'sha256': '373871da6faecb01e52a7b6208d1df5ed8d486e52a8080147d9dbf03eb591d18'},
 'installation-originals-01/installation-staged.py': {'bytes': 5074,
                                                      'sha256': '0a1d07391d9401f2b98dbbbeb311aa91a4a771c4eb789bfb7edc59e0b061d41e'},
 'installation-originals-01/package-upload-receipts-01.json': {'bytes': 1282,
                                                               'sha256': 'a4e8e7f12c35b7f14057098123bc723ea5fbee929606b69e89ff4ecb81af2839'},
 'installation-originals-01/qualification-start-01.json': {'bytes': 1306,
                                                           'sha256': 'da98a914d721d4d5719a5051cdf2b8427d1330b663ead5d5835af06f73e69153'}}
Q_NATIVE_NAMES={'qualification-terminal-status-01.json','qualification-native-read-01.json'}
assert type(payload.get('originals')) is list and len(payload['originals'])==16
assert {f['name'] for f in payload['originals']}==Q_NATIVE_NAMES|set(COPY_PINS)
original_bytes={}
for f in payload['originals']:
    assert set(f)=={'name','bytes','sha256','data_base64'} and type(f['bytes']) is int and 0<f['bytes']<=8*1024*1024
    assert type(f['sha256']) is str and len(f['sha256'])==64 and set(f['sha256'])<=set('0123456789abcdef')
    assert type(f['data_base64']) is str
    raw=base64.b64decode(f['data_base64'],validate=True)
    assert len(raw)==f['bytes'] and hashlib.sha256(raw).hexdigest()==f['sha256']
    if f['name'] in COPY_PINS:
        assert {k:f[k] for k in ('bytes','sha256')}==COPY_PINS[f['name']]
    original_bytes[f['name']]=raw
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
assert q['schema']=='hepta-x230-composed-qualification/v1' and q['source']==str(SOURCE)
assert p['schema']=='hepta-x230-r35-preparation/v1' and p['qualification_started'] is True
assert q['jobs']==2 and q['automatic_test_retries']==p['automatic_retries']==0
assert p['source_after_qualification']==m and not q.get('error') and not p.get('error')
assert p['qualification_report_sha256']==bound['qualification-01/report.json']['sha256']
assert q['source_tested']==q['source_after']==m and len(m)==220
assert q['harness_before']==q['harness_after'] and len(q['harness_after'])==19
assert [r['name'] for r in q['stages']]==['format','fmt-check','harness-tests','clippy','test-build','isolated-tests','audit-isolated-tests','release']
assert all(r['returncode']==0 for r in q['stages'])
counts={k:s[k] for k in ('passed','failed','ignored','selected','retries')}
assert counts==payload['counts']
assert s['success'] and s['enumeration_errors']==[] and s['source_manifest_sha256']==bound['qualification-01/source-map.json']['sha256']
assert a['success'] and a['errors']==[] and a['executed']==counts['passed']
assert all(a[k]==counts[k] for k in ('passed','failed','ignored','selected'))
assert a['input_sha256']['summary.json']==bound['qualification-01/isolated-tests/summary.json']['sha256']
candidate=json.loads(read_bound(ROOT/'candidate/input.json',{'bytes':53380,'sha256':'7089775ed203f2a9d93dbb3528e63826c0b295c35c1aad782e51c99c9e5e059d'})[1])
assert candidate['schema']=='hepta-x230-r35-candidate/v1' and candidate['new_test_functions']==[]
assert candidate['baseline_commit']==candidate['git_parent']=='baab4def80be7af015b2e7a594cb302f66c4130e'
baseline=candidate['baseline_compile_inputs']
changed={'src/mcp/runtime/jobs.rs','src/mcp/runtime/ssh_observation_pool.rs','src/mcp/runtime/ssh_observation_pool_tests.rs'}
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
native={name:json.loads(original_bytes[name]) for name in Q_NATIVE_NAMES}
terminal=native['qualification-terminal-status-01.json'];reading=native['qualification-native-read-01.json']
assert terminal['job_id']==reading['job_id']==payload['qualification_job_id']
first_launch=json.loads(original_bytes['installation-originals-01/qualification-start-01.json'])
assert first_launch['job']['id']==terminal['job_id'] and first_launch['job']['launch_state']=='launched'
assert first_launch['launch']['ok'] is True and first_launch['reused'] is False
assert terminal['audit_recorded'] is True and reading['audit_recorded'] is True
assert terminal['terminal_publication_protocol']==1
assert terminal['state']=='succeeded' and terminal['exit_code']==0
assert terminal['output_complete'] and terminal['output_durable'] and terminal['terminal_publication_confirmed']
assert not terminal['automatic_retry'] and not terminal['timed_out'] and not terminal['cancelled']
for stream in ('stdout','stderr'):
    row=reading[stream];raw=bytes.fromhex(row['bytes_hex'])
    assert row['offset']==0 and row['eof'] and row['size']==row['next_offset']==len(raw)
    assert row['text']==raw.decode() and terminal['log_bytes'][stream]['seen']==terminal['log_bytes'][stream]['stored']==len(raw)
    assert terminal['log_synced'][stream] and terminal['log_errors'][stream] is None and not terminal['log_truncated'][stream]
assert p['cache_transferred_by_rename'] and (ROOT/'target-build').is_dir()
assert not os.path.lexists(pathlib.Path('/home/qian/hepta-runtime-optimization-20261106-r34/target-build'))
bound['qualification-package-install-02.json'],install_raw=read_bound(
    ROOT/'qualification-package-install-02.json',
    {'bytes':7081,'sha256':'0ebcc8a7ad1a4ec397de179e68ff50bd7da19cf9b6ff5100d816c2245eab1e34'})
install=json.loads(install_raw)
assert install['schema']=='hepta-r35-qualification-package-install/v1' and install['root']==str(ROOT)
assert install['file_count']==39 and install['qualification_started'] is False
assert install['source_materialized'] is False and install['cache_moved'] is False and install['cache_deleted'] is False
history_dir=ROOT/'installation-originals-01'
assert not os.path.lexists(history_dir)
assert all(not os.path.lexists(ROOT/f['name']) for f in payload['originals'])
assert not os.path.lexists(ROOT/'qualification-postflight-01.json')
os.mkdir(history_dir,0o700)
assert history_dir.resolve(strict=True)==history_dir and stat.S_ISDIR(history_dir.lstat().st_mode)
for f in payload['originals']:
    raw=original_bytes[f['name']]
    with (ROOT/f['name']).open('xb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
    identity,_=read_bound(ROOT/f['name'],f);bound[f['name']]=identity
paths_after=[SOURCE/n for n in ('Cargo.toml','Cargo.lock','rustfmt.toml')]
for directory in ('src','examples'): paths_after.extend(x for x in (SOURCE/directory).rglob('*') if x.is_file())
assert {x.relative_to(SOURCE).as_posix() for x in paths_after}==set(m)
for n,digest in m.items(): assert read_bound(SOURCE/n)[0]['sha256']==digest
for directory in (history_dir,ROOT):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
result={'schema':'hepta-r35-qualified-source-postflight/v1','passed':True,'qualification_job_id':terminal['job_id'],'qualified':True,
'counts':counts,'compiler_input_count':220,'changed_paths_from_r24':sorted(changed),'current_source_matches_qualified_map':True,
'original_harness_count':19,'harness_unchanged':True,'retained_programs':programs,'originals':bound,
'cache_transferred_by_rename':True,'cache_owner':'/home/qian/hepta-runtime-optimization-20261106-r34',
'installation_originals_copied':14,'qualification_native_originals_copied':2,'existing_install_receipt_rehashed_not_rewritten':True,
'installers_or_reconciliation_reexecuted':False,'tests_benchmarks_or_original_auditors_reexecuted':False,'candidate_adopted':False,
'current_machine_idle_claimed':False,'production_services_modified':False}
raw=(json.dumps(result,indent=2,sort_keys=True)+'\n').encode()
path=ROOT/'qualification-postflight-01.json'
with path.open('xb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
try:os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'passed':True,'qualification_job_id':terminal['job_id'],'counts':counts,'retained_programs':programs,
'postflight':{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'installed_originals':{f['name']:bound[f['name']] for f in payload['originals']}},sort_keys=True))
