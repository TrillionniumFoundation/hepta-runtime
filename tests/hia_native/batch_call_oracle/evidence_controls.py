"""Physical and re-signed refusal tests for complete Batch retained evidence."""
from pathlib import Path
import argparse,copy,gzip,hashlib,importlib.util,json,os,re,shutil,struct,sys,time,traceback
parser=argparse.ArgumentParser()
for option in ('reader-source','request','expected','output'):parser.add_argument('--'+option,type=Path,required=True)
selected=parser.parse_args()
SOURCE=selected.reader_source.resolve(strict=True);OUT=selected.output.absolute()
READER_NAMES=('async_evidence.py','capture_format.py','final_evidence.py','native_predecessor.py',
              'private_evidence.py','qualification.py','retained_comparison.py','strict_reference.py','trace_evidence.py')
OUT.mkdir();(OUT/'mutations').mkdir();began=time.monotonic_ns()
(OUT/'remote-process.json').write_text(json.dumps({'pid':os.getpid(),'argv':sys.argv,'cwd':os.getcwd(),'cgroup':Path('/proc/self/cgroup').read_text(),'started_monotonic_ns':began}))
sys.path.insert(0,str(SOURCE))
import qualification as q,strict_reference as original,retained_comparison as compare,trace_evidence as traces,native_predecessor as native
from capture_format import Files,actual_process,blob,canonical,fields,need,parse_records,pin,same,sha,strict_json,uint
args=strict_json(selected.request.read_bytes())
before={name:pin(SOURCE/name)for name in READER_NAMES}
(OUT/'SOURCE.json').write_bytes(canonical(before));(OUT/'source').mkdir()
for name in READER_NAMES:shutil.copyfile(SOURCE/name,OUT/'source'/name)
records=[];physical={};group_counts={}
def keep(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);physical[str(path)]={'bytes':len(raw),'sha256':sha(raw)};return path
def pj(label,value):
 path=keep(OUT/'mutations'/label/'value.json',canonical(value));return strict_json(path.read_bytes())
def pr(label,raw):
 path=keep(OUT/'mutations'/label/'raw.bin',raw);return path.read_bytes()
def pg(label,raw):
 path=keep(OUT/'mutations'/label/'raw.bin.gz',gzip.compress(raw,compresslevel=1,mtime=0));return gzip.decompress(path.read_bytes())
def reject(group,label,call,expected):
 start=time.monotonic_ns()
 try:call()
 except (ValueError,FileNotFoundError,UnicodeError)as error:
  message=str(error);assert any(s in message for s in expected),(label,type(error).__name__,message,expected)
  row={'group':group,'name':label,'rejected':True,'type':type(error).__name__,'error':message,
       'elapsed_seconds':(time.monotonic_ns()-start)/1e9}
 else:raise AssertionError('corrupt evidence accepted: '+label)
 records.append(row);group_counts[group]=group_counts.get(group,0)+1
 (OUT/'CONTROLS.json').write_bytes(canonical(records))
def snapshot_sources(source,target):
 target.mkdir(parents=True)
 for path in source.rglob('*'):
  if path.relative_to(source).parts[0]=='files':continue
  if path.is_file():
   dest=target/path.relative_to(source);dest.parent.mkdir(parents=True,exist_ok=True);os.link(path,dest)
def replace(path,raw):
 tmp=path.with_name(path.name+'.replacement');keep(tmp,raw);os.replace(tmp,path)
 physical[str(path)]=physical.pop(str(tmp))
def reencoded(label,record,raw,mutate=None,changed_blobs=None):
 meta=copy.deepcopy(record['metadata'])
 if mutate:mutate(meta)
 values=[blob(raw,record,i)for i in range(len(record['blobs']))]
 for i,value in (changed_blobs or {}).items():values[i]=value
 data=canonical(meta)
 encoded=b'HBCCO002'+struct.pack('<Q',1)+struct.pack('<2Q',len(data),len(values))+data+b''.join(struct.pack('<Q',len(v))+v for v in values)
 actual=pr(label,encoded);row=parse_records(actual,b'HBCCO002')[0]
 return row['metadata'],lambda i:blob(actual,row,i),actual,row
def control_map(*pairs):return Files([*pairs,*args['origins']])
try:
 baseline=q.evidence(**args);expected=strict_json(selected.expected.read_bytes())
 same(baseline,expected,'qualified complete baseline changed before refusal controls')
 (OUT/'BASELINE.json').write_bytes(canonical(baseline))
 # 1. Strict JSON and scalar typing.
 group='typed-json'
 for label,raw,message in [
  ('duplicate-member',b'{"pid":1,"pid":2}',('duplicate',)),
  ('nan-token',b'{"n":NaN}',('nonfinite',)),
  ('infinity-token',b'{"n":Infinity}',('nonfinite',)),
  ('overflow-float',b'{"n":1e9999}',('nonfinite',)),
  ('surrogate-string',b'{"s":"\\ud800"}',('surrogates',))]:
  reject(group,label,lambda l=label,r=raw:strict_json(pr(l,r)),message)
 reject(group,'boolean-integer',lambda:uint(pj('boolean-integer',True),'typed actual PID'),('typed actual PID',))
 # 2. Actual Popen receipts: no synthetic clock/default field acceptance.
 group='actual-process'
 process=copy.deepcopy(strict_json((Path(args['reference']['outer_receipt'])).read_bytes()))
 cmd=process['command'];cwd=process['cwd']
 specs=[
 ('missing-start-error',lambda r:r.pop('start_error'),('incomplete actual process',)),
 ('missing-timeout-result',lambda r:r.pop('timed_out'),('incomplete actual process',)),
 ('boolean-pid',lambda r:r.__setitem__('pid',True),('actual process PID',)),
 ('changed-deadline',lambda r:r.__setitem__('timeout_seconds',181),('actual process deadline',)),
 ('changed-cwd',lambda r:r.__setitem__('cwd','/different-owned-root'),('actual process cwd',)),
 ('changed-command',lambda r:r['command'].append('--not-executed'),('actual process argv',)),
 ('zero-interval',lambda r:r.__setitem__('finished_monotonic_ns',r['started_monotonic_ns']),('nonpositive',)),
 ('resigned-over-deadline',lambda r:r.update(finished_monotonic_ns=r['started_monotonic_ns']+181_000_000_000,elapsed_seconds=181.0),('elapsed budget',))]
 for label,change,message in specs:
  value=copy.deepcopy(process);change(value)
  reject(group,label,lambda l=label,v=value:actual_process(pj(l,v),cmd,cwd),message)
 # 3. Explicit mapped storage/source closure.
 group='origin-source'
 linkdir=OUT/'mutations/symlink-root';linkdir.mkdir()
 (linkdir/'source-link').symlink_to(SOURCE,target_is_directory=True)
 reject(group,'symlink-root',lambda:Files([('/origin',str(linkdir/'source-link'))]).raw('/origin/capture_format.py'),('symlink',))
 reject(group,'parent-traversal',lambda:Files([('/origin',str(SOURCE))]).raw('/origin/../capture_format.py'),('traverses parent',))
 reject(group,'unmapped-live-fallback',lambda:Files([('/different',str(SOURCE))]).raw(str(SOURCE/'capture_format.py')),('unmapped artifact',))
 reject(group,'missing-retained-stream',lambda:Files([('/origin',str(OUT/'mutations'))]).raw('/origin/absent-full-stream'),('No such file',))
 ref=args['reference'];orig_source=Path(ref['original_source']);orig_output=Path(ref['original_output'])
 original_result=strict_json((orig_output/'RESULT.json').read_bytes())
 changed=OUT/'mutations/changed-whole-module/source';snapshot_sources(orig_source,changed)
 target=changed/'oracle/original/text_editing.rs';replace(target,target.read_bytes()+b'\n')
 reject(group,'changed-whole-module',
        lambda:original.source_evidence(control_map((str(orig_source),str(changed))),orig_source,orig_output,original_result),
        ('complete pinned original source',))
 omitted=copy.deepcopy(original_result);omitted['source_files'].pop('oracle/original/request_ctx.rs')
 reject(group,'omitted-whole-module',
        lambda:original.source_evidence(control_map(),orig_source,orig_output,pj('omitted-whole-module',omitted)),
        ('capture original source identities',))
 # Full retained original/native records used by targeted semantic refusals.
 native_run=Path(ref['native_run']);capture=native_run/'output-small'
 original_raw=(orig_output/'processes/original-small/stdout').read_bytes();original_rows=parse_records(original_raw,b'HBCCO002')
 input_raw=(orig_output/'small/input.bin').read_bytes();input_rows=parse_records(input_raw,b'HBCCI002')
 native_rows=native.json_lines((capture/'native-cases.jsonl').read_bytes())
 trace_raw=(orig_output/'small/strace.log').read_bytes();trace=traces.parse_trace(trace_raw)
 record=original_rows[0];nrow=native_rows[0];meta=input_rows[0]['metadata']
 def cmp_scope(label,change):
  new,get,raw,r=reencoded(label,record,original_raw,change)
  return compare.compare_partition(control_map(),capture,[nrow],raw,[r],[input_rows[0]],trace)
 group='complete-record'
 reject(group,'inflated-original-sdk',lambda:cmp_scope('inflated-original-sdk',lambda r:r.__setitem__('original_sdk_executed',True)),
        ('original inner result scope changed',))
 reject(group,'different-original-case',lambda:cmp_scope('different-original-case',lambda r:r.__setitem__('case_id',999)),
        ('original case input case_id',))
 def canonical_mismatch():
  index=record['metadata']['canonical_parameters_blob'];v=blob(original_raw,record,index)+b' '
  row,get,raw,r=reencoded('resigned-typed-body',record,original_raw,changed_blobs={index:v})
  typed=compare.Comparison(control_map(),capture).native_blob(nrow['typed']);plen=native.words(typed,16,1)[0]
  compare.Comparison(control_map(),capture).same(typed[64+plen:],get(index),'complete typed original projection')
 reject(group,'resigned-typed-body',canonical_mismatch,('complete typed original projection',))
 def final_body_mismatch():
  index=record['metadata']['result']['body_blob'];v=blob(original_raw,record,index)+b'changed'
  row,get,raw,r=reencoded('resigned-final-body',record,original_raw,changed_blobs={index:v})
  c=compare.Comparison(control_map(),capture);c.same(c.native_blob(nrow['result']['body']),get(index),'complete original String')
 reject(group,'resigned-final-body',final_body_mismatch,('complete original String',))
 def history_mismatch():
  row,get,_,_=reencoded('history-byte-accounting',record,original_raw,
      lambda r:r['after']['history'].__setitem__('total_bytes',r['after']['history']['total_bytes']+1))
  compare.Comparison.history_original(get,row['after'])
 reject(group,'history-byte-accounting',history_mismatch,('history byte count',))
 def cache_mismatch():
  selected=next(i for i,r in enumerate(original_rows)if any(c['entries']for c in r['metadata']['after']['caches']))
  rr=original_rows[selected];nr=native_rows[selected]
  cache=next(c for c in rr['metadata']['after']['caches']if c['entries']);old=cache['entries'][0]['value_blob']
  row,get,_,_=reencoded('resigned-cache-value',rr,original_raw,changed_blobs={old:blob(original_raw,rr,old)+b'cache'})
  c=compare.Comparison(control_map(),capture)
  c.same(c.cache_native(nr['after']),c.cache_original(get,row['after']),'complete all-session cache')
 reject(group,'resigned-cache-value',cache_mismatch,('complete all-session cache',))
 def inode_mismatch():
  for nr,rr in zip(native_rows,original_rows):
   nodes=rr['metadata']['before']['tree']['nodes'];seen={}
   for index,node in enumerate(nodes):
    ident=(node['metadata']['dev'],node['metadata']['ino'])
    if ident in seen:
     def change(row):row['before']['tree']['nodes'][index]['metadata']['ino']+=1_000_000_000
     new,get,_,_=reencoded('hardlink-inode-relationship',rr,original_raw,change)
     c=compare.Comparison(control_map(),capture);return c.states(nr['before'],new['before'],get,'before',{}, {})
    seen[ident]=index
  raise AssertionError('retained hardlink baseline absent')
 reject(group,'hardlink-inode-relationship',inode_mismatch,('complete_tree_and_inode_relationships',))
 def wrong_context():
  def change(row):
   event=next(e for e in row['events']if e['kind']=='scope_first_poll')
   event['request_context']['present']=1
  row,get,_,_=reencoded('context-boolean-type',record,original_raw,change)
  traces.lifecycle(row,meta,get,trace)
 reject(group,'context-boolean-type',wrong_context,('typed context state',))
 # 5. Actual syscall and cancellation event evidence, preserving all other bytes.
 group='trace-lifecycle'
 reject(group,'trace-truncated-final-line',lambda:traces.parse_trace(pg('trace-truncated-final-line',trace_raw[:-1])),('complete original trace',))
 reject(group,'trace-unknown-line',lambda:traces.parse_trace(pg('trace-unknown-line',b'invalid trace\n'+trace_raw)),('unrecognized full trace',))
 lines=trace_raw.splitlines(keepends=True);marker_index=next(i for i,l in enumerate(lines)if b'getpgid(1000000001)'in l)
 missing=b''.join(lines[:marker_index]+lines[marker_index+1:])
 reject(group,'trace-missing-marker',lambda:traces.parse_trace(pg('trace-missing-marker',missing)),('markers are complete',))
 duplicate=b''.join(lines[:marker_index]+[lines[marker_index]]+lines[marker_index:])
 reject(group,'trace-duplicate-marker',lambda:traces.parse_trace(pg('trace-duplicate-marker',duplicate)),('duplicate or non-observer',))
 tail=trace_raw+b'999999 1.000000 openat(AT_FDCWD, <unfinished ...>\n'
 reject(group,'trace-unfinished-tail',lambda:traces.parse_trace(pg('trace-unfinished-tail',tail)),('unretired original trace',))
 close_index=next(i for i,l in enumerate(lines)if b' close('in l and b' = 0 <'in l)
 bad_lines=list(lines);bad_lines[close_index]=re.sub(rb' close\([^)]*\) = 0 ',b' close(9999999) = 0 ',bad_lines[close_index])
 bad_close=b''.join(bad_lines);need(bad_close!=trace_raw,'physical close mutation missing')
 reject(group,'trace-unpaired-close',lambda:traces.descriptor_lifetimes(traces.parse_trace(pg('trace-unpaired-close',bad_close))),('unpaired original close',))
 last_close=max(i for i,l in enumerate(lines)if b' close('in l and b' = 0 <'in l)
 unclosed=b''.join(lines[:last_close]+lines[last_close+1:])
 reject(group,'trace-unclosed-descriptor',lambda:traces.descriptor_lifetimes(traces.parse_trace(pg('trace-unclosed-descriptor',unclosed))),('still live',))
 async_raw=(orig_output/'processes/original-async/stdout').read_bytes();async_rows=parse_records(async_raw,b'HBCCO002')
 async_input=parse_records((orig_output/'async/input.bin').read_bytes(),b'HBCCI002')
 async_trace=traces.parse_trace((orig_output/'async/strace.log').read_bytes())
 def cancel_order():
  def change(row):
   events=row['events'];a=next(i for i,e in enumerate(events)if e['kind']=='cancel_before_abort')
   b=next(i for i,e in enumerate(events)if e['kind']=='cancel_after_abort');events[a],events[b]=events[b],events[a]
  row,get,_,_=reencoded('cancel-drop-order',async_rows[0],async_raw,change)
  traces.lifecycle(row,async_input[0]['metadata'],get,async_trace)
 reject(group,'cancel-drop-order',cancel_order,('cancel/drop/late/followup event order',))
 # 6. Complete, re-signed native rejection buffers and transport.
 group='native-wire-buffers'
 private=q.load_private(control_map(),args['private_reader'])
 state=native_run/'state-controls';state_raw=gzip.decompress((state/'complete.bin.gz').read_bytes())
 state_index=native.json_lines((state/'index.jsonl').read_bytes())
 def state_variant(label,change):
  folder=OUT/'mutations'/label/'state-controls';folder.mkdir(parents=True)
  raw=bytearray(state_raw);index=copy.deepcopy(state_index);change(raw,index)
  for r in index:
   body=bytes(raw[r['offset']:r['offset']+r['bytes']]);r['sha256']=sha(body)
   r['return_code']=struct.unpack_from('<Q',body,8)[0]
  keep(folder/'complete.bin.gz',gzip.compress(bytes(raw),compresslevel=1,mtime=0))
  keep(folder/'index.jsonl',b''.join(canonical(r)for r in index))
  keep(folder/'RESULT.json',(state/'RESULT.json').read_bytes())
  return private.state_evidence(control_map((str(state),str(folder))),native_run,ref['native_source'])
 def tail(raw,index):raw.extend(b'\x00')
 reject(group,'unindexed-private-tail',lambda:state_variant('unindexed-private-tail',tail),('unindexed private stream tail',))
 chosen=next(i for i,r in enumerate(state_index)if r['label']=='corrupt-saved-delivery')
 def altered(which):
  def change(raw,index):
   r=index[chosen];off=r['offset'];qwords=struct.unpack_from('<8Q',raw,off);ilen,ocap,wcap=qwords[2:5]
   pos=off+64+ilen+ocap+wcap if which=='output'else off+64+ilen+2*ocap+wcap+464
   raw[pos]^=1
  return change
 reject(group,'resigned-refused-output',lambda:state_variant('resigned-refused-output',altered('output')),('refused private call changed borrowed buffers',))
 reject(group,'resigned-refused-workspace',lambda:state_variant('resigned-refused-workspace',altered('work')),('refused private call changed borrowed buffers',))
 def changed_code(raw,index):struct.pack_into('<Q',raw,index[chosen]['offset']+8,0xffffffff)
 reject(group,'resigned-refusal-code',lambda:state_variant('resigned-refusal-code',changed_code),('private control complete input',))
 native_stdin=gzip.decompress((capture/'sessions/sync/stdin.bin.gz').read_bytes())
 native_stdout=gzip.decompress((capture/'sessions/sync/stdout.bin.gz').read_bytes())
 pos=native_stdin.index(b'HBCACK02');corrupt=bytearray(native_stdin);corrupt[pos+16]^=1
 reject(group,'child-ack-sequence',lambda:native.full_transport(pg('child-ack-sequence',bytes(corrupt)),native_stdout),('child ACK order',))
 def forged_held_after_cancel():
  run=Path(args['async_run']);process=Path(args['async_process'])
  target=OUT/'mutations/resigned-held-after-cancel';target.mkdir()
  copied=target/'run';copied_process=target/'process'
  snapshot_sources(run,copied);snapshot_sources(process,copied_process)
  controls=strict_json((copied/'CONTROLS.json').read_bytes());c=controls[0]
  item=c['lock_after_cancel'];body=gzip.decompress((copied/item['response']['artifact']).read_bytes())
  altered=bytearray(body);struct.pack_into('<Q',altered,48,1);altered=bytes(altered)
  descriptor={'artifact':'blobs/'+sha(altered)+'.bin.gz','bytes':len(altered),'sha256':sha(altered)}
  path=copied/descriptor['artifact']
  if path.exists():replace(path,gzip.compress(altered,compresslevel=1,mtime=0))
  else:keep(path,gzip.compress(altered,compresslevel=1,mtime=0))
  item['response']=descriptor;item['decoded'][5]=1
  folder=copied/'sessions/213';stdout=bytearray(gzip.decompress((folder/'stdout.bin.gz').read_bytes()))
  event=item['wire']['response'];at=event['offset']+16
  stdout[at+32:at+96]=altered;event['payload_sha256']=sha(bytes(stdout[at:at+96]))
  msgs=native.json_lines((folder/'messages.jsonl').read_bytes())
  index=next(i for i,e in enumerate(msgs)if e['offset']==event['offset']);msgs[index]=event
  replace(folder/'messages.jsonl',b''.join(canonical(r)for r in msgs))
  replace(folder/'stdout.bin.gz',gzip.compress(bytes(stdout),compresslevel=1,mtime=0))
  receipt=strict_json((folder/'process.json').read_bytes())
  receipt['streams']['stdout']={'bytes':len(stdout),'sha256':sha(bytes(stdout))};replace(folder/'process.json',canonical(receipt))
  replace(copied/'CONTROLS.json',canonical(controls))
  summary=strict_json((copied/'RESULT.json').read_bytes());summary['control_capture']=pin(copied/'CONTROLS.json')
  replace(copied/'RESULT.json',canonical(summary));replace(copied_process/'stdout',canonical(summary))
  outer=strict_json((copied_process/'PROCESS.json').read_bytes());outer['stdout']=pin(copied_process/'stdout')
  replace(copied_process/'PROCESS.json',canonical(outer))
  files=control_map((str(run),str(copied)),(str(process),str(copied_process)))
  return q.async_evidence.control_evidence(files,run,process,args['async_test'],ref['native_run'],ref['native_source'],ref['manifest'])
 reject(group,'resigned-held-after-cancel',forged_held_after_cancel,('actual held-borrow count lock_after_cancel',))
 same(group_counts,{'typed-json':6,'actual-process':8,'origin-source':6,'complete-record':8,'trace-lifecycle':8,'native-wire-buffers':6},
      'fixed meaningful refusal groups')
 same(len(records),42,'fixed refusal controls')
 retired_symlinks=[]
 for path in (OUT/'mutations').rglob('*'):
  if path.is_symlink():
   info=path.lstat();target=os.readlink(path)
   row={'path':str(path),'target':target,'dev':info.st_dev,'ino':info.st_ino,'mode':info.st_mode}
   path.unlink();assert not path.exists() and not path.is_symlink();row['absent_after']=True;retired_symlinks.append(row)
 keep(OUT/'retired-symlinks.json',canonical(retired_symlinks))
 physical={str(path):pin(path)for path in (OUT/'mutations').rglob('*')if path.is_file()}
 physical[str(OUT/'retired-symlinks.json')]=pin(OUT/'retired-symlinks.json')
 assert before=={name:pin(SOURCE/name)for name in READER_NAMES}
 summary={'schema':'hepta.runtime.batch-call-evidence-controls.v1','status':'PASS','test_groups':6,'controls':42,
          'group_counts':group_counts,'baseline':pin(OUT/'BASELINE.json'),'new_native_calls':0,'new_rust_processes':0,
          'physical_files':physical,'results':records,'reader_sources':before,'test_source':pin(__file__)}
except BaseException:
 summary={'schema':'hepta.runtime.batch-call-evidence-controls.v1','status':'FAIL','completed_controls':len(records),
          'group_counts':group_counts,'error':traceback.format_exc(),'physical_files':physical,'results':records}
summary['elapsed_seconds']=(time.monotonic_ns()-began)/1e9
(OUT/'RESULT.json').write_bytes(canonical(summary));print(json.dumps({'status':summary['status'],'controls':len(records),
 'elapsed_seconds':summary['elapsed_seconds'],'result':pin(OUT/'RESULT.json')},sort_keys=True),flush=True)
if summary['status']!='PASS':raise SystemExit(1)
