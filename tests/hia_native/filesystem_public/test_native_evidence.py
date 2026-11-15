"""Physical refusal and two-root admission checks on actual FS SDK captures.

This suite starts only Python readers. It neither invokes HIA/Rust binaries nor
restores/mutates the live filesystem fixture used by the original executions.
"""
from pathlib import Path
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import time
import traceback
sys.dont_write_bytecode = True

ADMISSION = ('strict_native.py','strict_native_provenance.py','strict_observations.py',
             'strict_trace.py','strict_original.py','strict_fixture.py','strict_transport.py')


def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def canonical(value): return json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()+b'\n'
def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(path):
    with Path(path).open('rb') as stream: return {'bytes':Path(path).stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}
def dump(path,value): Path(path).write_bytes(canonical(value))
def need(condition,message):
    if not condition: raise ValueError('FS SDK physical controls: '+message)


def mapping(bundle):
    metadata=json.loads((bundle/'mapping.json').read_bytes())
    def read(path):
        path=Path(path).absolute()
        if path.is_relative_to(bundle): relative=path.relative_to(bundle)
        else:
            need(str(path) in metadata['files'],'unmapped actual artifact origin '+str(path))
            relative=Path(metadata['files'][str(path)])
        need(not relative.is_absolute() and '..' not in relative.parts,'mapped path escape')
        current=bundle
        for part in relative.parts:
            current/=part; mode=current.lstat().st_mode; need(not stat.S_ISLNK(mode),'mapped artifact symlink')
        need(stat.S_ISREG(mode) and current.stat().st_uid==bundle.stat().st_uid,'mapped artifact type/owner')
        return current.read_bytes()
    return metadata,read


def admit_bundle(bundle):
    metadata,read=mapping(bundle); args={key:bundle/value for key,value in metadata['arguments'].items()}
    return load(bundle/'admission/strict_native.py','_physical_native_admission').evidence(**args,artifact_reader=read)


def admit_native_bundle(bundle):
    metadata,read=mapping(bundle);args={key:bundle/value for key,value in metadata['arguments'].items()
        if key not in ('original_capture','original_driver_source')}
    return load(bundle/'admission/strict_native.py','_physical_native_only_admission').native_evidence(**args,artifact_reader=read)


def prepare_bundle(destination, plan, baseline):
    destination.mkdir(mode=0o700); origins={}; pins={}
    def put(source,relative):
        source=Path(source).absolute(); target=destination/relative
        if str(source) in origins and origins[str(source)]==str(relative): return
        need(source.resolve()==source and source.is_file(),'actual artifact not regular before copy')
        target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source,target)
        need(pin(source)==pin(target),'complete artifact copy differs')
        origins.setdefault(str(source),str(relative)); pins[str(relative)]=pin(target)
    for name in ADMISSION+('test_native_evidence.py',): put(Path(__file__).parent/name,Path('admission')/name)
    native_root=Path(plan['native_source']).absolute()
    build_paths={}
    for key,fallback in (('build_reader','admission/dual_build_evidence.py'),('build_primitive','admission/qualification-reader-v1.py')):
        actual=Path(plan[key]).absolute()
        relative=Path('native-source')/actual.relative_to(native_root) if actual.is_relative_to(native_root) else Path(fallback)
        put(actual,relative);build_paths[key]=str(relative)
    put(plan['original_reader'],Path('original-reader/strict_reference.py'))
    for name in baseline['provenance']['exact_artifact_names']+['NATIVE.json']:
        put(Path(plan['native_capture'])/name,Path('native')/name)
    source=json.loads((Path(plan['native_capture'])/'SOURCE.json').read_bytes())
    for name in source['driver_sources']: put(Path(plan['producer_source'])/name,Path('native-producer')/name)
    original=baseline['comparison']['original_evidence']
    for name in original['artifact_sha256']:
        for prefix,key,target in (('reference-source/','reference_source','reference'),
                ('producer-source/','original_driver_source','original-producer'),('original-capture/','original_capture','original')):
            if name.startswith(prefix):
                relative=name[len(prefix):];put(Path(plan[key])/relative,Path(target)/relative)
    for name in source['native_source_files']: put(Path(plan['native_source'])/name,Path('native-source')/name)
    put(Path(plan['native_source'])/'native/runtime_mcp_sources.json',Path('native-source/native/runtime_mcp_sources.json'))
    for number,name in enumerate(baseline['build']['artifacts']):
        if name.startswith('build-reader/'): continue
        if name not in origins: put(name,Path('external')/('%04d'%number)/Path(name).name)
    args={'native_capture':'native','original_capture':'original','reference_source':'reference',
        'original_reader':'original-reader/strict_reference.py','producer_source':'native-producer',
        'original_driver_source':'original-producer','native_source':'native-source',
        **build_paths}
    blocked=[str(Path(plan[k]).absolute()) for k in ('native_capture','original_capture','reference_source',
        'original_reader','producer_source','original_driver_source','native_source','build_reader','build_primitive')]
    blocked+=list(baseline['build']['artifacts'])
    dump(destination/'mapping.json',{'files':origins,'arguments':args,'blocked_original_paths':sorted(set(blocked)),'copy_pins':pins})


def child(bundle, output):
    metadata,_=mapping(bundle); forbidden=[Path(p) for p in metadata['blocked_original_paths'] if p.startswith('/')]
    attempts=[];native_phase=[True]
    def audit(event,args):
        if event!='open' or not args or not isinstance(args[0],(str,bytes,os.PathLike)): return
        path=Path(os.fsdecode(args[0])).absolute()
        if native_phase[0] and (path==bundle/'original' or path.is_relative_to(bundle/'original')):
            attempts.append(str(path));raise PermissionError('native-only reader opened original output: '+str(path))
        if path.is_relative_to(bundle): return
        if any(path==root or path.is_relative_to(root) for root in forbidden):
            attempts.append(str(path)); raise PermissionError('original execution artifact denied during relocation: '+str(path))
    sys.addaudithook(audit)
    native_proof=admit_native_bundle(bundle);native_phase[0]=False
    dump(output.with_name('NATIVE-EVIDENCE.json'),native_proof)
    proof=admit_bundle(bundle);need(not attempts,'reader attempted original-path/live-fixture access')
    dump(output,proof)
    print(json.dumps({'status':'PASS','proof_sha256':sha(canonical(proof)),'original_path_read_attempts':0,'native_processes':0,'rust_processes':0},sort_keys=True))


def main():
    p=argparse.ArgumentParser();p.add_argument('--plan',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--relocation-child',type=Path)
    a=p.parse_args()
    if a.relocation_child is not None: child(a.relocation_child.absolute(),a.output.absolute());return
    need(a.plan is not None,'source plan required');plan=json.loads(a.plan.read_bytes());a.output=a.output.absolute();a.output.mkdir(mode=0o700);os.umask(0o077)
    started=time.monotonic();events=[];processes=[];here=Path(__file__).absolute().parent
    dump(a.output/'remote-process.json',{'argv':sys.argv,'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text()})
    sources={name:pin(here/name) for name in ADMISSION+('test_native_evidence.py',)};dump(a.output/'SOURCE.json',{'files':sources,'actual_plan':plan})
    gate=load(here/'strict_native.py','_physical_native_baseline')
    native_baseline=gate.native_evidence(**{k:Path(v) for k,v in plan.items() if k not in ('original_capture','original_driver_source')})
    dump(a.output/'NATIVE-BASELINE.json',native_baseline)
    baseline=gate.evidence(**{k:Path(v) for k,v in plan.items()})
    dump(a.output/'BASELINE.json',baseline);bundle=a.output/'relocated-one';prepare_bundle(bundle,plan,baseline)
    ref=load(here/'strict_original.py','_physical_original');q=ref.bootstrap(bundle/'original-reader/strict_reference.py')
    obs=load(here/'strict_observations.py','_physical_observations');tr=load(here/'strict_trace.py','_physical_trace');fixture=load(here/'strict_fixture.py','_physical_fixture')
    corpus=q.strict_json((bundle/'native/INPUTS.json').read_bytes());scenes=[s for g in corpus['groups'] for s in g['scenarios']]
    source=q.strict_json((bundle/'native/SOURCE.json').read_bytes());controls_directory=a.output/'controls';controls_directory.mkdir()
    def refuse(group,name,paths,mutate,check):
        began=time.monotonic();before={Path(path):Path(path).read_bytes() for path in paths};directory=controls_directory/name;directory.mkdir()
        modes={path:stat.S_IMODE(path.stat().st_mode) for path in before}
        for path,mode in modes.items():
            need(path.is_relative_to(bundle) and path.stat().st_uid==bundle.stat().st_uid,'mutation must remain inside owned evidence copy')
            path.chmod(mode|stat.S_IWUSR)
        try:
            mutate();changed={str(path.relative_to(bundle)):{'before':{'bytes':len(raw),'sha256':sha(raw)},'after':pin(path) if path.is_file() and not path.is_symlink() else {'file_type':stat.S_IFMT(path.lstat().st_mode)}} for path,raw in before.items()}
            try: check()
            except (ValueError,OSError,KeyError,TypeError,EOFError,struct.error) as error:
                events.append({'group':group,'name':name,'rejected':type(error).__name__,'message':str(error),'physical_files':changed,'elapsed_seconds':time.monotonic()-began})
                dump(directory/'REFUSAL.json',events[-1])
            else: raise AssertionError('physical evidence alteration admitted: '+name)
        finally:
            for path,raw in before.items():
                if path.is_symlink() or not path.is_file(): path.unlink()
                path.write_bytes(raw)
                path.chmod(modes[path])
            need(all(path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==modes[path] for path,raw in before.items()),'physical control not restored')
    def json_change(path,fn):
        value=q.strict_json(path.read_bytes());fn(value);path.write_bytes(q.canonical(value))
    def process_args(scene):
        name='observed/scenario-%03d'%scene['scenario_id'];folder=bundle/'native'/name/'process';receipt=q.strict_json((folder/'process.json').read_bytes())
        requests,_=obs.plan(scene,True)
        kwargs={'binary':source['binaries']['fixture'],'argv':receipt['native_argv'],'cwd':receipt['cwd'],
                'fence':corpus['fence_environments'][scene['fence_id']],'requests':requests,'strace_path':source['strace']['path'],'trace':True}
        return folder,kwargs
    def parsed_process(scene):
        folder,kwargs=process_args(scene);fixture.fixture_evidence(q,folder,**kwargs)
        process=q.strict_json((folder/'process.json').read_bytes());ex=q.strict_json((folder/'exchanges.json').read_bytes())
        parsed=tr.trace_process(q,(folder/'native.strace').read_bytes(),gzip.decompress((folder/'stdout.bin.gz').read_bytes()),
            gzip.decompress((folder/'stderr.bin.gz').read_bytes()),process['native_argv'],process['cwd'],ex,True)
        return folder,parsed
    def check_process(scene):
        folder,parsed=parsed_process(scene);process=q.strict_json((folder/'process.json').read_bytes())
        c=tr.Continuations(q,len(os.fsencode(process['cwd'])));e=tr.Effects(q)
        for segment in parsed['segments']:
            h=segment['header'];c.segment(segment,h['session'],18 if h['slot']==34 else h['slot'],initial=segment['index']==0);e.segment(segment,h['session'])
        return parsed
    # Actual private-process contract: coherent full receipts, not mock handlers.
    folder,kwargs=process_args(scenes[0]);receipt=folder/'process.json'
    for name,fn in [('missing_timeout',lambda v:v.pop('timed_out')),('integer_timeout_false',lambda v:v.update(timed_out=0)),
            ('deadline_changed',lambda v:v.update(drain_deadline_seconds=61)),('command_changed',lambda v:v['command'].append('--invented')),
            ('cleanup_failed',lambda v:v.update(cleanup_error='actual cleanup failed')),('incomplete_eof',lambda v:v['pipe_eof'].update(stdout=False))]:
        refuse('process_contract',name,[receipt],lambda f=fn:json_change(receipt,f),lambda:fixture.fixture_evidence(q,folder,**kwargs))
    # Alter complete physical receipt/write pairs, then re-sign both stream
    # containers and the actual process metadata. These controls must reach
    # sequence/ownership validation, not merely fail an old gzip checksum.
    parsed_cache={}
    def original_process(scene):
        identifier=scene['scenario_id']
        if identifier not in parsed_cache: parsed_cache[identifier]=parsed_process(scene)
        return parsed_cache[identifier]
    def find_receipt(predicate):
        for scene in scenes:
            folder,parsed=original_process(scene)
            for row in parsed['receipts']:
                if predicate(row): return scene,folder,row
        raise AssertionError('required actual receipt not present')
    def replace_word(raw,offset,value):
        result=bytearray(raw);struct.pack_into('<Q',result,offset,value);return bytes(result)
    def resign_stream(folder,name,raw):
        path=folder/(name+'.bin.gz');path.write_bytes(gzip.compress(raw,compresslevel=1,mtime=0))
        def update(value):
            value['streams'][name]['compressed']=pin(path)
            value['streams'][name]['uncompressed']={'bytes':len(raw),'sha256':sha(raw)}
        json_change(folder/'process.json',update)
    def receipt_control(name,predicate,offset,transform):
        scene,folder,row=find_receipt(predicate);old=row['raw'];new=replace_word(old,offset,transform(struct.unpack_from('<Q',old,offset)[0]))
        need(old!=new,'receipt control is unchanged')
        def mutate():
            path=folder/'stderr.bin.gz';raw=gzip.decompress(path.read_bytes());at=row['offset']
            need(raw[at:at+len(old)]==old,'original receipt span differs');resign_stream(folder,'stderr',raw[:at]+new+raw[at+len(old):])
            trace=folder/'native.strace';lines=trace.read_bytes().splitlines(keepends=True);index=row['trace_line']-1
            encoded=lambda value:b'"'+b''.join(('\\x%02x'%byte).encode() for byte in value)+b'"'
            before,after=encoded(old),encoded(new)
            need(lines[index].count(before)==1,'receipt not wholly visible in its actual write')
            lines[index]=lines[index].replace(before,after);trace.write_bytes(b''.join(lines))
            json_change(folder/'process.json',lambda v:v['trace'].update(pin(trace)))
        refuse('receipt_semantics',name,[folder/'stderr.bin.gz',folder/'native.strace',folder/'process.json'],mutate,lambda:check_process(scene))
        events[-1]['actual_parent']={'scenario_id':scene['scenario_id'],'magic':row['magic'],'receipt_offset':row['offset'],
            'trace_line':row['trace_line'],'original_receipt_sha256':sha(old),'changed_receipt_sha256':sha(new)}
        dump(controls_directory/name/'REFUSAL.json',events[-1])
    is_trace=lambda r:r['magic']=='HRGTR002'
    is_fs=lambda r:r['magic']=='HFSPAK02'
    is_canon=lambda r:r['magic']=='HRCNAK02'
    receipt_control('trace_sequence_gap',lambda r:is_trace(r) and r['words'][0]>1,8,lambda v:v+1)
    receipt_control('completion_wrong_sequence',lambda r:is_trace(r) and r['words'][2]==4,144,lambda v:v+1)
    receipt_control('short_delivery_claimed_complete',lambda r:is_trace(r) and r['words'][2]==4 and struct.unpack_from('<Q',r['raw'],152)[0]==tr.DELIVERY,152,lambda v:32)
    receipt_control('delivery_only_dispatched_again',lambda r:is_trace(r) and r['words'][2]==1 and r['words'][3]==tr.CALL and r['raw'][80:88] in tr.MAGICS.values() and struct.unpack_from('<Q',r['raw'],104)[0]==1,24,lambda v:3)
    receipt_control('resize_lost_pending_action',lambda r:is_trace(r) and r['words'][2]==2,80,lambda v:v^1)
    receipt_control('filesystem_late_ack',is_fs,72,lambda v:v+1)
    receipt_control('filesystem_wrong_generation',is_fs,80,lambda v:v+1)
    receipt_control('filesystem_false_errno',is_fs,152,lambda v:v^1)
    receipt_control('filesystem_wrong_owned_fd',is_fs,32,lambda v:v^1)
    receipt_control('rename_replaced_noreplace',lambda r:is_fs(r) and struct.unpack_from('<Q',r['raw'],88)[0]==5,176,lambda v:0)
    receipt_control('canonical_repeated_ack',is_canon,8,lambda v:v+1)
    receipt_control('canonical_false_kernel_return',is_canon,48,lambda v:v^1)
    receipt_control('canonical_false_stat_mode',lambda r:is_canon(r) and r['words'][2] in (3,5,6) and r['words'][6]==0,112,lambda v:v^1)

    # Decode full observer bytes taken from actual stdout. These are private
    # state rejection controls, not extra original-semantic cases.
    state_parent=None
    for scene in scenes:
        folder,_=original_process(scene);rows=q.strict_json((folder/'exchanges.json').read_bytes())
        stdout=gzip.decompress((folder/'stdout.bin.gz').read_bytes())
        for row in rows:
            if row['slot']!=33: continue
            area=row['body'];raw=stdout[area['offset']:area['offset']+area['bytes']]
            _,_,parts=obs.states(q,raw)
            if all(parts[key][:8]==magic for key,magic in (('scope',b'HRSCST01'),('lease',b'HRCLST01'))):
                state_parent=(scene['scenario_id'],area,raw);break
        if state_parent is not None: break
    need(state_parent is not None,'actual initialized observer missing');state_id,state_area,state_raw=state_parent
    n,m=struct.unpack_from('<2Q',state_raw,8);state_path=bundle/'actual-observer.bin';state_path.write_bytes(state_raw)
    state_controls=[('session_version',64+48,2),('session_latch_type',64+40,2),('cache_record_overflow',64+n+24,(1<<64)-1),
        ('context_dirty_after_restore',64+n+m+32,1),('scope_not_closed',64+n+m+64+24,1),('lease_request_clone_leaked',64+n+m+64+256+32,2)]
    for name,offset,value in state_controls:
        refuse('observer_state',name,[state_path],lambda off=offset,v=value:state_path.write_bytes(replace_word(state_raw,off,v)),lambda:obs.states(q,state_path.read_bytes()))
        events[-1]['actual_parent']={'scenario_id':state_id,'body_span':state_area,'whole_observer_sha256':sha(state_raw)}
        dump(controls_directory/name/'REFUSAL.json',events[-1])

    metadata,read=mapping(bundle);graph=load(bundle/metadata['arguments']['build_reader'],'_physical_graph')
    def graph_check():
        return graph.dual_build_evidence(bundle/'native-source',Path(source['builds']['public']['path']),Path(source['builds']['fixture']['path']),
            read_bytes=read,reader_path=bundle/metadata['arguments']['build_primitive'])
    need(graph_check()['status']=='PASS','copied complete graph must pass before graph alterations')
    origins=metadata['files']
    def mapped(predicate):
        names=[name for name in baseline['build']['artifacts'] if predicate(name)]
        need(bool(names),'actual graph artifact not found');return bundle/origins[names[0]]
    graph_targets=[('compiled_source_changed',mapped(lambda name:name.endswith('/native/filesystem_parity.hepta'))),
        ('compiler_output_changed',mapped(lambda name:name.endswith('/module.output.bin'))),
        ('full_pack_input_changed',mapped(lambda name:name.endswith('/pack.input.bin'))),
        ('complete_elf_changed',mapped(lambda name:name.endswith('/runtime-mcp.elf')))]
    for name,path in graph_targets:
        raw=path.read_bytes();position=len(raw)//2
        refuse('source_and_build',name,[path],lambda p=path,b=raw,i=position:p.write_bytes(b[:i]+bytes([b[i]^1])+b[i+1:]),graph_check)

    folder,kwargs=process_args(scenes[0]);receipt=folder/'process.json';stream=folder/'stdout.bin.gz'
    link_target=bundle/'owned-copy-of-stdout.gz';shutil.copy2(stream,link_target)
    def link_stream(): stream.unlink();stream.symlink_to(link_target)
    def fifo_stream(): stream.unlink();os.mkfifo(stream,0o600)
    refuse('files_and_json','inward_symlink',[stream],link_stream,lambda:fixture.fixture_evidence(q,folder,**kwargs))
    refuse('files_and_json','fifo_instead_of_regular',[stream],fifo_stream,lambda:fixture.fixture_evidence(q,folder,**kwargs))
    raw_receipt=receipt.read_bytes()
    for name,token in [('duplicate_json_key',b'"timed_out":false,'),('nonfinite_json',b'"extra":NaN,'),('overflowing_json_float',b'"extra":1e999,')]:
        refuse('files_and_json',name,[receipt],lambda t=token:receipt.write_bytes(b'{'+t+raw_receipt[1:]),lambda:fixture.fixture_evidence(q,folder,**kwargs))

    # A complete input byte outside the trace's text representation remains
    # bound to the independent generator, after re-signing all transport pins.
    long_scene=None
    for scene in scenes:
        folder,kwargs=process_args(scene);rows=q.strict_json((folder/'exchanges.json').read_bytes())
        candidates=[r for r in rows if r['slot']==34 and r['accepted_input']['bytes']>8192]
        if candidates: long_scene=(scene,folder,kwargs,rows,max(candidates,key=lambda r:r['accepted_input']['bytes']));break
    need(long_scene is not None,'wide actual input missing');scene,folder,kwargs,rows,selected=long_scene
    input_raw=gzip.decompress((folder/'stdin.bin.gz').read_bytes());area=selected['accepted_input'];i=area['offset']+area['bytes']//2
    while i<area['offset']+area['bytes'] and not 97<=input_raw[i]<=122:i+=1
    need(i<area['offset']+area['bytes'],'wide input has no mutable literal');new_input=input_raw[:i]+bytes([98 if input_raw[i]==97 else 97])+input_raw[i+1:]
    def change_input():
        resign_stream(folder,'stdin',new_input);resign_stream(folder,'attempted-stdin',new_input)
        def update(value):
            row=value[selected['index']]
            for name in ('attempted_input','accepted_input'):
                span=row[name];span['sha256']=sha(new_input[span['offset']:span['offset']+span['bytes']])
        json_change(folder/'exchanges.json',update)
    refuse('whole_streams','wide_input_middle_byte',[folder/'stdin.bin.gz',folder/'attempted-stdin.bin.gz',folder/'process.json',folder/'exchanges.json'],
        change_input,lambda:fixture.fixture_evidence(q,folder,**kwargs))

    # Change a real public reply in the middle of a wide body. Re-sign its
    # actual syscall text too when that byte was visible in the write prefix.
    # Unchanged Rust bytes must still reject the coherently changed capture.
    chosen=None
    for scene in scenes:
        folder,parsed=original_process(scene);rows=q.strict_json((folder/'exchanges.json').read_bytes())
        stdout=gzip.decompress((folder/'stdout.bin.gz').read_bytes())
        for row in rows:
            if row['slot']!=34 or row['body']['bytes']<=8192: continue
            area=row['body'];end=area['offset']+area['bytes']
            for event in parsed['events']:
                if event['name']!='write' or event.get('fd')!=1: continue
                at=max(event['stream_offset'],area['offset']+area['bytes']//2);stop=min(event['stream_offset']+event['full_bytes'],end)
                while at<stop and not (65<=stdout[at]<=90 or 97<=stdout[at]<=122):at+=1
                if at<stop:
                    changed=stdout[:at]+bytes([98 if stdout[at]==97 else 97])+stdout[at+1:]
                    q.strict_json(changed[area['offset']:end]);chosen=(scene,folder,rows,row,changed,at,event);break
            if chosen is not None:break
        if chosen is not None:break
    need(chosen is not None,'wide actual output missing');scene,folder,rows,selected,changed,changed_offset,write_event=chosen
    inventory=bundle/'native/NATIVE.json';all_processes=bundle/'native/processes.json';original_source=bundle/'original/SOURCE.json';original_report=bundle/'original/ORIGINAL.json'
    prior_admission=bundle/'original/NATIVE-ADMISSION.json'
    changed_files=[folder/'stdout.bin.gz',folder/'process.json',folder/'exchanges.json',folder/'native.strace',all_processes,inventory,original_source,original_report,prior_admission]
    visible_write,clipped_write=q.quoted(write_event['args'][1],4096);write_offset=changed_offset-write_event['stream_offset']
    prefix_changed=write_offset<len(visible_write)
    def change_output():
        resign_stream(folder,'stdout',changed)
        if prefix_changed:
            trace=folder/'native.strace';lines=trace.read_bytes().splitlines(keepends=True);index=write_event['line']-1
            old=b'"'+b''.join(('\\x%02x'%byte).encode() for byte in visible_write)+b'"'
            value=visible_write[:write_offset]+changed[changed_offset:changed_offset+1]+visible_write[write_offset+1:]
            new=b'"'+b''.join(('\\x%02x'%byte).encode() for byte in value)+b'"'
            need(lines[index].count(old)==1,'whole reply write prefix not found');lines[index]=lines[index].replace(old,new)
            trace.write_bytes(b''.join(lines));json_change(folder/'process.json',lambda v:v['trace'].update(pin(trace)))
        def exchanges(value):
            for name in ('response','body'):
                area=value[selected['index']][name];area['sha256']=sha(changed[area['offset']:area['offset']+area['bytes']])
        json_change(folder/'exchanges.json',exchanges)
        process=q.strict_json((folder/'process.json').read_bytes())
        def processes_update(value):
            found=[r for r in value if r['layer']=='observed' and r['scenario_id']==scene['scenario_id']]
            need(len(found)==1,'native process index identity');found[0]['receipt']=process
        json_change(all_processes,processes_update)
        def update_inventory(value):
            for path in changed_files[:5]: value['artifacts'][str(path.relative_to(bundle/'native'))]=pin(path)
        json_change(inventory,update_inventory)
        proof=admit_native_bundle(bundle);dump(prior_admission,proof)
        def source_update(value):
            value['native_predecessor'].update({str(path.relative_to(bundle/'native')):pin(path) for path in changed_files[:6]})
            value['native_admission'].update(pin(prior_admission));value['native_admission_artifact_sha256']=proof['artifact_sha256']
        json_change(original_source,source_update)
        def original_update(value):
            value['artifacts'].update({'SOURCE.json':pin(original_source),'NATIVE-ADMISSION.json':pin(prior_admission)})
            value['native_admission'].update(pin(prior_admission))
        json_change(original_report,original_update)
    def compare_output():
        return obs.compare_original(bundle/'original-reader/strict_reference.py',bundle/'reference',bundle/'native-producer',
            bundle/'native',bundle/'original',bundle/'original-producer')
    refuse('whole_streams','wide_reply_middle_byte',changed_files,change_output,compare_output)
    need('whole reply bytes differ' in events[-1]['message'],'wide output alteration did not reach full original comparison')
    events[-1]['actual_parent']={'scenario_id':scene['scenario_id'],'exchange_index':selected['index'],'changed_full_stream_offset':changed_offset,
        'actual_body_span':selected['body'],'strace_prefix_changed':prefix_changed,'all_intermediate_pins_recomputed':True}
    dump(controls_directory/'wide_reply_middle_byte/REFUSAL.json',events[-1])
    # These additional physical controls cover the portable tool/predecessor
    # contract. The original 36 controls above remain unchanged in scope.
    provenance=load(here/'strict_native_provenance.py','_physical_portable_provenance')
    native_report=bundle/'native/NATIVE.json';native_host=bundle/'native/HOST.json';tool_receipt=bundle/'native/tool-processes.json'
    def resign_native(path,fn):
        json_change(path,fn)
        json_change(native_report,lambda v:v['artifacts'].update({str(path.relative_to(bundle/'native')):pin(path)}))
    def native_provenance():return provenance.provenance(q,bundle/'native',corpus,ref,baseline['build'])
    refuse('process_contract','portable_tracer_command',[tool_receipt,native_report],
        lambda:resign_native(tool_receipt,lambda v:v[0]['command'].append('--invented')),native_provenance)
    need('tracer version command' in events[-1]['message'],'portable tracer control did not reach actual command binding')
    refuse('process_contract','portable_native_boot_missing',[native_host,native_report],
        lambda:resign_native(native_host,lambda v:v.pop('boot_id')),native_provenance)
    for label,root,descriptor in [('native',bundle/'native',source['strace']),
            ('original',bundle/'original',q.strict_json(original_source.read_bytes())['tool_executables']['strace'])]:
        copied=root/descriptor['captured_file']
        def change_tool(path=copied):
            raw=path.read_bytes();path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        refuse('source_and_build',label+'_selected_tool_bytes',[copied],change_tool,
            lambda root=root,descriptor=descriptor:ref.tool_evidence(q,q.Binder(root),'strace',descriptor))
    def source_contract_control(fn):
        json_change(original_source,fn)
        json_change(original_report,lambda v:v['artifacts'].update({'SOURCE.json':pin(original_source)}))
    def original_admission():return ref.reference_evidence(bundle/'reference',bundle/'original-reader/strict_reference.py',
        bundle/'original-producer',bundle/'native',bundle/'original')
    refuse('source_and_build','complete_native_predecessor_required',[original_source,original_report],
        lambda:source_contract_control(lambda v:v['native_predecessor'].pop('SOURCE.json')),original_admission)
    need('predecessor pins' in events[-1]['message'],'predecessor control did not reach complete physical inventory')
    refuse('source_and_build','complete_native_admission_required',[original_source,original_report],
        lambda:source_contract_control(lambda v:v['native_admission_artifact_sha256'].pop(next(iter(v['native_admission_artifact_sha256'])))),original_admission)
    need('admitted predecessor identity' in events[-1]['message'],'predecessor control did not reach complete admission map')
    need(len(events)==42 and len({r['name'] for r in events})==42,'complete necessary control set')
    groups={name:sum(e['group']==name for e in events) for name in sorted({e['group'] for e in events})}
    need(groups=={'process_contract':8,'receipt_semantics':13,'observer_state':6,'source_and_build':8,'files_and_json':5,'whole_streams':2},'exact refusal groups')
    dump(a.output/'REFUSALS.json',{'groups':groups,'controls':events,'actual_native_processes':0,'actual_rust_processes':0})

    def relocated(index,root):
        directory=a.output/('relocation-%d'%index);directory.mkdir();proof_path=directory/'EVIDENCE.json'
        command=[sys.executable,'-I','-B',str(root/'admission/test_native_evidence.py'),'--relocation-child',str(root),'--output',str(proof_path)]
        began=time.monotonic();completed=subprocess.run(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
        (directory/'stdout.bin').write_bytes(completed.stdout);(directory/'stderr.bin').write_bytes(completed.stderr)
        receipt={'command':command,'cwd':str(root),'timeout_seconds':180,'timed_out':False,'exit_code':completed.returncode,
            'elapsed_seconds':time.monotonic()-began,'stdout':pin(directory/'stdout.bin'),'stderr':pin(directory/'stderr.bin')}
        dump(directory/'PROCESS.json',receipt);processes.append(receipt)
        need(completed.returncode==0 and completed.stderr==b'','actual relocated reader failed: '+completed.stderr.decode(errors='replace'))
        result=q.strict_json(proof_path.read_bytes());need(result==baseline,'whole admitted object changed after relocation')
        native_path=directory/'NATIVE-EVIDENCE.json';need(q.strict_json(native_path.read_bytes())==native_baseline,'whole native-only object changed after relocation')
        return {'root':str(root),'proof':pin(proof_path),'native_only_proof':pin(native_path),'entire_object_equal':True,
            'native_only_original_output_open_denied':True,'original_path_reads_denied':True,'live_fixture_required':False}
    first=relocated(1,bundle);second_root=a.output/'relocated-two';bundle.rename(second_root);need(not bundle.exists(),'old relocated root remains')
    second=relocated(2,second_root)
    need({name:pin(here/name) for name in sources}==sources,'evidence suite source changed during execution')
    result={'schema':'hepta.runtime.filesystem-sdk-native-evidence-controls.v1','status':'PASS','groups':len(groups),'controls':len(events),
        'group_counts':groups,'baseline':pin(a.output/'BASELINE.json'),'native_only_baseline':pin(a.output/'NATIVE-BASELINE.json'),
        'refusals':pin(a.output/'REFUSALS.json'),'relocations':[first,second],
        'actual_reader_child_processes':len(processes),'actual_native_processes':0,'actual_rust_processes':0,'new_compiler_processes':0,
        'formal_fresh_member_qualification':True,'fresh_cold_qualification':False,'whole_original_domain_cases':323,'private_fixture_controls':9,
        'actual_processes':processes,'source_files':sources,'elapsed_seconds':time.monotonic()-started}
    dump(a.output/'RESULT.json',result);print(json.dumps({k:result[k] for k in ('status','groups','controls','actual_reader_child_processes','elapsed_seconds')},sort_keys=True))


if __name__=='__main__': main()
