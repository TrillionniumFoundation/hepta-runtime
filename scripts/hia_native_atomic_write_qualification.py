"""Strict source, artifact, complete native corpus and original-Rust evidence."""
from __future__ import annotations
import collections,copy,gzip,hashlib,json,os,shutil,stat,struct,sys,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
for p in (ROOT/'scripts',ROOT/'tests/hia_native'):
    if str(p) not in sys.path:sys.path.insert(0,str(p))
from hia_native_atomic_write_build import (inspect_bundle,native_receipt,inspect_elf,read,obj,sha,canonical,file_record,exact,require,
 COMMIT,COMPILER,DEPENDENCY,POLICY_SOURCE,POLICY_IMAGE,PACKER_SOURCE,PACKER_IMAGE,COMPILE_FILES,PACK_FILES)
import atomic_write_cases as case_module
from atomic_write_kernel import request_pieces,records,encoded
from atomic_write_harness import frame,stream
ORIGINAL_SHA='e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590'
ORIGINAL_BLOB='4a8114e72a51238608201e108288294c6282ab20'
ORIGINAL_OWNER='78f128e5938311d9248df09e94fa340a37bea4c759538e93b8d342feee046dfa'
PATH_INPUT=('95714e07fcd06d93733d371e35aa88d8e8512040f8dd5573255fa20e6fe3c02b',17232080)
PATH_OUTPUT=('2c173890db1f9318bdf955a442838f4e560ba8e25576f032e9e7cedcb660a3a4',26067579)
CONTRACTS=('283ec86d98e8e1d431b9fc1c06679bbe8c7e5cb305990f150ce3eb3da977c1e5',19643251)
PROPERTIES='f88ff140c2c976db5a6c11e8c62fa16957af3205396344eccd43e16aea56bc7d'
PROBE_SOURCE='c6d89613aa38bd714d023bd8b047c3a61998375fb5b4bfef61ba2bc4e636b870'
PROBE_IMAGE='44072faff6f231c3861e6d2cb946711005c9f78f5a993e4aaa32617ab844c54d'
CASE_SHA='dffd3296d316b2c4fbdfe4aa1f8201775b6594f2150a9fe8189d92a2325f084c'
OWN_FILES=('native/atomic_write.hepta','native/atomic_write_packer.hepta','native/atomic_write_composition.json','native/atomic_write_layout.json',
 'scripts/hia_native_build.py','scripts/hia_native_loader.py','scripts/hia_native_atomic_write_build.py','scripts/hia_native_atomic_write_qualification.py',
 'tests/hia_native/atomic_write_harness.py','tests/hia_native/atomic_write_cases.py','tests/hia_native/atomic_write_kernel.py',
 'tests/hia_native/atomic_write_supervisor.py','tests/hia_native/test_atomic_write_policy.py','tests/hia_native/test_atomic_write_kernel.py',
 'tests/hia_native/test_atomic_write_boundary.py','tests/hia_native/atomic_write_contract_probe.hepta',
 'tests/hia_native/test_atomic_write_evidence.py',
 'tests/hia_native/atomic_write_rust_io_properties.txt','tests/hia_native/oracle_atomic_write.rs',
 'tests/hia_native/compare_atomic_write_original.py','tests/hia_native/atomic_write_oracle/Cargo.toml',
 'tests/hia_native/atomic_write_oracle/Cargo.lock','tests/hia_native/atomic_write_oracle/build.rs')
REFERENCE_FILES=('src/mcp/fs/text_editing.rs','native/text_budget.hepta','native/policy.hepta')
def pins(root=ROOT,reference=None):
    root=Path(root);reference=Path(reference or root)
    return {'owner':{p:file_record(root/p) for p in OWN_FILES},'reference':{p:file_record(reference/p) for p in REFERENCE_FILES}}
def source_contract(root=ROOT,reference=None,hepta=None):
    root=Path(root);reference=Path(reference or root);hepta=Path(hepta or os.environ['HIA_HEPTA_DIR'])
    require(read(root/'tests/hia_native/atomic_write_cases.py')==read(case_module.__file__),'loaded atomic case source differs')
    raw=read(reference/'src/mcp/fs/text_editing.rs')
    exact(sha(raw),ORIGINAL_SHA,'complete original atomic owner source differs')
    exact(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),ORIGINAL_BLOB,'original Git blob differs')
    first=raw.index(b'pub async fn atomic_write(');end=raw.index(b'\nconst LF_ENDING:',first)
    exact(sha(raw[first:end]),ORIGINAL_OWNER,'complete original function differs')
    proof=obj(root/'native/atomic_write_composition.json')
    for k,v in {'schema':'hepta.runtime.atomic-write-composition.v1','source_sha256':POLICY_SOURCE,
      'original_commit':'a0dcdda1991ec536d5e2d252c006a778993fa566','original_path':'src/mcp/fs/text_editing.rs',
      'original_sha256':ORIGINAL_SHA,'errno_probe_sha256':PROPERTIES}.items():exact(proof.get(k),v,'atomic source composition differs: '+k)
    exact(sha(read(root/'native/atomic_write.hepta')),POLICY_SOURCE,'native atomic policy source changed')
    exact(sha(read(root/'native/atomic_write_packer.hepta')),PACKER_SOURCE,'fixed atomic boundary source changed')
    exact(sha(read(root/'tests/hia_native/atomic_write_rust_io_properties.txt')),PROPERTIES,'actual Rust errno properties changed')
    sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    def functions(path):return {f['name']:f for f in assemble_program(read(path)).as_dict()['functions']}
    actual=functions(root/'native/atomic_write.hepta');exact(len(actual),28,'atomic function closure differs')
    exact({r['path'] for r in proof['imports']},{'native/text_budget.hepta','native/policy.hepta'},'atomic imported owner set differs')
    count=0
    for row in proof['imports']:
        path=reference/row['path'];exact(sha(read(path)),row['sha256'],'atomic imported source differs')
        old=functions(path);reverse={new:name for name,new in row['function_relocation'].items()}
        for name,new in row['function_relocation'].items():
            f=copy.deepcopy(actual[new]);f['name']=name
            for block in f['blocks']:
                for operation in block['ops']:
                    if operation['op']=='call':operation['attrs']['function']=reverse[operation['attrs']['function']]
            exact(f,old[name],'atomic imported function body changed')
            exact(sha(canonical(f)),row['functions'][name],'atomic imported function digest differs');count+=1
    exact(count,5,'atomic imported function count differs')
    exact(sha(read(root/'scripts/hia_native_build.py')),'02cc0f23764d3a2bc6c1325e2ed5beb7986a6b64b22827c6ddcb10d2799de7d1','atomic compiler driver changed')
    exact(sha(read(root/'scripts/hia_native_loader.py')),'58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06','actual atomic loader changed')
    lock=tomllib.loads(read(root/'tests/hia_native/atomic_write_oracle/Cargo.lock').decode())
    dependencies={}
    expected={'tokio':('1.53.1','202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed'),
      'anyhow':('1.0.104','330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470'),
      'libc':('0.2.189','3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2')}
    for name,(version,digest) in expected.items():
        found=[p for p in lock['package'] if p['name']==name];require(len(found)==1,'original dependency missing')
        record=found[0];exact(record['version'],version,'original dependency version differs')
        exact(record['checksum'],digest,'original dependency checksum differs')
        exact(record['source'],'registry+https://github.com/rust-lang/crates.io-index','original dependency registry differs')
        dependencies[name]={'version':version,'checksum':digest}
    return {'status':'PASS','source_sha256':POLICY_SOURCE,'image_sha256':POLICY_IMAGE,'packer_source_sha256':PACKER_SOURCE,
      'original_source_sha256':ORIGINAL_SHA,'original_owner_sha256':ORIGINAL_OWNER,'imported_functions':count,
      'locked_dependencies':dependencies,'complete_original_tool_parity':False,'remote_ssh_parity':False,'production_activated':False}

def gzip_digest(path,wanted_bytes=None):
    total=0;h=hashlib.sha256()
    with gzip.open(path,'rb') as stream:
        while part:=stream.read(1<<20):
            total+=len(part)
            if wanted_bytes is not None:require(total<=wanted_bytes,'retained gzip exceeds complete domain')
            h.update(part)
    if wanted_bytes is not None:exact(total,wanted_bytes,'retained gzip was truncated')
    return {'bytes':total,'sha256':h.hexdigest()}

def completed_stdout(result,path,*,omit_observations=False):
    expected={k:v for k,v in result.items() if not omit_observations or k!='observations'}
    exact(obj(path),expected,'actual completed process stdout differs from retained result')
    return file_record(path)

def policy_evidence(directory,bundle,*,source_root=ROOT,stdout=None):
    directory=Path(directory);root=Path(source_root);result=obj(directory/'result.json')
    fixed={'schema':'hepta.runtime.atomic-write-policy-suite.v1','status':'PASS','path_cases':88807,'synthetic_cases':16414,
      'synthetic_error_projections':16377,'abi_refusals':19,'actual_filesystem_effects':0,'original_rust_status':'PENDING',
      'native_calls':170947,'original_error_display_property_rows':4095,'contract_rows':16433,
      'contracts_sha256':CONTRACTS[0],'contracts_bytes':CONTRACTS[1],
      'requests_sha256':PATH_INPUT[0],'requests_bytes':PATH_INPUT[1],'outputs_sha256':PATH_OUTPUT[0],'outputs_bytes':PATH_OUTPUT[1]}
    for k,v in fixed.items():exact(result.get(k),v,'native atomic policy receipt differs: '+k)
    require(0<result['elapsed']<180,'policy suite missed unchanged deadline')
    exact(result['identity'],{'manifest_sha256':bundle['modules']['policy']['manifest']['sha256'],
      'source_sha256':POLICY_SOURCE,'image_sha256':POLICY_IMAGE,'compiler_commit':COMMIT,'compiler_sha256':COMPILER},'actual loaded policy differs')
    expected_source_names={'native/atomic_write.hepta','native/atomic_write_composition.json','tests/hia_native/atomic_write_harness.py',
      'tests/hia_native/test_atomic_write_policy.py','tests/hia_native/atomic_write_rust_io_properties.txt'}
    exact(set(result['source_files']),expected_source_names,'policy execution source set differs')
    exact(result['source_files'],{p:sha(read(root/p)) for p in expected_source_names},'policy execution source changed')
    files={}
    for name,(digest,size) in [('path-requests.bin.gz',PATH_INPUT),('path-native-output.bin.gz',PATH_OUTPUT),('contracts.jsonl.gz',CONTRACTS)]:
        exact(gzip_digest(directory/name,size),{'bytes':size,'sha256':digest},'complete policy corpus changed')
        files[name]=file_record(directory/name)
    domains=collections.Counter();calls=88807;rows=0
    with gzip.open(directory/'contracts.jsonl.gz','rb') as stream:
        while raw:=stream.readline(1<<20):
            require(raw.endswith(b'\n'),'contract row exceeds reviewed bounds')
            row=json.loads(raw);exact(row['ordinal'],rows,'contract ordinal omitted');rows+=1;domains[row['domain']]+=1
            for key in ('source_unchanged','guards_unchanged','output_tail_unchanged'):exact(row[key],True,'native borrowed-buffer protection differs')
            exact(row['calls'],len(row['effects'])+1,'actual policy invocation accounting differs')
            exact(len(row['effects']),len(row['completions']),'policy completion omitted')
            for index,effect in enumerate(row['effects']):exact(effect['sequence'],index+1,'policy effect sequence omitted')
            out=bytes.fromhex(row['output_hex'])
            if row['code']<0xffff0000:exact(len(out),row['code'],'actual policy output length differs')
            else:exact(out,b'','policy refusal disclosed output')
            calls+=row['calls']
    exact(dict(domains),{'errno_projection':16377,'effect_error':28,'short_write':3,'cancel':6,'invalid_frame':13,'capacity':6},'policy domains incomplete')
    exact(rows,16433,'policy contract corpus incomplete');exact(calls,170947,'policy actual call total differs')
    answer={'status':'PASS','result':file_record(directory/'result.json'),'files':files,'path_cases':88807,
      'contract_rows':rows,'native_calls':calls,'actual_filesystem_effects':0}
    if stdout is not None:answer['completed_stdout']=completed_stdout(result,stdout)
    return answer

def snapshot_contents(entry,name,rows):
    folder=entry/name;wanted=set();files={};total=0
    for index,row in enumerate(rows):
        require(type(row['path'])is str and type(row['mode'])is int,'invalid retained filesystem state')
        path=bytes.fromhex(row['path']);require(not path.startswith(b'/') and b'..' not in path.split(b'/'),'snapshot path escaped its fixture')
        if stat.S_ISREG(row['mode']):
            filename=f'{index:04d}.bin.gz';exact(row.get('content_archive'),filename,'regular-file content was not retained')
            require(type(row['content_bytes'])is int and 0<=row['content_bytes']<=505<<20,'snapshot content extent differs')
            observed=gzip_digest(folder/filename,row['content_bytes'])
            exact(observed['sha256'],row['content_sha256'],'actual retained file bytes changed')
            exact(row['content_bytes'],row['size'],'actual file size differs from full retained contents')
            files[name+'/'+filename]=file_record(folder/filename);wanted.add(filename);total+=row['content_bytes']
        else:require('content_archive' not in row,'nonregular snapshot acquired a payload')
    exact({p.name for p in folder.iterdir()},wanted,'retained content archive set differs')
    return files,total

def identity_custody(receipt,before):
    """Admit real observer-held inode lifetimes through the after-snapshot."""
    exact(set(receipt),{'schema','flags','pins','observed_after_snapshot','closed_fds',
      'close_errors','all_closes_verified','body_error'},'identity custody fields differ')
    exact(receipt['schema'],'hepta.runtime.atomic-identity-custody.v1','identity custody schema differs')
    exact(receipt['flags'],os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,'identity pin flags differ')
    require(receipt['observed_after_snapshot'] is True and receipt['all_closes_verified'] is True,
      'identity pins did not span the complete snapshot and close')
    exact(receipt['close_errors'],[],'identity pin close failed')
    exact(receipt['body_error'],None,'identity snapshot did not complete')
    pins=receipt['pins'];exact(len(pins),len(before),'original inode was not pinned')
    handles=[]
    for pin,observed in zip(pins,before,strict=True):
        exact(set(pin),{'path','fd','before','inheritable','after'},'identity pin fields differ')
        exact(pin['path'],observed['path'],'identity pin path differs')
        require(type(pin['fd'])is int and pin['fd']>=0 and pin['fd'] not in handles,
          'identity pin descriptor is invalid or reused while live')
        handles.append(pin['fd']);require(pin['inheritable'] is False,'identity pin reached the tested child')
        wanted={'dev':observed['dev'],'inode':observed['inode'],'file_type':stat.S_IFMT(observed['mode'])}
        exact(pin['before'],wanted,'pinned inode differs from the original snapshot')
        exact(set(pin['after']),{'dev','inode','file_type','nlink'},'identity pin final observation differs')
        require(type(pin['after']['nlink'])is int and pin['after']['nlink']>=0,'invalid pinned link count')
        exact({k:pin['after'][k] for k in wanted},wanted,'original inode custody changed before the after-snapshot')
    exact(receipt['closed_fds'],handles,'not every identity pin was closed exactly once')
    return receipt


def retire_fixtures(output,fixtures,receipt,evidence,*,create=False):
    """Retire only owned live targets after their complete evidence is admitted."""
    output=Path(output);receipt=Path(receipt)
    expected={'schema':'hepta.runtime.atomic-write-fixture-retirement.v1','status':'PASS',
      'fixture_directories':list(fixtures),'complete_evidence_sha256':sha(canonical(evidence)),
      'semantic_invocations_added':0}
    if receipt.exists():
        if receipt.is_symlink() or obj(receipt)!=expected:
            raise ValueError('atomic fixture retirement receipt differs')
    elif create:
        if output.is_symlink() or output.resolve(strict=True)!=output:
            raise ValueError('atomic fixture retirement root differs')
        paths=[]
        for name in fixtures:
            relative=Path(name)
            if relative.is_absolute() or '..' in relative.parts or relative.name!='fixture':
                raise ValueError('atomic fixture retirement path escaped its owner')
            path=output/relative;info=path.lstat()
            if path.resolve()!=path or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid():
                raise ValueError('atomic live fixture is not an owned real directory')
            paths.append(path)
        # Each tested child has been reaped. Preserve every captured stream,
        # snapshot and content archive; only its separate live target is removed.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('atomic fixture retirement requires descriptor-based removal')
        for path in paths:
            path.chmod(0o700)
            for base,dirs,_ in os.walk(path,followlinks=False):
                for name in dirs:
                    child=Path(base)/name;info=child.lstat()
                    if stat.S_ISDIR(info.st_mode):
                        if info.st_uid!=os.getuid():
                            raise ValueError('atomic live fixture contains an unowned directory')
                        child.chmod(0o700,follow_symlinks=False)
            shutil.rmtree(path)
        with receipt.open('x') as stream:
            stream.write(json.dumps(expected,sort_keys=True,indent=2)+'\n')
    else:raise ValueError('completed atomic fixture retirement receipt is missing')
    if any((output/name).exists() or (output/name).is_symlink() for name in fixtures):
        raise ValueError('retired atomic live fixture reappeared')
    return expected


def original_fixture_retirement(directory,kernel_receipts,*,create=False):
    exact(set(kernel_receipts),{'native','original'},'original fixture custody omitted a writer')
    fixtures=tuple(f'{kind}-kernel/{index:04d}-{case["name"]}/fixture'
      for kind in ('native','original') for index,case in enumerate(case_module.cases()))
    return retire_fixtures(directory,fixtures,Path(directory)/'retired-fixtures.json',kernel_receipts,create=create)


def kernel_evidence(directory,binary_sha,*,source_root=ROOT,stdout=None,artifact=None):
    directory=Path(directory);root=Path(source_root);result=obj(directory/'result.json')
    corpus=case_module.cases();definition=encoded(corpus);exact(sha(definition),CASE_SHA,'atomic kernel domain changed')
    fixed={'schema':'hepta.runtime.atomic-write-kernel-suite.v1','status':'PASS','cases':151,'requests':171,
      'total_declared_cases':151,'case_definition_sha256':CASE_SHA,'native_or_original_executable_sha256':binary_sha,
      'actual_kernel_cases':77,'kernel_fault_cases':48,'actual_partial_limit_cases':2,'cancellation_cases':24}
    for key,wanted in fixed.items():exact(result.get(key),wanted,'atomic kernel receipt differs: '+key)
    require(0<result['elapsed']<180,'kernel suite missed unchanged deadline')
    exact(read(directory/'cases.json'),definition+b'\n','complete kernel case definitions changed')
    expected_names={'atomic_write_cases.py','atomic_write_kernel.py','atomic_write_supervisor.py'}
    exact(set(result['source_files']),expected_names,'kernel execution source set differs')
    exact(result['source_files'],{n:sha(read(root/'tests/hia_native'/n)) for n in expected_names},'kernel execution source changed')
    require(type(result['execution_uid'])is int and type(result['execution_gid'])is int,'kernel execution identity missing')
    original_directory=Path(result['execution_directory']);require(original_directory.is_absolute(),'original execution directory missing')
    observations=result['observations'];exact(len(observations),151,'complete kernel observations omitted')
    all_input=hashlib.sha256();all_output=hashlib.sha256();input_bytes=output_bytes=requests=0;content_bytes=0
    files={'result.json':file_record(directory/'result.json'),'cases.json':file_record(directory/'cases.json')};normalized=[]
    for index,(case,row) in enumerate(zip(corpus,observations,strict=True)):
        label=f'{index:04d}-{case["name"]}';entry=directory/label
        exact(row['index'],index,'kernel observation ordinal changed');exact(row['name'],case['name'],'kernel observation name changed')
        exact(row['request_file'],label+'/request.bin.gz','kernel corpus path differs')
        exact(row['fixture_path'],str(original_directory/label/'fixture'),'original owned fixture identity differs')
        h=hashlib.sha256();size=0
        with gzip.open(entry/'request.bin.gz','rb') as incoming:
            for _ in range(case.get('requests',1)):
                for expected in request_pieces(case):
                    actual=incoming.read(len(expected));exact(actual,expected,'complete actual kernel request differs')
                    h.update(actual);all_input.update(actual);size+=len(actual);input_bytes+=len(actual)
            exact(incoming.read(1),b'','kernel request contains undeclared trailing bytes')
        exact(row['request_sha256'],h.hexdigest(),'kernel request digest differs');exact(row['request_bytes'],size,'kernel request extent differs')
        actual=read(entry/'stdout.bin');err=read(entry/'stderr.bin');trace=obj(entry/'trace.json')
        for name,raw,digest,length in [('stdout.bin',actual,'stdout_sha256','stdout_bytes'),('stderr.bin',err,'stderr_sha256','stderr_bytes')]:
            exact(row[digest],sha(raw),'kernel retained stream differs');exact(row[length],len(raw),'kernel retained stream length differs')
        exact(err,b'','successful kernel qualification emitted stderr');exact(row['exit_code'],0,'kernel process did not complete')
        exact(row['stdout_hex'],actual.hex(),'actual kernel response text differs');exact(row['trace'],trace,'retained raw syscall trace changed')
        answers=records(actual);exact(len(answers),case.get('requests',1),'kernel response omitted')
        requests+=len(answers);all_output.update(actual);output_bytes+=len(actual)
        exact(trace['status'],'PASS','kernel supervisor did not pass');exact(trace['failure'],None,'kernel supervision failed')
        exact(trace['exit_code'],0,'supervised writer did not complete');exact(trace['config'],case['config'],'kernel fault domain changed')
        exact(trace['executable_sha256'],binary_sha,'supervisor executed a different artifact')
        exact(trace['stdout_sha256'],sha(actual),'supervised stdout differs');exact(trace['stderr_sha256'],sha(err),'supervised stderr differs')
        require(0<trace['elapsed']<15,'kernel invocation missed its retained deadline')
        require(set(trace['memory_readers'])<={'owned-process-vm-readv','owned-proc-mem-pread'},
                'undeclared process-memory observer')
        if case['name'] in ('nul-filename','nul-parent'):
            exact(trace['events'],[],'NUL path reached a kernel effect')
            # The observer may have read a Rust dynamic-loader path before
            # classifying it outside the owned fixture. That is independent
            # of the required absence of atomic-write filesystem effects.
        else:require(bool(trace['memory_readers']),'actual owned process memory observation missing')
        counts=collections.Counter()
        faults={(f['kind'],f.get('ordinal',1)):f for f in case['config'].get('faults',[])};reached=set()
        for event in trace['events']:
            counts[event['kind']]+=1;exact(event['ordinal'],counts[event['kind']],'syscall event ordinal omitted')
            key=(event['kind'],event['ordinal'])
            if key in faults:
                fault=faults[key];reached.add(key)
                if 'errno' in fault:
                    exact(event['completion'],'injected_errno_without_kernel_effect','declared errno injection missing')
                    exact(event['errno'],fault['errno'],'injected errno changed')
                else:
                    exact(event['completion'],'injected_zero_without_kernel_effect','declared zero injection missing')
                    exact(event['returned'],0,'injected zero changed')
            else:exact(event['completion'],'kernel_continue','undeclared simulated kernel completion')
        exact(dict(counts),trace['counts'],'complete kernel event count differs');exact(reached,set(faults),'declared fault was not reached')
        if 'cancel' in case['config']:
            exact(answers[0],(0xfffffff7,b''),'original cancellation result changed')
            exact(trace['cancel_ack']['worker_syscall_still_held'],True,'cancellation did not precede blocked worker release')
            matches=[e for e in trace['events'] if e.get('cancel_acknowledged_before_kernel_release') is True]
            exact(len(matches),1,'held cancellation event missing')
        else:exact(trace['cancel_ack'],None,'unrequested cancellation occurred')
        fixture=Path(row['fixture_path']);normalized_row=case_module.normalized_trace(trace,fixture)
        exact(row['normalized_trace'],normalized_row,'kernel normalization omitted an event')
        exact(row['semantic_snapshot'],case_module.semantic_snapshot(row['before'],row['after'],result['execution_uid'],result['execution_gid']),
              'filesystem state projection differs')
        custody=identity_custody(obj(entry/'identity-custody.json'),row['before'])
        exact(row['identity_custody'],custody,'retained inode lifetime receipt differs')
        for name in ('before','after'):
            payloads,total=snapshot_contents(entry,name+'-content',row[name]);content_bytes+=total
            files.update({label+'/'+n:v for n,v in payloads.items()})
        exact(obj(entry/'observation.json'),row,'individual kernel observation changed')
        for name in ('request.bin.gz','stdout.bin','stderr.bin','trace.json','observation.json','config.json','identity-custody.json'):
            files[label+'/'+name]=file_record(entry/name)
        exact(obj(entry/'config.json'),case['config'],'retained kernel configuration changed')
        normalized.append({'name':case['name'],'stdout_hex':actual.hex(),'semantic_snapshot':row['semantic_snapshot'],'trace':normalized_row})
    for key,wanted in {'requests':requests,'requests_bytes':input_bytes,'requests_sha256':all_input.hexdigest(),
                       'outputs_bytes':output_bytes,'outputs_sha256':all_output.hexdigest()}.items():
        exact(result[key],wanted,'complete kernel aggregate differs: '+key)
    if artifact is not None:
        exact(result['artifact_evidence'],artifact,'actual kernel bundle receipt differs')
        exact(result['wrapper_source'],file_record(root/'tests/hia_native/test_atomic_write_kernel.py'),'kernel wrapper source changed')
    answer={'status':'PASS','cases':151,'requests':171,'source_files':result['source_files'],'files':files,
      'normalized_sha256':sha(canonical(normalized)),'retained_content_bytes':content_bytes,
      'requests_sha256':all_input.hexdigest(),'requests_bytes':input_bytes,'outputs_sha256':all_output.hexdigest(),'outputs_bytes':output_bytes,
      'observations':observations}
    if stdout is not None:answer['completed_stdout']=completed_stdout(result,stdout,omit_observations=True)
    return answer

def boundary_evidence(directory,bundle,*,source_root=ROOT,stdout=None):
    directory=Path(directory);root=Path(source_root);value=obj(directory/'result.json')
    for key,wanted in {'schema':'hepta.runtime.atomic-write-boundary-suite.v1','status':'PASS','artifact_evidence':bundle,
      'contract_requests':19,'contract_effects':38,'transport_processes':8,'parent_death_processes':1,'original_rust_calls':0,
      'actual_elf_processes':28,'actual_contract_refusals':19,'actual_owned_worker_deaths':1,'production_activated':False,'whole_runtime_replaced':False}.items():
        exact(value.get(key),wanted,'boundary qualification differs: '+key)
    require(0<value['elapsed']<180,'boundary suite missed unchanged deadline')
    names={'tests/hia_native/test_atomic_write_boundary.py','tests/hia_native/atomic_write_contract_probe.hepta',
      'tests/hia_native/atomic_write_supervisor.py','tests/hia_native/atomic_write_harness.py','tests/hia_native/atomic_write_cases.py'}
    exact(set(value['source_files']),names,'boundary execution source set differs')
    exact(value['source_files'],{p:file_record(root/p) for p in names},'boundary execution sources changed')
    source=read(root/'tests/hia_native/atomic_write_contract_probe.hepta');exact(sha(source),PROBE_SOURCE,'fixture HIA source changed')
    compiled=directory/'probe-compile';image=read(compiled/'module.image.bin');exact(sha(image),PROBE_IMAGE,'fixture actual image differs')
    receipt=native_receipt(compiled,'module',source=source,produced=image,producer=COMPILER)
    exact(obj(compiled/'build.json')['compile_receipt'],receipt,'fixture compile receipt differs')
    exact(sha(canonical(obj(compiled/'build.json')['compiler_dependency'])),DEPENDENCY,'fixture compiler dependency differs')
    exact(read(compiled/'source.hepta'),source,'fixture compiled source differs')
    fixture=value['fixture'];exact(fixture['compilation'],{n:file_record(compiled/n) for n in (*COMPILE_FILES,'source.hepta')},'fixture compilation files changed')
    packed=directory/'probe-pack';elf=read(packed/'probe.elf');inspection=inspect_elf(elf,image)
    for key,wanted in {'source_sha256':PROBE_SOURCE,'image_sha256':PROBE_IMAGE,'executable_sha256':sha(elf),'inspection':inspection}.items():
        exact(fixture[key],wanted,'actual fixture embedding differs')
    pack_frame=b'HIAATPK1'+struct.pack('<Q',len(image))+image
    native_receipt(packed,'pack',source=pack_frame,produced=elf,producer=PACKER_IMAGE)
    exact(fixture['pack_files'],{n:file_record(packed/n) for n in (*PACK_FILES,'probe.elf')},'fixture native packing files changed')
    rows=value['observations'];exact(len(rows),28,'boundary observation omitted')
    files={'result.json':file_record(directory/'result.json')}
    for index,row in enumerate(rows):
        if index<19:
            exact(row['kind'],index,'contract refusal ordinal omitted');entry=directory/f'contract-{index:02d}'
            trace=obj(entry/'trace.json');exact(row['trace'],trace,'actual descriptor trace changed')
            exact(trace['executable_sha256'],sha(elf),'contract refusal used a different executable')
            exact(trace['failure'],None,'contract-refusal supervisor failed');exact(trace['exit_code'],70,'contract refusal did not terminate')
            exact(trace['counts'],{'open':1,'close':1},'contract refusal leaked or reclosed a descriptor')
            exact([e['kind'] for e in trace['events']],['open','close'],'contract refusal performed an additional effect')
            exact([e['completion'] for e in trace['events']],['kernel_continue','kernel_continue'],'descriptor recovery was simulated')
            exact(read(entry/'input.bin'),struct.pack('<Q',73)+struct.pack('<Q',index)+bytes(62)+b'abc','invalid-effect input differs')
            exact(obj(entry/'config.json'),{},'contract refusal acquired injected effects')
            exact(row['exit_code'],70,'invalid-effect process did not exit')
            exact(read(entry/'stdout.bin'),struct.pack('<I',0xfffffff9),'contract refusal emitted payload')
        elif index<27:
            name=['empty','short-length','short-frame','over-capacity','empty-frame','bad-frame','extra-argument','invalid-recovery'][index-19]
            exact(row['transport'],name,'transport control omitted');entry=directory/('transport-'+name)
            expected_codes=[0,74,74,3,0,0,64,0];exact(row['exit_code'],expected_codes[index-19],'transport terminal status differs')
            requests=[b'',bytes(7),struct.pack('<Q',64)+bytes(10),struct.pack('<Q',(512<<20)+1),struct.pack('<Q',0),
              stream([bytes(64)]),b'',stream([bytes(64),frame(b'target',b'after')])]
            outputs=[b'',b'',b'',struct.pack('<I',0xfffffffe),struct.pack('<I',0xffffffff),struct.pack('<I',0xffffffff),b'',
              struct.pack('<I',0xffffffff)+struct.pack('<I8s3Q',32,b'HRAWR001',0,0,0)]
            exact(read(entry/'input.bin'),requests[index-19],'actual native transport input differs')
            exact(read(entry/'stdout.bin'),outputs[index-19],'actual native transport response differs')
        else:
            entry=directory/'parent-death';trace=obj(entry/'trace.json')
            exact(row['parent_death'],trace,'actual parent-death trace differs')
            exact(trace['failure'],None,'parent-death supervision failed')
            exact(trace['executable_sha256'],bundle['executable']['sha256'],'parent-death control used a different executable')
            death=trace['parent_death']
            for key,wanted in {'exit_code':-9,'reaped':True,'blocked_effect_completed':False,'parent_exit_code':-9}.items():
                exact(death[key],wanted,'parent-death ownership differs')
            exact(trace['counts'],{'statx':1,'open':1,'write':1},'parent-death effect sequence differs')
            exact([e['completion'] for e in trace['events']],['kernel_continue','kernel_continue','owned_parent_killed_before_kernel_release'],
                  'held syscall was falsely recorded as executed')
            exact(read(entry/'input.bin'),stream([frame(b'target',b'pending')]),'parent-death request differs')
            exact(obj(entry/'config.json'),{'kill_parent':{'kind':'write'}},'parent-death ownership control differs')
            exact(read(entry/'stdout.bin'),b'','killed parent published a response')
        wanted_files={'input.bin','stdout.bin','stderr.bin'}
        if index<19 or index==27:
            wanted_files|={'config.json','trace.json'}
            exact(trace['stdout_sha256'],sha(read(entry/'stdout.bin')),'actual refusal trace stdout differs')
            exact(trace['stderr_sha256'],sha(read(entry/'stderr.bin')),'actual refusal trace stderr differs')
            require(0<trace['elapsed']<5,'boundary invocation missed unchanged deadline')
            after={r['path']:r for r in row['after']}
            exact(set(after),{'',b'target'.hex(),b'.octofs_tmp_target.tmp'.hex()},'contract cleanup created another file')
            for path,data in ((b'target',b'original'),(b'.octofs_tmp_target.tmp',b'')):
                state=after[path.hex()]
                require(stat.S_ISREG(state['mode']),'contract cleanup changed the file kind')
                exact(state['content_sha256'],sha(data),'contract cleanup changed file content')
                exact(state['content_bytes'],len(data),'contract cleanup file size differs')
        exact(set(row['files']),wanted_files,'actual boundary evidence file omitted')
        exact(row['files'],{n:file_record(entry/n) for n in row['files']},'actual boundary files changed')
        exact(read(entry/'stderr.bin'),b'','boundary control emitted an unaccounted error')
        files.update({entry.name+'/'+n:v for n,v in row['files'].items()})
    answer={'status':'PASS','actual_elf_processes':28,'contract_refusals':19,'worker_deaths':1,'files':files,
      'fixture':fixture,'result':file_record(directory/'result.json')}
    if stdout is not None:answer['completed_stdout']=completed_stdout(value,stdout,omit_observations=True)
    return answer

def evidence(bundle_path,policy_dir,kernel_dir,boundary_dir,*,source_root=ROOT,reference_root=None,hepta=None,
             policy_stdout=None,kernel_stdout=None,boundary_stdout=None):
    require(all(p is not None for p in (policy_stdout,kernel_stdout,boundary_stdout)),
            'qualification requires the actual completed stdout of all three native processes')
    root=Path(source_root);reference=Path(reference_root or root)
    closure=source_contract(root,reference,hepta);source_files=pins(root,reference)
    artifact=inspect_bundle(bundle_path,source_root=root)
    policy=policy_evidence(policy_dir,artifact,source_root=root,stdout=policy_stdout)
    kernel=kernel_evidence(kernel_dir,artifact['executable']['sha256'],source_root=root,stdout=kernel_stdout,artifact=artifact)
    boundary=boundary_evidence(boundary_dir,artifact,source_root=root,stdout=boundary_stdout)
    exact(pins(root,reference),source_files,'atomic qualification source closure changed')
    return {'schema':'hepta.runtime.atomic-write-qualification.v1','status':'PASS','source_contract':closure,'source_files':source_files,
      'artifact':artifact,'policy':policy,'kernel':{k:v for k,v in kernel.items() if k!='observations'},'boundary':boundary,
      'original_rust_status':'PENDING','complete_original_tool_parity':False,'remote_ssh_parity':False,
      'production_activated':False,'whole_runtime_replaced':False}
def original_comparison_evidence(directory,bundle_path,policy_corpus,*,source_root=ROOT,reference_root=None,stdout):
    """Inspect a retained completed execution; this function does not run Rust."""
    directory=Path(directory);root=Path(source_root);reference=Path(reference_root or root)
    value=obj(directory/'result.json');before=pins(root,reference)
    artifact=inspect_bundle(bundle_path,source_root=root)
    fixed={'schema':'hepta.runtime.atomic-write-original-comparison.v2','status':'PASS','artifact_evidence':artifact,
      'source_files':before['owner'],'original_source_sha256':ORIGINAL_SHA,'original_owner_sha256':ORIGINAL_OWNER,
      'original_error_display_property_rows':4095,'original_nul_and_writezero_properties':2,
      'kernel_cases':151,'kernel_requests':171,'complete_actual_kernel_comparisons':151,'rust_path_cases':88807,
      'original_atomic_write_requests':171,'local_linux_gnu_only':True,'remote_ssh_parity':False,
      'production_activated':False,'whole_runtime_replaced':False}
    for key,wanted in fixed.items():exact(value.get(key),wanted,'completed original comparison differs: '+key)
    require(0<value['elapsed']<180,'original replay missed its unchanged outer deadline')
    raw=read(reference/'src/mcp/fs/text_editing.rs');exact(sha(raw),ORIGINAL_SHA,'original source changed')
    begin=raw.index(b'pub async fn atomic_write(');end=raw.index(b'\nconst LF_ENDING:',begin);owner=raw[begin:end]
    execution=Path(value['execution_directory']);source=Path(value['execution_source_root']);ref=Path(value['execution_reference_root'])
    require(all(p.is_absolute() for p in (execution,source,ref)),'original execution identities missing')
    require(type(value['offline'])is bool,'original Cargo mode missing')
    cleared=['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC_BOOTSTRAP']
    exact(value['cleared_environment_names'],cleared,'original compile environment policy changed')
    removed=value['removed_environment_names'];exact(removed,sorted(set(removed)),'original environment observation is not complete')
    require(set(removed)<=set(cleared),'original compile removed undeclared environment names')
    compiler=Path(value['rustc']['path']);cargo=Path(value['cargo']['path'])
    require(compiler.is_absolute() and cargo.is_absolute(),'actual Rust tool identities missing')
    for tool in ('rustc','cargo'):
        record=value[tool]
        require(type(record['bytes'])is int and record['bytes']>0 and len(bytes.fromhex(record['sha256']))==32,'invalid actual Rust tool identity')
    exact(value['environment'],{'RUSTC':str(compiler),'CARGO_TARGET_DIR':str(execution/'target'),
      'HIA_REFERENCE_RUNTIME':str(ref),'TMPDIR':str(execution/'tmp')},'original build did not use its owned paths')
    original=directory/'target/release/hia-atomic-write-original'
    exact(file_record(original),value['original_binary'],'actual original binary changed')
    exact(value['native_binary'],artifact['executable'],'actual native writer identity differs')
    exact(value['native_manifest'],artifact['manifest'],'actual native bundle identity differs')
    copied=value['compiled_original_owner'];relative=Path(copied['file'])
    require(not relative.is_absolute() and '..' not in relative.parts and len(relative.parts)==6 and
      relative.parts[:3]==('target','release','build') and relative.parts[3].startswith('hia-atomic-write-original-') and
      relative.parts[-2:]==('out','atomic_write_original.rs'),'compiled original owner escaped the owned target')
    exact(read(directory/relative),owner,'the actual original build compiled a different function')
    exact({k:copied[k] for k in ('bytes','sha256')},file_record(directory/relative),'compiled original owner digest differs')
    version=read(directory/'rustc-version.stdout').decode()
    exact(version,value['rustc']['version'],'actual original compiler version stream differs')
    require(version.startswith('rustc 1.95.0 ') and '\nrelease: 1.95.0\n' in version and
      '\nhost: x86_64-unknown-linux-gnu\n' in version,'original std/Linux-GNU identity differs')
    build=[str(cargo),'build','--release','--locked','--manifest-path',str(source/'tests/hia_native/atomic_write_oracle/Cargo.toml')]
    if value['offline']:build.append('--offline')
    step_specs=[('rustc-version',[str(compiler),'-Vv'],10),('original-build',build,120),
      ('original-properties',[str(execution/'target/release/hia-atomic-write-original'),'--properties'],10),
      ('original-path',[str(execution/'target/release/hia-atomic-write-original')],30)]
    exact(len(value['steps']),4,'a required actual original process was omitted')
    files={'result.json':file_record(directory/'result.json'),'original-binary':file_record(original),str(relative):file_record(directory/relative)}
    for record,(name,argv,budget) in zip(value['steps'],step_specs,strict=True):
        exact(set(record),{'name','argv','timeout','exit_code','elapsed','stdout','stderr'},'original process completion field set differs')
        for key,wanted in {'name':name,'argv':argv,'timeout':budget,'exit_code':0}.items():
            exact(record.get(key),wanted,'actual original process differs: '+name+'/'+key)
        require(0<record['elapsed']<budget,'original child process exceeded its unchanged deadline')
        for channel in ('stdout','stderr'):
            filename=name+'.'+channel;actual=file_record(directory/filename)
            exact(record[channel],actual,'actual original process stream changed');files[filename]=actual
    exact(read(directory/'original-properties.stdout'),read(root/'tests/hia_native/atomic_write_rust_io_properties.txt'),
      'actual Rust errno/NUL/WriteZero property output changed')
    for name in ('rustc-version','original-properties','original-path'):
        exact(read(directory/(name+'.stderr')),b'','original replay emitted an unaccounted diagnostic')
    for filename,(digest,size) in [('path-requests.bin',PATH_INPUT),('path-native.bin',PATH_OUTPUT),('original-path.stdout',PATH_OUTPUT)]:
        actual=file_record(directory/filename);exact(actual,{'bytes':size,'sha256':digest},'full original path replay changed')
        files[filename]=actual
    exact(value['path'],{'status':'PASS','cases':88807,'requests':{'bytes':PATH_INPUT[1],'sha256':PATH_INPUT[0]},
      'output':{'bytes':PATH_OUTPUT[1],'sha256':PATH_OUTPUT[0]}},'original Path replay domain differs')
    policy=policy_evidence(policy_corpus,artifact,source_root=root)
    exact(value['policy_evidence'],policy,'original replay consumed a different native policy corpus')
    native=kernel_evidence(directory/'native-kernel',artifact['executable']['sha256'],source_root=root)
    rust=kernel_evidence(directory/'original-kernel',value['original_binary']['sha256'],source_root=root)
    for name,observed in (('native',native),('original',rust)):
        stripped={key:item for key,item in observed.items() if key!='observations'}
        exact(value['kernel_evidence'][name],stripped,'retained complete kernel evidence differs')
        receipt=obj(directory/(name+'-kernel')/'result.json')
        exact(value[name+'_kernel'],{key:item for key,item in receipt.items() if key!='observations'},'original result omitted kernel completion')
        files.update({name+'-kernel/'+key:item for key,item in observed['files'].items()})
    retirement=original_fixture_retirement(directory,value['kernel_evidence'])
    exact(value['fixture_retirement'],retirement,'original live-target retirement differs')
    files['retired-fixtures.json']=file_record(directory/'retired-fixtures.json')
    for left,right in zip(native['observations'],rust['observations'],strict=True):
        for field in ('name','request_bytes','request_sha256','stdout_hex','semantic_snapshot','normalized_trace'):
            exact(left[field],right[field],'actual original atomic_write differs: '+left['name']+'/'+field)
    exact(json.loads(read(directory/'mismatches.json')),[],'original writer had a retained mismatch')
    files['mismatches.json']=file_record(directory/'mismatches.json')
    exact(pins(root,reference),before,'original comparison sources changed during evidence inspection')
    return {'schema':'hepta.runtime.atomic-write-original-evidence.v1','status':'PASS',
      'evidence_kind':'retained_completed_original_execution','completed_stdout':completed_stdout(value,stdout),
      'source_files':before,'artifact':artifact,'files':files,'rust_path_cases':88807,
      'original_atomic_write_requests':171,'kernel_state_and_trace_comparisons':151,
      'original_error_display_property_rows':4095,'original_nul_and_writezero_properties':2,
      'local_linux_gnu_only':True,'remote_ssh_parity':False,'production_activated':False,'whole_runtime_replaced':False}
def controls_evidence(directory,qualification,*,source_root=ROOT,reference_root=None,stdout):
    directory=Path(directory);root=Path(source_root);reference=Path(reference_root or root)
    value=obj(directory/'result.json')
    fixed={'schema':'hepta.runtime.atomic-write-evidence-controls.v1','status':'PASS','source_files':pins(root,reference),
      'fresh_native_invocations':0,'fresh_original_rust_invocations':0,'artifact_evidence':qualification['artifact'],
      'test_groups':4,'accepted_complete_native_receipts':1,'negative_controls':34,
      'actual_native_calls_recounted':170947,'actual_kernel_cases_recounted':151,'actual_elf_boundary_processes_recounted':28,
      'production_activated':False,'whole_runtime_replaced':False}
    for key,wanted in fixed.items():exact(value.get(key),wanted,'actual evidence-control completion differs: '+key)
    require(0<value['elapsed']<180,'evidence controls exceeded the unchanged suite deadline')
    exact(obj(directory/'native-evidence.json'),qualification,'evidence controls accepted another qualification')
    exact(value['native_evidence'],file_record(directory/'native-evidence.json'),'accepted complete receipt changed')
    names=['compiler-pin','native-capacity','runtime-fallback-claim','missing-compile-file','module-profile','module-compiler',
      'consistently-rehashed-policy-image','consistently-rehashed-fixed-boundary','consistently-rehashed-compiler-output-tail',
      'compiler-stderr','compiler-dependency','packer-source-protection','native-invocation-workspace',
      'omitted-path-domain','synthetic-as-real-kernel','actual-native-call-count','incomplete-path-requests.bin.gz',
      'incomplete-path-native-output.bin.gz','incomplete-contracts.jsonl.gz','omitted-real-kernel-case',
      'omitted-blocked-signal-domain','wrong-kernel-executable','omitted-kernel-observation','invented-file-state',
      'actual-kernel-stdout-tamper','full-file-content-tamper','omitted-actual-contract-refusal','omitted-parent-death',
      'omitted-boundary-stream','invented-refusal-file-state','transport-success-for-invalid-frame','unreaped-parent-death',
      'fabricated-completed-policy-stdout','missing-completed-process-stdout']
    exact([c['name'] for c in value['controls']],names,'actual refusal control omitted')
    for row in value['controls']:
        exact(set(row),{'name','status','reason'},'refusal control report differs')
        exact(row['status'],'REFUSED','a mutated receipt was accepted')
        require(type(row['reason'])is str and bool(row['reason']),'actual refusal diagnostic missing')
    return {'schema':'hepta.runtime.atomic-write-control-evidence.v1','status':'PASS',
      'test_groups':4,'negative_controls':34,'fresh_native_invocations':0,'fresh_original_rust_invocations':0,
      'source_files':value['source_files'],'result':file_record(directory/'result.json'),
      'accepted_native_evidence':file_record(directory/'native-evidence.json'),'completed_stdout':completed_stdout(value,stdout)}
