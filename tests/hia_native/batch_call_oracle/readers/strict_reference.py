"""Strict pure admission of an unchanged Rust Batch replay and its native predecessor.

All public parameters name execution-origin paths. The explicit origin mapper
selects retained read roots; there is no fallback to a live fixture or old root.
No native code, Rust program, or filesystem fixture is executed by this reader.
"""
from pathlib import Path
import importlib.util
import io
import json
import os
import re
import struct
import sys
from capture_format import Files,actual_process,blob,canonical,fields,need,parse_records,pin,same,sha,strict_json,uint
import native_predecessor
import retained_comparison
import trace_evidence

SOURCE_PINS = json.loads(r'''{"PROTOCOL.md":{"bytes":5292,"sha256":"0149b69547043116f03da6b1551733bc7c48b6fe50cc0457ce67c41bd44db485"},"capture_format.py":{"bytes":7701,"sha256":"1d1a2ee15ce58b28f285bd24a5103ed654940ce4829a55cf4b6e40a112623fd9"},"cases.py":{"bytes":13241,"sha256":"6288fc54dbef5786fb867c5255996808316fba41c752568eaf65bc45ed912b21"},"control_inputs.py":{"bytes":1098,"sha256":"0144beec3a1b22a11027278f81658f56bf96b38bbb24c3f200900c1d7dbcabd1"},"native_predecessor.py":{"bytes":58392,"sha256":"6db3c8e36c7cbbb60454ee8851db3bb84400ee5688969ceee4ba580ec9b5eee0"},"oracle/Cargo.lock":{"bytes":19709,"sha256":"0df4a30a64d6715cd19eae658549dfa39238d6f007ad48762488926879ba080c"},"oracle/Cargo.toml":{"bytes":562,"sha256":"574543031ac035a8854d6938fcdea635baf0719ec1c682a0d4245ec819aa4db4"},"oracle/original/Cargo.lock":{"bytes":90148,"sha256":"7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43"},"oracle/original/Cargo.toml":{"bytes":4157,"sha256":"377e7dca547f0ff0d832fb28cf01862a6d84b4b6ed42c8b36dae9075cbbbb78f"},"oracle/original/config.rs":{"bytes":25272,"sha256":"228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35"},"oracle/original/core.rs":{"bytes":26443,"sha256":"51c9a864c6b18ac43957cf3e6c74b07d8ee8952e0589b68e1051e976c1dd09ec"},"oracle/original/delta.rs":{"bytes":9765,"sha256":"a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1"},"oracle/original/effect_owner_fence.rs":{"bytes":23890,"sha256":"1e2f2cd32289cd93915076981436b79c04a2756dfc184fa219f043a88f907207"},"oracle/original/line_hash.rs":{"bytes":9153,"sha256":"904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57"},"oracle/original/mcp_mod.rs":{"bytes":3316,"sha256":"9e9b7933372418ef361f85d64a1d36567618b13ae77c45d16df16799231b690c"},"oracle/original/remote.rs":{"bytes":48174,"sha256":"d87cae1d18cfaf3479cc94e0df8c8c6eefe5d2eec34f62b7ba0f0c4693704d8c"},"oracle/original/remote_unavailable.rs":{"bytes":1431,"sha256":"727d612dfccd5a7ecd83258f14507f0c97a3d7640c6f7706d5e33a38c4566ad5"},"oracle/original/request_ctx.rs":{"bytes":2860,"sha256":"81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943"},"oracle/original/server.rs":{"bytes":178908,"sha256":"ea43d13d2e870188abc33afca771eb3f5ecacdf982a56467c7b7c2fa0fa81d0d"},"oracle/original/text_editing.rs":{"bytes":63372,"sha256":"e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590"},"oracle/original/truncation.rs":{"bytes":4492,"sha256":"3967bee0b0a897d470737c64dd735ee8f206c00d87f3778dee212f326334283e"},"oracle/src/context_observer.rs":{"bytes":310,"sha256":"0e7b8eb6f4e279e1087346bce35eb7589bf732cc920965b60b6aa800e7c1c76c"},"oracle/src/delta_observer.rs":{"bytes":424,"sha256":"edc615a03fc6dace620173bf0ed030e4c6208dc15008c735568939e3eeb12cde"},"oracle/src/driver.rs":{"bytes":22465,"sha256":"99d151068765368db7a38bca2bb193449b05cc570e003a0afebaf82d3e05767c"},"oracle/src/editing_observer.rs":{"bytes":750,"sha256":"8cf8a85ca17e4fc8e5abfbac6e86a3029efdaed17db8f71a9806df966b3d03d8"},"oracle/src/observe.rs":{"bytes":12399,"sha256":"08e16f67890d37c078c6388e67f1352b8980b0cd88991fd9fa221c9cd104f54e"},"oracle/src/observed_tokio.rs":{"bytes":4052,"sha256":"1d525c6d309cb82bb0b6e21d09f24703388153a6defc119a62ffb145dbbba052"},"oracle/src/public_driver.rs":{"bytes":10452,"sha256":"466e6908b5994714549b5f6864b0c7f087b75f75a27ee18374c93d41f6e22b2b"},"oracle/verify_sources.py":{"bytes":10561,"sha256":"60bb28e4ae4ccf328cf53030c7efb53a5b71d835bb19bf730053572e422179da"},"public_cases.py":{"bytes":10335,"sha256":"dff26bd6a93b5dc2e0e5743f4f94831acd2fe9786a56d8528c77426240b64912"},"run.py":{"bytes":17785,"sha256":"181fd51b95733125072cc399a9a465b2ba505e26b9257ba653b975fe289a7e9e"}}''')
TRACE = ('getpgid,openat,read,readv,pread64,write,writev,close,newfstatat,fstat,statx,'
         'readlink,readlinkat,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,'
         'chmod,fchmod,fchmodat,clone,clone3,wait4,fcntl,lseek,fsync,fdatasync')
PARTITIONS = ('small','wide','async')
PROCESS_FIELDS = ('name','command','cwd','pid','started_monotonic_ns','finished_monotonic_ns',
    'elapsed_seconds','timeout_seconds','exit_code','timed_out','start_error','umask',
    'proc_status_at_start','controlled_env','stdin','stdout','stderr')
RESULT_FIELDS = ('actual_processes','binary','captures','cases','finished_monotonic_ns',
    'fixture_origins_retired','fresh_locked_builds','full_input_and_result_bytes_retained',
    'native_original_comparison_complete','native_predecessor','new_native_calls',
    'original_full_router_executed','original_inner_execute_batch_edit_executed',
    'original_outer_batch_method_executed','original_replay_processes','original_sdk_executed',
    'post_cancel_followup_calls','public_handler_replaced','schema','source','source_files',
    'source_unchanged','started_monotonic_ns','status','toolchain','trace_payloads_may_be_clipped',
    'trace_string_limit','whole_runtime_replaced')


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_pin(files,path):
    raw=files.raw(str(path))
    return {'bytes':len(raw),'sha256':sha(raw)}


def bound_file(files,value,expected_path):
    fields(value,('path','bytes','sha256'),'complete retained stream descriptor')
    same(value['path'],str(expected_path),'recorded retained stream location')
    raw=files.raw(str(expected_path))
    same({k:value[k] for k in ('bytes','sha256')},{'bytes':len(raw),'sha256':sha(raw)},
         'complete retained process/artifact stream')
    return raw


def source_evidence(files,source,output,result):
    table=files.json(str(output/'SOURCE-FILES.json'))
    same(table,SOURCE_PINS,'exact unchanged original execution source closure')
    same(result['source_files'],table,'capture original source identities')
    for name,expected in table.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'original source escape')
        same(file_pin(files,source/name),expected,'complete pinned original source '+name)
    verifier=load(files.path(str(source/'oracle/verify_sources.py')),'_batch_bound_source_materializer')
    materialized,proof=verifier.assemble(files.path(str(source/'oracle/verify_sources.py')).parent)
    same(len(proof['unchanged_spans']),25,'all unchanged original spans')
    same(len(proof['unchanged_whole_modules']),8,'all unchanged original modules')
    same(proof['registry_dependencies'],82,'exact locked upstream registry dependencies')
    same(files.json(str(output/'SOURCE.json')),proof,'independent source materialization proof')
    same(result['source'],file_pin(files,output/'SOURCE.json'),'complete original source proof bytes')
    for name,body in materialized.items():
        same(files.raw(str(output/'crate'/name)),body,'unchanged materialized crate full bytes '+name)
    return proof


def selected_tools(files,source,output,result):
    tools=files.json(str(output/'TOOLCHAIN.json'))
    fields(tools,('cargo','rustc','strace'),'selected original tools')
    same(result['toolchain'],tools,'capture selected tools')
    for name,value in tools.items():
        fields(value,('invocation','resolved_path','retained','bytes','sha256'),'complete selected executable')
        need(Path(value['invocation']).is_absolute() and Path(value['resolved_path']).is_absolute(),
             'relative selected executable')
        same(value['retained'],str(output/'tools'/name),'retained selected executable location')
        same(file_pin(files,output/'tools'/name),{k:value[k] for k in ('bytes','sha256')},
             'complete selected executable bytes')
    cargo,rustc,tracer=[tools[name]['invocation'] for name in ('cargo','rustc','strace')]
    need(Path(cargo).parent==Path(rustc).parent,'Cargo/rustc are not one explicit toolchain')
    env={'PATH':str(Path(cargo).parent)+':/usr/bin:/bin','RUSTC':rustc,'CARGO_BUILD_JOBS':'2',
         'CARGO_TARGET_DIR':str(output/'target'),'LC_ALL':'C'}
    return tools,env


def actual_original_processes(files,source,output,result,tools,env,admission,outer_pid):
    rows=files.json(str(output/'processes.json'))
    names=['rustc-version','cargo-version','strace-version','build',
           'original-small','original-wide','original-async']
    same([r['name'] for r in rows],names,'complete exact original process sequence')
    cargo,rustc,tracer=[tools[name]['invocation'] for name in ('cargo','rustc','strace')]
    commands=[[rustc,'--version','--verbose'],[cargo,'--version','--verbose'],[tracer,'-V'],
              [cargo,'build','--locked','--release','--manifest-path',str(output/'crate/Cargo.toml')]]
    for part in PARTITIONS:
        fixture=Path(admission['native_run'])/('output-'+part)/'files'
        commands.append([tracer,'-f','-qq','-ttt','-T','-s','128','-xx','-yy','-e','trace='+TRACE,
            '-o',str(output/part/'strace.log'),'--',str(output/'reference.elf'),'--inner',str(fixture)])
    prior=uint(admission['admitted_monotonic_ns'],'native admission completed clock')
    ids=[]
    bodies={}
    for row,name,command in zip(rows,names,commands):
        fields(row,PROCESS_FIELDS,'complete actual original process fields')
        actual_process(row,command,source)
        same(row['controlled_env'],env,'actual controlled original environment')
        same(files.json(str(output/'processes'/name/'process.json')),row,
             'individual and aggregate actual process receipt')
        need(row['started_monotonic_ns']>prior,'original process ran before complete predecessor admission')
        prior=row['finished_monotonic_ns']
        ids.append(row['pid'])
        stdout=bound_file(files,row['stdout'],output/'processes'/name/'stdout')
        stderr=bound_file(files,row['stderr'],output/'processes'/name/'stderr')
        if name!='build':same(stderr,b'','unexpected original process stderr')
        if name.startswith('original-'):
            part=name[len('original-'):]
            bound_file(files,row['stdin'],output/part/'input.bin')
            mask=uint(row['umask'],'original actual selected umask')
            need(mask<=0o777,'invalid selected umask')
            status=bound_file(files,row['proc_status_at_start'],output/'processes'/name/'proc-status-at-start.txt')
            native_predecessor.proc_identity(status,pid=row['pid'],parent=outer_pid,umask=mask)
        else:
            need(row['stdin'] is None and row['umask'] is None and row['proc_status_at_start'] is None,
                 'tool identity/build receipt gained fabricated fixture fields')
        bodies[name]=(stdout,stderr)
    need(len(ids)==len(set(ids)),'reused actual original process PID')
    rust_version=bodies['rustc-version'][0]
    need(re.fullmatch(rb'rustc 1\.95\.0 \([^\n]+\)\nbinary: rustc\ncommit-hash: [0-9a-f]{40}\n'
                     rb'commit-date: [0-9-]+\nhost: x86_64-unknown-linux-gnu\nrelease: 1\.95\.0\n'
                     rb'LLVM version: [0-9.]+\n',rust_version) is not None,'actual fixed Rust 1.95 identity')
    need(bodies['cargo-version'][0].startswith(b'cargo 1.95.0 ') and
         b'\nhost: x86_64-unknown-linux-gnu\n' in bodies['cargo-version'][0],
         'actual selected Cargo target/version')
    need(bodies['strace-version'][0].startswith(b'strace -- version '),'actual retained tracer version')
    same(bodies['build'][0],b'','unexpected build stdout')
    build_log=bodies['build'][1]
    need(b'Finished ' in build_log and b'release' in build_log and b'hepta-batch-call-original' in build_log and
         b'error: could not compile' not in build_log,'actual fresh locked build did not finish')
    info=files.json(str(output/'target.rustc_info.json'))
    fields(info,('rustc_fingerprint','outputs','successes'),'fresh target compiler cache record')
    uint(info['rustc_fingerprint'],'actual rustc target fingerprint')
    versions=[x for x in info['outputs'].values() if x.get('stdout','').startswith('rustc ')]
    need(len(versions)==1,'fresh target compiler identity is ambiguous')
    same(versions[0]['stdout'].encode(),rust_version,'fresh Cargo target actual compiler version')
    for value in info['outputs'].values():
        need(value['success'] is True and value['code']==0 and value['stderr']=='',
             'fresh target compiler query failed')
    return rows,bodies


def outer_evidence(files,source,output,native_args,tools,receipt_path):
    row=files.json(str(receipt_path))
    fields(row,('command','cwd','elapsed_seconds','exit_code','finished_monotonic_ns','pid',
        'start_error','started_monotonic_ns','stderr','stdout','timed_out','timeout_seconds'),
        'actual original outer process fields')
    need(type(row['command']) is list and Path(row['command'][0]).is_absolute(),'actual Python invocation')
    command=[row['command'][0],'-I','-B',str(source/'run.py'),'--source',str(source),
        '--native-source',str(native_args['native_source']),'--native-run',str(native_args['native_run']),
        '--build-source',str(native_args['build_source']),'--native-manifest',str(native_args['manifest']),
        '--output',str(output),'--cargo',tools['cargo']['invocation'],'--rustc',tools['rustc']['invocation'],
        '--strace',tools['strace']['invocation']]
    need(Path(row['cwd']).is_absolute(),'actual original outer cwd')
    actual_process(row,command,row['cwd'])
    parent=Path(receipt_path).parent
    # The actual launcher stores the complete producer streams adjacent to its
    # process.json; these names are source-owned, not supplied by a summary.
    stdout=files.raw(str(parent/'original.stdout'))
    stderr=files.raw(str(parent/'original.stderr'))
    same(row['stdout'],{'bytes':len(stdout),'sha256':sha(stdout)},'complete original producer stdout')
    same(row['stderr'],{'bytes':len(stderr),'sha256':sha(stderr)},'complete original producer stderr')
    same(stderr,b'','unexpected original producer stderr')
    emitted=strict_json(stdout)
    same(emitted,{'status':'CAPTURED','cases':215,'original_replay_processes':3,
                  'actual_processes':7,'result':file_pin(files,output/'RESULT.json'),
                  'native_original_comparison_complete':False},'actual original capture terminal stdout')
    remote=files.json(str(output/'remote-process.json'))
    fields(remote,('argv','boot_id','cgroup','cwd','pid','started_monotonic_ns'),'actual original process identity')
    same(remote['argv'],command[3:],'actual interpreter argv')
    same(remote['pid'],row['pid'],'actual captured producer PID')
    same(remote['cwd'],row['cwd'],'actual captured producer cwd')
    need(re.fullmatch(r'[0-9a-f-]{36}',remote['boot_id']) is not None and
         type(remote['cgroup']) is str and remote['cgroup'].endswith('\n'),
         'complete actual boot/cgroup identity')
    need(row['started_monotonic_ns']<remote['started_monotonic_ns']<row['finished_monotonic_ns'],
         'original driver clock outside actual parent process')
    return row,remote


def input_bytes(files,source,native_run,part):
    generator=load(files.path(str(source/'cases.py')),'_batch_bound_input_generator')
    controls=load(files.path(str(source/'control_inputs.py')),'_batch_bound_followup_generator')
    rows=[]
    for case in generator.iter_cases():
        meta,blobs=dict(case['metadata']),list(case['blobs'])
        partition='async' if meta['execution']=='async' else ('wide' if meta['large'] else 'small')
        if part!=partition:continue
        directory='sequence-'+meta['sequence'] if meta['sequence'] else 'case-'+str(meta['case_id']).zfill(4)
        cwd=str(native_run/('output-'+part)/'files'/directory).encode()
        suffix=bytes.fromhex(meta['workdir_rel_hex'])
        if suffix:cwd+=b'/'+suffix
        meta['fixture_cwd_hex']=cwd.hex()
        if part=='async':
            followup=controls.cancel_followup(meta)
            meta['followup']=followup['metadata']
            meta['followup_blob_base']=len(blobs)
            blobs.extend(followup['blobs'])
        rows.append((meta,blobs))
    same(len(rows),{'small':209,'wide':4,'async':2}[part],'full independent partition domain')
    stream=io.BytesIO();stream.write(b'HBCCI002'+struct.pack('<Q',len(rows)))
    for meta,blobs in rows:stream.write(generator.record(meta,blobs))
    raw=stream.getvalue()
    return raw,parse_records(raw,b'HBCCI002')


def retirement_evidence(files,output,native_run):
    raw=files.raw(str(output/'fixture-renames.jsonl'))
    need(raw.endswith(b'\n'),'complete actual fixture retirement receipt')
    rows=[strict_json(line) for line in raw.split(b'\n')[:-1]]
    same(len(rows),9,'all three native-retain/recreate/original-retire sequences')
    def identity(value,path):
        fields(value,('path','dev','ino','mode','uid','gid'),'complete actual directory identity')
        same(value['path'],str(path),'actual fixture directory path')
        for name in ('dev','ino','mode','uid','gid'):uint(value[name],'actual fixture '+name)
        same(value['mode'],0o40700,'exclusive owned fixture permissions')
        need(value['ino']>0,'invalid actual fixture inode')
        return {k:value[k] for k in ('dev','ino','mode','uid','gid')}
    for part,(retained,created,retired) in zip(PARTITIONS,zip(rows[::3],rows[1::3],rows[2::3])):
        origin=native_run/('output-'+part)/'files'
        keep=origin.with_name('files.before-original-'+output.name)
        done=origin.with_name('files.original-'+output.name)
        fields(retained,('kind','partition','before','after','original_path_absent'),'actual native retirement')
        fields(created,('kind','partition','identity','native_fixture'),'actual exact-origin recreation')
        fields(retired,('kind','partition','before','after','original_path_absent'),'actual original retirement')
        same([x['partition'] for x in (retained,created,retired)],[part]*3,'fixture retirement partition order')
        same([x['kind'] for x in (retained,created,retired)],
             ['native-fixture-retained','original-fixture-created','original-fixture-retired'],
             'actual fixture retirement sequence')
        before=identity(retained['before'],origin)
        same(identity(retained['after'],keep),before,'native inode preserved by rename')
        same(identity(created['native_fixture'],keep),before,'retained native identity before replay')
        current=identity(created['identity'],origin)
        need((current['dev'],current['ino'])!=(before['dev'],before['ino']),
             'original replay reused native live inode')
        same(identity(retired['before'],origin),current,'original same fixture root throughout replay')
        same(identity(retired['after'],done),current,'original inode preserved by retirement')
        need(retained['original_path_absent'] is True and retired['original_path_absent'] is True,
             'old fixture origin was not actually absent')
    return {'partitions':3,'actual_directory_events':9,'exact_original_fixture_origins':True,
            'native_and_original_trees_distinct':True,'pure_reader_accesses_live_fixtures':False}


def evidence(*,original_source,original_output,native_source,native_run,build_source,manifest,
             outer_receipt,origins,reader_source=None):
    """Full pure source/build/process/value/trace admission; no hidden origins."""
    original_source,original_output,native_source,native_run,build_source,manifest,outer_receipt=map(
        Path,(original_source,original_output,native_source,native_run,build_source,manifest,outer_receipt))
    need(all(p.is_absolute() for p in (original_source,original_output,native_source,native_run,
         build_source,manifest,outer_receipt)),'explicit absolute execution origins')
    native_args=dict(native_source=native_source,native_run=native_run,build_source=build_source,
                     manifest=manifest,origins=origins)
    native=native_predecessor.native_evidence(**native_args)
    files=Files(origins)
    result=files.json(str(original_output/'RESULT.json'))
    fields(result,RESULT_FIELDS,'complete original capture result fields')
    for name,value in {'schema':'hepta.runtime.batch-call-original-capture.v1','status':'CAPTURED',
        'cases':215,'post_cancel_followup_calls':2,'actual_processes':7,'original_replay_processes':3,
        'fresh_locked_builds':1,'trace_string_limit':128,'trace_payloads_may_be_clipped':True,
        'source_unchanged':True,'full_input_and_result_bytes_retained':True,
        'native_original_comparison_complete':False,'original_inner_execute_batch_edit_executed':True,
        'original_outer_batch_method_executed':False,'original_sdk_executed':False,
        'original_full_router_executed':False,'fixture_origins_retired':True,
        'new_native_calls':0,'public_handler_replaced':False,'whole_runtime_replaced':False}.items():
        same(result[name],value,'actual original capture scope/count '+name)
    previous=files.json(str(original_output/'NATIVE-PREDECESSOR.json'))
    same(previous,native,'entire independently read native predecessor')
    native_pin=file_pin(files,original_output/'NATIVE-PREDECESSOR.json')
    same(result['native_predecessor'],native_pin,'complete causal native proof bytes')
    admission=files.json(str(original_output/'NATIVE-ADMISSION.json'))
    fields(admission,('schema','native_source','native_run','build_source','manifest','native_evidence',
         'admitted_monotonic_ns','native_artifact_sha256','new_native_calls','original_execution_started'),
         'complete causal native admission')
    same(admission['schema'],'hepta.runtime.batch-call-original-predecessor.v1','causal admission schema')
    for name in ('native_source','native_run','build_source','manifest'):
        same(admission[name],str(native_args[name]),'causal predecessor origin '+name)
    same(admission['native_evidence'],native_pin,'causal complete native proof')
    same(admission['native_artifact_sha256'],native['artifact_sha256'],'all admitted native predecessor bytes')
    need(admission['new_native_calls']==0 and type(admission['new_native_calls']) is int and
         admission['original_execution_started'] is False,'native-first admission state')
    source=source_evidence(files,original_source,original_output,result)
    tools,env=selected_tools(files,original_source,original_output,result)
    outer,remote=outer_evidence(files,original_source,original_output,native_args,tools,outer_receipt)
    need(result['started_monotonic_ns']==remote['started_monotonic_ns'] and
         remote['started_monotonic_ns']<admission['admitted_monotonic_ns']<
         result['finished_monotonic_ns']<outer['finished_monotonic_ns'],'actual producer/predecessor interval')
    processes,streams=actual_original_processes(files,original_source,original_output,result,tools,env,admission,outer['pid'])
    need(processes[-1]['finished_monotonic_ns']<result['finished_monotonic_ns'],'original capture terminated early')
    binary_pin=file_pin(files,original_output/'reference.elf')
    same(result['binary'],binary_pin,'complete executed original ELF')
    raw_binary=files.raw(str(original_output/'reference.elf'))
    need(raw_binary[:4]==b'\x7fELF' and raw_binary[4:7]==b'\x02\x01\x01' and
         struct.unpack_from('<H',raw_binary,18)[0]==62,'actual original Linux x86-64 ELF identity')
    build=files.json(str(original_output/'BUILD.json'))
    same(build,{'binary':binary_pin,'target_binary':binary_pin,
        'target_rustc_info':file_pin(files,original_output/'target.rustc_info.json'),
        'materialized_source':source['materialized'],'native_predecessor':native_pin,
        'fixed_rust_release':'1.95.0','fresh_target':True,'locked_build':True},'complete actual fresh build identity')
    same([x['partition'] for x in result['captures']],list(PARTITIONS),'complete actual partition capture order')
    captures=[]
    for part,capture,process in zip(PARTITIONS,result['captures'],processes[4:]):
        fields(capture,('partition','input','process','trace','fixture_origin','native_fixture_retained',
                        'original_fixture_retired'),'complete original partition capture')
        same(capture['process'],process,'capture and actual process identity')
        same(capture['fixture_origin'],str(native_run/('output-'+part)/'files'),'exact native/original fixture origin')
        same(capture['native_fixture_retained'],str(native_run/('output-'+part)/('files.before-original-'+original_output.name)),
             'native retained fixture path')
        same(capture['original_fixture_retired'],str(native_run/('output-'+part)/('files.original-'+original_output.name)),
             'original retained fixture path')
        expected,inputs=input_bytes(files,original_source,native_run,part)
        same(files.raw(str(original_output/part/'input.bin')),expected,'complete independent original input')
        same(capture['input'],{'bytes':len(expected),'sha256':sha(expected),
             'case_ids':[r['metadata']['case_id'] for r in inputs]},'complete independent input identity')
        admitted=next(x for x in native['captures'] if x['partition']==part)
        same(process['umask'],admitted['fixture_umask'],'actual original/native fixture umask')
        same(sorted(set(admitted['elf_umasks'].values())),[process['umask']],'all native process umasks')
        output=streams['original-'+part][0]
        rows=parse_records(output,b'HBCCO002')
        trace=trace_evidence.parse_trace(bound_file(files,capture['trace'],original_output/part/'strace.log'))
        native_capture=native_run/('output-'+part)
        raw_rows=files.raw(str(native_capture/'native-cases.jsonl'))
        need(raw_rows.endswith(b'\n'),'complete native case index')
        native_rows=[strict_json(line) for line in raw_rows.split(b'\n')[:-1]]
        compared=retained_comparison.compare_partition(files,native_capture,native_rows,output,rows,inputs,trace)
        captures.append(dict(partition=part,**compared))
    retired=retirement_evidence(files,original_output,native_run)
    reader_pins={}
    if reader_source is not None:
        reader_source=Path(reader_source)
        for name in ('capture_format.py','native_predecessor.py','trace_evidence.py','retained_comparison.py','strict_reference.py'):
            reader_pins[name]=file_pin(files,reader_source/name)
    artifacts=dict(native['artifact_sha256'])
    for name,value in files.artifacts.items():
        if name in artifacts:same(artifacts[name],value['sha256'],'source/artifact changed during combined read')
        artifacts[name]=value['sha256']
    return {'schema':'hepta.runtime.batch-call-original-evidence.v1','status':'PASS',
        'native_predecessor':native,'native_original_comparison_complete':True,
        'cases':215,'post_cancel_followup_calls':2,'actual_original_processes':7,
        'actual_original_replay_processes':3,'fresh_locked_builds':1,'fixed_rust_release':'1.95.0',
        'complete_comparisons':sum(x['complete_comparisons'] for x in captures),
        'full_body_bytes':sum(x['full_body_bytes'] for x in captures),
        'complete_read_snapshot_bytes':sum(x['complete_read_snapshot_bytes'] for x in captures),
        'completed_operation_boundaries':sum(x['completed_operation_boundaries'] for x in captures),
        'actual_atomic_effect_receipts':sum(x['atomic_receipts'] for x in captures),
        'actual_original_trace_syscalls':sum(x['trace']['syscalls'] for x in captures),
        'actual_original_markers':sum(x['trace']['markers'] for x in captures),
        'captures':captures,'source':source,'toolchain':tools,'fixture_retirement':retired,
        'reader_sources':reader_pins,'new_native_calls':0,'new_rust_processes':0,
        'original_inner_execute_batch_edit_executed':True,'original_outer_batch_method_executed':False,
        'original_sdk_executed':False,'original_full_router_executed':False,
        'public_handler_replaced':False,'whole_runtime_replaced':False,
        'trace_syscall_sequence_equated_to_native':False,'trace_payloads_may_be_clipped':True,
        'artifact_sha256':dict(sorted(artifacts.items()))}
