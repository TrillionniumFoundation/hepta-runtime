"""Exact capture topology and producer provenance; no live fixture access."""
from pathlib import Path
import re


def provenance(q, capture_root, corpus, ref, build_evidence):
    capture = q.Binder(capture_root)
    r, s = capture.json('NATIVE.json'), capture.json('SOURCE.json')
    q.fields(r, ('schema','status','counts','fixture_root','completed_case_ids','original_replayed','original_comparison_complete',
        'all_processes_terminated','observed_layer','public_stdio_layer','actual_native_processes','actual_tool_version_processes','new_rust_processes','fresh_compiles',
        'monotonic_started_ns','monotonic_finished_ns','elapsed_seconds','artifacts','semantic_parity_status'), 'complete native report')
    q.fields(s, ('schema','reference_source_root','reference_source_files','reference_reader','driver_source_root','driver_sources',
        'native_source_root','native_source_files','build_result','builds','binaries','strace','original_response_inputs','original_executions'), 'complete native source record')
    q.same(s['schema'], 'hepta.runtime.filesystem-sdk-native-source.v1', 'source schema')
    ref.tool_evidence(q,capture,'strace',s['strace'])
    q.need(r['new_rust_processes'] == r['fresh_compiles'] == s['original_executions'] == 0 and
           type(r['new_rust_processes']) is type(r['fresh_compiles']) is type(s['original_executions']) is int,
           'native producer invents compiler/original work')
    scenes = [scene for group in corpus['groups'] for scene in group['scenarios']]
    ordinary = [scene for scene in scenes if len(scene['sessions']) == 1]
    q.same(r['observed_layer'], {'scenarios':28,'public_attempts':323,'private_controls':9,'actual_allocated_sessions':56,
        'same_process_two_session_scenarios':[s['scenario_id'] for s in scenes if len(s['sessions']) == 2],
        'private_session_selector':True,'actual_public_frontend_and_publisher':True,'mode3_is_os_broken_pipe':False}, 'exact observed scope')
    q.same(r['public_stdio_layer'], {'scenarios':26,'public_attempts':317,'private_fixture_actions':5,
        'excludes_two_session_cache_injection':True}, 'exact ordinary process domain')
    q.same(r['actual_native_processes'],54,'all actual ELF processes')
    q.same(r['actual_tool_version_processes'],1,'one separate actual tracer version process')
    expected = ['SOURCE.json','HOST.json','INPUTS.json','COMMON-SETUP.json','SCENARIOS.json','processes.json','remote-process.json',
                'build-result.json','fixture-build.json','public-build.json','tool-strace.bin','tool-processes.json',
                'strace-version.stdout','strace-version.stderr']
    summaries = []
    for scene in scenes:
        for layer in ('observed','public'):
            if layer == 'public' and len(scene['sessions']) != 1: continue
            prefix = layer+'/scenario-%03d'%scene['scenario_id']
            expected += [prefix+'/'+name for name in ('records.jsonl','setup.json','reset.json','policy.json')]
            expected += [prefix+'/process/'+name for name in ('started.json','process.json','exchanges.json','native.strace',
                        'attempted-stdin.bin.gz','stdin.bin.gz','stdout.bin.gz','stderr.bin.gz')]
            summaries.append({'layer':layer,'scenario_id':scene['scenario_id'],'directory':prefix,
                'records':len(scene['steps'])+2,'sessions_in_frozen_inputs':len(scene['sessions']),
                'actual_allocated_sessions':2 if layer=='observed' else 1,'steps':len(scene['steps'])})
    q.same(sorted(r['artifacts']),sorted(expected),'complete native artifact inventory')
    for name in expected: capture.file(name,r['artifacts'][name])
    q.same(capture.json('SCENARIOS.json'),summaries,'all scenario/layer/process declarations')
    host = capture.json('HOST.json'); producer = capture.json('remote-process.json')
    q.fields(host,('uid','euid','gid','egid','uname','status','cwd','fixture_identity','monotonic_started_ns','boot_id'),'complete native host')
    ref.boot_evidence(q,host['boot_id'])
    for key in ('uid','euid','gid','egid'): q.need(q.uint(host[key],'native '+key)>0,'native fixture run as root')
    q.same(host['uid'],host['euid'],'native real/effective UID'); q.same(host['gid'],host['egid'],'native real/effective GID')
    q.need(type(host['status']) is str and '\nUmask:\t0077\n' in host['status'] and '\nCapEff:\t0000000000000000\n' in host['status'],'native umask/capabilities')
    q.need(type(host['uname']) is list and len(host['uname'])==5 and host['uname'][0]=='Linux' and host['uname'][-1]=='x86_64','actual native target')
    q.need(type(host['fixture_identity']) is list and len(host['fixture_identity'])==3 and all(type(v) is int and v>=0 for v in host['fixture_identity']),'actual fixture dev/ino/owner')
    q.same(host['fixture_identity'][2],host['uid'],'native actual fixture owner')
    q.fields(producer,('pid','cgroup','argv'),'native durable producer fields')
    q.need(q.uint(producer['pid'],'native producer PID')>0 and '\nPid:\t'+str(producer['pid'])+'\n' in host['status'],'native actual producer PID/host')
    ref.cgroup_evidence(q,producer['cgroup'])
    old_capture = ref.absolute(q,r['fixture_root'],'fixture origin').parent
    old_driver = ref.absolute(q,s['driver_source_root'],'native producer origin')
    q.same(host['cwd'],str(old_driver),'actual producer cwd')
    args = {'--reference-source':s['reference_source_root'],'--reference-reader':s['reference_reader']['path'],
        '--native-source':s['native_source_root'],'--native-build-result':s['build_result']['path'],
        '--fixture-build':s['builds']['fixture']['path'],'--public-build':s['builds']['public']['path'],
        '--fixture-binary':s['binaries']['fixture']['path'],'--public-binary':s['binaries']['public']['path'],'--output':str(old_capture),
        '--strace':s['strace']['path']}
    ref.command_arguments(q,producer['argv'],old_driver/'native_capture.py',args)
    start, finish = q.uint(r['monotonic_started_ns'],'native start'),q.uint(r['monotonic_finished_ns'],'native finish')
    q.need(0<start<finish,'native actual monotonic interval'); q.same(host['monotonic_started_ns'],start,'actual native start clock')
    q.positive(r['elapsed_seconds'],'native whole elapsed')
    q.need(abs((finish-start)/1e9-r['elapsed_seconds'])<0.1,'native monotonic/elapsed interval')
    tool_processes=capture.json('tool-processes.json')
    q.need(type(tool_processes) is list and len(tool_processes)==1,'complete native tool process list')
    tool=tool_processes[0]
    q.fields(tool,('name','command','cwd','environment','pid','exit_code','timeout_seconds','timed_out','start_error',
        'elapsed_seconds','stdin','stdout','stderr'),'complete native tool process receipt')
    q.same(tool['name'],'strace-version','actual tracer process name')
    q.same(tool['command'],[s['strace']['path'],'-V'],'actual tracer version command')
    q.same(tool['cwd'],str(old_driver),'actual tracer cwd')
    q.same(tool['environment'],{'PATH':'','LC_ALL':'C'},'actual tracer version environment')
    q.need(q.uint(tool['pid'],'tracer PID')>0 and tool['pid']!=producer['pid'],'actual distinct tracer process')
    q.same(tool['exit_code'],0,'actual tracer version exit');q.same(tool['timeout_seconds'],180,'actual tracer version deadline')
    q.need(tool['timed_out'] is False and tool['start_error'] is None and tool['stdin'] is None,'actual tracer process completion')
    q.positive(tool['elapsed_seconds'],'tracer duration');q.need(tool['elapsed_seconds']<180 and tool['elapsed_seconds']<=r['elapsed_seconds'],'tracer time within complete capture')
    for kind in ('stdout','stderr'):
        name='strace-version.'+kind;q.same(tool[kind],{'path':str(old_capture/name),**capture.artifacts[name]},'complete tracer '+kind)
    q.need(capture.data('strace-version.stdout').startswith(b'strace -- version ') and not capture.data('strace-version.stderr'),'actual tracer version streams')
    q.same(s['native_source_files'],build_evidence['frozen_source_binding']['files'],'capture and admitted complete graph source')
    for kind, private in (('public',False),('fixture',True)):
        bundle = next(v for v in build_evidence['bundles'] if v['private_fixture'] is private)
        q.same(s['builds'][kind]['path'],bundle['manifest'],'executed bundle origin')
        q.same(s['builds'][kind]['sha256'],bundle['manifest_sha256'],'executed actual bundle bytes')
        q.same({k:s['binaries'][kind][k] for k in ('bytes','sha256')},
            {'bytes':bundle['elf_bytes'],'sha256':bundle['elf_sha256']},'executed full actual ELF identity')
        q.need(capture.data(kind+'-build.json') == capture.data(kind+'-build.json', {k:s['builds'][kind][k] for k in ('bytes','sha256')}),'copied actual manifest')
    capture.file('build-result.json',{k:s['build_result'][k] for k in ('bytes','sha256')})
    return {'status':'PASS','actual_processes':54,'actual_tool_version_processes':1,'tool_identity':s['strace'],
        'actual_tool_process':tool,'boot_id':host['boot_id'],'exact_artifact_names':sorted(expected),'actual_producer':producer,
        'elapsed_seconds':r['elapsed_seconds'],'native_before_original_proved_by_original_reader':False,
        'artifact_sha256':{name:v['sha256'] for name,v in sorted(capture.artifacts.items())},'live_fixture_required':False}
