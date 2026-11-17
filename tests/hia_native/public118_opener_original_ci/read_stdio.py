"""Reopen every raw stream, line, source-bound input, fixture byte and process receipt."""
from pathlib import Path
import gzip,hashlib,json,math,stat
import archive_stream,raw_domain,all_lines,restore_stdio
def need(ok,text):
    if not ok:raise ValueError(text)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def doc(path):return json.loads(Path(path).read_bytes())
def source_check(source,profile):
    source=Path(source);need(archive_stream.pin(source/'PACKAGE.json')['sha256']==profile,'frozen package profile')
    rows=doc(source/'PACKAGE.json')['files'];need({p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'},'full source closure')
    for name,row in rows.items():need(archive_stream.pin(source/name)=={k:row[k] for k in ('bytes','sha256')} and not (source/name).is_symlink() and stat.S_IMODE((source/name).stat().st_mode)==0o644,'frozen source '+name)
    return rows
def read_snapshot(case,snapshot,fixture,used):
    raw=snapshot['complete_metadata'];need(len(raw)==1 and raw[0]['root_hex']==str(fixture).encode().hex(),'absolute unchanged fixture root')
    nodes={n['relative_hex']:n for n in raw[0]['nodes']};need(len(nodes)==len(raw[0]['nodes']) and '' in nodes,'complete unique metadata tree')
    relative={k:v for k,v in nodes.items() if k};view=snapshot['filesystem'];need({n['path_hex'] for n in view['nodes']}==set(relative),'same complete filesystem paths')
    links={}
    for row in view['nodes']:
        path=bytes.fromhex(row['path_hex']);need(path and not path.startswith(b'/') and b'..' not in path.split(b'/'),'owned observed path')
        meta=relative[row['path_hex']]
        need(row['mode']==stat.S_IMODE(meta['mode']) and all(row[k]==meta[k] for k in ('uid','gid','links')),'complete filesystem metadata')
        if row['kind']=='file':
            need(stat.S_ISREG(meta['mode']),'file kind');blob=row['content'];need(blob['path']==blob['sha256']+'.bin','content-addressed bytes')
            value=(case/'blobs'/blob['path']).read_bytes();need(pin(value)=={k:blob[k] for k in ('bytes','sha256')} and value.hex()==meta['content_hex'] and len(value)==meta['size'],'complete original filesystem bytes')
            used.add(blob['path']);links.setdefault((meta['device'],meta['inode']),[]).append(row['path_hex'])
        elif row['kind']=='directory':need(stat.S_ISDIR(meta['mode']),'directory kind')
        elif row['kind']=='symlink':need(stat.S_ISLNK(meta['mode']) and row['target_hex']==meta['target_hex'],'full symlink target')
        else:raise ValueError('unexpected observed filesystem object')
    need(view['hardlink_groups']==sorted(sorted(x) for x in links.values() if len(x)>1),'complete hardlink relationships')
    return view
def read_process(folder,report,plan,binary,fixture,side):
    folder=Path(folder);row=doc(folder/'process.json');need(row==report,'full actual process receipt')
    need(row['schema']=='hepta.runtime.complete-stdio-observer.v1' and row['binary']==binary,'actual executed binary')
    need(row['environment']=={'PATH':'','LC_ALL':'C'} and row['cwd']==str(fixture),'exact environment and unchanged cwd')
    need(row['command']==row['native_argv'] and row['native_argv'][1:]==(['--stdio'] if side=='original' else []),'actual public stdio entry')
    need(type(row['pid']) is int and row['pid']>0 and type(row['exit_code']) is int and row['start_error'] is None,'actual process identity and terminal exit')
    need(row['timed_out'] is False and row['wait_timed_out'] is False and row['kill_requested'] is False and row['failure_cleanup_requested'] is False and row['cleanup_error'] is None,'actual process completed without deadline kill')
    need(row['drain_deadline_seconds']==60 and row['drain_elapsed_seconds']<60 and row['wait_deadline_seconds']==row['kill_cleanup_deadline_seconds']==5 and row['pipe_eof']=={'stdout':True,'stderr':True} and row['stdin_closed_by_driver'] is True,'complete actual EOF and fixed deadlines')
    need(row['response_count_assumed'] is None and row['nonzero_exit_is_observed_data'] is True,'unknown response cardinality retained')
    started=doc(folder/'started.json');need(all(started[k]==row[k] for k in ('command','native_argv','cwd','environment','pid','binary')) and started['observer_fd'] is None,'actual process launch provenance')
    streams={}
    for name,item in row['streams'].items():
        path=folder/(name+'.bin.gz');need(Path(item['path']).name==path.name and archive_stream.pin(path)==item['compressed'],'complete compressed '+name)
        with gzip.open(path,'rb') as f:value=f.read()
        need(pin(value)==item['uncompressed'],'complete uncompressed '+name);streams[name]=value
    need(set(streams)=={'attempted-stdin','stdin','stdout','stderr'},'full actual stream set')
    raw=streams['stdout'];lines=[];values=[];cursor=0
    while True:
        end=raw.find(b'\n',cursor)
        if end<0:break
        value=raw[cursor:end+1];lines.append({'index':len(lines),'offset':cursor,**pin(value)});values.append(value);cursor=end+1
    need(doc(folder/'lines.json')==lines and archive_stream.pin(folder/'lines.json')==row['lines'] and row['complete_stdout_lines']==len(lines),'every complete actual line')
    need(row['trailing_stdout']=={'offset':cursor,**pin(raw[cursor:])},'complete actual non-LF tail')
    exchanges=doc(folder/'exchanges.json');journal=(folder/'exchanges.jsonl').read_bytes()
    need([json.loads(x) for x in journal.splitlines()]==exchanges and row['exchange_journal']['records']==row['exchanges']==len(exchanges) and row['exchange_journal']['recording_error'] is None and Path(row['exchange_journal']['path']).name=='exchanges.jsonl' and pin(journal)=={k:row['exchange_journal'][k] for k in ('bytes','sha256')},'complete flushed exchange journal')
    need(len(exchanges)<=len(plan),'bounded input plan');at=accepted=out=err=line=0;milestones=[]
    for i,exchange in enumerate(exchanges):
        step=plan[i];value=step['wire'];need(exchange['index']==i and exchange['label']==step['label'] and exchange['correlation_id']==step['correlation_id'] and exchange['segments']==step['segments'],'exact source-bound scheduling and ID')
        need(exchange['response_count_assumed'] is None and exchange['deadline_seconds']==60 and exchange['elapsed_seconds']<60 and exchange['timed_out'] is False,'unchanged exchange bound')
        need(exchange['transport'] in ('sent','correlated','eof','write-error'),'actual exchange completion')
        need(exchange['attempted_input']=={'offset':at,**pin(value)} and streams['attempted-stdin'][at:at+len(value)]==value,'complete frozen input attempt');at+=len(value)
        count=exchange['accepted_input']['bytes'];need(type(count) is int and 0<=count<=len(value) and exchange['accepted_input']=={'offset':accepted,**pin(value[:count])} and streams['stdin'][accepted:accepted+count]==value[:count],'complete actual accepted input');accepted+=count
        need(exchange['stdout_range']['offset']==out and exchange['stderr_range']['offset']==err,'contiguous actual stream coverage')
        out+=exchange['stdout_range']['bytes'];err+=exchange['stderr_range']['bytes'];need(0<=out<=len(raw) and 0<=err<=len(streams['stderr']),'bounded full stream spans')
        span=exchange['line_range'];need(span['first']==line and type(span['count']) is int and span['count']>=0 and line+span['count']<=len(lines),'complete actual line partition')
        actual_match=step['correlation_id'] is not None and any(all_lines.AllLines.matches(v,step['correlation_id']) for v in values[line:line+span['count']])
        need(exchange['matched_correlation']==actual_match,'actual observed known-ID correlation');line+=span['count']
        if actual_match:milestones.append(i)
        if exchange['transport']=='correlated':need(actual_match and count==len(value),'completed actual correlation')
        if count<len(value):need(exchange['transport'] in ('eof','write-error'),'captured incomplete write provenance')
        if exchange['error'] is not None:need(exchange['error']['type']=='BrokenPipeError' and exchange['error']['errno']==32,'ordinary observed pipe closure')
    need(at==len(streams['attempted-stdin']) and accepted==len(streams['stdin']),'all attempted and accepted bytes owned by declared inputs')
    need(row['drain_line_range']=={'first':line,'count':len(lines)-line},'all late responses retained through EOF')
    need(len(exchanges)==len(plan) or (exchanges and exchanges[-1]['stdout_eof'] is True),'remaining frozen requests skipped only after observed EOF')
    need({p.name for p in folder.iterdir()}=={'started.json','process.json','lines.json','exchanges.json','exchanges.jsonl',*(n+'.bin.gz' for n in streams)},'complete process artifact inventory')
    return {'pid':row['pid'],'stdout':raw,'stderr':streams['stderr'],'attempted_stdin':streams['attempted-stdin'],'accepted_stdin':streams['stdin'],'exit_code':row['exit_code'],'milestone_steps':milestones,'exchanges':len(exchanges),'lines':len(lines)}
def read_capture(folder,*,side,binary):
    folder=Path(folder);report=doc(folder/'CAPTURE.json');fixture=Path(report['fixture'])
    need(report['schema']=='hepta.runtime.extract-complete-stdio-capture.v1' and report['side']==side and report['status']==('COMPLETE_ORIGINAL_STDIO_DOMAIN_CAPTURED' if side=='original' else 'COMPLETE_NATIVE_STDIO_DOMAIN_CAPTURED'),'complete actual stdio capture')
    need(report['lane_seconds']==180 and report['per_exchange_seconds']==60 and type(report['elapsed_seconds']) in (float,int) and math.isfinite(report['elapsed_seconds']) and 0<=report['elapsed_seconds']<180 and report['full_public_domain_qualified'] is False,'unchanged whole lane deadline')
    frozen=raw_domain.domain(report['domain'],fixture);need(doc(folder/'DOMAIN.json')==raw_domain.serial(frozen),'complete frozen raw input domain')
    need(archive_stream.pin(folder/'tool-runtime.bin')==binary and {k:report['binary'][k] for k in ('bytes','sha256')}==binary and report['binary']['captured_file']=='tool-runtime.bin','copied actual executable')
    need(len(report['cases'])==len(frozen['cases']),'all source-bound raw scenarios')
    pairs=[];pids=set();total_lines=0
    for i,(entry,item) in enumerate(zip(report['cases'],frozen['cases'],strict=True)):
        case=folder/f'{i:03d}';need(entry=={'index':i,'name':item['name'],'case':archive_stream.pin(case/'CASE.json')},'whole case identity')
        row=doc(case/'CASE.json');plan=raw_domain.steps(item);need(row['index']==i and row['name']==item['name'] and row['input']==raw_domain.serial(item) and row['planned_steps']==raw_domain.serial(plan) and row['status']=='COMPLETE_WITH_ACTUAL_PROCESS_EXIT','full frozen case and scheduling')
        need([x['action'] for x in row['setup']]==item['actions'] and all(x['status']=='EXECUTED' for x in row['setup']),'actual owned fixture setup')
        observed=read_process(case/'process',row['process'],plan,binary,fixture,side);need(observed['pid'] not in pids,'fresh raw stdio process');pids.add(observed['pid']);total_lines+=observed['lines']
        need(row['not_attempted_steps']==[p['label'] for p in plan[observed['exchanges']:]],'complete unissued input suffix')
        need([r['after_step'] for r in row['milestones']]==observed['milestone_steps'],'all completed known-ID filesystem observations')
        used=set();initial=read_snapshot(case,row['initial'],fixture,used)
        milestones=[{'after_step':r['after_step'],'filesystem':read_snapshot(case,r['snapshot'],fixture,used)} for r in row['milestones']]
        final=read_snapshot(case,row['final'],fixture,used);need({p.name for p in (case/'blobs').iterdir()}==used,'complete retained filesystem byte inventory')
        metadata=row['final']['complete_metadata'][0]['nodes'];expect={str(fixture).encode().hex() if not r['relative_hex'] else (str(fixture).encode()+b'/'+bytes.fromhex(r['relative_hex'])).hex():r for r in metadata}
        need({r['path_hex'] for r in row['cleanup']}==set(expect) and len(row['cleanup'])==len(expect),'complete owned cleanup receipt')
        for r in row['cleanup']:need(all(r[k]==expect[r['path_hex']][k] for k in ('device','inode','mode')),'owned final cleanup metadata')
        need({p.name for p in case.iterdir()}=={'CASE.json','blobs','process'},'complete per-case evidence closure')
        pairs.append({'name':row['name'],'initial':initial,'milestones':milestones,'final':final,
            'attempted_stdin':observed['attempted_stdin'].hex(),'accepted_stdin':observed['accepted_stdin'].hex(),'stdout':observed['stdout'].hex(),'stderr':observed['stderr'].hex(),'exit_code':observed['exit_code'],'not_attempted_steps':row['not_attempted_steps']})
    need({p.name for p in folder.iterdir()}=={'CAPTURE.json','DOMAIN.json','tool-runtime.bin',*(f'{i:03d}' for i in range(len(frozen['cases'])))},'complete raw lane artifact inventory')
    return {'status':'COMPLETE_RAW_STDIO_CAPTURE_READ_PASS','domain':report['domain'],'actual_processes':len(pids),'all_stdout_lines':total_lines,'pairs':pairs,'fresh_native_or_rust_executions':0,'full_public_domain_qualified':False}
def read(root,source,profile):
    root,source=Path(root),Path(source);rows=source_check(source,profile)
    need((root/'source/PACKAGE.json').read_bytes()==(source/'PACKAGE.json').read_bytes(),'complete recorded source identity')
    for name in rows:need((root/'source'/name).read_bytes()==(source/name).read_bytes(),'recorded input and reader '+name)
    prior=restore_stdio.verify(root/'retained/reference');guard=doc(root/'retained/REFERENCE_READONLY.json')
    need(guard['evidence']==prior and guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0,'retained source-bound reference guard')
    return read_capture(root/'original',side='original',binary=restore_stdio.BINARY)
