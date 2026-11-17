"""Physical controls for the repaired catalog configuration argument custody."""
from pathlib import Path
import gzip,json,shutil,stat
from receipt_support import PIN,regular,require
import read_public,read_only_guard,restore
CASES=[('native-config-bytes','native/runtime-config.json','tail'),('original-config-bytes','original/runtime-config.json','tail'),
('native-omitted-config-argv','native','argv'),('original-omitted-config-argv','original','argv'),
('native-output-byte','native/process/stdout.bin.gz','tail'),('original-output-byte','original/process/stdout.bin.gz','tail'),
('original-driver-byte','original-source/qualify_public.py','tail'),('native-driver-byte','source/qualify_public.py','tail')]
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def inventory(root):
    return {p.relative_to(root).as_posix():{**PIN(regular(p)),'mode':stat.S_IMODE(p.stat().st_mode)} for p in sorted(root.rglob('*')) if p.is_file()}
def comparison(root):
    domain=json.loads(regular(root/'native/result.json'))['domain']
    return read_public.compare_lane(root/'native',root/'original',root/'source',native_binary={k:restore.BINARIES['native-private'][k] for k in ('bytes','sha256')},original_binary={k:restore.BINARIES['original'][k] for k in ('bytes','sha256')},domain=domain,original_source_root=root/'original-source')
def run(capture,output):
    capture,output=Path(capture),Path(output);output.mkdir(exist_ok=False)
    require(json.loads(regular(capture/'RUN.json'))['domain'] in ('catalog-legacy','catalog-modern'),'fixed catalog controls')
    base=output/'baseline';base.mkdir()
    for name in ('native','original','source'):shutil.copytree(capture/name,base/name)
    shutil.copytree(capture/'retained/prior/source',base/'original-source')
    comparison(base);baseline=inventory(base);rows=[]
    for name,relative,kind in CASES:
        clone=output/(name+'.clone');shutil.copytree(base,clone);before=inventory(clone);require(before==baseline,'complete baseline clone')
        if kind=='tail':
            target=clone/relative;raw=regular(target);target.write_bytes(raw[:-1]+bytes([raw[-1]^1]));changed=[relative]
        else:
            role=relative;report_path=clone/role/'result.json';process_path=clone/role/'process/process.json';start_path=clone/role/'process/started.json'
            report=json.loads(regular(report_path));process=json.loads(regular(process_path));started=json.loads(regular(start_path))
            size=2 if role=='native' else 1
            for value in (process,started):
                for field in ('command','native_argv'):
                    require(len(value[field])==1+size,'actual configured argv extent');value[field]=value[field][:-size]
            report['process']=process
            for path,value in ((report_path,report),(process_path,process),(start_path,started)):path.write_bytes(read_public.common.canonical(value))
            changed=[p.relative_to(clone).as_posix() for p in (report_path,process_path,start_path)]
        after=inventory(clone);require({n for n in before if before[n]!=after[n]}==set(changed),'only declared complete physical changes')
        def reject():
            try:comparison(clone)
            except (AssertionError,ValueError,OSError,EOFError,gzip.BadGzipFile) as error:return {'rejected':True,'type':type(error).__name__,'message':str(error)}
            raise AssertionError('physical corruption accepted')
        guard=read_only_guard.guarded(reject,roots=[clone,Path(__file__).resolve().parent],foreign_path='/proc/self/status')
        require(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0 and guard['evidence']['rejected'],'strict physical refusal')
        if kind=='argv':require(guard['evidence']['message']=='rebuilt Batch evidence: actual process/cwd/environment custody','omitted config rejected by actual argv custody')
        evidence=output/name;evidence.mkdir()
        for rel in changed:
            dest=evidence/'changed'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(clone/rel,dest);require(regular(dest)==regular(clone/rel),'full mutation retained')
        put(evidence/'GUARD.json',guard)
        row={'name':name,'changes':{rel:{'before':before[rel],'after':after[rel]} for rel in changed},'guard':PIN(regular(evidence/'GUARD.json')),'rejection':guard['evidence'],'native_or_rust_executions':0}
        put(evidence/'CONTROL.json',row);rows.append(row)
        require(inventory(clone)==after,'clone unchanged after read')
        for rel in after:
            expected=evidence/'changed'/rel if rel in changed else base/rel
            require(regular(clone/rel)==regular(expected) and stat.S_IMODE((clone/rel).stat().st_mode)==stat.S_IMODE(expected.stat().st_mode),'full byte/mode clone retirement')
        shutil.rmtree(clone)
    require(inventory(base)==baseline,'unchanged baseline');shutil.rmtree(base)
    report={'status':'CATALOG_CONFIG_PHYSICAL_CONTROLS_PASS','refusals':len(CASES),'guard_probes':len(CASES)*11,'cases':rows,'native_or_rust_executions':0,'complete_mutated_bytes_retained':True};put(output/'REPORT.json',report);return report
def verify(output):
    output=Path(output);report=json.loads(regular(output/'REPORT.json'))
    require(report['status']=='CATALOG_CONFIG_PHYSICAL_CONTROLS_PASS' and report['refusals']==len(CASES) and report['guard_probes']==len(CASES)*11 and report['native_or_rust_executions']==0,'complete catalog control gate')
    require([r['name'] for r in report['cases']]==[r[0] for r in CASES],'all catalog controls')
    for row in report['cases']:
        folder=output/row['name'];require(json.loads(regular(folder/'CONTROL.json'))==row and PIN(regular(folder/'GUARD.json'))==row['guard'],'complete physical control receipt')
        guard=json.loads(regular(folder/'GUARD.json'));require(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0 and guard['evidence']==row['rejection'] and row['rejection']['rejected'] is True,'actual guarded refusal')
        for rel,identities in row['changes'].items():require(PIN(regular(folder/'changed'/rel))=={k:identities['after'][k] for k in ('bytes','sha256')} and identities['before']!=identities['after'],'complete physical mutation bytes')
    return report
