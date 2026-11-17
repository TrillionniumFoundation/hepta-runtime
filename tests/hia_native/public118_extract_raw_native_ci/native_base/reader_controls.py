"""Twelve physical mutations against a previously complete public comparison."""
from pathlib import Path
import gzip,hashlib,json,os,shutil,stat
from receipt_support import PIN,regular,require
import read_public,read_only_guard,restore
CASES=[('native-binary-tail','native/tool-native.bin','tail'),('original-binary-tail','original/tool-original.bin','tail'),
 ('native-stdout-tail','native/process/stdout.bin.gz','tail'),('original-stdout-tail','original/process/stdout.bin.gz','tail'),
 ('native-input-tail','native/process/stdin.bin.gz','tail'),('original-input-tail','original/process/stdin.bin.gz','tail'),
 ('native-accepted-span','native/process/exchanges.json','span'),('original-response-ledger','original/process/exchanges.json','reply'),
 ('native-case-count','native/result.json','count'),('original-final-state','original/result.json','final'),
 ('captured-input-source','source/public_cases.py','tail'),('native-full-file-observation','native/events.jsonl.gz','event')]
def inventory(root):
    return {p.relative_to(root).as_posix():{**PIN(regular(p)),'mode':stat.S_IMODE(p.stat().st_mode)} for p in sorted(root.rglob('*')) if p.is_file()}
def comparison(root):
    return read_public.compare_lane(root/'native',root/'original',root/'source',native_binary={k:restore.BINARIES['native-private'][k] for k in ('bytes','sha256')},original_binary={k:restore.BINARIES['original'][k] for k in ('bytes','sha256')},domain='typed-legacy')
def run(capture,output):
    capture,output=Path(capture),Path(output);output.mkdir(exist_ok=False);require(json.loads(regular(capture/'RUN.json'))['domain']=='typed-legacy','control domain frozen')
    base=output/'baseline';base.mkdir()
    for name in ('native','original','source'):shutil.copytree(capture/name,base/name)
    comparison(base);baseline=inventory(base);rows=[]
    for name,relative,kind in CASES:
        clone=output/(name+'.clone');shutil.copytree(base,clone);before=inventory(clone);require(before==baseline,'physical original clone changed');target=clone/relative;raw=regular(target);changed=[relative]
        if kind=='tail':mutated=raw[:-1]+bytes([raw[-1]^1])
        elif kind in ('span','reply'):
            value=json.loads(raw)
            if kind=='span':value[0]['accepted_input']['bytes']+=1
            else:value[0]['responses'][0]['bytes']+=1
            mutated=read_public.common.canonical(value)
        elif kind in ('count','final'):
            value=json.loads(raw)
            if kind=='count':value['case_count']-=1
            else:value['final_observation']['state']['scope_unbound_after_exchange']=False
            mutated=read_public.common.canonical(value)
        else:
            lines=gzip.decompress(raw).splitlines(keepends=True);value=json.loads(lines[0]);node=next(n for n in value['after_filesystem'][0]['nodes'] if 'content_hex' in n);content=bytes.fromhex(node['content_hex']);node['content_hex']=(content[:-1]+bytes([content[-1]^1])).hex();lines[0]=read_public.common.canonical(value);decoded=b''.join(lines);mutated=gzip.compress(decoded,mtime=0)
            result=clone/'native/result.json';r=json.loads(regular(result));r['events']['compressed']=PIN(mutated);r['events']['uncompressed']=PIN(decoded);result.write_bytes(read_public.common.canonical(r));changed.append('native/result.json')
        target.write_bytes(mutated);require(mutated!=raw,'control changed no physical bytes');after=inventory(clone);require({n for n in before if before[n]!=after[n]}==set(changed),'control changed undeclared files')
        def reject():
            try:comparison(clone)
            except (AssertionError,ValueError,OSError,EOFError,gzip.BadGzipFile) as error:return {'rejected':True,'type':type(error).__name__,'message':str(error)}
            raise AssertionError('physical corruption was accepted')
        guard=read_only_guard.guarded(reject,roots=[clone,Path(__file__).resolve().parent],foreign_path=Path('/dev/null'));require(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0 and guard['evidence']['rejected'],'strict physical mutation refused')
        evidence=output/name;evidence.mkdir()
        for rel in changed:
            dest=evidence/'changed'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(clone/rel,dest);require(regular(dest)==regular(clone/rel),'complete mutation copy')
        (evidence/'GUARD.json').write_text(json.dumps(guard,sort_keys=True)+'\n');row={'name':name,'changes':{rel:{'before':before[rel],'after':after[rel]} for rel in changed},'guard':PIN(regular(evidence/'GUARD.json')),'rejection':guard['evidence'],'native_or_rust_executions':0};(evidence/'CONTROL.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n');rows.append(row)
        require(inventory(clone)==after,'control clone changed after guarded read')
        for rel in after:
            expected=evidence/'changed'/rel if rel in changed else base/rel;require(regular(clone/rel)==regular(expected) and stat.S_IMODE((clone/rel).stat().st_mode)==stat.S_IMODE(expected.stat().st_mode),'clone retirement full bytes and mode')
        shutil.rmtree(clone)
    require(inventory(base)==baseline,'unchanged control baseline');shutil.rmtree(base)
    report={'status':'PUBLIC_EXTRACT_PHYSICAL_READER_CONTROLS_PASS','refusals':12,'guard_probes':132,'cases':rows,'native_or_rust_executions':0,'complete_mutated_bytes_retained':True};(output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');return report
def verify(output):
    output=Path(output);report=json.loads(regular(output/'REPORT.json'));require(report['status']=='PUBLIC_EXTRACT_PHYSICAL_READER_CONTROLS_PASS' and report['refusals']==12 and report['guard_probes']==132 and report['native_or_rust_executions']==0,'complete physical control gate')
    require([r['name'] for r in report['cases']]==[x[0] for x in CASES],'all frozen physical controls')
    for row in report['cases']:
        folder=output/row['name'];require(json.loads(regular(folder/'CONTROL.json'))==row and PIN(regular(folder/'GUARD.json'))==row['guard'],'full physical control receipt');guard=json.loads(regular(folder/'GUARD.json'));require(guard['before']==guard['after'] and len(guard['probes'])==11 and guard['reader_writes']==guard['native_or_rust_executions']==0 and guard['evidence']==row['rejection'] and row['rejection']['rejected'] is True,'actual read-only control refusal')
        for rel,pins in row['changes'].items():require(PIN(regular(folder/'changed'/rel))=={k:pins['after'][k] for k in ('bytes','sha256')} and pins['before']!=pins['after'],'full physical mutation bytes')
    return report
