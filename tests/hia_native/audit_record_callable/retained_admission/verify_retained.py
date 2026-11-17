"""Independently read the full relocated capture and existing controls; execute no producer."""
from pathlib import Path
import argparse,importlib.util,io,json,math,os,sys,tarfile,time,zipfile
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
import read_archive as archive
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module)
    return module
def custody(root):
    old=None;rows=[]
    for phase in ('semantic','controls','final'):
        folder=root/'recovery/processes'/phase
        name='readonly-'+phase
        archive.need({p.name for p in folder.iterdir()}=={'processes.json',name+'.stdout',name+'.stderr'},
                     'full exact recovery process files')
        records=json.loads((folder/'processes.json').read_bytes())
        archive.need(len(records)==1,'one owned recovery child per phase')
        row=records[0]
        archive.need(row['name']==name and row['exit_code']==0 and type(row['exit_code']) is int
            and row['timed_out'] is False and row['completed'] is True
            and type(row['timeout_seconds']) is int and row['timeout_seconds']==180
            and type(row['elapsed_seconds']) in (int,float) and math.isfinite(row['elapsed_seconds'])
            and 0<row['elapsed_seconds']<=180 and row['stdin'] is None,'successful original fixed-deadline pure reader')
        archive.need(all(type(row[k]) is int and row[k]>1 for k in ('pid','parent_pid','pgid'))
            and row['pid']==row['pgid'] and row['pid']!=row['parent_pid'],'actual reader process group custody')
        argv=row['argv']
        archive.need(len(argv)==11 and argv[1:3]==['-I','-B'] and argv[4:8]==['--child','--phase',phase,'--restored']
            and argv[9]=='--output','exact pure recovery child command')
        # Old paths are compared only as recorded strings; none is opened.
        identities=(row['cwd'],argv[8],argv[10])
        archive.need(Path(identities[0]).is_absolute() and argv[3]==identities[0]+'/recover.py'
            and all(Path(x).is_absolute() and str(Path(x))==x for x in identities),'recorded source/capture/output identity')
        if old is None:old=identities
        archive.need(identities==old,'all three phases share exactly one retained source and capture')
        streams={}
        for label in ('stdout','stderr'):
            item=row[label];body=(folder/item['file']).read_bytes()
            archive.need(item==dict(file=name+'.'+label,bytes=len(body),sha256=archive.sha(body)),
                         'complete original reader stream')
            streams[label]=body
        archive.need(streams['stderr']==b'','zero actual pure reader stderr')
        proof=json.loads((root/'recovery'/(phase+'-read.json')).read_bytes())
        if phase=='controls':
            expected=dict(status=proof['status'],admissions=proof['admissions'],refusals=proof['refusals'],
                          native_or_rust_executions=0)
        else:
            archive.need(proof['before']==proof['after'] and len(proof['probes'])==12
                and proof['native_or_rust_executions']==proof['reader_writes']==0,
                'original complete bytes/metadata unchanged and twelve guard refusals')
            expected=dict(status=proof['evidence']['status'],probes=len(proof['probes']),
                physical_entries=len(proof['before']),evidence=proof['evidence'],
                native_or_rust_executions=0,reader_writes=0)
        archive.need(streams['stdout']==archive.encoded(expected),'entire actual reader stdout equals retained result')
        rows.append(dict(name=name,pid=row['pid'],parent_pid=row['parent_pid'],pgid=row['pgid'],
                         timeout_seconds=180,elapsed_seconds=row['elapsed_seconds']))
    return rows
def main(root,report,zip_path):
    started=time.monotonic_ns()
    own=archive.source()
    raw=zip_path.read_bytes()
    archive.need(len(raw)==archive.ZIP_SIZE and archive.sha(raw)==archive.ZIP_SHA,'independent complete fixed uploaded ZIP')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        archive.need(z.testzip() is None,'independent complete ZIP CRC')
        packed=z.read('audit-record-io-recovery.tar.gz')
    archive.need(len(packed)==archive.TAR_SIZE and archive.sha(packed)==archive.TAR_SHA,'independent complete fixed TAR')
    with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as t:
        retained_manifest=json.load(t.extractfile('artifact-manifest.json'))
    archive.need((root/'ARCHIVE_MANIFEST.json').read_bytes()==archive.encoded(retained_manifest),
                 'relocated manifest equals exact original archive bytes')
    adapter_root=root/'recovery-source'
    sys.path.insert(0,str(adapter_root))
    adapter=load_module('read_adapter',adapter_root/'read_adapter.py')
    archive.need(adapter.check_adapter()==archive.ADAPTER_SHA,'complete exact recovery reader source')
    reader,controls,guard=adapter.install(root/'retained/source')
    import reader_cli
    reader_cli.prepare()
    capture=root/'retained/run/semantic'
    def operation():
        archive.need(archive.source()==own,'independent reader source unchanged')
        current={}
        for folder,dirs,names in os.walk(root,followlinks=False):
            for name in names:
                path=Path(folder)/name;relative=path.relative_to(root).as_posix()
                if relative=='ARCHIVE_MANIFEST.json':continue
                current[relative]=archive.file_pin(path)
        expected={name:{k:row[k] for k in ('bytes','sha256','mode')}
                  for name,row in retained_manifest['files'].items()}
        archive.need(current==expected,'every relocated complete retained file and mode unchanged')
        process_rows=custody(root)
        value=reader.verify(capture,root/'recovery/controls')
        archive.need(value==retained_manifest['gate']
            ==json.loads((root/'recovery/final-read.json').read_bytes())['evidence'],
            'independent current reader equals the complete exported qualification')
        return dict(schema='hepta.audit-record-io.independent-read.v1',status='PASS',source_sha256=own,
            all_retained_files=len(current),all_retained_bytes=sum(v['bytes'] for v in current.values()),
            complete_recovery_processes=process_rows,evidence=value,original_producer_status='FAIL',
            previous_recovery_export_status='FAIL',native_or_rust_executions=0,reader_writes=0,
            public_handler_qualified=False,whole_runtime_replaced=False)
    proof=guard.guarded(operation,roots=[root,ROOT],foreign_path=str(report.parent/'foreign-copy/CAPTURE.json'))
    proof=dict(proof,independent_process=dict(pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),timeout_seconds=180,elapsed_ns=time.monotonic_ns()-started))
    archive.need(proof['independent_process']['elapsed_ns']<=180_000_000_000,'same independent reader 180 seconds')
    report.parent.mkdir(parents=True,exist_ok=True);report.write_bytes(archive.encoded(proof))
    print(archive.encoded(dict(status=proof['evidence']['status'],guards=len(proof['probes']),
        complete_entries=len(proof['before']),retained_files=proof['evidence']['all_retained_files'],
        retained_bytes=proof['evidence']['all_retained_bytes'],original_producer_status='FAIL',
        previous_recovery_export_status='FAIL',native_or_rust_executions=0,reader_writes=0,
        evidence=proof['evidence']['evidence'])).decode(),end='')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True);p.add_argument('--report',type=Path,required=True)
    p.add_argument('--zip',type=Path,required=True)
    a=p.parse_args();main(a.root.resolve(strict=True),a.report.absolute(),a.zip.resolve(strict=True))
