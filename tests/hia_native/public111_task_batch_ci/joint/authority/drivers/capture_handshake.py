"""Capture all 54 native sessions independently of the actual Rust responses."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,signal,subprocess,sys,time
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def packed(path,raw):
    data=gzip.compress(raw,mtime=0);path.write_bytes(data)
    return dict(path=path.name,bytes=len(raw),sha256=SHA(raw),compressed_bytes=len(data),compressed_sha256=SHA(data))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('build','source','output'):p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute()
    raw=(source/'scripts/cases.py').read_bytes()
    manifest=json.loads((source/'source-manifest.json').read_bytes())
    assert manifest['files']['scripts/cases.py']==dict(bytes=len(raw),sha256=SHA(raw))
    sys.path.insert(0,str(source/'scripts'));from cases import cases
    corpus=cases();assert len(corpus)==54
    built=json.loads((a.build.resolve(strict=True)/'BUILD.json').read_bytes())
    assert built['status']=='NATIVE_BUILD_PASS'
    binary=Path(built['elf']).resolve(strict=True)
    assert SHA(binary.read_bytes())==built['elf_sha256']
    out.mkdir(parents=True,exist_ok=False);put(out/'CORPUS.json',corpus)
    report=dict(schema='hepta.current-get-info.native-handshake54.v1',status='RUNNING',
        source_case_sha256=SHA(raw),source_manifest_sha256=SHA((source/'source-manifest.json').read_bytes()),
        elf_sha256=built['elf_sha256'],manifest_sha256=built['manifest_sha256'],
        physical_images=built['physical_images'],cases=[],completed_sessions=0,
        target_reference_read=False,original_rust_executed=False,actual_original_wire_compared=False,
        full_sdk_qualified=False,production_activated=False,old_path_removed=False)
    start=time.monotonic()
    def save():report['elapsed_seconds']=time.monotonic()-start;put(out/'SUMMARY.json',report)
    save()
    try:
        for i,case in enumerate(corpus):
            folder=out/('case-'+str(i).zfill(3));folder.mkdir();(folder/'cwd').mkdir()
            stdin=b''.join(event['wire'].encode()+b'\n' for event in case['events'])
            begin=time.monotonic();timed=False
            process=subprocess.Popen([str(binary)],cwd=folder/'cwd',env={'PATH':'','LC_ALL':'C'},
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:stdout,stderr=process.communicate(stdin,timeout=60)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(process.pid,signal.SIGKILL);stdout,stderr=process.communicate()
            receipt=dict(index=i,label=case['label'],exit_code=process.returncode,timed_out=timed,
                deadline_seconds=60,elapsed_seconds=time.monotonic()-begin,environment={'PATH':'','LC_ALL':'C'},
                stdin=packed(folder/'stdin.bin.gz',stdin),stdout=packed(folder/'stdout.bin.gz',stdout),
                stderr=packed(folder/'stderr.bin.gz',stderr),response_lines=len(stdout.splitlines()),
                cwd_entries=[str(p.relative_to(folder/'cwd')) for p in sorted((folder/'cwd').rglob('*'))],
                target_reference_read=False,original_rust_executed=False,
                write_segmentation='complete ordered ordinary session via subprocess.communicate')
            put(folder/'PROCESS.json',receipt)
            report['cases'].append(dict(index=i,label=case['label'],folder=folder.name,
                process_sha256=SHA((folder/'PROCESS.json').read_bytes())))
            report['completed_sessions']+=1;save()
            assert process.returncode==0 and not timed and not stderr and receipt['cwd_entries']==[],case['label']
        report['status']='NATIVE_HANDSHAKE54_CAPTURE_COMPLETE'
    except BaseException as error:report.update(status='FAIL',error=repr(error));raise
    finally:save()
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},sort_keys=True))
if __name__=='__main__':main()
