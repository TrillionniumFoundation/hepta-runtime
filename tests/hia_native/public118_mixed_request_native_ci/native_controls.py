"""Physical corruption controls for the complete native/original raw comparison."""
from pathlib import Path
import json,shutil
import archive_stream,read_native_raw,read_only_guard
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def run(root,source,profile,out):
    out=Path(out);out.mkdir(exist_ok=False);rows=[]
    for name in ('native-source','native-output','native-filesystem','actual-exit'):
        folder=out/name;folder.mkdir();clone=folder/'capture';shutil.copytree(root,clone)
        if name=='native-source':target=clone/'source/all_lines.py'
        elif name=='native-output':target=clone/'native/000/process/stdout.bin.gz'
        elif name=='native-filesystem':target=sorted((clone/'native/000/blobs').iterdir())[0]
        else:
            target=clone/'native/000/process/process.json';process=json.loads(target.read_bytes());process['exit_code']+=1;put(target,process)
            casepath=clone/'native/000/CASE.json';case=json.loads(casepath.read_bytes());case['process']=process;put(casepath,case)
            capturepath=clone/'native/CAPTURE.json';capture=json.loads(capturepath.read_bytes());capture['cases'][0]['case']=archive_stream.pin(casepath);put(capturepath,capture)
        if name!='actual-exit':
            raw=bytearray(target.read_bytes());assert raw;raw[-1]^=1;target.write_bytes(raw)
        def reject():
            try:read_native_raw.read(clone,source,profile)
            except (ValueError,AssertionError,OSError) as error:return {'rejected':True,'type':type(error).__name__,'message':str(error)}
            raise RuntimeError('physical raw differential corruption accepted '+name)
        g=read_only_guard.guarded(reject,roots=[clone,source],foreign_path='/proc/self/status');put(folder/'GUARD.json',g)
        row={'name':name,'changed_path':target.relative_to(clone).as_posix(),'changed_file':archive_stream.pin(target),'refusal':g['evidence'],'guard':archive_stream.pin(folder/'GUARD.json'),'guard_probes':11,'native_or_rust_executions':0};put(folder/'CONTROL.json',row);rows.append(row)
    report={'status':'COMPLETE_RAW_DIFFERENTIAL_PHYSICAL_CONTROLS_PASS','refusals':4,'guard_probes':44,'cases':rows,'native_or_rust_executions':0};put(out/'REPORT.json',report);return report
