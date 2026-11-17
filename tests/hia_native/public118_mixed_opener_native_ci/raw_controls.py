"""Four physical raw-reader refusals; no mutated runtime is executed."""
from pathlib import Path
import json,shutil
import archive_stream,read_only_guard,read_stdio
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def run(root,source,profile,out):
    out=Path(out);out.mkdir(exist_ok=False);rows=[]
    for label in ('input-source','captured-binary','complete-output','exchange-budget'):
        case=out/label;case.mkdir();clone=case/'capture';shutil.copytree(root,clone)
        if label=='input-source':target=clone/'source/peer/extract_public_inputs.py'
        elif label=='captured-binary':target=clone/'original/tool-runtime.bin'
        elif label=='complete-output':target=clone/'original/000/process/stdout.bin.gz'
        else:
            target=clone/'original/000/process/exchanges.json';value=json.loads(target.read_bytes());assert value;value[0]['deadline_seconds']=61;put(target,value)
        if label!='exchange-budget':
            raw=bytearray(target.read_bytes());assert raw;raw[-1]^=1;target.write_bytes(raw)
        def reject():
            try:read_stdio.read(clone,source,profile)
            except (AssertionError,ValueError,OSError) as error:return {'rejected':True,'type':type(error).__name__,'message':str(error)}
            raise RuntimeError('physical raw-reader corruption accepted: '+label)
        guard=read_only_guard.guarded(reject,roots=[clone,source],foreign_path='/proc/self/status');put(case/'GUARD.json',guard)
        row={'name':label,'changed_path':target.relative_to(clone).as_posix(),'changed_bytes':archive_stream.pin(target),'refusal':guard['evidence'],'guard':archive_stream.pin(case/'GUARD.json'),'guard_probes':11,'native_or_rust_executions':0};put(case/'CONTROL.json',row);rows.append(row)
    report={'status':'RAW_STDIO_READER_PHYSICAL_CONTROLS_PASS','refusals':4,'guard_probes':44,'cases':rows,'native_or_rust_executions':0};put(out/'REPORT.json',report);return report
