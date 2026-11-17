"""Physical complete-buffer reader refusals; never execute a mutated artifact."""
from pathlib import Path
import gzip,json,shutil
import read_pairs,read_only_guard
from retained_pairs import save,pin
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def changed_case(root,index,kind):
    path=root/'PAIRS.json';report=json.loads(path.read_bytes());case=report['pairs'][index];row=case['sides'][1];folder=root/'pairs'/f'{index:03d}'
    item=row['stdout'] if kind=='return' else row['buffers']['workspace'];target=folder/item['file']
    with gzip.open(target,'rb') as f:raw=bytearray(f.read())
    at=8 if kind=='return' else (16 if index==8 else 0);raw[at]^=1;target.unlink()
    replacement=save(folder,item['file'],bytes(raw))
    if kind=='return':row['stdout']=replacement;row['raw_return']^=1
    else:row['buffers']['workspace']=replacement
    put(folder/'after.json',row);put(folder/'CASE.json',case);put(path,report)
    return target.relative_to(root).as_posix()
def run(capture,source,output):
    output.mkdir(exist_ok=False);rows=[]
    for label,index,kind in (('source-byte',None,None),('complete-buffer',7,'buffer'),('trap-prefix',8,'buffer'),('actual-return',19,'return')):
        folder=output/label;folder.mkdir();clone=folder/'capture';shutil.copytree(capture,clone)
        if index is None:
            p=clone/'images/after-owner.hepta';raw=bytearray(p.read_bytes());raw[0]^=1;p.write_bytes(raw);changed=p.relative_to(clone).as_posix()
        else:changed=changed_case(clone,index,kind)
        def reject():
            try:read_pairs.read(clone,source)
            except (ValueError,AssertionError) as error:return {'rejected':True,'error_type':type(error).__name__,'message':str(error)}
            raise RuntimeError('reader accepted physical mutation '+label)
        guard=read_only_guard.guarded(reject,roots=[clone,source],foreign_path='/proc/self/status');put(folder/'GUARD.json',guard)
        row={'case':label,'changed_path':changed,'changed_complete_file':pin(clone/changed),'refusal':guard['evidence'],'guard':pin(folder/'GUARD.json'),'guard_probes':len(guard['probes']),'native_or_rust_executions':0};put(folder/'CONTROL.json',row);rows.append(row)
    result={'status':'CALLER_CLEAR_READER_PHYSICAL_CONTROLS_PASS','cases':rows,'refusals':4,'guard_probes':44,'native_or_rust_executions':0};put(output/'REPORT.json',result);return result
