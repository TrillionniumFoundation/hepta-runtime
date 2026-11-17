"""Fixed inputs for actual SDK Parameters/adapter; observing fixture body only."""
from pathlib import Path
import copy,importlib.util,json

def iter_router_sdk_cases():
    spec=importlib.util.spec_from_file_location('original_view_sdk_inputs',Path(__file__).with_name('sdk_cases.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    rows=list(module.iter_sdk_cases());assert len(rows)==36
    lookup={row['case_id']:row for row in rows}
    for row in rows:yield copy.deepcopy(row)
    cap='io.modelcontextprotocol/clientCapabilities'
    identifier=100
    for name,value in (('roots',True),('sampling',0),('elicitation',[])):
        for era,base_id in (('legacy',24),('modern',30)):
            row=copy.deepcopy(lookup[base_id]);row.update(case_id=identifier,name=era+'-malformed-'+name+'-with-valid-experimental')
            row['messages'][-1]['params'].setdefault('_meta',{})[cap]={'experimental':{'session':{'workdir':'/invalid-metadata-override'}},name:value}
            yield row;identifier+=1
    identifier=200
    for era,base_id in (('legacy',24),('modern',30)):
        for label,arguments,capabilities in (
            ('typed-missing',{},{}),('typed-wrong-path',{'path':7},{}),('typed-sorted-first',{'path':7,'full':'yes'},{}),
            ('bad-caps-and-typed',{'path':7},{'experimental':{'session':{'workdir':'/replacement'}},'roots':True}),
            ('bad-caps-and-valid',{'path':'file'},{'experimental':{'session':{'workdir':'/replacement'}},'sampling':0}),
            ('string-tool-error',{'path':'fixture:error'},{}),
        ):
            row=copy.deepcopy(lookup[base_id]);row.update(case_id=identifier,name=era+'-actual-extractor-'+label)
            request=row['messages'][-1];request['params']['arguments']=arguments;request['params'].setdefault('_meta',{})[cap]=capabilities
            yield row;identifier+=1

def materialize(path):
    Path(path).write_bytes(b''.join(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()+b'\n' for row in iter_router_sdk_cases()))

if __name__=='__main__':
    for row in iter_router_sdk_cases():print(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False))
