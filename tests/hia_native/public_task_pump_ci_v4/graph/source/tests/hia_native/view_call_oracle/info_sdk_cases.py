"""Input-only original get_info and list-header SDK cases; empty catalog fixture."""
from pathlib import Path
import copy,json

def iter_info_sdk_cases():
    cap='io.modelcontextprotocol/clientCapabilities';ver='io.modelcontextprotocol/protocolVersion'
    def meta(version='2026-07-28',capabilities=None):return {ver:version,cap:{} if capabilities is None else capabilities}
    def listing(identifier=2,metadata=None):
        request={'jsonrpc':'2.0','id':identifier,'method':'tools/list','params':{}}
        if metadata is not None:request['params']['_meta']=metadata
        return request
    def initialize(version):return {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':version,'capabilities':{},'clientInfo':{'name':'original-info-oracle','version':'1'}}}
    initialized={'jsonrpc':'2.0','method':'notifications/initialized'}
    rows=[]
    def add(name,messages):rows.append(dict(case_id=len(rows),name=name,messages=messages))
    for version in ('2024-11-05','2025-03-26','2025-06-18','2025-11-25','2026-07-28','2099-01-01'):
        add('initialize-'+version,[initialize(version),copy.deepcopy(initialized),listing()])
    add('modern-first-list',[listing(1,meta())])
    add('modern-first-list-bad-capabilities',[listing(1,meta(capabilities={'roots':True}))])
    add('legacy-list-modern-request-metadata',[initialize('2025-11-25'),copy.deepcopy(initialized),listing(2,meta())])
    add('legacy-list-malformed-request-metadata',[initialize('2025-11-25'),copy.deepcopy(initialized),listing(2,meta(capabilities={'roots':True}))])
    add('modern-second-list-missing-metadata',[listing(1,meta()),listing(2,{})])
    add('first-list-old-request-version',[listing(1,meta('2025-11-25'))])
    add('modern-discover',[{'jsonrpc':'2.0','id':1,'method':'server/discover','params':{'_meta':meta()}}])
    return iter(rows)

def materialize(path):
    Path(path).write_bytes(b"".join(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()+b"\n" for row in iter_info_sdk_cases()))

if __name__=="__main__":
    for row in iter_info_sdk_cases(): print(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=False))
