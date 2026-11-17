"""Frozen input plans. Values are requests/setup, never expected tool responses."""
from pathlib import Path
import os,struct,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'peer'))
import extract_public_inputs as peer
import body_cases
encode,initialize,inline_meta,tool_wire=peer.encode,peer.initialize,peer.inline_meta,peer.tool_wire
DOMAINS={'typed-legacy':189,'typed-modern':189,'session-legacy':35,'session-modern':35,
         'context-legacy':13,'context-modern':13,'body-legacy':153,'body-modern':153,
         'catalog-legacy':6,'catalog-modern':5}
def body_specs():
    rows=body_cases.cases();assert len(rows)==153 and sum(len(r['operations']) for r in rows)==175
    return rows
def canonical(work,path):return os.path.realpath(os.path.join(os.fsencode(work),path)).decode('utf-8','replace').encode()
def cache_frame(path,content):
    key=path.encode();value=content.encode();return b'HVCACH01'+struct.pack('<5Q',2,0,len(key),len(value),0)+key+value
def plan(domain,fixture,case_index=None):
    assert domain in DOMAINS;modern=domain.endswith('-modern');fixture=Path(fixture)
    if domain.startswith(('typed-','session-','context-')):
        assert case_index is None
        p=peer.all_inputs(fixture)['domains'][domain];p['modern']=modern;p.setdefault('actions',[]);p['seeds']=[];p['body_spec']=None;p['case_name']=domain
        assert len(p['rows'])==DOMAINS[domain];return p
    initial=peer.initialization_inputs(modern=False,sessions=(1,)) if modern else peer.initialization_inputs(modern=False)
    if domain.startswith('catalog-'):
        assert case_index is None
        params=[{}, {'cursor':None},{'cursor':''},{'cursor':'opaque'},{'unknown':{'input':True}}]
        values=[] if modern else [None]
        values+=params;rows=[]
        for i,value in enumerate(values):
            request={'jsonrpc':'2.0','id':1000+i,'method':'tools/list'}
            if value is not None:
                request['params']=dict(value)
                if modern:request['params']['_meta']=inline_meta()
            rows.append({'name':'actual-installed-catalog-'+str(i),'domain':'actual-catalog','session':0,
                'wire':encode(request)+b'\n','actions':[],'after_actions':[],'response':True})
        assert len(rows)==DOMAINS[domain]
        return {'initial':initial,'actions':[],'seeds':[],'body_spec':None,'modern':modern,'rows':rows,'case_name':domain,'runtime_config':{'controller_workspace_roots':[str(fixture)]}}
    assert type(case_index) is int and 0<=case_index<153
    spec=body_specs()[case_index];rows=[]
    for i,op in enumerate(spec['operations']):
        value={'from_path':op['source'],'from_start':op['start'],'append_path':op['target'],'append_line':op['append']}
        if op['end']!=body_cases.ABSENT:value['from_end']=op['end']
        assert op['context'] in (1,2)
        rows.append({'name':spec['name']+'-operation-'+str(i),'domain':'body-public-lift','session':op['context']-1,
            'tool':'extract_lines','raw_arguments':encode(value),'actions':[],'after_actions':[],
            'response':True,'original_case_id':case_index,'original_operation':i})
    seeds=[{'owner':'history','session':0,'wire':b'HHISTQ01'+bytes(56)}]
    for path,value in spec['cache']:
        key=canonical(fixture,path);v=value.encode();seeds.append({'owner':'cache','session':0,'wire':b'HVCACH01'+struct.pack('<5Q',2,0,len(key),len(v),0)+key+v})
    for path,value,cap in spec['history']:
        key=canonical(fixture,path);v=value.encode();seeds.append({'owner':'history','session':0,'wire':b'HHISTQ01'+struct.pack('<7Q',1,cap,len(key),len(v),0,0,0)+key+v})
    if spec['cache_poison']:seeds.append({'owner':'cache','session':0,'wire':b'HVCACH01'+struct.pack('<5Q',9,0,0,0,0)})
    if spec['history_poison']:seeds.append({'owner':'history','session':0,'wire':b'HHISTQ01'+struct.pack('<7Q',3,0,0,0,0,0,0)})
    return {'initial':initial,'actions':[],'seeds':seeds,'body_spec':spec,'modern':modern,'rows':rows,'case_name':spec['name'],
        'context_mapping':{'1':'actual public session 0 cache','2':'actual public session 1 initially empty independent cache'}}
def row_wire(row,index,modern):
    if 'wire' in row:return row['wire']
    return peer.wire_for_row(row,index,modern=modern)
def serial(value):return peer.serial_inputs(value)
