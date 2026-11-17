"""Frozen input states, without expected owner results."""
import hashlib,struct
SIZE=1<<24
MAX=(1<<64)-1
def specifications():
    helper=[
        ('empty-zero',0,0,0),('empty-past',0,1,0),('empty-max',0,MAX,0),('empty-trap',0,0,1),
        ('one-full',1,0,1),('one-at-end-empty',1,1,0),('one-at-end-trap',1,1,1),
        ('middle-five',17,4,5),('partial-before-trap',17,16,2),('max-offset-trap',64,MAX,2),
        ('wrapped-offset-trap',64,MAX-3,8),('partial-long-trap',64,0,65535),
        ('page-all',4096,0,4096),('page-last',4096,4095,1),('page-past-trap',4096,0,4097),
        ('lifecycle-all',SIZE,0,SIZE-256),('lifecycle-used-tail',SIZE,8192,SIZE-256-8192),
        ('large-empty-max',SIZE,MAX,0),('large-full',SIZE,0,SIZE)]
    rows=[{'name':name,'kind':'helper','workspace_size':size,'offset':at,'count':count,'output_size':37,'fill':165} for name,size,at,count in helper]
    variants=[
        ('dispose',{},0,SIZE,256),('dispose-zero-output',{},0,SIZE,0),
        ('dispose-live-scope',{56:1},0,SIZE,256),('already-disposed',{0:3},0,SIZE,256),
        ('already-fatal',{0:4},0,SIZE,256),('invalid-phase',{16:99},0,SIZE,256),
        ('wrong-transport',{8:2},0,SIZE,256),('stale-ticket',{96:2},0,SIZE,256),
        ('dispose-input-present',{},1,SIZE,256),('short-workspace',{},0,SIZE-1,256),
        ('long-workspace',{},0,SIZE+1,256),('pending-native-borrow',{'footer128':1},0,SIZE,256),
        ('pending-output-borrow',{'footer136':1},0,SIZE,256),('invalid-lifetime',{'footer120':99},0,SIZE,256),
        ('initial-stdio',{0:0,8:0,96:0,'footer120':0},0,SIZE,256),
        ('unsupported-startup',{0:0,8:0,96:0,'footer120':0,'footer160':4},0,SIZE,256)]
    rows += [{'name':name,'kind':'owner','fields':{str(k):v for k,v in fields.items()},'input_size':insize,'workspace_size':size,'output_size':outsize,'fill':90} for name,fields,insize,size,outsize in variants]
    return rows
def inputs(row):
    work=bytearray(bytes([row['fill']])*row['workspace_size'])
    if row['kind']=='helper':source=struct.pack('<2Q',row['offset'],row['count'])
    else:
        source=b'X'*row['input_size'];work[:512]=bytes(512);work[-256:]=bytes(256)
        fields={0:2,8:1,16:0,56:0,96:1,216:8192,SIZE-256+120:2,SIZE-256+160:1,SIZE-256+168:1}
        for key,value in row['fields'].items():
            at=SIZE-256+int(key[6:]) if key.startswith('footer') else int(key);fields[at]=value
        for at,value in fields.items():
            if at+8<=len(work):struct.pack_into('<Q',work,at,value)
    output=bytes((i*29+13)%256 for i in range(row['output_size']))
    return source,output,bytes(work)
def domain():
    rows=[]
    for i,spec in enumerate(specifications()):
        data=inputs(spec);rows.append({'index':i,'spec':spec,'inputs':{key:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for key,raw in zip(('input','output','workspace'),data,strict=True)}})
    return {'schema':'hepta.runtime.caller-authority-clear-inputs.v1','cases':rows,'actual_target_outputs_present':False,'exchange_seconds':60,'lane_seconds':180}
