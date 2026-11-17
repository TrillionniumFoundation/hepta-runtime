"""Read every retained byte and replay unchanged Python assertions, never HIA.

The qualification drivers are admitted source. Their original input loops,
control order and complete-array assertions run against a finite tape reader.
The substitute buffer operations manipulate Python bytearrays only; there is
no ctypes import, native loader, executable mapping or process launch here.
"""
from __future__ import annotations
import contextlib,gzip,io,json,struct,sys,types
from pathlib import Path
from worker_common import BASE,document,read,require,sha

Q=struct.Struct('<Q')
DOMAINS={
    'timed-core':('diagnose_timed_core.py',43156,68834437072,9907662216),
    'timed-commitment':('diagnose_timed_commitment.py',26912,1815900942,60141812),
    'pool':('diagnose_pool.py',389,2061520,None),
    'elapsed':('diagnose_elapsed.py',2617,459893,None),
    'timed-core-controls':('diagnose_timed_core_controls.py',265,984192,152376),
}

class Tape:
    def __init__(self,folder):
        self.rows=document(folder/'calls.json');self.index=document(folder/'buffers.json')
        require(type(self.rows) is list and type(self.index) is dict,'buffer tape shape')
        ordered=sorted(self.index,key=lambda h:self.index[h]['index'])
        require([self.index[h]['index'] for h in ordered]==list(range(len(ordered))),'buffer index sequence')
        self.ordered=ordered;self.last={};self.retire={};self.cache={};self.next=0;self.position=0
        for i,row in enumerate(self.rows):
            fields=['input','output'] if row.get('phase')=='actual-commitment' else ['input','before_output','before_workspace','after_output','after_workspace']
            require(set(row)=={'case','phase',*fields}|(set() if fields==['input','output'] else {'code'}),'unclaimed capture row fields')
            for key in fields:
                h=row[key];require(h in self.index,'missing complete buffer');self.last[h]=i
        require(set(self.last)==set(self.index),'unclaimed complete buffer')
        for h,i in self.last.items():self.retire.setdefault(i,[]).append(h)
        self.stream=gzip.open(folder/'buffers.bin.gz','rb');self.total=0;self.peak_bytes=0

    def get(self,h):
        require(h in self.index,'unknown buffer')
        if h not in self.cache:
            target=self.index[h]['index'];require(target>=self.next,'discarded live buffer')
            while self.next<=target:
                digest=self.ordered[self.next];pin=self.index[digest]
                require(set(pin)=={'index','bytes'} and type(pin['bytes']) is int and pin['bytes']>=0,'buffer pin shape')
                header=self.stream.read(8);require(len(header)==8 and Q.unpack(header)[0]==pin['bytes'],'buffer packet extent')
                body=self.stream.read(pin['bytes']);require(len(body)==pin['bytes'] and sha(body)==digest,'complete buffer bytes changed')
                self.cache[digest]=body;self.total+=len(body);self.next+=1
                self.peak_bytes=max(self.peak_bytes,sum(map(len,self.cache.values())))
        return self.cache[h]

    def row(self):
        require(self.position<len(self.rows),'extra native call claimed');return self.rows[self.position]

    def accept(self,row):
        require(row==self.row(),'call input/order/full-array identity changed')
        for h in self.retire.get(self.position,[]):self.cache.pop(h,None)
        self.position+=1

    def finish(self):
        require(self.position==len(self.rows) and self.next==len(self.index),'omitted call or buffer')
        require(self.stream.read(1)==b'','unclaimed trailing buffer data')
        self.stream.close();require(not self.cache,'unretired buffer')

class Buffer:
    def __init__(self,size):self.data=bytearray(size)
    @property
    def raw(self):return bytes(self.data)

class Pointer:
    def __init__(self,buffer,offset=0):self.buffer=buffer;self.offset=offset
    def __add__(self,n):return Pointer(self.buffer,self.offset+n)

class ByteOperations:
    @staticmethod
    def addressof(buffer):return Pointer(buffer)
    @staticmethod
    def memset(target,value,size):
        target=target if isinstance(target,Pointer) else Pointer(target)
        require(type(size) is int and 0<=target.offset<=target.offset+size<=len(target.buffer.data),'fixture memset bounds')
        target.buffer.data[target.offset:target.offset+size]=bytes([value])*size
    @staticmethod
    def memmove(target,body,size):
        target=target if isinstance(target,Pointer) else Pointer(target)
        require(isinstance(body,bytes) and len(body)>=size and 0<=target.offset<=target.offset+size<=len(target.buffer.data),'fixture memmove bounds')
        target.buffer.data[target.offset:target.offset+size]=body[:size]

class Session:
    def __init__(self,module,output_capacity,workspace_capacity):
        self.module=module;self.output_capacity=output_capacity;self.workspace_capacity=workspace_capacity
        self._output=Buffer(output_capacity);self._workspace=Buffer(workspace_capacity);self.closed=False
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def close(self):self.closed=True

class CheckedRows(list):
    def __init__(self,tape):super().__init__();self.tape=tape
    def append(self,row):self.tape.accept(row);super().append(row)

class Output:
    def __init__(self,files,name=''):self.files=files;self.name=name
    def __truediv__(self,name):return Output(self.files,self.name+'/'+name if self.name else name)
    def write_text(self,text):
        require(self.name in {'progress.json','report.json'},'unadmitted diagnostic write intent')
        self.files[self.name]=text.encode();return len(text)

def verify_buffers(folder,root,build,domain,*,trace=None):
    require(domain in DOMAINS,'unadmitted buffer domain')
    filename,count,logical,unique=DOMAINS[domain];report=document(folder/'report.json');tape=Tape(folder)
    require(len(tape.rows)==count,'fixed complete native-call domain changed')
    files={};captures=[];modules=[];sessions=[]
    class EvidenceCapture:
        def __init__(self,path):
            require(isinstance(path,Output) and not captures,'extra capture');captures.append(self)
            self.rows=CheckedRows(tape);self.last={};self.bytes=0;self.unique_bytes=0
        def blob(self,body,kind=None):
            self.bytes+=len(body)
            if kind in self.last and (body is self.last[kind][0] or body==self.last[kind][0]):return self.last[kind][1]
            h=sha(body)
            if kind is not None:self.last[kind]=(body,h)
            return h
        def invoke(self,session,wire,*,case,phase):
            require(not session.closed and not session.module.closed,'closed session consumed')
            row=tape.row();require(row['case']==case and row['phase']==phase,'fixed input iteration changed')
            require(tape.get(row['input'])==wire,'complete native input changed')
            before_o=tape.get(row['before_output']);before_w=tape.get(row['before_workspace'])
            require(before_o==session._output.raw and before_w==session._workspace.raw,'complete before-state continuity changed')
            out=tape.get(row['after_output']);work=tape.get(row['after_workspace'])
            require(len(out)==session.output_capacity and len(work)==session.workspace_capacity,'complete borrowed-array extent changed')
            session._output.data[:]=out;session._workspace.data[:]=work
            self.rows.append({'case':case,'phase':phase,'code':row['code'],'input':self.blob(wire,'input'),
                              'before_output':self.blob(before_o,'output'),'before_workspace':self.blob(before_w,'workspace'),
                              'after_output':self.blob(out,'output'),'after_workspace':self.blob(work,'workspace')})
            self.unique_bytes=tape.total
            return row['code'],out,work
        def close(self):
            tape.finish();require(self.bytes==logical,'logical complete-buffer extent changed')
            require(unique is None or tape.total==unique,'unique complete-buffer extent changed')
    class EvidenceModule:
        def __init__(self,path,*,manifest_sha256):
            require(path.name=='manifest.json' and path.parent.parent==build/'modules','unadmitted native module path')
            self.metadata=document(path);require(sha(read(path))==manifest_sha256,'native manifest changed')
            self.name=path.parent.name;self.closed=False;modules.append(self)
        def __enter__(self):return self
        def __exit__(self,*args):self.close()
        def close(self):self.closed=True
        def session(self,*,output_capacity,workspace_capacity):
            s=Session(self,output_capacity,workspace_capacity);sessions.append(s);return s
        def invoke(self,wire,*,output_capacity,workspace_capacity):
            require(self.name=='commitment' and domain=='timed-core' and output_capacity==8388736 and workspace_capacity==8404992,'unadmitted child invocation')
            row=tape.row();require(row['phase']=='actual-commitment' and tape.get(row['input'])==wire,'complete commitment input changed')
            return tape.get(row['output'])
    class Parser:
        def __init__(self,*args,**kwargs):pass
        def add_argument(self,*args,**kwargs):pass
        def parse_args(self):return types.SimpleNamespace(source_root=root,build=build,output=Output(files),limit=None,trace=trace,all_timeouts=True)
    class Clock:
        calls=0
        @classmethod
        def monotonic(cls):
            cls.calls+=1;return 0 if cls.calls==1 else report['elapsed_seconds']
    module_path=root/BASE/filename;namespace={'__name__':'readonly_driver_assertions','__file__':str(module_path)}
    original_paths=list(sys.path);old_loader=sys.modules.get('hia_native_loader');loader=types.ModuleType('hia_native_loader');loader.NativeModule=EvidenceModule
    try:
        sys.path.insert(0,str(module_path.parent));sys.modules['hia_native_loader']=loader
        exec(compile(read(module_path),str(module_path),'exec'),namespace)
        namespace.update(Capture=EvidenceCapture,ctypes=ByteOperations,argparse=types.SimpleNamespace(ArgumentParser=Parser),time=Clock)
        with contextlib.redirect_stdout(io.StringIO()):namespace['main']()
        require(json.loads(files['report.json'])==report,'regenerated full diagnostic report differs')
        require(all(s.closed for s in sessions) and all(m.closed for m in modules),'fixture omitted resource closure')
    finally:
        sys.path[:]=original_paths
        if old_loader is None:sys.modules.pop('hia_native_loader',None)
        else:sys.modules['hia_native_loader']=old_loader
        tape.stream.close()
    return {'status':'READ_ONLY_COMPLETE_BUFFERS_PASS','domain':domain,'calls':count,'logical_complete_bytes':logical,
            'unique_complete_bytes':tape.total,'peak_live_buffer_bytes':tape.peak_bytes,
            'source_driver_sha256':sha(read(module_path)),'calls_sha256':sha(read(folder/'calls.json')),
            'report_sha256':sha(read(folder/'report.json')),'native_or_rust_executed':False,'writes_performed':False}
