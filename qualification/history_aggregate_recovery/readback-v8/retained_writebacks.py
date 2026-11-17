"""Compare the two exact retained View schema writebacks without writing.

The original additional_reference_summary function still parses and recounts
every reference stream. Only its two Path.write_bytes calls are translated
to complete byte comparisons, in their original order and source context.
This is a fixed-reader regression adapter, not an arbitrary Python sandbox.
"""
from __future__ import annotations
import hashlib,stat,sys,threading
from pathlib import Path

PINS={
 'tests/hia_native/view_call_oracle/run.py':(13903,'19ed876d121a1c917c667ccc3ead4dae1ed25c4a5b7cf1744625773c921ca33b'),
 'scripts/hia_native_runtime_mcp_original.py':(13097,'b051ed49dba6dfa33cdc17b812caa9ff395746905aba1bc395f99cc00ce60ec9')}
INPUT='public-schema.stdout'
OUTPUTS=('raw-input-schema.json','public-input-schema.json')
CALLER=('tests/hia_native/view_call_oracle/run.py','additional_reference_summary')
PARENT=('scripts/hia_native_runtime_mcp_original.py','view_reference')

def need(value,label):
    if not value:raise ValueError(label)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def identity(path):
    v=path.lstat()
    need(stat.S_ISREG(v.st_mode) and not path.is_symlink() and path.resolve(strict=True)==path,
         'ordinary retained schema file')
    raw=path.read_bytes()
    row={'mode':v.st_mode,'inode':v.st_ino,'device':v.st_dev,'bytes':v.st_size,
         'mtime_ns':v.st_mtime_ns,'ctime_ns':v.st_ctime_ns,**pin(raw)}
    after=path.lstat()
    need((v.st_mode,v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)==
         (after.st_mode,after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
         'retained schema file changed during read')
    return row,raw

class RetainedSchemaWrites:
    def __init__(self,source,output):
        self.source=Path(source).absolute();self.output=Path(output).absolute()
        need(self.source.resolve(strict=True)==self.source and self.output.resolve(strict=True)==self.output,
             'non-aliased schema roots')
        self.folder=self.output/'view-call-original'
        need(self.folder.resolve(strict=True)==self.folder and self.folder.is_dir(),'retained View folder')
        self.source_files={}
        for name,(size,digest) in PINS.items():
            path=self.source/name;raw=path.read_bytes()
            need(not path.is_symlink() and len(raw)==size and pin(raw)['sha256']==digest,'exact schema-writeback source: '+name)
            self.source_files[name]=pin(raw)
        self.initial_inventory={};raws={}
        for name in (INPUT,*OUTPUTS):self.initial_inventory[name],raws[name]=identity(self.folder/name)
        lines=raws[INPUT].split(b'\n')
        need(len(lines)==3 and lines[-1]==b'','complete two-line original schema stream')
        self.expected=tuple(line+b'\n' for line in lines[:2])
        need(tuple(raws[name] for name in OUTPUTS)==self.expected,'retained schemas equal the complete original stream lines')
        self.owner_thread=threading.get_ident();self.pending_frame=None;self.pending=[]
        self.records=[];self.violations=[];self.installed=False;self.saved=None

    def reject(self,label):
        self.violations.append(label);raise PermissionError('read-only retained schema writeback: '+label)

    def check_inventory(self):
        for name,row in self.initial_inventory.items():
            if identity(self.folder/name)[0]!=row:self.reject('retained schema bytes or metadata changed')

    def write_bytes(self,path,data,frame):
        parent=frame.f_back
        if (frame.f_code.co_filename,frame.f_code.co_name)!=(str(self.source/CALLER[0]),CALLER[1]):
            self.reject('undeclared summary writer')
        if parent is None or (parent.f_code.co_filename,parent.f_code.co_name)!=(str(self.source/PARENT[0]),PARENT[1]):
            self.reject('undeclared summary caller')
        if threading.get_ident()!=self.owner_thread:self.reject('foreign summary thread')
        if frame.f_locals.get('output')!=self.folder:self.reject('summary output root')
        if type(data)is not bytes:self.reject('summary bytes type')
        index=len(self.pending)
        if index not in (0,1):self.reject('summary write count')
        if index==0:
            if self.pending_frame is not None:self.reject('unmatched summary frame')
            self.check_inventory();self.pending_frame=frame
        elif self.pending_frame is not frame:self.reject('summary pair changed frame')
        if Path(path).absolute()!=self.folder/OUTPUTS[index]:self.reject('summary output order or identity')
        self.check_inventory()
        if data!=self.expected[index] or data!=(self.folder/OUTPUTS[index]).read_bytes():
            self.reject('complete recomputed schema bytes differ')
        self.pending.append({'operation':'write_bytes','path':OUTPUTS[index],
            'complete_bytes':pin(data),'input_stream':pin((self.folder/INPUT).read_bytes()),
            'physical_writes':0})
        if index==1:
            self.check_inventory()
            self.records.append({'status':'PASS','caller_source':CALLER[0],'caller_function':CALLER[1],
                'parent_source':PARENT[0],'parent_function':PARENT[1],'folder':str(self.folder),
                'operations':self.pending})
            self.pending=[];self.pending_frame=None
        return len(data)

    def check_complete(self):
        need(not self.violations and self.pending_frame is None and self.pending==[] and self.records,
             'complete original retained schema writeback pairs')
        self.check_inventory()

    def install(self):
        need(not self.installed,'schema writeback adapter already installed')
        self.saved=Path.write_bytes
        def write_bytes(path,data):return self.write_bytes(path,data,sys._getframe(1))
        self.installed=True;Path.write_bytes=write_bytes

    def restore(self):
        if self.installed:Path.write_bytes=self.saved;self.installed=False

    def evidence(self):
        return {'schema':'hepta.history.retained-schema-writebacks.v1','source':str(self.source),
            'output':str(self.output),'folder':str(self.folder),'source_files':self.source_files,
            'input_name':INPUT,'output_names':list(OUTPUTS),'initial_inventory':self.initial_inventory,
            'records':self.records,'pending_operations':self.pending,
            'pending_frame':self.pending_frame is not None,'violations':self.violations,
            'physical_writes':0,'native_or_rust_executions':0,
            'original_summary_function_modified':False,'summary_result_cached':False}
