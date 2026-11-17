"""Run the exact View crate generator as complete read/compare operations.

The original generator and caller are byte-bound and remain unmodified. Its
seven generated/copied file bodies are recomputed every time. The narrow
TemporaryDirectory spelling denotes the already captured crate only while
that exact caller is active; it is not a general filesystem virtualization.
All would-be writes compare complete bytes and the exact ten-operation order.
"""
from __future__ import annotations
import hashlib,io,locale,os,shutil,stat,sys,tempfile,threading
from pathlib import Path

PINS={
 'scripts/hia_native_view_call_qualification.py':(87273,'6797db0667a828bd38ad27784cf7d17e1414b9bb1a7ed7a5891ed3938f78b85d'),
 'tests/hia_native/view_call_oracle/verify_sources.py':(14395,'2118c3d91971887451bd3d72f468dfcfeb8e74f853c54f9273829fa676e4356c'),
 'tests/hia_native/view_call_oracle/run.py':(13903,'19ed876d121a1c917c667ccc3ead4dae1ed25c4a5b7cf1744625773c921ca33b')}
FILES=('Cargo.toml','Cargo.lock','src/main.rs','src/bin/view_call_sdk.rs',
 'src/bin/view_call_router_sdk.rs','src/bin/view_call_public_schema.rs','src/bin/view_call_info_sdk.rs')
DIRECTORIES=('.', 'src','src/bin')
OPERATIONS=(('mkdir','.'),('mkdir','src'),('copyfile','Cargo.toml'),('copyfile','Cargo.lock'),
 ('write_text','src/main.rs'),('mkdir','src/bin'),('write_text','src/bin/view_call_sdk.rs'),
 ('write_text','src/bin/view_call_router_sdk.rs'),('write_text','src/bin/view_call_public_schema.rs'),
 ('write_text','src/bin/view_call_info_sdk.rs'))

def need(value,label):
    if not value:raise ValueError(label)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def metadata(path):
    v=path.lstat()
    return {'mode':v.st_mode,'inode':v.st_ino,'device':v.st_dev,'bytes':v.st_size,
            'mtime_ns':v.st_mtime_ns,'ctime_ns':v.st_ctime_ns}

class SourceReconstructionReads:
    def __init__(self,source,output):
        self.source=Path(source).absolute();self.output=Path(output).absolute()
        need(self.source.resolve(strict=True)==self.source and self.output.resolve(strict=True)==self.output,
             'source reconstruction roots must be non-aliased existing directories')
        self.oracle=self.source/'tests/hia_native/view_call_oracle'
        self.original=self.output/'view-call-original';self.crate=self.original/'crate'
        self.sources={}
        for relative,(size,digest) in PINS.items():
            path=self.source/relative;raw=path.read_bytes()
            need(not path.is_symlink() and len(raw)==size and pin(raw)['sha256']==digest,
                 'exact unchanged source-reconstruction dependency: '+relative)
            self.sources[relative]=pin(raw)
        self.default_encoding=io.text_encoding(None)
        self.locale_encoding=locale.getencoding()
        resolved=self.locale_encoding if self.default_encoding=='locale' else self.default_encoding
        need(resolved.lower().replace('-','')=='utf8' and os.linesep=='\n','original Linux UTF-8 text-write contract')
        self.owner_thread=threading.get_ident();self.active=None;self.records=[];self.violations=[]
        self.installed=False;self.saved={};self.wrappers={}
        self.initial_inventory=self.inventory()

    def reject(self,label):
        self.violations.append(label);raise PermissionError('read-only source reconstruction: '+label)

    def inventory(self):
        need(self.crate.resolve(strict=True)==self.crate and stat.S_ISDIR(self.crate.lstat().st_mode),'captured crate directory')
        paths={'.':self.crate}
        for path in self.crate.rglob('*'):
            name=path.relative_to(self.crate).as_posix();need(name not in paths,'duplicate crate member')
            paths[name]=path
        need(set(paths)==set(FILES)|set(DIRECTORIES),'complete original seven-file crate inventory')
        result={}
        for name,path in sorted(paths.items()):
            info=metadata(path)
            info['sha256']=None
            need(not path.is_symlink() and path.resolve(strict=True)==path,'non-aliased crate member')
            if name in DIRECTORIES:
                need(stat.S_ISDIR(info['mode']),'exact crate directory type')
            else:
                need(stat.S_ISREG(info['mode']),'exact crate regular file type')
                info.update(pin(path.read_bytes()))
            result[name]=info
        return result

    def caller(self,frame,relative,name):
        if frame.f_code.co_filename!=str(self.source/relative) or frame.f_code.co_name!=name:
            self.reject('undeclared source caller')
        if threading.get_ident()!=self.owner_thread:self.reject('foreign reconstruction thread')

    def temporary(self,*args,**kwargs):
        self.caller(sys._getframe(1),'scripts/hia_native_view_call_qualification.py','_original_evidence')
        if args or kwargs!={'prefix':'view-original-materialization-'}:self.reject('undeclared temporary-directory request')
        if self.active is not None:self.reject('nested source reconstruction')
        owner=self
        class ExistingCrate:
            name=str(owner.original)
            def __enter__(self):
                if owner.active is not None:owner.reject('nested source reconstruction')
                need(owner.inventory()==owner.initial_inventory,'captured crate changed before reconstruction')
                owner.active={'operations':[],'temporary_prefix':'view-original-materialization-',
                    'temporary_path':str(owner.original),'crate':str(owner.crate)}
                return self.name
            def __exit__(self,kind,value,tb):
                row=owner.active;owner.active=None
                need(row is not None,'unmatched source reconstruction exit')
                if kind is not None:
                    row['status']='FAIL';row['error']={'type':kind.__name__,'message':str(value)}
                    owner.records.append(row);return False
                try:
                    need([(r['operation'],r['path']) for r in row['operations']]==list(OPERATIONS),
                         'complete original source-reconstruction operation order')
                    need(owner.inventory()==owner.initial_inventory,'reconstruction modified complete crate bytes/metadata')
                    row['status']='PASS';row['error']=None
                except BaseException as exc:
                    row['status']='FAIL';row['error']={'type':type(exc).__name__,'message':str(exc)}
                    owner.records.append(row);raise
                owner.records.append(row);return False
        return ExistingCrate()

    def expect(self,operation,path,caller):
        self.caller(caller,'tests/hia_native/view_call_oracle/verify_sources.py','materialize')
        if self.active is None:self.reject('source write outside reconstruction')
        path=Path(path).absolute()
        try:relative='.' if path==self.crate else path.relative_to(self.crate).as_posix()
        except ValueError:self.reject('source write outside captured crate')
        if path.resolve(strict=True)!=path:self.reject('aliased source destination')
        position=len(self.active['operations'])
        if position>=len(OPERATIONS) or (operation,relative)!=OPERATIONS[position]:
            self.reject('source operation order or destination')
        return path,relative

    def mkdir(self,path,mode,parents,exist_ok,caller):
        path,name=self.expect('mkdir',path,caller)
        if mode!=0o777 or type(parents)is not bool or type(exist_ok)is not bool or exist_ok or parents!=(name=='.'):
            self.reject('source mkdir argument contract')
        if not stat.S_ISDIR(path.lstat().st_mode):self.reject('source mkdir destination type')
        self.active['operations'].append({'operation':'mkdir','path':name,'mode':mode,'parents':parents,'exist_ok':exist_ok,'physical_writes':0})
        return None

    def copyfile(self,source,target,follow_symlinks,caller):
        path,name=self.expect('copyfile',target,caller)
        source=Path(source).absolute()
        if follow_symlinks is not True or source!=self.oracle/name or source.resolve(strict=True)!=source:
            self.reject('source copy identity or options')
        raw=source.read_bytes();actual=path.read_bytes()
        if raw!=actual:self.reject('complete copied original bytes differ')
        self.active['operations'].append({'operation':'copyfile','path':name,'source':str(source),
            'complete_bytes':pin(raw),'physical_writes':0})
        return target

    def write_text(self,path,data,encoding,errors,newline,caller):
        path,name=self.expect('write_text',path,caller)
        if type(data)is not str or encoding is not None or errors is not None or newline is not None:
            self.reject('source write_text argument contract')
        raw=data.encode('utf-8');actual=path.read_bytes()
        if raw!=actual:self.reject('complete regenerated original bytes differ')
        self.active['operations'].append({'operation':'write_text','path':name,'characters':len(data),
            'complete_bytes':pin(raw),'physical_writes':0})
        return len(data)

    def install(self):
        need(not self.installed,'source reconstruction adapter already installed')
        self.saved={'temporary':tempfile.TemporaryDirectory,'copyfile':shutil.copyfile,
                    'mkdir':Path.mkdir,'write_text':Path.write_text}
        def mkdir(path,mode=0o777,parents=False,exist_ok=False):
            if self.active is None:return self.saved['mkdir'](path,mode=mode,parents=parents,exist_ok=exist_ok)
            return self.mkdir(path,mode,parents,exist_ok,sys._getframe(1))
        def write_text(path,data,encoding=None,errors=None,newline=None):
            return self.write_text(path,data,encoding,errors,newline,sys._getframe(1))
        def copyfile(source,target,*,follow_symlinks=True):
            return self.copyfile(source,target,follow_symlinks,sys._getframe(1))
        self.wrappers={'temporary':self.temporary,'copyfile':copyfile,'mkdir':mkdir,'write_text':write_text}
        self.installed=True
        tempfile.TemporaryDirectory=self.wrappers['temporary'];shutil.copyfile=copyfile
        Path.mkdir=mkdir;Path.write_text=write_text

    def restore(self):
        if self.installed:
            try:
                tempfile.TemporaryDirectory=self.saved['temporary'];shutil.copyfile=self.saved['copyfile']
            finally:
                Path.mkdir=self.saved['mkdir'];Path.write_text=self.saved['write_text'];self.installed=False

    def evidence(self):
        return {'schema':'hepta.history.view-source-reconstruction.v1','source':str(self.source),
            'output':str(self.output),'source_files':self.sources,'crate':str(self.crate),
            'expected_files':list(FILES),'expected_directories':list(DIRECTORIES),
            'initial_inventory':self.initial_inventory,'default_encoding':self.default_encoding,
            'locale_encoding':self.locale_encoding,'records':self.records,'violations':self.violations,
            'active_reconstruction':self.active is not None,'new_file_writes':0,
            'native_or_rust_executions':0,'original_materialize_function_modified':False,
            'materialization_summary_cached':False}
