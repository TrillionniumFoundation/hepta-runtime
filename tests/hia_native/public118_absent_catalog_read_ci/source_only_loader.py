"""Load admitted retained Python readers directly from their exact source bytes."""
from contextlib import contextmanager
import hashlib,importlib.machinery
from pathlib import Path
import stat
@contextmanager
def exact_source_only(root):
    root=Path(root).resolve(strict=True)
    admitted={}
    for path in root.rglob('*.py'):
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.resolve(strict=True)!=path or info.st_nlink!=1:
            raise ValueError('nonregular retained Python source')
        raw=path.read_bytes()
        admitted[str(path)]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    loader=importlib.machinery.SourceFileLoader
    original=loader.get_code;calls=[]
    def get_code(self,fullname):
        path=Path(self.path).absolute();name=str(path)
        if name not in admitted:return original(self,fullname)
        raw=path.read_bytes()
        actual={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        if actual!=admitted[name]:raise ValueError('retained Python source changed')
        calls.append({'module':fullname,'path':name,**actual})
        return compile(raw,name,'exec',dont_inherit=True)
    loader.get_code=get_code
    try:yield calls
    finally:loader.get_code=original
