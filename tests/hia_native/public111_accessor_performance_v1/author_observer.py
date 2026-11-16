"""Derive a fixed FD4 observer from the already frozen complete stdio observer."""
from pathlib import Path
import argparse
import ast
import hashlib
import json

def sha(b):return hashlib.sha256(b).hexdigest()

def generate(original):
    text=original;edits=[]
    def replace(before,after):
        nonlocal text
        assert text.count(before)==1,before
        text=text.replace(before,after,1);edits.append({"before":before,"after":after})
    replace("PROCESS_SECONDS = 180\n","PROCESS_SECONDS = 60\n")
    replace("        self.journal_fd = None\n        self.journal_path",
            "        self.journal_fd = None\n        self.trace_fd = None\n        self.trace_path = self.output / 'host-trace.bin'\n        self.journal_path")
    replace("            assert stat.S_ISREG(os.fstat(self.journal_fd).st_mode)\n",
            "            assert stat.S_ISREG(os.fstat(self.journal_fd).st_mode)\n"
            "            self.trace_fd = os.open(self.trace_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)\n"
            "            assert self.trace_fd == 4, 'fixed owned trace FD4 is unavailable'\n"
            "            assert stat.S_ISREG(os.fstat(self.trace_fd).st_mode)\n")
    replace("stderr=subprocess.PIPE, pass_fds=(3,), start_new_session=True)",
            "stderr=subprocess.PIPE, pass_fds=(3, 4), start_new_session=True)")
    replace("'binary': expected_binary, 'journal_fd': 3}","'binary': expected_binary, 'journal_fd': 3, 'trace_fd': 4}")
    replace("        errors = []\n        if self.journal_fd is not None:\n",
            "        errors = []\n        if self.trace_fd is not None:\n"
            "            try:\n                os.close(self.trace_fd)\n"
            "            except BaseException as failure:\n                errors.append(failure)\n"
            "            self.trace_fd = None\n        if self.journal_fd is not None:\n")
    replace("            'private_owned_journal_fd': 3}",
            "            'trace': {'file': self.trace_path.name, **file_pin(self.trace_path)},\n"
            "            'private_owned_journal_fd': 3, 'private_owned_trace_fd': 4}")
    back=text
    for edit in reversed(edits):
        assert back.count(edit['after'])==1;back=back.replace(edit['after'],edit['before'],1)
    assert back==original
    old=ast.parse(original);new=ast.parse(text)
    cls=lambda t:next(n for n in t.body if isinstance(n,ast.ClassDef) and n.name=='NativeStdio')
    old_methods={n.name:ast.dump(n,include_attributes=False) for n in cls(old).body if isinstance(n,ast.FunctionDef)}
    new_methods={n.name:ast.dump(n,include_attributes=False) for n in cls(new).body if isinstance(n,ast.FunctionDef)}
    assert set(old_methods)==set(new_methods)
    unchanged=sorted(set(old_methods)-{'__init__','_seal'})
    assert all(old_methods[n]==new_methods[n] for n in unchanged)
    return text,{'schema':'hepta.runtime.fixed-fd4-stdio-observer.v1','baseline_sha256':sha(original.encode()),
        'successor_sha256':sha(text.encode()),'edits':edits,'inverse_recovers_full_baseline':True,
        'unchanged_original_method_ast':unchanged,'original_exchange_and_cleanup_methods_unchanged':True,
        'diagnostic_process_seconds':60,'production_process_seconds_unchanged':180,
        'hia_source_changed':False,'executed':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--retained',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    original=a.retained.read_text();text,proof=generate(original)
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'capture_stdio_trace.py').write_text(text)
    (a.output/'OBSERVER_PROOF.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in proof.items() if k!='edits'},sort_keys=True))

if __name__=='__main__':main()
