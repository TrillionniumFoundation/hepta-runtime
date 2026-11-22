"""Finite synthetic child behavior for the separate aggregate-CPU supervisor gate."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def burn(seconds):
    start=time.process_time()
    while time.process_time()-start<seconds:pass


mode=sys.argv[1];result=Path(sys.argv[2]) if len(sys.argv)>2 else None
if mode=='burn':burn(float(sys.argv[2]));raise SystemExit(0)
if mode=='normal':result.write_text(json.dumps(dict(status='PASS')))
elif mode=='nonzero':result.write_text(json.dumps(dict(status='FAILED')));raise SystemExit(7)
elif mode=='missing':pass
elif mode=='sleep':time.sleep(2)
elif mode=='aggregate':
    for _ in range(3):subprocess.run([sys.executable,__file__,'burn','0.65'],check=True)
elif mode=='orphan':
    pid=os.fork()
    if pid==0:time.sleep(3);os._exit(0)
    result.write_text(json.dumps(dict(status='PASS')))
else:raise ValueError('unknown synthetic mode')
