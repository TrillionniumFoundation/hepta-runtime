"""Public byte-stream regressions for exact and rounded localization (Python stdlib)."""
import math
import struct
import subprocess
import sys

worker=sys.argv[1]
def run(mode, corruption, width=0., repeat=False):
    rows=[]
    # Bounded basis spanning all hidden coordinates and an independent bias.
    for i in range(49):
        h=[float((i==j or repeat and j==7) and (not repeat or j==7)) for j in range(48)]+[1.]
        y=[sum(scale*h[c] for row,c,scale in corruption if row==k) for k in range(4)]
        vals=y if mode==1 else [v-width for v in y]+[v+width for v in y]
        rows.append(struct.pack('<'+'d'*(49+len(vals)),*(h+vals)))
    w=b'WSL'+str(mode).encode()+struct.pack('<II',1,len(rows))+b''.join(rows)
    p=subprocess.run([worker],input=w,check=True,capture_output=True)
    return p.stdout.decode().strip().split()
for mode in (1,2):
    assert run(mode,[])==['KEEP']
    single=run(mode,[(2,7,.25)],width=.001 if mode==2 else 0)
    assert single[:3]==['EDIT','2','7'] and math.isclose(float(single[3]),.25)
    assert run(mode,[(2,7,.25),(2,17,-.3)])==['ABSTAIN']
    assert run(mode,[(2,7,.25)],repeat=True)==['ABSTAIN']
bad=subprocess.run([worker],input=b'WSL2'+struct.pack('<II',1,0),capture_output=True)
assert bad.returncode!=0
print('9 public stream checks passed')
