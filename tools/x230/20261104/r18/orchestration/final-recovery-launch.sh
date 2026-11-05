/usr/bin/python3 -B - <<'PY'
import hashlib,os
from pathlib import Path
root=Path('/Users/qianqi/work/hepta-runtime-x230-r16-20261104/r18-recovery-tools')
expected={'held_agent_r18_recovery.py':'6f6e5b38129b664c476faf7b65dcb094a9e52cf03ab773bb9714bac13476771f','r18_recovery_remote.py':'d983bda9993bddb2269929f8953ba9e6212d743e2ea4b98b0ba23638d95e9c98'}
for name,want in expected.items():
 p=root/name
 if p.resolve()!=p or hashlib.sha256(p.read_bytes()).hexdigest()!=want:raise RuntimeError('launcher bytes changed: '+name)
argv=['/usr/bin/python3','-B',str(root/'held_agent_r18_recovery.py'),'--remote-script',str(root/'r18_recovery_remote.py'),'--out','/Users/qianqi/work/hepta-runtime-x230-r16-20261104/r18-final-recovery-01','--timeout-seconds','1200']
os.execv(argv[0],argv)
PY
