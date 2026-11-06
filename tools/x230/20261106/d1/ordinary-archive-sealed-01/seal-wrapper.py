from pathlib import Path
import hashlib,json,subprocess,sys,time
base=Path('/tmp/hepta-runtime-recovery-20261106')
originals=base/'d1-ordinary-actual-originals-02'
review=base/'d1-ordinary-archive-independent-review-01'
template=review/'archive_d1_ordinary.unsealed.py'
sealer=review/'seal_ordinary_archive.py'
output=base/'d1-ordinary-archive-sealed-01'
execution=base/'d1-ordinary-archive-seal-execution-01'
expected={"ordinary-02/report.json":{"bytes":82472,"sha256":"6e14524b1f970efa62bba51873b8ed4db757216ff84eb9958b138ffa90274fce"},"ordinary-native-02.json":{"bytes":729,"sha256":"02a5daf8bd346e10e9a2a01ae6a0c3e3d3e3b071ba9743af606e5ab3e86c269a"},"ordinary-native-read-02-000.json":{"bytes":3055,"sha256":"a9ab2bca707d9f5e184751dda26b8d65b27e724f6a737e0d0f755a517d3849f1"},"ordinary-02/isolated-tests/summary.json":{"bytes":6807,"sha256":"652c858300b84895f6dbd58a89b739e844a52ea2f11a1a9e24d39cca192f95e3"},"ordinary-02/isolated-tests.audit.json":{"bytes":1419880,"sha256":"67d0043dcbe3159cd34422c77cf65ff6bdc2508856f88053aa3b52d7f73df859"},"ordinary-02/source-map.json":{"bytes":24368,"sha256":"98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133"},"ordinary-plan-02.json":{"bytes":382677,"sha256":"e03c418468af90962db508a76f2d66e260f0ed3aea6affad9c9b29f50b38bc1c"},"ordinary-installation-02.json":{"bytes":2743,"sha256":"09bcd3d10b833ce36c2f44022db05ad240407ec8015e2ad024e673b1d17c072c"},"ordinary-installation-started-02.json":{"bytes":401,"sha256":"31aca3e1569ae6788082d01859c378d472d664f373a47631a23dbe9eece0fd7d"},"ordinary-verification-input-02.json":{"bytes":2166,"sha256":"c3b66fe04ec09c54dfc1104cbf050f408dd68c72a24dbd0062a0c86607d57136"},"ordinary-postflight-02.json":{"bytes":223078,"sha256":"db8a2cddf7e13b48ad9dbcf8ebdf03664dd604114acb7e36dafe176598b17ed5"},"ordinary-postflight-native-02.json":{"bytes":729,"sha256":"3c62cd62bcc84c0a7ab392418eb697003e21b3590b728f7a9e5e1b6b1a8c5bd6"},"ordinary-postflight-native-read-02-000.json":{"bytes":1230,"sha256":"3f898f45c63daf3f486db6698ce6abddeab608f17a516413dd3e684169fb8870"}}
pins={}
for path,want in [(template,{'bytes':48334,'sha256':'88926948ee409d9cb15e3013243a486eca522aefc27b03da56dee28f6dab0009'}),(sealer,{'bytes':14116,'sha256':'1e6eae1ca85513164e7c92dd68d62ffa8a8cb8c69bebba2eab406cff91843cf9'})]:
 raw=path.read_bytes(); got={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 assert got==want,(str(path),got)
 pins[str(path)]=got
for name,want in expected.items():
 path=originals/name;raw=path.read_bytes()
 got={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 assert got==want,(name,got)
 pins[str(path)]=got
assert not output.exists() and not execution.exists()
execution.mkdir(mode=0o700)
argv=['/usr/bin/python3','-B',str(sealer),'--template',str(template),'--originals',str(originals),'--output',str(output)]
started=time.time()
result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
for name,raw in [('stdout.log',result.stdout),('stderr.log',result.stderr)]:
 with (execution/name).open('xb') as f:f.write(raw)
receipt={'schema':'hepta-d1-ordinary-archive-local-seal-execution/v1','argv':argv,'started_unix':started,'finished_unix':time.time(),'returncode':result.returncode,'input_pins':pins,'stdout':{'bytes':len(result.stdout),'sha256':hashlib.sha256(result.stdout).hexdigest()},'stderr':{'bytes':len(result.stderr),'sha256':hashlib.sha256(result.stderr).hexdigest()},'collector_executed':False,'verifier_or_auditor_reexecuted':False,'host_requests':0}
with (execution/'receipt.json').open('xb') as f:f.write((json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode())
print(json.dumps({'returncode':result.returncode,'stdout':result.stdout.decode(),'stderr':result.stderr.decode(),'execution_receipt':str(execution/'receipt.json')}))
sys.exit(result.returncode)

