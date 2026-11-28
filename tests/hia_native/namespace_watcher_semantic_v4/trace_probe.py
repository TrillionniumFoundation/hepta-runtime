"""Test-owned child for tracer startup, failure, and actual orphan-reap controls."""
import json,os,sys,time
mode=sys.argv[1]
if mode=="exit":raise SystemExit(23)
ready=dict(command="ready",role="probe",pid=os.getpid(),parent_pid=os.getppid(),
    pgid=os.getpgrp(),uid=os.geteuid(),gid=os.getegid(),layout={})
if mode=="wrong-parent":ready["parent_pid"]=0
print(json.dumps(ready,sort_keys=True),flush=True)
if mode in("block","wrong-parent"):
    while True:time.sleep(1000)
for line in sys.stdin.buffer:
    request=json.loads(line)
    print(json.dumps(dict(command=request["cmd"],case=request["case"]),sort_keys=True),flush=True)
