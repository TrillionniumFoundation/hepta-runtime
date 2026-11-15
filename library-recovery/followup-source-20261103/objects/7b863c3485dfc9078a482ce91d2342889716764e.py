import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("runtime_remote_guard.py")
BASE_REQUEST = {"job_id": "job-1", "request_fingerprint": "aabb", "request_digest": "fullhash"}

def case(name, request_content=None, files=None, request_patch=None, expect_ok=False, expect=""):
    with tempfile.TemporaryDirectory() as d:
        job=Path(d)/"job"
        job.mkdir()
        if request_content is not None:
            (job/"request.json").write_text(request_content)
        for path, content in (files or {}).items():
            (job/path).write_text(content)
        request=dict(BASE_REQUEST, job_dir=str(job), **(request_patch or {}))
        p=subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(request), text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        result = (p.returncode==0) == expect_ok and expect in ((p.stdout if expect_ok else p.stderr))
        print(f"{'PASS' if result else 'FAIL'} {name}: exit={p.returncode}, message={(p.stdout+p.stderr).strip()[:120]}")
        if not result: raise AssertionError(name)

if __name__=="__main__":
    request=json.dumps(BASE_REQUEST)
    case("corrupt request refuses replay", "{partial", expect="corrupt remote job state")
    case("request without launch refuses replay", request, expect="ambiguous prior launch")
    case("launch_failed refuses reused success", request, {"launch.json":'{"backend":"launch_failed"}'}, expect="prior remote launch failed")
    case("orphaned remote started state refuses launch", None, {"started.json":"{}"}, expect="orphaned remote job state")
    case("mismatched fingerprint refuses replay", request, request_patch={"request_fingerprint":"wrong"}, expect="bound to a different request")
    case("confirmed launch is reused", request, {"launch.json":'{"backend":"systemd","unit":"u"}'}, expect_ok=True, expect="reused_remote")
    case("confirmed terminal status is reused", request, {"exit.json":'{"exit_code":0}'}, expect_ok=True, expect="completed")
    case("fresh request is only prepared", None, expect_ok=True, expect="prepared_only")
