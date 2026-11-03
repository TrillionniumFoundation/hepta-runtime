import json, os, pathlib, stat, subprocess, sys, tempfile

ORIGINAL = r'''
import json, subprocess, sys
q = json.load(sys.stdin)
argv = ["sudo", "-n", q["executable"], *q.get("fixed_args", []), *q.get("args", [])]
try:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=float(q.get("timeout_seconds", 30)))
    result = {"exit_code": p.returncode, "stdout": p.stdout[-1048576:], "stderr": p.stderr[-1048576:]}
except subprocess.TimeoutExpired as exc:
    result = {"exit_code": 124, "stdout": (exc.stdout or "")[-1048576:], "stderr": "privileged action timed out"}
print(json.dumps(result, sort_keys=True))
'''

PATCHED = r'''
import json, subprocess, sys
q = json.load(sys.stdin)
argv = ["sudo", "-n", q["executable"], *q.get("fixed_args", []), *q.get("args", [])]

def bounded_text(value):
    if isinstance(value, bytes):
        return value[-1048576:].decode("utf-8", errors="replace")
    return (value or "")[-1048576:]

try:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", timeout=float(q.get("timeout_seconds", 30)))
    result = {"exit_code": p.returncode, "stdout": p.stdout[-1048576:], "stderr": p.stderr[-1048576:]}
except subprocess.TimeoutExpired as exc:
    result = {"exit_code": 124, "stdout": bounded_text(exc.stdout), "stderr": "privileged action timed out"}
print(json.dumps(result, sort_keys=True))
'''

def execute(script, sudo_script, timeout):
    with tempfile.TemporaryDirectory() as td:
        shim = pathlib.Path(td) / 'sudo'
        shim.write_text(sudo_script)
        shim.chmod(0o700)
        env = dict(os.environ, PATH=f'{td}:{os.environ.get("PATH", "")}')
        return subprocess.run([sys.executable,'-c',script], input=json.dumps({'executable':'/bin/true','timeout_seconds':timeout}), text=True, capture_output=True, env=env, timeout=12)

scenario1 = "#!/bin/sh\nprintf 'started\\n'\nexec sleep 4\n"
original = execute(ORIGINAL,scenario1,1.0)
assert original.returncode != 0 and 'Object of type bytes is not JSON serializable' in original.stderr, (original.returncode, original.stderr)
print('CONFIRMED old timeout bug:', original.stderr.strip().splitlines()[-1])
patched = execute(PATCHED,scenario1,1.0)
assert patched.returncode == 0, patched.stderr
result = json.loads(patched.stdout)
assert result['exit_code']==124 and result['stdout']=='started\n', result
print('PATCHED timeout JSON:', result)
scenario2 = "#!/bin/sh\nprintf '\\377'\n"
original2 = execute(ORIGINAL,scenario2,1.0)
assert original2.returncode != 0 and 'UnicodeDecodeError' in original2.stderr, original2.stderr
print('CONFIRMED old nonutf8 bug:', original2.stderr.strip().splitlines()[-1])
patched2 = execute(PATCHED,scenario2,1.0)
assert patched2.returncode == 0, patched2.stderr
result2 = json.loads(patched2.stdout)
assert result2['exit_code']==0 and result2['stdout']=='\ufffd', result2
print('PATCHED nonutf8 JSON:', result2)
