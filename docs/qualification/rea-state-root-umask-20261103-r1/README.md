# State-root creation under umask 022: pre-fix MCP evidence

## Recorded result

A paired experiment with the same pinned, pre-fix release executable reproduced
the audit failure. Each case used a new private temporary fixture and a newly
started real stdio MCP controller. The requested state directory did not exist
before controller startup. Both cases called `rea_inspect_artifact` on the same
synthetic eight-byte WebAssembly header.

| Child umask | Fixture parent | Runtime-created state root | audit/jobs children | First tools/call |
| --- | --- | --- | --- | --- |
| 022 | 0700 | 0755 | 0700 / 0700 | JSON-RPC -32603: request audit unavailable; dispatch refused |
| 077 | 0700 | 0700 | 0700 / 0700 | Successful WASM header inspection |

The raw result is copied byte-for-byte in [results.json](results.json),
SHA-256 `c80ac2679cd35db460794349f71e23e27bec24a0216b044409a2e94484f63961`.
Its original schema spelling is preserved. The 077 response contains only
the synthetic artifact's preview and path, not production data.

The successful wrapper job is [recorded separately](job-receipt.json):
`1a1a17fa624-96a-6f71`, authoritative `succeeded`, exit 0,
`output_complete=true`, not cancelled or timed out. Exit 0 means the wrapper
observed the expected 022 failure and 077 control success; it does not mean
the 022 MCP request succeeded.

## Binary, source and CI identities

The reproduced executable is the existing fixed release artifact:

- SHA-256: `a697e102520cc483fe047665d86a3fab3049c74e7298936319d0f4bb224d0a82`.
- Size: 16,486,368 bytes.
- Recorded build source manifest: `d2e3016c002ca8a06a38ef4dcdd096e4b8686b348dcee91931fd2b20ccfe1ca6`.
- Baseline: `f9756508462ebc72e814a12f5dbba1b067edabe4` plus the integration
  source listed in that release's manifest.
- Original build/benchmark job: `1a1a14efda3-96a-6e38`.
- [Original release build provenance](../../weight-runtime/benchmarks/20261103-release-build-provenance.json).

The separate, older GitHub failure is
[run 41614880662, job 125845725090](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/41614880662/job/125845725090),
at exact PR84 head `f9756508462ebc72e814a12f5dbba1b067edabe4`.
Its explicitly 022 nextest job failed these two tests at the first audited
tool call in `tests/rea_mcp_external.rs`, with the same -32603 message:

- `external_mcp_policy_worker_and_controller_restart`.
- `model_pages_ranges_and_archive_roles_use_the_shipped_mcp_workers`.

That CI run and the a697 release reproduction are distinct executions and
distinct build identities. The 022/077 reproduction is not presented as
rerunning the exact old CI executable. The relevant pre-fix initializer and
request-audit source matched the old head; file hashes and the current fix
snapshot are in [provenance.json](provenance.json).

## Cause and repair boundary

The pre-fix initializer called `create_dir_all(state_dir)` without an explicit
mode. A missing state root therefore became 0755 under umask 022. Its startup
check only rejected group/world *write* permission, so 0755 passed. The
initializer separately made its jobs/audit children 0700.

Request auditing subsequently opened the state root itself and required its
actual filesystem UID to match the process UID and its permission bits to be
exactly 0700. The 0755 root failed that check before the tool implementation
was dispatched. The server deliberately returned the generic audit-unavailable
JSON-RPC error. A private 0700 fixture parent does not replace this independent
state-root inode check.

The submitted fix creates missing components using a recursive directory
builder with Unix mode 0700 at creation time. It preserves canonicalization,
then validates the final root's actual UID and exact 0700 mode before creating
controller locks. Existing nonprivate or foreign-owned roots are refused;
they are not chmod'ed into compliance. Request-audit checks remain unchanged.
Non-Unix creation/canonicalization behavior is preserved with the Unix-specific
operations conditionally compiled.

The source snapshot includes tests that isolate umask changes to exec children,
cover 000/022/077, verify pre-existing unsuitable directory metadata and
contents remain unchanged, and make the existing real-MCP regression always
start its child with 022. Fixture code does not pre-create a private state
directory to hide the initializer behavior.

**This evidence package contains pre-fix execution only.** The fixed-source
hashes record what was submitted for qualification; they are not a claim that
the new implementation has compiled or passed a post-fix test. The root's
focused 022 and full r3 qualification job, `1a1a18da495-96a-6fb4`, must be
bound to its own completed source snapshot and receipts separately. This
package does not assign that job a success status.

## Data handling and scope

The result was inspected before inclusion. It contains the synthetic WASM
response, temporary fixture paths, directory modes and child names, binary/CI
identities and the two protocol outcomes. It contains no credential, token,
SSH identity, production model or private runtime database contents.

Only the reviewed result and outer-job receipt are copied. Actual fixture
policy files, controller locks, request-audit/archive records, directories and
logs are not included. Original fixtures remain on the development host under
`/home/qian-qi/work/hepta-state-root-umask-repro-20261103-r1`. Parent temporary
directories were 0700. Both child environments were cleared; the configuration
used explicit private state/workspace roots and a synthetic host with execution,
PTY, writes and job networking disabled.

This is a two-case functional reproduction, not a performance experiment. It
does not test remote execution, other filesystems, hostile same-UID mutation,
power-loss durability or recovery of an existing unsafe state directory.
Changing permissions on an existing production directory is outside this
recipe. The old CI incident and this local reproduction retain their separate
identities.

## Reproduction recipe

Use the already-built executable with the exact a697 digest and a **new**
absolute output directory. The recipe generates its own configuration and
eight-byte WASM fixture, verifies the binary digest, applies umask only to each
child, captures replies with bounded waits, and terminates only those children.
No Cargo invocation or production profile is required.

This recipe intentionally asserts the **pre-fix** 022 failure. To qualify a
fixed binary, use the dedicated regression tests and a separately recorded
post-fix run; do not reinterpret a failed pre-fix assertion as a new regression.

~~~sh
python3 - /absolute/path/to/pinned-a697-hepta-runtime /absolute/new/private-output <<'PY'
import hashlib,json,os,pathlib,queue,subprocess,sys,tempfile,threading,time
root=pathlib.Path(sys.argv[2])
assert root.is_absolute(), "use a new absolute output path"
root.mkdir(mode=0o700)
binary=pathlib.Path(sys.argv[1])
assert binary.is_absolute(), "use the existing pinned binary"
digest=hashlib.sha256(binary.read_bytes()).hexdigest()
assert digest=="a697e102520cc483fe047665d86a3fab3049c74e7298936319d0f4bb224d0a82"
rows=[]
for mask in [0o022,0o077]:
 fixture=pathlib.Path(tempfile.mkdtemp(prefix=f"mask-{mask:03o}-",dir=root))
 workspace=fixture/"workspace";workspace.mkdir(mode=0o700)
 source=workspace/"owned.wasm";source.write_bytes(b"\0asm\x01\0\0\0")
 state=fixture/"state";assert not state.exists()
 config=fixture/"runtime.json"
 config.write_text(json.dumps({"state_dir":str(state),"controller_workspace_roots":[str(workspace)],
  "hosts":{"never-connect":{"ssh_target":"never-connect-ci","remote_state_dir":str(fixture/"remote"),
   "allow_execute":False,"allow_pty":False,"allow_write":False,"allow_job_network":False}}}))
 replies=queue.Queue()
 with (fixture/"server.stderr").open("wb") as errors:
  child=subprocess.Popen([str(binary),"mcp","--runtime-config",str(config)],cwd=fixture,env={},
   stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,umask=mask)
  def read():
   for raw in child.stdout:replies.put(raw)
   replies.put(None)
  reader=threading.Thread(target=read,daemon=True);reader.start()
  def send(value):
   child.stdin.write(json.dumps(value,separators=(",",":")).encode()+b"\n");child.stdin.flush()
  def request(identifier,method,params):
   send({"jsonrpc":"2.0","id":identifier,"method":method,"params":params})
   end=time.monotonic()+45
   while True:
    raw=replies.get(timeout=max(.001,end-time.monotonic()))
    assert raw is not None,"controller closed stdout"
    result=json.loads(raw)
    if result.get("id")==identifier:return result
  try:
   initialized=request(1,"initialize",{"protocolVersion":"2026-07-28","capabilities":{},
    "clientInfo":{"name":"private-state-umask-reproduction","version":"1"}})
   assert "error" not in initialized,initialized
   send({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
   reply=request(2,"tools/call",{"name":"rea_inspect_artifact","arguments":{"path":str(source)}})
   row={"umask":f"{mask:03o}","fixture":str(fixture),"fixture_mode":f"{fixture.stat().st_mode&0o7777:04o}",
    "state_mode":f"{state.stat().st_mode&0o7777:04o}","jobs_mode":f"{(state/'jobs').stat().st_mode&0o7777:04o}",
    "audit_mode":f"{(state/'audit').stat().st_mode&0o7777:04o}","state_children":sorted(p.name for p in state.iterdir()),
    "rpc_response":reply,"remote_host_contacted":False,"production_state_accessed":False}
   if mask==0o022:
    assert reply["error"]["code"]==-32603
    assert reply["error"]["message"]=="request audit unavailable; dispatch refused"
    assert row["state_mode"]=="0755"
   else:
    assert "error" not in reply and not reply["result"].get("isError"),reply
    assert row["state_mode"]=="0700"
   rows.append(row)
  finally:
   if child.poll() is None:child.terminate()
   try:child.wait(timeout=10)
   except subprocess.TimeoutExpired:child.kill();child.wait(timeout=10)
   child.stdin.close();child.stdout.close();reader.join(timeout=5)
record={"schema":"hepta.state-root-umask-prefixed-reproduction.v1","binary":str(binary),"binary_sha256":digest,
 "old_ci":{"head":"f9756508462ebc72e814a12f5dbba1b067edabe4","run":41614880662,"job":125845725090},
 "scope":"Existing pinned release artifact; all state/config/source paths under new private fixtures. No Cargo invocation or production configuration used.",
 "cases":rows}
(root/"results.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
print(json.dumps({"result":str(root/"results.json"),"binary_sha256":digest,"cases":[
 {"umask":r["umask"],"state_mode":r["state_mode"],"audit_mode":r["audit_mode"],"rpc_error":r["rpc_response"].get("error"),"success":"result" in r["rpc_response"]} for r in rows]},sort_keys=True))

PY
~~~

[SHA256SUMS](SHA256SUMS) covers every other file in this evidence directory.
