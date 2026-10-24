#!/usr/bin/env python3
"""R19 owned sequential cohort driver. Frozen code 503; no production mutation."""
import argparse, hashlib, json, os, pathlib, stat, subprocess, sys, time, traceback
ROOT=pathlib.Path("/home/qian-qi/hepta-runtime-v9-code-frozen-5037262-20261013")
OUT=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013/docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix")
BINARY=pathlib.Path("/home/qian-qi/hepta-runtime-v9-pinned-native-92c3ae-20261013")
CONFIG=pathlib.Path("/home/qian-qi/.config/hepta-runtime-operator/runtime.json")
HEAD="50372629e0522d19b5bc4c1a800bfc311e4597f9"
FP="b376418a2b3346a707dfd2592f99ce6fbceb6c86c8445995069f1e4ac0ed32bf"
BINARY_SHA="92c3ae0eb64e8d2213e4938312ae636a2ab6d18ef417b2167086d0737d7664ce"
CONFIG_SHA="ebd29c10ed8498f2662c5bab556de701a628e8870631db40cc1e6719db70fac5"
CONTRACT=ROOT/"deploy/contracts/hepta-runtime-full-operator-v9.json"
CONTRACT_SHA="3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"
PINS={
"tests/dc_successor_contract.py":"0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde",
"tests/dc_functional_v9_version_pin.py":"ac6dbe8a29c9a1e1d31712f4862d3895962bd92e3dbf5d805bee15b5466b7059",
"tests/runtime_http_acceptance.py":"8b7ee206ccfc7978ac4abdf3eac3ddb8f7e7c36d053f601b5cfcb66f52fb8dba",
"deploy/mcp_tool_contract.py":"e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216",
"deploy/chatgpt_full_operator.py":"b35313888a70a90dc72be44dc45d3f20be45337d7c2353556a382564299d649a",
"tests/dc_parity_release_six_host_acceptance.py":"f9ec9fdeb9a5aaa77cb6f813aa7afe4dd3db24f199731a20d579f687c3883227",
"tests/host_health_acceptance.py":"73f1105414b5362ab007843b4138ac7dc3bb43766630da7f70406283705cd5ea",
"tests/multi_read_six_host_acceptance.py":"55b91cc2ef6207e0f23eefd3584a890621e8bf075926aa676f3b79debaf35f57",
"tests/dc_functional_v9_credential_scope_acceptance.py":"3c93e4c32b56b04c9d8bca0020917c9491657fcdcc1e466f27701ddc31fe9e06",
"tests/dc_functional_v9_search_six_host_acceptance.py":"3f30d46877a3d29c25dbc28a605ffe8a3ec8152a4b4c4dc47839af395cdeabca",
"tests/dc_functional_v9_real_facade_cancel_acceptance.py":"4c57801854090036169eccc9b225c399db781b53494766ee4943c1d5eea5538c",
"tests/dc_functional_v9_signal_audit_acceptance.py":"9c19eace90ac21ae70949e7f3718500f44a07f19edbf47350d398cef80c0858a",
"tests/dc_functional_v9_health_multiread_acceptance.py":"6cd20cc16d3982150e0dca549ed4e1440409798bf60e218145b053addd785c77",
"tests/dc_functional_v9_job_inventory_snapshot_acceptance.py":"0f2cb22ab64d635e4e8e093568c19fbf09266545547174f9f480b965027cdad9",
"tests/dc_functional_v6_operator_six_host_acceptance.py":"05e389b6bea9ea5769c10cb5b267c9084b1fea4b0b906af4b3c40ec403d1fdc6",
"tests/operator_acceptance.py":"f1f3d9b88cae9b522e2b275d7a9088a69cc1be8c1bc048e82b6c3600e7dadcda",
"tests/dc_parity_native_acceptance.py":"347d695ae672ecefe7489cb083788ea21f0812a051855eff4a0e3ecef2f197b9",
"tests/operator_job_identity_real_acceptance.py":"c1a1dbd7032125fe5d2406992a9d66d4e953e00ab45e0de0223dc882733bba43",
"tests/operator_job_identity_mac_acceptance.py":"f03ee0b01293910ca153f27ea9757f5d68205a33c802e0ac35746205d0146e54",
"tests/search_effects_native_acceptance.py":"fb1a246db2a2bdfbeb7171dfe3c58c463c2ebda655161a9ee4bf2c69eb174dc0",
"deploy/contracts/hepta-runtime-full-operator-v4.json":"d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1",
"deploy/contracts/hepta-runtime-full-operator-v8.json":"b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318",
"deploy/contracts/hepta-runtime-full-operator-v9.json":CONTRACT_SHA,
}
UNITS={"hepta-runtime-operator.service":2863,"hepta-openai-full-operator.service":2873,"desktop-commander-remote.service":2809}
def digest(p):
    p=pathlib.Path(p)
    if p.is_symlink() or not p.is_file():raise ValueError("ordinary input required")
    return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as f:json.dump(v,f,indent=2,sort_keys=True);f.write("\n");f.flush();os.fsync(f.fileno())
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def proof(script):
    code_head=subprocess.check_output(["git","-C",str(ROOT),"rev-parse","HEAD"],text=True).strip()
    paths=set(ROOT.glob("src/**/*.rs"))|set(ROOT.glob("src/**/*.py"))|{ROOT/"Cargo.toml",ROOT/"Cargo.lock"}
    entries={p.relative_to(ROOT).as_posix():{"bytes":p.stat().st_size,"sha256":digest(p)} for p in sorted(paths)}
    source_fp=hashlib.sha256(canonical(entries)).hexdigest()
    helpers={name:digest(ROOT/name) for name in PINS}
    if code_head!=HEAD or source_fp!=FP or digest(BINARY)!=BINARY_SHA or digest(CONFIG)!=CONFIG_SHA or helpers!=PINS:
        raise ValueError("frozen source/native/config/helper identity differs")
    env=dict(os.environ);env.update(XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")
    services={}
    for unit,pid in UNITS.items():
        text=subprocess.check_output(["systemctl","--user","show",unit,"-p","MainPID","-p","ActiveState","-p","InvocationID"],text=True,env=env,timeout=15)
        row=dict(line.split("=",1) for line in text.splitlines() if "=" in line)
        if row.get("ActiveState")!="active" or row.get("MainPID")!=str(pid):raise ValueError("protected production service identity differs")
        data=pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ",1)[1].split()
        row.update(start_ticks=int(data[19]),uid=pathlib.Path(f"/proc/{pid}").stat().st_uid)
        services[unit]=row
    return {"source_HEAD":code_head,"source_fingerprint":source_fp,"native_sha256":digest(BINARY),"contract_sha256":digest(CONTRACT),"runtime_config_sha256":digest(CONFIG),"helpers":helpers,"driver_sha256":digest(__file__),"selected_harness_sha256":digest(script),"protected_services":services,"production_unit_file_modes_not_pinned":True}
def args_for(phase,d):
    common=["--expected-loader-sha256",PINS["tests/dc_successor_contract.py"],"--expected-tool-helper-sha256",PINS["deploy/mcp_tool_contract.py"],"--expected-http-helper-sha256",PINS["tests/runtime_http_acceptance.py"],"--expected-version-helper-sha256",PINS["tests/dc_functional_v9_version_pin.py"]]
    output=d/"cohort.json";receipts=d/"receipts"
    std=["--binary",str(BINARY),"--contract",str(CONTRACT),"--expected-binary-sha256",BINARY_SHA,"--expected-source-fingerprint",FP]
    if phase=="01-credential":
        return ROOT/"tests/dc_functional_v9_credential_scope_acceptance.py",std+["--runtime-config",str(CONFIG),"--out",str(output)]+common,output
    if phase=="02-search":
        return ROOT/"tests/dc_functional_v9_search_six_host_acceptance.py",std+["--receipt-dir",str(receipts),"--out",str(output),"--max-workers","1"]+common,output
    if phase=="03-facade":
        return ROOT/"tests/dc_functional_v9_real_facade_cancel_acceptance.py",["--binaryrelease",str(BINARY),"--contract",str(CONTRACT),"--expected-binary-sha256",BINARY_SHA,"--compiled-source-fingerprint",FP,"--receipt-dir",str(receipts),"--out",str(output)]+common,output
    if phase=="04-signal":
        return ROOT/"tests/dc_functional_v9_signal_audit_acceptance.py",["--binary",str(BINARY),"--contract",str(CONTRACT),"--receipt-dir",str(receipts),"--out",str(output),"--expected-head",HEAD,"--expected-candidate-sha256",BINARY_SHA,"--expected-contract-sha256",CONTRACT_SHA,"--expected-source-fingerprint",FP]+common,output
    if phase=="05-health-multiread":
        return ROOT/"tests/dc_functional_v9_health_multiread_acceptance.py",["--binary",str(BINARY),"--expected-candidate-sha256",BINARY_SHA,"--contract",str(CONTRACT),"--expected-contract-sha256",CONTRACT_SHA,"--expected-head",HEAD,"--expected-source-fingerprint",FP,"--expected-fixture-helper-sha256",PINS["tests/dc_functional_v9_signal_audit_acceptance.py"],"--expected-multiread-helper-sha256",PINS["tests/multi_read_six_host_acceptance.py"],"--runtime-config",str(CONFIG),"--expected-runtime-config-sha256",CONFIG_SHA,"--receipt-dir",str(receipts),"--out",str(output),"--mode","both","--max-workers","1"]+common,output
    if phase=="06-neutral-operator":
        return OUT/"r19-neutral-sequential-driver.py",["--receipt-dir",str(receipts),"--out",str(output)],output
    if phase=="07-native-files":
        return ROOT/"tests/dc_parity_native_acceptance.py",["--binary",str(BINARY),"--verify-contract",str(ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json"),"--allow-v4-directory-move","--successor-contract",str(CONTRACT),"--out",str(output)],output
    if phase=="08-main-identity":
        return ROOT/"tests/operator_job_identity_real_acceptance.py",["--receipt-dir",str(receipts)],receipts/"receipt.json"
    if phase=="09-mac-identity":
        return ROOT/"tests/operator_job_identity_mac_acceptance.py",["--receipt-dir",str(receipts)],receipts/"receipt.json"
    if phase=="10-search-ACKfault":
        return ROOT/"tests/search_effects_native_acceptance.py",["--binary",str(BINARY),"--contract",str(CONTRACT),"--contract-sha256",CONTRACT_SHA,"--compiled-source-fingerprint",FP,"--out",str(output)],output
    if phase=="11-inventory":
        jobs=os.environ.get("HEPTA_R19_SOURCE_JOBS_DIR")
        if not jobs or not pathlib.Path(jobs).is_absolute():raise ValueError("explicit actual source jobs directory required")
        return ROOT/"tests/dc_functional_v9_job_inventory_snapshot_acceptance.py",std+["--source-jobs-dir",jobs,"--min-input-records","4000","--min-legacy-metadata-wire-bytes","8000000","--out",str(output)]+common,output
    raise ValueError("unknown owned qualification phase")
def main():
    p=argparse.ArgumentParser();p.add_argument("--phase",required=True);a=p.parse_args()
    phase=a.phase
    if phase not in {"01-credential","02-search","03-facade","04-signal","05-health-multiread","06-neutral-operator","07-native-files","08-main-identity","09-mac-identity","10-search-ACKfault","11-inventory"}:raise ValueError("unknown phase")
    d=OUT/phase;d.mkdir(mode=0o700,exist_ok=False)
    script,arguments,receipt=args_for(phase,d)
    argv=[sys.executable,"-B",str(script),*arguments]
    save(d/"00-admission.json",{"schema":"hepta-r19-phase-admission-v1","phase":phase,"argv":argv,"source_root":str(ROOT),"expected_HEAD":HEAD,"expected_FP":FP,"expected_native_SHA":BINARY_SHA,"effects_started":False,"automatic_retry":False,"full_DC_replacement_qualified":False})
    before=None;child=None;rc=None;failure=None;started=time.monotonic();complete=False
    try:
        before=proof(script);save(d/"01-before.json",before)
        pycache=d/"empty-pycache";pycache.mkdir(mode=0o700)
        env=dict(os.environ);env.update(PYTHONDONTWRITEBYTECODE="1",PYTHONPYCACHEPREFIX=str(pycache))
        save(d/"02-dispatch-intent.json",{"argv":argv,"harness_SHA":digest(script),"fresh_private_empty_pycache":True,"lifetime_owner_PID":os.getpid(),"no_live_state_writer":True})
        with (d/"stdout.log").open("xb") as out,(d/"stderr.log").open("xb") as err:
            child=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
            print("STARTED",phase,"owned_child",child.pid,flush=True)
            while True:
                try:rc=child.wait(timeout=30);break
                except subprocess.TimeoutExpired:
                    print("RUNNING",phase,"seconds",round(time.monotonic()-started),"stdout_bytes",(d/"stdout.log").stat().st_size,flush=True)
                    if time.monotonic()-started>2400:
                        child.terminate()
                        try:rc=child.wait(timeout=10)
                        except subprocess.TimeoutExpired:child.kill();rc=child.wait(timeout=10)
                        failure={"type":"OwnedHarnessDeadline","effects_may_continue":True,"no_replay":True};break
        after=proof(script);stable=before==after
        native=json.loads(receipt.read_text()) if receipt.is_file() else None
        complete=rc==0 and stable and isinstance(native,dict) and native.get("complete") is True and failure is None
        save(d/"03-settled.json",{"schema":"hepta-r19-phase-settled-v1","phase":phase,"exit_code":rc,"before_after_pins_stable":stable,"before":before,"after":after,"native_receipt_path":str(receipt),"native_receipt_sha256":digest(receipt) if receipt.is_file() else None,"native_reported_complete":native.get("complete") if isinstance(native,dict) else None,"complete":complete,"failure":failure,"elapsed_seconds":time.monotonic()-started,"counts_are_from_fresh_native_receipt":True,"actual_binary_qualification_claim":phase not in {"08-main-identity","09-mac-identity"},"Python_backend_identity_only":phase in {"08-main-identity","09-mac-identity"},"model_business_fullreplacement_qualified":False,"DC_rescue_modified":False})
    except BaseException as error:
        failure={"type":type(error).__name__,"detail":str(error)[:512],"owned_child_PID":child.pid if child else None,"effects_started":child is not None,"effects_may_continue":child is not None and child.poll() is None,"automatic_retry":False}
        save(d/"03-failure.json",{"phase":phase,"failure":failure,"exit_code":rc,"source_HEAD":HEAD,"source_FP":FP,"native_SHA":BINARY_SHA,"complete":False,"old_evidence_retained":True})
        traceback.print_exc()
    print("SETTLED",phase,"exit",rc,"complete",complete,flush=True)
    return 0 if complete else 1
if __name__=="__main__":raise SystemExit(main())
