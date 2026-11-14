"""Strict source, native-image and original-owner evidence for the OS scope.

The published fixture scope remains independently mandatory. This module adds
real Linux entropy through the fixed eight-member internal profile. It does
not activate a production tool, bearer verifier or concurrent scope service.
"""
from collections import Counter
from pathlib import Path
import errno
import hashlib
import importlib.util
import json
import struct
import tomllib

from hia_native_build import HEPTA_COMMIT
from hia_native_entropy_qualification import digest, exact_counts, inspect_elf, native_receipt, object_at, read
from hia_native_scope_qualification import embedded_images, json_bytes, PACKER_SOURCE_SHA256

ORIGINAL_SOURCE="src/mcp/runtime/operation_crypto.rs"
ORIGINAL_SHA="a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633"
FOLDER="operation-scope-os-reference"
NATIVE_RECEIPT="scope-os-native.json"
PACKER_RECEIPT="scope-os-packer.json"
PAIRED_RECEIPT="scope-os-original.json"
EVIDENCE_RECEIPT="scope-os-evidence.json"
SPECS=(
 ("scope-os-hex-fixture","tests/hia_native/scope_os_hex_transport.hepta",1,64,8<<20,8<<20,16<<20),
 ("operation-record","native/operation_record.hepta",1,28,8<<20,2<<20,3<<20),
 ("operation-kdf","native/operation_kdf.hepta",0,0,8<<20,128,2048),
 ("binary-codec","native/binary_codec.hepta",0,0,8<<20,32,1184),
 ("operation-aead","native/operation_aead.hepta",0,0,8<<20,1048640,512),
 ("operation-nonce","native/operation_nonce.hepta",0,0,164,64,1576960),
 ("operation-scope","native/operation_scope.hepta",1,166,8<<20,2<<20,3<<20),
 ("system-entropy","native/entropy_policy.hepta",4,0,24,128,1024),
)
NATIVE_COUNTS={"native_contract_requests_without_response":2,"native_impossible_count_refusals":2,
 "native_injected_completions":371,"native_kernel_completions":148,"native_processes":37,
 "native_refusals":54,"native_responses":238,"native_transport_requests_without_response":2}
ORIGINAL_COUNTS={"actual_cross_owner_opens":2,"deterministic_byte_compared_responses":114,
 "original_clones":2,"original_compared_process_pairs":31,"original_idempotency_bindings":18,
 "original_injected_completions":363,"original_kernel_completions":106,"original_last_releases":29,
 "original_opens":45,"original_policy_bindings":18,"original_processes":31,"original_refusals":52,
 "original_releases":31,"original_request_bindings":18,"original_responses":226,"original_seals":53,
 "original_standard_library_seed_calls":31,"original_stdio_constructors":17,"original_verified_constructors":18}
PACKER_COUNTS={"native_packer_calls":103,"successful_packings":2,"native_admission_refusals":99,
 "native_capacity_refusals":2,"rehashed_elf_refusals":37,"exact_imported_functions":7}
EVIDENCE_COUNTS={"accepted_reference_reports":2,"mutation_refusals":33,"native_calls_added":0,"original_calls_added":0}
SUITES=(("test_scope_os_packer.py","HIA_SCOPE_OS_PACKER_RESULT",PACKER_RECEIPT,6,PACKER_COUNTS),
        ("test_scope_os.py","HIA_SCOPE_OS_RESULT",NATIVE_RECEIPT,11,NATIVE_COUNTS),
        ("test_scope_os_evidence.py","HIA_SCOPE_OS_EVIDENCE_RESULT",EVIDENCE_RECEIPT,6,EVIDENCE_COUNTS))
ORACLE_SOURCES=("oracle_scope_os.rs","scope_os_oracle/Cargo.toml","scope_os_oracle/Cargo.lock",
                "scope_os_oracle/build.rs","scope_os_oracle/original_access.rs")
KERNEL_SOURCES=("test_scope_os.py","scope_os_supervisor.py","scope_os_support.py","io_fault_supervisor.py",*ORACLE_SOURCES)

def sha(path):
    return digest(read(path))

def exact_profile(root, manifest):
    # A fixed, source-bound test helper is imported by explicit local path. Its
    # complete body is included in source_pins and every retained test receipt.
    spec=importlib.util.spec_from_file_location("_hia_scope_os_exact_elf",root/"tests/hia_native/scope_os_support.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.inspect_scope_os(manifest,root)

def source_pins(root):
    names={source for _,source,*_ in SPECS}
    names.update({"native/composition_packer.hepta","native/scope_os_profile.json","native/scope_os_packer_provenance.json",
                  "scripts/hia_native_scope_os_build.py","scripts/hia_native_scope_os_qualification.py",
                  "scripts/hia_native_composition_build.py","scripts/hia_native_scope_qualification.py",ORIGINAL_SOURCE})
    names.update("tests/hia_native/"+name for name in (*KERNEL_SOURCES,"test_scope_os_packer.py"))
    names.update({"tests/hia_native/test_scope_os_evidence.py","tests/hia_native/scope_os_receipt_fixture.json.gz",
                  "scripts/hia_native_entropy_qualification.py","scripts/hia_native_build.py",
                  "scripts/hia_native_loader.py","scripts/check_hia_native_inventory.py"})
    return {name:sha(root/name) for name in sorted(names)}

def composition_evidence(root: Path, output: Path, report: dict) -> dict:
    owner = report["modules"]["operation_scope_os"]
    relative = Path(owner["manifest"])
    if (owner.get("builder") != "scope_os_composition" or owner.get("source") != "native/operation_scope.hepta"
            or relative.is_absolute() or ".." in relative.parts or relative.parts[:2] != ("build", "composition")):
        raise ValueError("scope composition registry or manifest path differs")
    manifest = output / relative
    metadata = object_at(manifest)
    expected = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
                "transport": "newline-json", "compiler_commit": HEPTA_COMMIT,
                "compiler_sha256": report["compiler_image_sha256"], "executable": "native-local-read.elf",
                "runtime_python_required": False, "runtime_libc_required": False, "whole_runtime_replaced": False}
    if sha(manifest) != owner.get("sha256") or any(
            type(metadata.get(key)) is not type(value) or metadata[key] != value for key, value in expected.items()):
        raise ValueError("scope composition manifest identity differs")
    profile = [{"id": index, "name": name, "source_sha256": sha(root / source), "flags": flags,
                "call_mask": mask, "input_capacity": inp, "output_capacity": out, "workspace_capacity": work}
               for index, (name, source, flags, mask, inp, out, work) in enumerate(SPECS)]
    if json_bytes(metadata.get("profile")) != json_bytes(profile) or len(metadata.get("members", [])) != 8:
        raise ValueError("scope fixed eight-image authority table differs")
    if sha(root / "native/composition_packer.hepta") != PACKER_SOURCE_SHA256:
        raise ValueError("scope OS packer source differs")
    admitted = exact_profile(root, manifest)
    if admitted["profile_sha256"] != sha(root / "native/scope_os_profile.json"):
        raise ValueError("scope OS fixed native image profile differs")
    if sha(root / ORIGINAL_SOURCE) != ORIGINAL_SHA:
        raise ValueError("scope OS original owner source differs")
    rows = [("packer", "native/composition_packer.hepta", metadata["packer"])]
    rows += [(f"module_{index:02d}", spec[1], metadata["members"][index]) for index, spec in enumerate(SPECS)]
    artifacts = {relative.as_posix(): sha(manifest)}
    compiler = read(output / "build/bootstrap/B3.image.bin")
    if digest(compiler) != report["compiler_image_sha256"]:
        raise ValueError("scope compiler image changed")
    frame = bytearray(b"HIABND01" + struct.pack("<3Q", 8, 0, 0))
    native_images = []
    scope = {}
    for position, (stem, source_name, row) in enumerate(rows):
        if row.get("manifest") != stem + ".json":
            raise ValueError("scope child manifest path differs")
        path = manifest.parent / row["manifest"]
        child = object_at(path)
        source, image = read(manifest.parent / (stem + ".hepta")), read(manifest.parent / (stem + ".image.bin"))
        contract = {"schema": "hepta.runtime.native-module.v1", "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1",
                    "target": "linux-x86_64", "compiler_commit": HEPTA_COMMIT,
                    "compiler_sha256": report["compiler_image_sha256"], "source": stem + ".hepta",
                    "image": stem + ".image.bin", "input_capacity": 8 << 20, "output_capacity": 8 << 20,
                    "workspace_capacity": 32 << 20, "standalone": None}
        if (sha(path) != row.get("manifest_sha256") or source != read(root / source_name)
                or digest(source) != row.get("source_sha256") or digest(source) != child.get("source_sha256")
                or digest(image) != row.get("image_sha256") or digest(image) != child.get("image_sha256")
                or not 0 < len(image) <= 1 << 20
                or any(type(child.get(key)) is not type(value) or child[key] != value for key, value in contract.items())):
            raise ValueError("scope packed source/image/compiler identity differs")
        compiled = output / "build/modules" / ("composition-" + digest(source)[:24])
        receipt = object_at(compiled / "module.receipt.json")
        native_receipt(receipt, image=compiler, source=source, output=read(compiled / "module.output.bin"), produced=image)
        built = object_at(compiled / "build.json")
        if (read(compiled / "module.input.bin") != source or read(compiled / "module.image.bin") != image
                or receipt.get("produced_sha256") != digest(image) or receipt.get("produced_bytes") != len(image)
                or built.get("compile_receipt") != receipt
                or built.get("compiler_dependency") != object_at(output / "build/bootstrap/bootstrap.json").get("dependency")):
            raise ValueError("scope native compilation receipt differs")
        for name in (stem + ".json", stem + ".hepta", stem + ".image.bin"):
            artifacts[(manifest.parent / name).relative_to(output).as_posix()] = sha(manifest.parent / name)
        for name in ("module.receipt.json", "module.input.bin", "module.output.bin", "module.image.bin", "build.json"):
            artifacts[(compiled / name).relative_to(output).as_posix()] = sha(compiled / name)
        if position == 7:
            scope = child
        if position in (2, 3, 4, 5, 6, 7, 8):
            key = {2: "operation_record", 3: "operation_kdf", 4: "binary_codec", 5: "operation_aead", 6: "operation_nonce", 7: "operation_scope", 8: "system_entropy"}[position]
            tested_owner = report["modules"][key]
            tested_relative = Path(tested_owner["manifest"])
            if tested_relative.is_absolute() or ".." in tested_relative.parts:
                raise ValueError("scope tested dependency escaped the retained result")
            tested_path = output / tested_relative
            tested = object_at(tested_path)
            if sha(tested_path) != tested_owner["sha256"]:
                raise ValueError("scope tested dependency manifest changed")
            if key == "operation_record":
                tested = tested["members"][1]
            elif key == "operation_scope":
                tested = tested["members"][6]
            elif key == "system_entropy":
                if tested.get("policy_manifest") != "policy.json":
                    raise ValueError("scope OS standalone entropy policy path differs")
                tested = object_at(tested_path.parent / "policy.json")
            if any(child.get(field) != tested.get(field) for field in ("source_sha256", "image_sha256")):
                raise ValueError("scope packed leaf differs from its independently tested owner")
        if position:
            native_images.append(image)
            p = profile[position - 1]
            frame.extend(struct.pack("<8Q", len(image), p["input_capacity"], p["output_capacity"], p["workspace_capacity"],
                                     p["flags"], p["call_mask"], 0, 0))
            frame.extend(bytes.fromhex(digest(source)) + bytes.fromhex(digest(image)) + image)
    key = digest(json_bytes({"compiler": report["compiler_image_sha256"], "members": profile,
                             "packer": sha(root / "native/composition_packer.hepta")}))
    executable = read(manifest.parent / "native-local-read.elf")
    layout = embedded_images(executable, profile, native_images)
    if (metadata.get("key") != key or metadata.get("frame_sha256") != digest(frame)
            or metadata.get("frame_bytes") != len(frame) or len(frame) > 8 << 20
            or metadata.get("executable_sha256") != digest(executable)
            or metadata.get("inspection") != inspect_elf(executable)
            or metadata.get("packing") != {"owner": "HIA", "input_unchanged": True,
                "buffer_canaries_unchanged": True, "packer_image_sha256": metadata["packer"]["image_sha256"]}):
        raise ValueError("scope packed frame or static executable differs")
    artifacts[(manifest.parent / "native-local-read.elf").relative_to(output).as_posix()] = digest(executable)
    return {"status": "PASS", "manifest_sha256": sha(manifest), "source_sha256": scope["source_sha256"],
            "image_sha256": scope["image_sha256"], "executable_sha256": digest(executable),
            "frame_sha256": digest(frame), "profile": profile, "members": metadata["members"],
            "packer": metadata["packer"], "artifact_sha256": artifacts, "embedded_layout": layout,
            "entropy_provider": "native Linux SystemEntropy-compatible policy", "real_os_entropy_connected": True}

ENTROPY, NONCE, INTEGRITY, STATE = 0xfffffffa, 0xfffffff9, 0xfffffff8, 0xfffffff6
PAYLOAD = b"owned native scope payload\0\xff\xe4\xb8\xad"
SEMANTIC = "semantic-results-and-system-entropy-trace"
EXACT = "deterministic-completions"
NATIVE_CONTRACT = "native-only-impossible-kernel-contract"
NATIVE_TRANSPORT = "native-only-transport"


def case_specs():
    """Declared domain; observed mismatches cannot remove cases from it."""
    result = []
    exercise = [(3,64),(4,64),(5,64),(6,115),(7,31),(7,INTEGRITY)]
    def add(label,mode,rows,fills,comparison=SEMANTIC,exit_code=0,auxiliary_at=0):
        result.append(dict(label=label,mode=mode,rows=rows,fills=fills,comparison=comparison,
                           exit_code=exit_code,auxiliary_at=auxiliary_at))
    for mode in ("constant","fallback_constant"):
        add("clone-"+mode,mode,[(1,0),(8,0),(6,115),(9,0),(6,NONCE),(6,115),(7,31),(9,0),(3,STATE)],[12]*3,EXACT)
    for mode in ("constant","fallback_constant","partial","fallback_partial"):
        aux={"constant":5,"fallback_constant":9,"partial":129,"fallback_partial":133}[mode]
        add("synthetic-"+mode,mode,[(2,0),*exercise,(9,0)],[32]*4+[12],EXACT,auxiliary_at=aux)
    for fail in range(1,5):
        add("stdio-failure-"+str(fail),"stdio_fail_"+str(fail),[(2,ENTROPY),(3,STATE),(2,0),*exercise,(9,0)],
            [32]*(fail+4)+[12],EXACT,auxiliary_at=fail+5)
    for mode in ("observe","probe_enosys"):
        add("active-eof-"+mode,mode,[(2,0),*exercise],[32]*4+[12],auxiliary_at=5 if mode=="observe" else 9)
    for mode in ("fallback_open_error","fallback_poll_error","fallback_urandom_open_error",
                 "fallback_read_error","partial_error","fallback_partial_error"):
        add("recovery-"+mode,mode,[(1,0),(6,ENTROPY),(6,115),(7,31),(9,0)],[12,12])
    for mode in ("bad_errno","fallback_bad_errno"):
        add("native-contract-"+mode,mode,[(1,0)],[12],NATIVE_CONTRACT,2)
    for mode in ("oversized","fallback_oversized"):
        add("native-contract-"+mode,mode,[(1,0),(6,ENTROPY),(3,64),(9,0)],[12],NATIVE_CONTRACT)
    for mode in ("eio","enosys","eagain","zero"):
        add("data-error-"+mode,mode,[(1,0),(6,0xfffffffb),(6,0xfffffffc),(6,ENTROPY),(6,ENTROPY),(9,0)],[12,12],EXACT)
    for mode in ("probe_eintr","probe_eio","probe_eagain","eintr","fallback_eintr"):
        add("retry-"+mode,mode,[(1,0),*exercise,(9,0)],[12])
    add("cross-open-real-nonces","observe",[(1,0),(6,115),(7,31),(9,0)],[12],"cross-owner-authenticated-plaintext")
    for mode in ("observe","probe_enosys","probe_eperm"):
        add("stdio-"+mode,mode,[(2,0),*exercise,(9,0)],[32]*4+[12],auxiliary_at=5 if mode=="observe" else 9)
    add("malformed-hex","probe_enosys",[(2,0)],[32]*4,NATIVE_TRANSPORT,2)
    add("broken-output","probe_enosys",[(2,0)],[32]*4,NATIVE_TRANSPORT,74)
    return result


def expected_events(spec, *, original):
    """Declared notification schedule, with opaque fd values omitted.

    This is an evidence coverage check, not a runtime entropy provider. It
    creates and counts no additional native or original-owner executions.
    """
    mode,events,calls=spec["mode"],[],Counter()
    def event(kind,size=None,used=0):
        calls[kind]+=1
        call=calls[kind]
        row={"kind":kind,"call":call,"completion":"kernel"}
        if size is not None: row["requested"]=size
        if size: row["destination_delta"]=used
        error,count=None,None
        if kind=="probe":
            if mode.startswith("fallback_") or mode=="probe_enosys": error=errno.ENOSYS
            elif mode.startswith("probe_"):
                error={"probe_eperm":errno.EPERM,"probe_eintr":errno.EINTR,"probe_eio":errno.EIO,"probe_eagain":errno.EAGAIN}[mode]
        elif kind=="open_random":
            if call==1 and mode=="fallback_eintr": error=errno.EINTR
            if call==1 and mode=="fallback_open_error": error=errno.EACCES
        elif kind=="poll":
            if mode=="fallback_eintr" and call<=2: error=errno.EINTR if call==1 else errno.EAGAIN
            if mode=="fallback_poll_error" and call==1: error=errno.EIO
        elif kind=="open_urandom":
            if mode=="fallback_eintr" and call==1: error=errno.EINTR
            if mode=="fallback_urandom_open_error" and call==1: error=errno.EACCES
        elif kind in ("getrandom","read_urandom"):
            if mode in ("bad_errno","fallback_bad_errno"): error=5000
            elif mode.startswith("stdio_fail_") and call==int(mode.rsplit("_",1)[1]): error=errno.EIO
            elif mode in ("constant","fallback_constant") or mode.startswith("stdio_fail_"): count=size
            elif kind=="getrandom" and mode in ("eio","enosys","eagain"):
                error={"eio":errno.EIO,"enosys":errno.ENOSYS,"eagain":errno.EAGAIN}[mode]
            elif call==1 and mode in ("eintr","fallback_eintr"): error=errno.EINTR
            elif call==1 and mode=="fallback_read_error": error=errno.EIO
            elif mode in ("zero","oversized","fallback_oversized"):
                row.update(completion="injected_return",returned=0 if mode=="zero" else size+1)
            elif mode in ("partial","fallback_partial"): count=1
            elif mode in ("partial_error","fallback_partial_error"):
                if call==1: count=min(5,size)
                elif call==2: error=errno.EIO
        if error is not None: row.update(completion="injected_error",error=error)
        if count is not None: row.update(completion="synthetic_partial_bytes",returned=count)
        events.append(row)
        return row
    def retry(kind,admitted):
        while True:
            row=event(kind)
            if row.get("error") not in admitted: return row
    backend,cached=0,False
    for wanted in spec["fills"]:
        if not backend:
            backend=2 if event("probe",0).get("error") in (errno.ENOSYS,errno.EPERM) else 1
        if backend==2 and not cached:
            if retry("open_random",(errno.EINTR,)).get("error"): continue
            polled=retry("poll",(errno.EINTR,errno.EAGAIN))
            event("close_random")
            if polled.get("error"): continue
            if retry("open_urandom",(errno.EINTR,)).get("error"): continue
            cached=True
        used=0
        while used<wanted:
            row=event("getrandom" if backend==1 else "read_urandom",wanted-used,used)
            if row.get("error")==errno.EINTR: continue
            if row.get("error"): break
            count=row.get("returned",wanted-used)
            if not 0<count<=wanted-used: break
            used+=count
    if cached and not original: event("close_urandom")
    return events


def hex_digest(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)


def integer(value,low=0,high=(1<<64)-1):
    return type(value) is int and low<=value<=high


def require(condition,message):
    if not condition: raise ValueError("scope OS evidence: "+message)


def callsite(site, *, auxiliary):
    require(type(site) is dict and set(site)=={"module_kind","library_sha256","symbol","symbol_value","symbol_bytes","instruction_offset"},
            "original RNG callsite record is incomplete")
    require(hex_digest(site["library_sha256"]) and integer(site["symbol_value"],1)
            and integer(site["symbol_bytes"],1) and integer(site["instruction_offset"],1,site["symbol_bytes"]-1),
            "original RNG symbol bounds or module hash differ")
    admitted={("linux-vdso","__vdso_getrandom"),("libc","getrandom")} if auxiliary else {("libc","syscall")}
    require((site["module_kind"],site["symbol"]) in admitted,"original RNG callsite belongs to the wrong domain")


def trace_evidence(session,spec, *, original,binary_sha256):
    trace=session.get("trace",{})
    require(trace.get("owned_child_reaped") is True and trace.get("executable_sha256")==binary_sha256,
            "owned process identity or reaping is missing")
    events=trace.get("events")
    require(type(events) is list,"raw notification trace is missing")
    normalized=[]
    for row in events:
        require(type(row) is dict,"notification record is not an object")
        has_fd=row.get("kind")=="read_urandom" or str(row.get("kind","")).startswith("close_")
        require(("device_fd" in row)==has_fd and (not has_fd or integer(row["device_fd"],0,(1<<31)-1)),
                "notification fd observation is missing or misplaced")
        normalized.append({k:v for k,v in row.items() if k!="device_fd"})
    require(json_bytes(normalized)==json_bytes(expected_events(spec,original=original)),
            "raw SystemEntropy schedule differs from the declared fault domain")
    order=trace.get("entropy_event_order")
    auxiliary=trace.get("original_auxiliary_entropy")
    sites=trace.get("original_system_rng_callsites")
    require(type(order) is list and type(auxiliary) is list and type(sites) is list,
            "original auxiliary calls or complete domain order is missing")
    expected_order=[{"domain":"system_entropy","index":i} for i in range(len(events))]
    if original:
        require(len(auxiliary)==1,"each original scope requires its separately observed HashSet seed")
        aux=auxiliary[0]
        require(type(aux) is dict and set(aux)=={"kind","requested","flags","completion","callsite"}
                and aux.get("kind")=="standard_library_hashset_seed" and type(aux.get("requested")) is int
                and aux["requested"]==32 and type(aux.get("flags")) is int and aux["flags"]==0
                and aux.get("completion")=="kernel","auxiliary entropy was changed or injected")
        callsite(aux["callsite"],auxiliary=True)
        expected_order.insert(spec["auxiliary_at"],{"domain":"original_standard_library","index":0})
        require(len(sites)==sum(row["kind"] in ("probe","getrandom") for row in events),
                "an original SystemEntropy callsite was omitted")
        for site in sites: callsite(site,auxiliary=False)
        require(trace.get("native_cleanup") is None and trace.get("native_idle_snapshots")==[],
                "native private cleanup was incorrectly attributed to the original owner")
    else:
        require(auxiliary==[] and sites==[],"native trace contains an original-only random domain")
        cleanup={"private_workspaces_zero":True,"transport_output_zero":True,
                 "private_entropy_descriptors_retired":True,"inspected_bytes":sum(row[-1] for row in SPECS)+(8<<20)+40,
                 "module_count":8,"exit_code":spec["exit_code"]}
        require(json_bytes(trace.get("native_cleanup"))==json_bytes(cleanup),"complete private cleanup inspection differs")
        snapshots=trace.get("native_idle_snapshots")
        require(type(snapshots) is list and len(snapshots)>=len(spec["rows"])+1,"idle private-workspace inspections are missing")
        previous=0
        for row in snapshots:
            require(type(row) is dict and set(row)=={"scope_state","scope_references","private_keys_zero","scope_transient_zero",
                "entropy_transient_zero","entropy_sequence","entropy_backend","entropy_cached_fd"},"idle inspection record differs")
            require(type(row["scope_state"]) is int and row["scope_state"] in (0,2,3)
                    and integer(row["scope_references"]) and type(row["private_keys_zero"]) is bool
                    and row["scope_transient_zero"] is True and row["entropy_transient_zero"] is True
                    and integer(row["entropy_sequence"],previous) and type(row["entropy_backend"]) is int
                    and row["entropy_backend"] in (0,1,2) and type(row["entropy_cached_fd"]) is int
                    and row["entropy_cached_fd"] in (0,1),"idle policy state or transient cleanup differs")
            require(row["scope_state"]==2 or (row["private_keys_zero"] and row["scope_references"]==0),
                    "retired scope retained keys or references")
            require(not row["entropy_cached_fd"] or row["entropy_backend"]==2,"cached fd has no fallback backend")
            previous=row["entropy_sequence"]
        require(snapshots[0]["scope_state"]==0 and snapshots[0]["entropy_sequence"]==0,
                "process did not begin with a fresh private scope and entropy sequence")
        if spec["label"].startswith("active-eof-"):
            require(snapshots[-1]["scope_state"]==2 and snapshots[-1]["private_keys_zero"] is False,
                    "EOF cleanup did not begin with live private keys")
        if spec["label"].startswith("stdio-") and not spec["label"].startswith("stdio-failure-"):
            last=snapshots[-1]
            require(last["scope_state"]==3 and last["entropy_sequence"]>0
                    and last["entropy_cached_fd"]==int(spec["mode"]!="observe"),
                    "scope release reset the cached entropy backend or sequence")
    require(json_bytes(order)==json_bytes(expected_order),"original/native domain order was dropped or reordered")
    return {"events":normalized,"auxiliary":auxiliary,"callsites":sites,"event_order":order}


def session_evidence(session,spec, *, original,binary_sha256):
    require(type(session) is dict and session.get("mode")==spec["mode"]
            and type(session.get("exit_code")) is int and session["exit_code"]==spec["exit_code"],
            "process mode or exit status differs")
    rows=session.get("rows")
    require(type(rows) is list and len(rows)==len(spec["rows"]),"response domain is incomplete")
    for row,(operation,code) in zip(rows,spec["rows"],strict=True):
        require(type(row) is dict and set(row)=={"operation","code","input_sha256","input_bytes","output_sha256","output_bytes"},
                "response receipt is incomplete")
        require(type(row["operation"]) is int and row["operation"]==operation and type(row["code"]) is int
                and row["code"]==code and integer(row["input_bytes"],24,8<<20)
                and type(row["output_bytes"]) is int and row["output_bytes"]==(0 if code>=0xffff0000 else code)
                and hex_digest(row["input_sha256"]) and hex_digest(row["output_sha256"]),"response contract differs")
        if not row["output_bytes"]: require(row["output_sha256"]==digest(b""),"empty/refused response exposed output")
        if operation==7 and code==len(PAYLOAD):
            require(row["output_sha256"]==digest(PAYLOAD),"authenticated plaintext differs")
    trace=trace_evidence(session,spec,original=original,binary_sha256=binary_sha256)
    prefix="original_" if original else "native_"
    counts=Counter({prefix+"processes":1,prefix+"responses":len(rows),
                    prefix+"refusals":sum(row["code"]>=0xffff0000 for row in rows),
                    prefix+"kernel_completions":sum(row["completion"]=="kernel" for row in trace["events"]),
                    prefix+"injected_completions":sum(row["completion"]!="kernel" for row in trace["events"])})
    if original:
        expected=Counter({name:0 for name in ("original_verified_constructors","original_stdio_constructors",
            "original_request_bindings","original_idempotency_bindings","original_policy_bindings",
            "original_seals","original_opens","original_clones","original_releases","original_last_releases")})
        mapping={1:"original_verified_constructors",2:"original_stdio_constructors",3:"original_request_bindings",
            4:"original_idempotency_bindings",5:"original_policy_bindings",6:"original_seals",7:"original_opens",
            8:"original_clones",9:"original_releases"}
        refs=0
        for row in rows:
            op,code=row["operation"],row["code"]
            if code!=STATE: expected[mapping[op]]+=1
            if op in (1,2) and code==0: refs=1
            elif op==8 and code==0: refs+=1
            elif op==9 and code==0:
                refs-=1
                if refs==0: expected["original_last_releases"]+=1
        owner={"schema":"hepta.runtime.scope-os-original-owner.v1","status":"PASS","actual_system_entropy":True,
               "fixture_entropy_owner_used":False,"requests":len(rows),"refusals":counts[prefix+"refusals"],**expected}
        require(json_bytes(session.get("original_owner"))==json_bytes(owner),"actual original-owner call accounting differs")
        counts.update(expected)
        counts["original_standard_library_seed_calls"]=len(trace["auxiliary"])
    else: require(session.get("original_owner") is None,"original calls were attributed to a native-only process")
    return counts,trace


def completion(report,tests,counts,schema):
    require(report.get("schema")==schema and report.get("status")=="PASS","suite did not pass")
    for key,value in {"tests_run":tests,"failures":0,"errors":0,"skipped":0}.items():
        require(type(report.get(key)) is int and report[key]==value,"suite completion is incomplete: "+key)
    exact_counts(report.get("counts"),counts)
    exact_counts(report.get("expected_counts"),counts)


def kernel_evidence(root,receipt,artifact, *, original_binary_sha256=None):
    paired=original_binary_sha256 is not None
    expected={**NATIVE_COUNTS,**(ORIGINAL_COUNTS if paired else {})}
    completion(receipt,11,expected,"hepta.runtime.scope-os-test.v1")
    pins={name:sha(root/"tests/hia_native"/name) for name in KERNEL_SOURCES}
    require(receipt.get("source_sha256")==pins and receipt.get("source_unchanged") is True,
            "kernel/reference test sources differ")
    require(receipt.get("original_source_sha256")==ORIGINAL_SHA and sha(root/ORIGINAL_SOURCE)==ORIGINAL_SHA,
            "complete original owner source changed")
    require(receipt.get("artifact")==artifact and receipt.get("native_executable_sha256")==artifact["executable_sha256"],
            "kernel suite used another native artifact")
    require(receipt.get("original_executable_sha256")==original_binary_sha256
            and receipt.get("original_reference_status")==("PASS" if paired else "PENDING"),
            "reference binary or reference phase status differs")
    for key in ("normal_random_bytes_equality_claimed","production_activated","concurrent_shared_capability_qualified"):
        require(receipt.get(key) is False,"suite overstates its qualified scope: "+key)
    specs=case_specs()
    cases=receipt.get("cases")
    require(type(cases) is list and len(cases)==len(specs),"declared process domain is incomplete")
    counts,domains,libraries=Counter(),[],{}
    for case,spec in zip(cases,specs,strict=True):
        wanted=spec["comparison"]
        if not paired and wanted=="cross-owner-authenticated-plaintext": wanted="native-authenticated-roundtrip"
        require(case.get("label")==spec["label"] and case.get("comparison")==wanted,"case domain or comparison changed")
        native,trace=session_evidence(case.get("native"),spec,original=False,binary_sha256=artifact["executable_sha256"])
        counts.update(native)
        if spec["comparison"]==NATIVE_CONTRACT:
            if spec["exit_code"]:
                require(hex_digest(case.get("pending_request_sha256")),"fatal contract request was omitted")
                counts["native_contract_requests_without_response"]+=1
            else: counts["native_impossible_count_refusals"]+=1
        elif spec["comparison"]==NATIVE_TRANSPORT: counts["native_transport_requests_without_response"]+=1
        reference=case.get("original")
        if paired and spec["comparison"] not in (NATIVE_CONTRACT,NATIVE_TRANSPORT):
            actual,original=session_evidence(reference,spec,original=True,binary_sha256=original_binary_sha256)
            counts.update(actual)
            counts["original_compared_process_pairs"]+=1
            require([row for row in trace["events"] if row["kind"]!="close_urandom"]==original["events"],
                    "SystemEntropy notification comparison differs")
            if wanted==EXACT:
                require(case["native"]["rows"]==reference["rows"],"deterministic byte comparison differs")
                counts["deterministic_byte_compared_responses"]+=len(reference["rows"])
            if wanted=="cross-owner-authenticated-plaintext": counts["actual_cross_owner_opens"]+=2
            for site in [*(row["callsite"] for row in original["auxiliary"]),*original["callsites"]]:
                module=site["module_kind"]
                previous=libraries.setdefault(module,site["library_sha256"])
                require(previous==site["library_sha256"],"read module identity changed within one retained replay")
            # Preserve each complete auxiliary record, including its symbol
            # bounds, library/vDSO hash and position before any injected call.
            domains.append({"label":spec["label"],"auxiliary_calls":original["auxiliary"],
                            "system_rng_callsites":original["callsites"],"entropy_event_order":original["event_order"],
                            "normalized_system_entropy_sha256":digest(json_bytes(original["events"]))})
        else: require(reference is None,"native-only fault/transport was attributed to original Rust")
    exact_counts(dict(counts),expected)
    owner_fields=("original_verified_constructors","original_stdio_constructors","original_request_bindings",
                  "original_idempotency_bindings","original_policy_bindings","original_seals","original_opens",
                  "original_clones","original_releases")
    calls=sum(counts[name] for name in owner_fields)
    require(not paired or (calls==220 and counts["original_responses"]-calls==6),"original owner/adapter domains differ")
    return {"status":"PASS","counts":dict(counts),"process_domains":domains,"read_module_sha256":libraries,
            "original_owner_calls":calls,"original_adapter_only_responses":6 if paired else 0,
            "normal_random_bytes_equality_claimed":False,"native_cleanup_inspected_bytes_per_process":33039048}


def packer_evidence(root,receipt,artifact):
    completion(receipt,6,PACKER_COUNTS,"hepta.runtime.scope-os-packer-test.v1")
    require(receipt.get("source_sha256")==sha(root/"native/composition_packer.hepta")==PACKER_SOURCE_SHA256
            and receipt.get("test_sha256")==sha(root/"tests/hia_native/test_scope_os_packer.py")
            and receipt.get("artifact")==artifact,"packer suite source or actual output artifact changed")
    return {"status":"PASS","counts":dict(PACKER_COUNTS)}


def refusal_evidence(root,receipt):
    completion(receipt,6,EVIDENCE_COUNTS,"hepta.runtime.scope-os-evidence-test.v1")
    for key,name in {"test_sha256":"tests/hia_native/test_scope_os_evidence.py",
                     "helper_sha256":"scripts/hia_native_scope_os_qualification.py",
                     "fixture_sha256":"tests/hia_native/scope_os_receipt_fixture.json.gz"}.items():
        require(receipt.get(key)==sha(root/name),"evidence refusal-control source or retained fixture changed")
    return {"status":"PASS","counts":dict(EVIDENCE_COUNTS)}


def oracle_dependencies(root):
    lock=tomllib.loads(read(root/"tests/hia_native/scope_os_oracle/Cargo.lock").decode())
    versions={"ring":"0.17.14","getrandom":"0.2.17","libc":"0.2.191","zeroize":"1.9.0","serde_json":"1.0.151"}
    result={}
    for name,version in versions.items():
        matches=[row for row in lock["package"] if row["name"]==name]
        require(len(matches)==1 and matches[0].get("version")==version,"locked oracle dependency differs: "+name)
        row=matches[0]
        require(row.get("source")=="registry+https://github.com/rust-lang/crates.io-index" and hex_digest(row.get("checksum")),
                "oracle dependency lacks a registry identity")
        result[name]={key:row[key] for key in ("version","source","checksum")}
    return result


def write_corpus(root,folder,artifact):
    """Called only after all three mandatory suite processes complete."""
    native=kernel_evidence(root,object_at(folder/NATIVE_RECEIPT),artifact)
    packer=packer_evidence(root,object_at(folder/PACKER_RECEIPT),artifact)
    metadata={"schema":"hepta.runtime.scope-os-native-corpus.v1","status":"NATIVE_COMPONENTS_PASS",
              "source_sha256":source_pins(root),"artifact":artifact,"native":native,"packer":packer,
              "evidence_controls":refusal_evidence(root,object_at(folder/EVIDENCE_RECEIPT)),
              "receipts":{name:sha(folder/name) for name in (NATIVE_RECEIPT,PACKER_RECEIPT,EVIDENCE_RECEIPT)},
              "original_reference_status":"PENDING","oracle_dependencies":oracle_dependencies(root)}
    path=folder/"native-corpus.json"
    with path.open("x") as stream: stream.write(json.dumps(metadata,sort_keys=True,indent=2)+"\n")
    return metadata


def native_evidence(root,output,report):
    composition=composition_evidence(root,output,report)
    manifest=output/report["modules"]["operation_scope_os"]["manifest"]
    artifact=exact_profile(root,manifest)
    folder=output/FOLDER
    metadata=object_at(folder/"native-corpus.json")
    expected={"schema":"hepta.runtime.scope-os-native-corpus.v1","status":"NATIVE_COMPONENTS_PASS",
              "source_sha256":source_pins(root),"artifact":artifact,
              "native":kernel_evidence(root,object_at(folder/NATIVE_RECEIPT),artifact),
              "packer":packer_evidence(root,object_at(folder/PACKER_RECEIPT),artifact),
              "evidence_controls":refusal_evidence(root,object_at(folder/EVIDENCE_RECEIPT)),
              "receipts":{name:sha(folder/name) for name in (NATIVE_RECEIPT,PACKER_RECEIPT,EVIDENCE_RECEIPT)},
              "original_reference_status":"PENDING","oracle_dependencies":oracle_dependencies(root)}
    require(json_bytes(metadata)==json_bytes(expected),"native corpus provenance or receipt content changed")
    return {"status":"PASS","composition":composition,"native":expected["native"],"packer":expected["packer"],
            "evidence_controls":expected["evidence_controls"],
            "source_sha256":expected["source_sha256"],"oracle_dependencies":expected["oracle_dependencies"],
            "corpus_sha256":{(folder/name).relative_to(output).as_posix():sha(folder/name)
                             for name in ("native-corpus.json",NATIVE_RECEIPT,PACKER_RECEIPT,EVIDENCE_RECEIPT)}}


def paired_evidence(root,folder,artifact,binary_sha256):
    require(hex_digest(binary_sha256),"original executable hash is missing")
    result=kernel_evidence(root,object_at(folder/PAIRED_RECEIPT),artifact,original_binary_sha256=binary_sha256)
    return {**result,"original_binary_sha256":binary_sha256,"paired_receipt_sha256":sha(folder/PAIRED_RECEIPT),
            "source_sha256":source_pins(root),"oracle_dependencies":oracle_dependencies(root),
            "native_processes_added_by_original_comparison":37,"native_responses_added_by_original_comparison":238}

