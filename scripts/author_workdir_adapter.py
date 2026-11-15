"""Compose the fixed existing OS boundary with four additional HIA call slots."""
from pathlib import Path
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
context = ROOT / "scripts/session_request_adapter.S"
canonical = ROOT / "scripts/local_canonical_adapter.S"
assert SHA(context.read_bytes()) == "c0760da9b6c4ae39cd24c82b322d14b7fc8b889834a788b9a36ffeb8789fd360"
assert SHA(canonical.read_bytes()) == "fbedfb21bdd324381f57048c295e206bec5a0360a880baaf460bb01222a73dbf"
source = context.read_text()
edits = []


def replace(old, new):
    global source
    assert source.count(old) == 1, old
    edits.append(dict(before_sha256=SHA(old.encode()), after_sha256=SHA(new.encode())))
    source = source.replace(old, new)


replace("    mov r15, rax\n    cmp qword ptr [rbx], 3", "    mov r15, rax\n    mov [r15 + WD_STACK], rbx\n    cmp qword ptr [rbx], 3")
replace("""    cmp rax, 16777256
    ja fatal
    mov [r15 + 888], rax
    xor edi, edi
    lea rsi, [r15 + POLICY_INPUT]
    mov rdx, rax
    call read_exact
    test eax, eax
    jnz fatal
    jmp context_resume
frame_eof:""", """    cmp rax, 16777256
    ja fatal
    mov [r15 + WD_LENGTH], rax
    xor edi, edi
    mov rsi, [r15 + WD_INPUT]
    mov rdx, rax
    call read_exact
    test eax, eax
    jnz fatal
    jmp wd_resume
frame_eof:""")
replace("""    cmp qword ptr [r15 + 800], 1
    jne fatal
    lea r13, [r15 + POLICY_WORK + 4096]""", """    cmp qword ptr [r15 + 800], 2
    je owner_input_selected
    cmp qword ptr [r15 + 800], 1
    jne fatal
    lea r13, [r15 + POLICY_WORK + 4096]""")
replace("""    cmp qword ptr [r15 + 80], 7
    je context_return""", """    cmp qword ptr [r15 + 80], 13
    je wd_params_value_completed
    cmp qword ptr [r15 + 80], 7
    je context_return""")
replace("""    cmp qword ptr [r15 + 800], 1
    je policy_child_completed
    cmp rax, ROOT_OUTPUT_CAP""", """    cmp qword ptr [r15 + 800], 1
    je policy_child_completed
    cmp qword ptr [r15 + 800], 2
    je wd_config_completed
    cmp rax, ROOT_OUTPUT_CAP""")
replace("""context_return:
    cmp eax, 0xfffffff0
    je context_dispatch
    cmp eax, 0xffffffff""", """context_return:
    cmp eax, 0xfffffff0
    je context_dispatch
    cmp qword ptr [r15 + WD_CHILD], 2
    je wd_context_completed
    cmp eax, 0xffffffff""")
replace("""    .byte 0xe8
value_call_displacement:""", """shared_value_call:
    .byte 0xe8
value_call_displacement:""")
replace("""session_return:
    cmp qword ptr [r15 + 912], 1""", """session_return:
    cmp qword ptr [r15 + 912], 3
    je wd_session_completed
    cmp qword ptr [r15 + 912], 1""")
replace("""    or rcx, [rdx + 24]
    jnz fatal
    jmp frame_next
context_observed:""", """    or rcx, [rdx + 24]
    jnz fatal
    jmp wd_initialize
context_observed:""")
replace("""    cmp [rdx + 24], rcx
    jne fatal
    jmp context_write
context_child_completed:""", """    cmp [rdx + 24], rcx
    jne fatal
    jmp wd_publish
context_child_completed:
    cmp qword ptr [r15 + WD_CHILD], 6
    je wd_policy_completed
    cmp qword ptr [r15 + WD_CHILD], 8
    je wd_policy_completed""")
routes = ROOT / "scripts/workdir_routes.S"
source += "\n" + routes.read_text() + "\n"

# The raw canonicalize bridge retains the complete checked two-descriptor
# syscall dispatcher.  Only its input/output transport and caller return differ.
raw = canonical.read_text()
body = raw[raw.index("invoke:\n"):raw.index("read_exact:\n")]
body = body.replace("    call policy_image\n", "    .byte 0xe8\nraw_canonical_call_displacement:\n    .long 0\n")
old = """    mov dword ptr [r15 + 56], eax
    lea rsi, [r15 + 56]
    mov edx, 4
    call write_exact
    mov edx, dword ptr [r15 + 56]
    mov rsi, qword ptr [r15 + 32]
    call write_exact
    jmp next_frame
refusal:
    mov dword ptr [r15 + 56], eax
    call cleanup
    lea rsi, [r15 + 56]
    mov edx, 4
    call write_exact
    jmp next_frame
"""
new = """    jmp raw_return
refusal:
    mov [rsp + 256], rax
    call cleanup
    mov rax, [rsp + 256]
    jmp raw_return
"""
assert body.count(old) == 1
body = body.replace(old, new)
grow_start = body.index("grow_output:\n")
grow_end = body.index("admit_effect:\n")
body = body[:grow_start] + "grow_output:\n    mov eax, 0xfffffffe\n    jmp refusal\n\n" + body[grow_end:]
cleanup_start = raw.index("\ncleanup:\n") + 1
cleanup_end = raw.index("\nsuccess:\n", cleanup_start) + 1
cleanup = raw[cleanup_start:cleanup_end]
body += cleanup
labels = set(re.findall(r"^([a-zA-Z_][a-zA-Z0-9_]*):", body, re.M))
labels.remove("raw_canonical_call_displacement")
labels.update(["raw_return", "contract_fail", "memory_fail", "io_fail", "parent_name"])
body = re.sub(r"\b(" + "|".join(sorted(labels, key=len, reverse=True)) + r")\b", lambda match: "wd_raw_" + match[0], body)
start = """
wd_raw_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, r8
    cmp qword ptr [r15 + 72], -1
    jne wd_raw_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne wd_raw_contract_fail
    mov [r15], rdi
    mov [r15 + 48], rsi
    mov [r15 + 32], rdx
    mov [r15 + 40], rcx
    cmp qword ptr [r15 + 16], 0
    jne wd_raw_workspace_ready
    mov edi, 1056768
    call wd_raw_allocate_guarded
    mov [r15 + 16], rax
    mov qword ptr [r15 + 24], 1056768
wd_raw_workspace_ready:
    mov rdi, [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, [r15 + 16]
    mov rax, [r15 + 64]
    mov [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
    jmp wd_raw_invoke
"""
end = """
wd_raw_raw_return:
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
wd_raw_contract_fail:
    call wd_raw_cleanup
    mov edi, 70
    mov eax, 231
    syscall
    ud2
wd_raw_memory_fail:
    call wd_raw_cleanup
    mov edi, 71
    mov eax, 231
    syscall
    ud2
wd_raw_io_fail:
    call wd_raw_cleanup
    mov edi, 74
    mov eax, 231
    syscall
    ud2
wd_raw_parent_name:
    .asciz ".."
"""
source += start + body + end
regex_wrapper = ROOT / "scripts/workdir_validation_resume.S"
regex_subtree = ROOT / "scripts/workdir_regex_subtree.S"
assert SHA(regex_wrapper.read_bytes()) == "0d2335908629a26d74ada3cef41177797eef15f8f063f7383a0e5d85dc66e68f"
assert SHA(regex_subtree.read_bytes()) == "05c300110c86089fc0517d0e12f147d9dd3415af3c6f974095e3d91a0765f1f4"
validation_start = source.index("validation_resume:\n")
validation_end = source.index("native_return:\n", validation_start)
replace(source[validation_start:validation_end], regex_wrapper.read_text())
replace(".equ MAP_BYTES, 2382368832", ".equ MAP_BYTES, 3489730624")
source += "\n" + regex_subtree.read_text()
out = ROOT / "scripts/workdir_adapter.S"
out.write_text(source)
work = ROOT / "authoring-workdir"
work.mkdir(exist_ok=True)
subprocess.run(["as", "--64", str(out), "-o", str(work / "adapter.o")], check=True)
assert b"There are no relocations" in subprocess.check_output(["readelf", "-r", str(work / "adapter.o")])
subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", str(work / "adapter.o"), str(work / "adapter.bin")], check=True)
proof = dict(schema="hepta.workdir.adapter-composition.v1", source_sha256=SHA(out.read_bytes()),
    original_context_adapter_sha256=SHA(context.read_bytes()), raw_canonical_adapter_sha256=SHA(canonical.read_bytes()),
    routing_source_sha256=SHA(routes.read_bytes()), context_edits=edits, raw_dispatcher_source_sha256=SHA(body.encode()),
    private_connection_snapshot_fd=4, user_path_semantics_in_hia=True, path_and_policy_decisions_in_hia=True,
    typed_parameter_errors_in_hia=True, raw_canonical_two_private_descriptor_slots=True,
    shared_session_state_and_statx_cache=True, qualification_observation_only=True,
    regex_wrapper_sha256=SHA(regex_wrapper.read_bytes()), regex_subtree_sha256=SHA(regex_subtree.read_bytes()),
    regex_continuation_graph=True, mapping_bytes=3489730624,
    remote_execution_qualified=False, whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False)
(ROOT / "native/workdir_adapter_composition.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
print(json.dumps(dict(adapter_sha256=proof["source_sha256"], adapter_bytes=out.stat().st_size,
    prefix_code_bytes=(work / "adapter.bin").stat().st_size, direct_context_edits=len(edits))))
