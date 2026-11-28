"""Add the fixed Bellman port and pending extent to the frozen 91-image engine.

Batch child 13 retains its explicitly reserved gateway slot 47. It is not
installed by this overlay; the existing zero-entry refusal still applies.
"""
import hashlib,json,pathlib,subprocess
BASE=pathlib.Path(__file__).resolve().parent
ROOT=BASE.parents[2]
ORIGINAL=ROOT/'sdk-target-work/public-authority-v1/ci-source-v2/source/scripts/runtime_mcp_extra_engine.S'
BATCH=ROOT/'batch-public-rebuild-v1/public-stage-v9/source/scripts/runtime_mcp_extra_engine.S'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 old=ORIGINAL.read_text();batch=BATCH.read_bytes()
 assert sha(batch)=='2791e3dc9590a833b1e182c4312ca8288554dc9e956c7f878e94d14a47b745ac'
 assert b'.byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 255, 47' in batch
 changes=[
  ('57 rows at engine+8192','58 rows at engine+8192'),
  ('.equ RG_SLOTS, 57','.equ RG_SLOTS, 58'),
  ('runtime_grow_destroy_fs_admitted:\n    xor ebp, ebp','runtime_grow_destroy_fs_admitted:\n    /* The process-owned Bellman port must be detached before freeing an engine. */\n    mov rax, [r15 + 440]\n    or rax, [r15 + 448]\n    jnz runtime_grow_destroy_invalid\n    xor ebp, ebp'),
  ('    cmp ebp, 56\n    je runtime_grow_authority_dispatch','    cmp ebp, 57\n    je runtime_grow_bellman_dispatch\n    cmp ebp, 56\n    je runtime_grow_authority_dispatch'),
  ('    cmp qword ptr [r13 + 8], 3\n    ja runtime_grow_bad\n    cmp qword ptr [r13 + 8], 3\n    jne runtime_grow_frontend_common','    cmp qword ptr [r13 + 8], 4\n    je runtime_grow_frontend_pending\n    cmp qword ptr [r13 + 8], 3\n    ja runtime_grow_bad\n    cmp qword ptr [r13 + 8], 3\n    jne runtime_grow_frontend_common'),
  ('runtime_grow_connection_result:\n','runtime_grow_frontend_pending:\n    /* A pending host result is exactly 64 bytes, with no public payload. */\n    mov rax, [r13 + 16]\n    or rax, [r13 + 24]\n    or rax, [r13 + 32]\n    or rax, [r13 + 40]\n    or rax, [r13 + 56]\n    jnz runtime_grow_bad\n    mov eax, 64\n    jmp runtime_grow_extent_ready\nruntime_grow_connection_result:\n'),
  ('runtime_grow_authority_dispatch:\n','runtime_grow_bellman_dispatch:\n    /* The installed fixed packed port is a private capability, not an HIA\n     * child selector supplied by input. Its SysV owned entry preserves r15. */\n    mov rax, [rbx]\n    test rax, rax\n    jz runtime_grow_resource_early\n    add rax, 2469 /* fixed runtime_bellman_owned export, component identity-bound */\n    call rax\n    jmp runtime_grow_done\nruntime_grow_authority_dispatch:\n'),
  ('runtime_grow_target_frontend:\n    cmp rsi, 12','runtime_grow_target_frontend:\n    cmp rsi, 14'),
  ('.zero 128 /* 41 empty; SDK42-45, constructor46, Batch47-52, shutdown53, get_info54, connection55, authority56. */','.zero 136 /* 41 empty; SDK42-45, constructor46, Batch47-52, shutdown53, get_info54, connection55, authority56, Bellman57. */'),
  ('.byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56','.byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56, 47, 57'),
 ]
 new=old
 for before,after in changes:
  assert new.count(before)==1,repr(before);new=new.replace(before,after,1)
 restored=new
 for before,after in reversed(changes):assert restored.count(after)==1;restored=restored.replace(after,before,1)
 assert restored==old
 out=BASE/'engine-overlay-v1';out.mkdir(exist_ok=True)
 target=out/'scripts/runtime_mcp_extra_engine.S';target.parent.mkdir(exist_ok=True);target.write_text(new)
 proof={'schema':'hepta.runtime.bellman-engine-overlay.v1','baseline':{'path':str(ORIGINAL),'bytes':len(old.encode()),'sha256':sha(old.encode())},'batch_reference':{'path':str(BATCH),'bytes':len(batch),'sha256':sha(batch)},'output':{'path':'scripts/runtime_mcp_extra_engine.S','bytes':len(new.encode()),'sha256':sha(new.encode())},'reversible_edits':len(changes),'all_other_source_bytes_unchanged':True,'frontend_mapping':{'12':56,'13':47,'14':57},'slot_count':58,'engine_bytes':16384,'descriptor_offset':8192,'pending_kind':4,'pending_extent':64,'pending_zero_offsets':[16,24,32,40,56],'frontend_sequence_offset':48,'host_record_offset':1280,'host_control_offset':1344,'port_owned_export_offset':2469,'runtime_context_scope':'one persistent handle per process, explicit host attach/detach','new_hia_or_rust_executed':False,'public_handler_qualified':False}
 (out/'source-proof.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n');print(json.dumps(proof,sort_keys=True))
if __name__=='__main__':main()
