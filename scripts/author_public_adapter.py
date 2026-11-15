#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compose the qualified config/regex bridge with the fixed SDK admission pair."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def once(source,old,new):
    if source.count(old)!=1:raise ValueError('adapter composition changed: '+old[:80])
    return source.replace(old,new)
def main():
    path=BASE/'scripts/config_mcp_adapter.S';raw=path.read_bytes()
    assert sha(raw)=='1a7393eed424d4777694e35b01bf36e679c25da2fb07c1ada857529b0c934855'
    source=raw.decode();prefix='''/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Seventeen fixed HIA images. Immutable startup and SDK admission precede
 * three real configured routes. Global audit/result durability is separate.
 */'''
    source=once(source,source.splitlines()[0],prefix)
    source=once(source,'.global value_call_displacement','.global message_call_displacement\n.global connection_call_displacement')
    position=3707834368;layout={}
    for name,size in [('MESSAGE_INPUT',16777216+24),('PROJECTION',67108864+24),('ADMISSION',134217728),('CONNECTION_WORK',268435456)]:
        layout[name]=position;position=(position+size+4095)//4096*4096
    assert position<2**32
    source=once(source,'.equ MAP_BYTES, 3707834368','\n'.join(f'.equ {k}, {v}'for k,v in layout.items())+f'\n.equ MAP_BYTES, {position}')
    begin=source.index('/* Only line framing occurs here.');end=source.index('owner_resume:',begin)
    transport=(ROOT/'scripts/public_connection_transport.S.txt').read_text();source=source[:begin]+transport+source[end:]
    source=once(source,'mcp_resume:\n    mov qword ptr [r15 + 80], 5\n    lea r13, [r15 + INPUT]',
         'mcp_resume:\n    mov qword ptr [r15 + 80], 5\n    mov r13d, ADMISSION\n    add r13, r15')
    source=once(source,'    lea r14, [r15 + MCP_WORK]\n    mov rdi, r13\n    mov rsi, [r15 + 24]',
         '    lea r14, [r15 + MCP_WORK]\n    mov rdi, r13\n    mov rsi, [r15 + 904]')
    source=once(source,'    cmp qword ptr [r15 + 80], 9\n    je mcp_value_completed\n','')
    begin=source.index('mcp_completed:');end=source.index('mcp_owner_completed:',begin)
    source=source[:begin]+'''mcp_completed:
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    mov rdx, rax
    lea rsi, [r15 + OUTPUT]
public_write:
    test rdx, rdx
    jz public_written
    mov edi, 1
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    lea rsi, [rip + newline]
    mov edx, 1
    call write_exact
    test eax, eax
    jnz fatal
public_written:
    cmp qword ptr [r15 + 912], 0
    jne config_eof
    jmp frame_next
'''+source[end:]
    source=once(source,'/* Closed calls from MCP5 to installed config0, execution6 and Value9.',
         '/* Closed calls from registry5 to installed config0 and execution6.')
    source=once(source,'    cmp rax, 9\n    je mcp_value_call\n','')
    begin=source.index('mcp_value_call:');end=source.index('mcp_execution_call:',begin);source=source[:begin]+source[end:]
    source=source.replace('mcp_value_completed:','mcp_child_completed:')
    target=ROOT/'scripts/public_runtime_adapter.S';target.write_text(source)
    record={'schema':'hepta.runtime.public-registry-adapter-composition.v1','source_sha256':sha(target.read_bytes()),
       'base_source':'scripts/config_mcp_adapter.S','base_source_sha256':sha(raw),'new_transport_sha256':sha(transport.encode()),
       'layout':layout,'mapping_bytes':position,'retained_config_regex_effect_graph':True,
       'replaced_image_9':'sdk_message','new_image_16':'sdk_connection','replaced_image_5':'public_tool_dispatch',
       'tool_children':[0,6],'only_effect_owner':1,'caller_config_installation':False,'production_activated':False}
    (ROOT/'native/public_runtime_adapter_composition.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'adapter_sha256':record['source_sha256'],'mapping_bytes':position,'layout':layout}))
if __name__=='__main__':main()
