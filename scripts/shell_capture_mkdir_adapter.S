/* Fixed Linux x86-64 primitives for the HIA blocking mkdir owner.
 * The HIA graph chooses ancestors, retries, metadata and the returned Result.
 * This fixture only transports owned buffers and records actual syscalls.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
.equ TRACEFD,0
.equ ENTRYFD,8
.equ ILEN,16
.equ WLEN,24
.equ PID,32
.equ ENTRIES,40
.equ SEQUENCE,48
.equ ACTION,56
.equ PATHPTR,64
.equ PATHLEN,72
.equ METALEN,80
.equ RAW,88
.equ ERRNO,96
.equ RAWMODE,104
.equ RETURNED,112
.equ IOERROR,120
.equ CONTRACT,128
.equ EXITCODE,136
.equ ISSUES,144
.equ COMPLETIONS,152
.equ PHASE,160
.equ SYSCALLNO,168
.equ EXTLEN,176
.equ TIMEBUF,192
.equ FRAME,208
.equ READY,240
.equ FOOTER,304
.equ RECORD,448
.equ META,640
.equ PATHMAP,928
.equ SLOT,96

_start:
    cld
    mov rbp,rsp
    cmp qword ptr [rbp],3
    jne usage
    mov rdi,[rbp+16]
    lea rsi,[rip+fixture_option]
    call equal_string
    test eax,eax
    jz usage
    mov esi,4096
    call allocate
    cmp rax,-4095
    jae exit_alloc
    mov r12,rax
    mov qword ptr [r12+TRACEFD],-1
    mov qword ptr [r12+ENTRYFD],-1
    mov eax,39
    syscall
    mov [r12+PID],rax
    mov rdi,[rbp+24]
    call string_length
    add rax,64
    jc exit_alloc
    mov rsi,rax
    shl rsi,1
    jc exit_alloc
    call allocate
    cmp rax,-4095
    jae exit_alloc
    mov [r12+PATHMAP],rax
    mov rdi,rax
    mov rsi,[rbp+24]
    lea rdx,[rip+trace_suffix]
    call make_path
    mov rsi,[r12+PATHMAP]
    call create_file
    test rax,rax
    js infrastructure
    mov [r12+TRACEFD],rax
    mov rdi,[r12+PATHMAP]
    mov rsi,[rbp+24]
    lea rdx,[rip+entry_suffix]
    call make_path
    mov rsi,[r12+PATHMAP]
    call create_file
    test rax,rax
    js infrastructure
    mov [r12+ENTRYFD],rax
    mov rax,[rip+ready_magic]
    mov [r12+READY],rax
    mov rax,[r12+PID]
    mov [r12+READY+8],rax
    mov eax,186
    syscall
    mov [r12+READY+16],rax
    mov rax,[r12+TRACEFD]
    mov [r12+READY+24],rax
    mov rax,[r12+ENTRYFD]
    mov [r12+READY+32],rax
    mov qword ptr [r12+READY+40],1
    mov edi,1
    lea rsi,[r12+READY]
    mov edx,64
    call write_all
    test rax,rax
    js infrastructure
    xor edi,edi
    lea rsi,[r12+FRAME]
    mov edx,16
    call read_exact
    cmp eax,1
    jne transport_error
    mov rax,[r12+FRAME]
    mov [r12+ILEN],rax
    add rax,32
    jc exit_alloc
    mov rsi,rax
    call allocate
    cmp rax,-4095
    jae exit_alloc
    lea r13,[rax+16]
    mov rdx,[r12+ILEN]
    mov rdi,rax
    mov r8b,0xc1
    mov r9b,0xc2
    call guards
    xor edi,edi
    mov rsi,r13
    mov rdx,[r12+ILEN]
    call read_exact
    cmp eax,1
    jne transport_error
    mov rax,[r12+FRAME+8]
    mov [r12+WLEN],rax
    add rax,32
    jc exit_alloc
    mov rsi,rax
    call allocate
    cmp rax,-4095
    jae exit_alloc
    lea r14,[rax+16]
    mov rdi,rax
    mov rdx,[r12+WLEN]
    mov r8b,0x5a
    mov r9b,0x5b
    call guards
    mov rdi,r14
    mov rcx,[r12+WLEN]
    mov al,0x5c
    rep stosb
    mov esi,96
    call allocate
    cmp rax,-4095
    jae exit_alloc
    lea r15,[rax+16]
    mov rdi,rax
    mov edx,64
    mov r8b,0xa5
    mov r9b,0xa6
    call guards
    mov rdi,r15
    mov ecx,64
    mov al,0xa7
    rep stosb

owner_next:
    inc qword ptr [r12+ENTRIES]
    jz contract_error
    mov qword ptr [r12+PHASE],0
    mov qword ptr [r12+RETURNED],0
    call entry_record
    mov rdi,r13
    mov rsi,[r12+ILEN]
    mov rdx,r15
    mov ecx,64
    mov r8,r14
    mov r9,[r12+WLEN]
    call .Lowner_image
    mov [r12+RETURNED],rax
    mov qword ptr [r12+PHASE],1
    call entry_record
    mov rax,[r12+RETURNED]
    mov rdx,rax
    shr rdx,32
    jnz contract_error
    cmp eax,0xfffffffd
    je pending
    cmp eax,32
    je result_ready
    cmp eax,0xffffffff
    je invalid_result
    cmp eax,0xfffffffe
    jne contract_error
    mov qword ptr [r12+EXITCODE],75
    jmp result_ready_empty
invalid_result:
    mov qword ptr [r12+EXITCODE],2
result_ready_empty:
    mov qword ptr [r12+EXTLEN],0
    jmp final_result
result_ready:
    mov qword ptr [r12+EXTLEN],32
final_result:
    call footer
    mov rax,[r12+RETURNED]
    mov [r12+FRAME],rax
    mov rax,[r12+EXTLEN]
    mov [r12+FRAME+8],rax
    mov edi,1
    lea rsi,[r12+FRAME]
    mov edx,16
    call write_all
    test rax,rax
    js infrastructure_exit
    mov edi,1
    mov rsi,r15
    mov rdx,[r12+EXTLEN]
    call write_all
    test rax,rax
    js infrastructure_exit
    jmp finish

pending:
    cmp qword ptr [r12+WLEN],192
    jb contract_error
    mov rax,[rip+effect_magic]
    cmp [r14+SLOT],rax
    jne contract_error
    mov rax,[r12+SEQUENCE]
    inc rax
    jz contract_error
    cmp [r14+SLOT+8],rax
    jne contract_error
    mov [r12+SEQUENCE],rax
    mov rax,[r14+SLOT+48]
    or rax,[r14+SLOT+56]
    or rax,[r14+SLOT+64]
    or rax,[r14+SLOT+72]
    or rax,[r14+SLOT+80]
    or rax,[r14+SLOT+88]
    jnz contract_error
    mov rax,[r14+SLOT+16]
    cmp rax,1
    jb contract_error
    cmp rax,4
    ja contract_error
    mov [r12+ACTION],rax
    mov qword ptr [r12+RAW],0
    mov qword ptr [r12+ERRNO],0
    mov qword ptr [r12+RAWMODE],0
    mov qword ptr [r12+METALEN],0
    mov qword ptr [r12+PATHLEN],0
    mov qword ptr [r12+PATHPTR],0
    cmp rax,3
    je validate_probe
    mov rax,[r14+SLOT+24]
    mov rdx,[r14+SLOT+32]
    mov rcx,rax
    add rcx,rdx
    jc contract_error
    cmp rcx,[r12+WLEN]
    jae contract_error
    cmp byte ptr [r14+rcx],0
    jne contract_error
    lea rsi,[r14+rax]
    mov [r12+PATHPTR],rsi
    mov [r12+PATHLEN],rdx
    xor ecx,ecx
validate_path:
    cmp rcx,rdx
    je validate_action
    cmp byte ptr [rsi+rcx],0
    je contract_error
    inc rcx
    jmp validate_path
validate_action:
    cmp qword ptr [r12+ACTION],1
    jne validate_statx
    cmp qword ptr [r14+SLOT+40],511
    jne contract_error
    mov qword ptr [r12+SYSCALLNO],83
    jmp issue
validate_statx:
    cmp qword ptr [r12+ACTION],2
    jne validate_stat
    cmp qword ptr [r14+SLOT+40],4095
    jne contract_error
    mov qword ptr [r12+SYSCALLNO],332
    jmp issue
validate_stat:
    cmp qword ptr [r14+SLOT+40],0
    jne contract_error
    mov qword ptr [r12+SYSCALLNO],262
    jmp issue
validate_probe:
    mov rax,[r14+SLOT+24]
    or rax,[r14+SLOT+32]
    jnz contract_error
    cmp qword ptr [r14+SLOT+40],4095
    jne contract_error
    mov qword ptr [r12+SYSCALLNO],332
issue:
    mov qword ptr [r12+PHASE],0
    call trace_record
    lea rdi,[r12+META]
    mov ecx,256
    xor eax,eax
    rep stosb
    cmp qword ptr [r12+ACTION],1
    je mkdir_raw
    cmp qword ptr [r12+ACTION],2
    je statx_raw
    cmp qword ptr [r12+ACTION],3
    je probe_raw
    mov rdi,-100
    mov rsi,[r12+PATHPTR]
    lea rdx,[r12+META]
    xor r10d,r10d
    mov eax,262
    syscall
    mov qword ptr [r12+METALEN],144
    test rax,rax
    js completed_raw
    mov edx,[r12+META+24]
    mov [r12+RAWMODE],rdx
    jmp completed_raw
mkdir_raw:
    mov rdi,[r12+PATHPTR]
    mov rsi,[r14+SLOT+40]
    mov eax,83
    syscall
    jmp completed_raw
statx_raw:
    mov rdi,-100
    mov rsi,[r12+PATHPTR]
    xor edx,edx
    mov r10,[r14+SLOT+40]
    lea r8,[r12+META]
    mov eax,332
    syscall
    mov qword ptr [r12+METALEN],256
    test rax,rax
    js completed_raw
    movzx edx,word ptr [r12+META+28]
    mov [r12+RAWMODE],rdx
    jmp completed_raw
probe_raw:
    xor edi,edi
    xor esi,esi
    xor edx,edx
    mov r10,[r14+SLOT+40]
    xor r8d,r8d
    mov eax,332
    syscall
completed_raw:
    mov [r12+RAW],rax
    cmp rax,-4095
    jb success_raw
    neg rax
    mov [r12+ERRNO],rax
success_raw:
    mov rax,[r12+RAW]
    mov [r14+SLOT+56],rax
    mov rax,[r12+ERRNO]
    mov [r14+SLOT+64],rax
    mov rax,[r12+RAWMODE]
    mov [r14+SLOT+72],rax
    mov qword ptr [r14+SLOT+48],1
    mov qword ptr [r12+PHASE],1
    call trace_record
    cmp qword ptr [r12+ILEN],24
    jb contract_error
    mov qword ptr [r13+8],2
    mov qword ptr [r13+16],0
    jmp owner_next

entry_record:
    lea rdi,[r12+RECORD]
    mov ecx,96
    xor eax,eax
    rep stosb
    mov rax,[rip+entry_magic]
    mov [r12+RECORD],rax
    mov rax,[r12+ENTRIES]
    mov [r12+RECORD+8],rax
    mov rax,[r12+PHASE]
    mov [r12+RECORD+16],rax
    mov rax,[r12+PID]
    mov [r12+RECORD+24],rax
    mov eax,186
    syscall
    mov [r12+RECORD+32],rax
    mov rax,[r12+ILEN]
    mov [r12+RECORD+40],rax
    mov qword ptr [r12+RECORD+48],64
    mov rax,[r12+WLEN]
    mov [r12+RECORD+56],rax
    mov rax,[r12+RETURNED]
    mov [r12+RECORD+64],rax
    call monotonic
    mov [r12+RECORD+72],rax
    mov rdi,[r12+ENTRYFD]
    lea rsi,[r12+RECORD]
    mov edx,96
    call write_all
    test rax,rax
    js infrastructure
    mov rdi,[r12+ENTRYFD]
    lea rsi,[r13-16]
    mov rdx,[r12+ILEN]
    add rdx,32
    call write_all
    test rax,rax
    js infrastructure
    mov rdi,[r12+ENTRYFD]
    lea rsi,[r15-16]
    mov edx,96
    call write_all
    test rax,rax
    js infrastructure
    mov rdi,[r12+ENTRYFD]
    lea rsi,[r14-16]
    mov rdx,[r12+WLEN]
    add rdx,32
    call write_all
    test rax,rax
    js infrastructure
    ret

trace_record:
    lea rdi,[r12+RECORD]
    mov ecx,192
    xor eax,eax
    rep stosb
    mov rax,[rip+trace_magic]
    mov [r12+RECORD],rax
    mov rax,[r12+SEQUENCE]
    mov [r12+RECORD+8],rax
    mov rax,[r12+PHASE]
    mov [r12+RECORD+16],rax
    mov rax,[r12+PID]
    mov [r12+RECORD+24],rax
    mov eax,186
    syscall
    mov [r12+RECORD+32],rax
    mov rax,[r12+SYSCALLNO]
    mov [r12+RECORD+40],rax
    mov rax,[r12+RAW]
    mov [r12+RECORD+48],rax
    mov rax,[r12+ERRNO]
    mov [r12+RECORD+56],rax
    mov rax,[r12+RAWMODE]
    mov [r12+RECORD+64],rax
    mov rax,[r12+PATHLEN]
    mov [r12+RECORD+72],rax
    mov rax,[r12+METALEN]
    mov [r12+RECORD+80],rax
    lea rdi,[r12+RECORD+96]
    lea rsi,[r14+SLOT]
    mov ecx,96
    rep movsb
    cmp qword ptr [r12+PHASE],0
    jne count_completion
    inc qword ptr [r12+ISSUES]
    jmp trace_write
count_completion:
    inc qword ptr [r12+COMPLETIONS]
trace_write:
    mov rdi,[r12+TRACEFD]
    lea rsi,[r12+RECORD]
    mov edx,192
    call write_all
    test rax,rax
    js infrastructure
    mov rdi,[r12+TRACEFD]
    mov rsi,[r12+PATHPTR]
    mov rdx,[r12+PATHLEN]
    call write_all
    test rax,rax
    js infrastructure
    mov rdi,[r12+TRACEFD]
    lea rsi,[r12+META]
    mov rdx,[r12+METALEN]
    call write_all
    test rax,rax
    js infrastructure
    ret

footer:
    lea rdi,[r12+FOOTER]
    mov ecx,128
    xor eax,eax
    rep stosb
    mov rax,[rip+footer_magic]
    mov [r12+FOOTER],rax
    mov rax,[r12+PID]
    mov [r12+FOOTER+8],rax
    mov rax,[r12+ENTRIES]
    mov [r12+FOOTER+16],rax
    mov rax,[r12+SEQUENCE]
    mov [r12+FOOTER+24],rax
    mov rax,[r12+ISSUES]
    mov [r12+FOOTER+32],rax
    mov rax,[r12+COMPLETIONS]
    mov [r12+FOOTER+40],rax
    mov rax,[r12+IOERROR]
    mov [r12+FOOTER+48],rax
    mov rax,[r12+CONTRACT]
    mov [r12+FOOTER+56],rax
    mov rax,[r12+RETURNED]
    mov [r12+FOOTER+64],rax
    mov rax,[r12+EXTLEN]
    mov [r12+FOOTER+72],rax
    mov rax,[r12+ILEN]
    mov [r12+FOOTER+80],rax
    mov rax,[r12+WLEN]
    mov [r12+FOOTER+88],rax
    mov qword ptr [r12+FOOTER+96],64
    mov rax,[r12+TRACEFD]
    mov [r12+FOOTER+104],rax
    mov rax,[r12+ENTRYFD]
    mov [r12+FOOTER+112],rax
    mov rdi,[r12+TRACEFD]
    cmp rdi,2
    jbe footer_entry
    cmp rdi,-1
    je footer_entry
    lea rsi,[r12+FOOTER]
    mov edx,128
    call write_all
    test rax,rax
    jns footer_entry
    mov [r12+IOERROR],rax
footer_entry:
    mov rdi,[r12+ENTRYFD]
    cmp rdi,2
    jbe footer_done
    cmp rdi,-1
    je footer_done
    lea rsi,[r12+FOOTER]
    mov edx,128
    call write_all
    test rax,rax
    jns footer_done
    mov [r12+IOERROR],rax
footer_done:
    ret

contract_error:
    mov qword ptr [r12+CONTRACT],1
    mov qword ptr [r12+EXITCODE],78
    call footer
    jmp finish
transport_error:
    mov rax,-5
infrastructure:
    mov [r12+IOERROR],rax
    mov qword ptr [r12+EXITCODE],74
    call footer
    jmp finish
infrastructure_exit:
    mov [r12+IOERROR],rax
    mov qword ptr [r12+EXITCODE],74
finish:
    mov rdi,[r12+TRACEFD]
    call close_if_owned
    mov rdi,[r12+ENTRYFD]
    call close_if_owned
    mov rdi,[r12+EXITCODE]
    cmp qword ptr [r12+IOERROR],0
    je exit_code
    mov edi,74
exit_code:
    mov eax,60
    syscall
usage:
    mov edi,64
    mov eax,60
    syscall
exit_alloc:
    mov edi,75
    mov eax,60
    syscall

monotonic:
    mov edi,1
    lea rsi,[r12+TIMEBUF]
    mov eax,228
    syscall
    test rax,rax
    js infrastructure
    mov rax,[r12+TIMEBUF]
    imul rax,rax,1000000000
    add rax,[r12+TIMEBUF+8]
    ret
allocate:
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    ret
guards:
    mov al,r8b
    mov ecx,16
    rep stosb
    add rdi,rdx
    mov al,r9b
    mov ecx,16
    rep stosb
    ret
create_file:
    mov rdi,-100
    mov edx,0xa00c1
    mov r10d,0x180
    mov eax,257
    syscall
    cmp rax,-4095
    jae created
    cmp rax,2
    ja created
    mov r8,rax
    mov rdi,rax
    mov esi,1030
    mov edx,3
    mov eax,72
    syscall
    mov r9,rax
    mov rdi,r8
    mov eax,3
    syscall
    mov rax,r9
created:
    ret
close_if_owned:
    cmp rdi,2
    jbe close_done
    cmp rdi,-1
    je close_done
    mov eax,3
    syscall
close_done:
    ret
read_exact:
    mov r8,rdx
read_exact_loop:
    test rdx,rdx
    jz read_exact_ok
    xor eax,eax
    syscall
    cmp rax,-4
    je read_exact_loop
    test rax,rax
    js read_exact_error
    jz read_exact_eof
    add rsi,rax
    sub rdx,rax
    jmp read_exact_loop
read_exact_ok:
    mov eax,1
    ret
read_exact_eof:
    cmp rdx,r8
    jne read_exact_error
    xor eax,eax
    ret
read_exact_error:
    mov eax,-1
    ret
write_all:
    test rdx,rdx
    jz write_ok
write_loop:
    mov eax,1
    syscall
    cmp rax,-4
    je write_loop
    test rax,rax
    js write_done
    jz write_zero
    add rsi,rax
    sub rdx,rax
    jnz write_loop
write_ok:
    xor eax,eax
write_done:
    ret
write_zero:
    mov rax,-5
    ret
equal_string:
    xor eax,eax
equal_loop:
    mov cl,[rdi]
    cmp cl,[rsi]
    jne equal_done
    test cl,cl
    jz equal_yes
    inc rdi
    inc rsi
    jmp equal_loop
equal_yes:
    mov eax,1
equal_done:
    ret
string_length:
    xor eax,eax
length_loop:
    cmp byte ptr [rdi+rax],0
    je length_done
    inc rax
    jmp length_loop
length_done:
    ret
make_path:
    mov al,[rsi]
    test al,al
    jz make_suffix
    mov [rdi],al
    inc rdi
    inc rsi
    jmp make_path
make_suffix:
    mov al,[rdx]
    mov [rdi],al
    inc rdi
    inc rdx
    test al,al
    jnz make_suffix
    ret

fixture_option: .asciz "--mkdir-fixture"
trace_suffix: .asciz "/effects.bin"
entry_suffix: .asciz "/entries.bin"
ready_magic: .ascii "HSHMKRD1"
effect_magic: .ascii "HSHMKFX1"
trace_magic: .ascii "HSHMKTR1"
entry_magic: .ascii "HSHMKEN1"
footer_magic: .ascii "HSHMKAU1"
.balign 16,0
.Lowner_image:
.byte 0
