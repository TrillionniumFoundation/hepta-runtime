/* Fixed Linux primitives. HIA owns all file, retry and lifetime decisions. */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
.equ DFD,0
.equ TFD,8
.equ EFD,16
.equ PID,24
.equ TID,32
.equ REQS,40
.equ ENTRIES,48
.equ ISSUED,56
.equ COMPLETED,64
.equ MINTED,72
.equ CLOSED,80
.equ LIVE,88
.equ IOERR,96
.equ BAD,104
.equ LASTRET,112
.equ WCAP,120
.equ WPTR,128
.equ WBASE,136
.equ WMAP,144
.equ IPTR,152
.equ IBASE,160
.equ IMAP,168
.equ ILEN,176
.equ OPTR,184
.equ OBASE,192
.equ HEAD,208
.equ TOKENS,224
.equ NEXTTOKEN,232
.equ ACTION,240
.equ PATHPTR,248
.equ PATHLEN,256
.equ NR,264
.equ FDARG,272
.equ FLAGS,280
.equ MODE,288
.equ RAW,296
.equ ERRNO,304
.equ HANDLE,312
.equ NODE,320
.equ WREADY,328
.equ EXTENT,336
.equ PHASE,344
.equ SLOT,384
.equ TRACEHEAD,512
.equ ENTRYHEAD,640
.equ FOOTER,768
.equ READY,896
.equ RESPONSE,960
.equ TS,976
.macro copyq destination,source
    mov rax,[r15+\source]
    mov [r15+\destination],rax
.endm
.macro audit_write fd,offset,length
    mov rdi,[r15+\fd]
    lea rsi,[r15+\offset]
    mov edx,\length
    call write_all
    test eax,eax
    jnz infrastructure
.endm
_start:
    mov rbx,rsp
    and rsp,-16
    sub rsp,8192
    mov r15,rsp
    xor eax,eax
    mov rdi,r15
    mov ecx,1024
    rep stosq
    mov qword ptr [r15+DFD],-1
    mov qword ptr [r15+TFD],-1
    mov qword ptr [r15+EFD],-1
    mov qword ptr [r15+NEXTTOKEN],1
    cmp qword ptr [rbx],3
    jne usage
    mov rdi,[rbx+16]
    lea rsi,[rip+option_name]
    call equal_cstring
    test eax,eax
    jz usage
    mov eax,39
    syscall
    mov [r15+PID],rax
    mov eax,186
    syscall
    mov [r15+TID],rax
    mov rdi,-100
    mov rsi,[rbx+24]
    mov edx,0xb0000
    xor r10d,r10d
    mov eax,257
    syscall
    test rax,rax
    js infrastructure
    mov [r15+DFD],rax
    mov rdi,rax
    lea rsi,[rip+effects_name]
    mov edx,0xa00c1
    mov r10d,384
    mov eax,257
    syscall
    test rax,rax
    js infrastructure
    call normalize_audit_fd
    mov [r15+TFD],rax
    mov rdi,[r15+DFD]
    lea rsi,[rip+entries_name]
    mov edx,0xa00c1
    mov r10d,384
    mov eax,257
    syscall
    test rax,rax
    js infrastructure
    call normalize_audit_fd
    mov [r15+EFD],rax
    mov rdi,[r15+DFD]
    mov eax,3
    syscall
    mov qword ptr [r15+DFD],-1
    mov edi,96
    call map_rw
    mov [r15+OBASE],rax
    lea rdx,[rax+16]
    mov [r15+OPTR],rdx
    mov rdi,rax
    mov ecx,16
    mov al,0xa5
    rep stosb
    mov ecx,64
    mov al,0xa7
    rep stosb
    mov ecx,16
    mov al,0xa6
    rep stosb
    mov rax,0x3159445246435348 /* HSCFRDY1 */
    mov [r15+READY],rax
    mov rax,[r15+PID]
    mov [r15+READY+8],rax
    mov rax,[r15+TID]
    mov [r15+READY+16],rax
    mov rax,[r15+TFD]
    mov [r15+READY+24],rax
    mov rax,[r15+EFD]
    mov [r15+READY+32],rax
    mov qword ptr [r15+READY+40],1
    mov edi,1
    lea rsi,[r15+READY]
    mov edx,64
    call write_all
    test eax,eax
    jnz infrastructure
next_request:
    xor edi,edi
    lea rsi,[r15+HEAD]
    mov edx,16
    call read_exact
    cmp eax,1
    je normal_exit
    test eax,eax
    jnz infrastructure
    mov rax,[r15+HEAD]
    mov [r15+ILEN],rax
    add rax,32
    jc infrastructure
    mov rbx,rax
    cmp qword ptr [r15+IBASE],0
    je no_old_input
    mov rdi,[r15+IBASE]
    mov rsi,[r15+IMAP]
    mov eax,11
    syscall
    test rax,rax
    js infrastructure
no_old_input:
    mov rdi,rbx
    call map_rw
    mov [r15+IBASE],rax
    mov [r15+IMAP],rbx
    lea rdx,[rax+16]
    mov [r15+IPTR],rdx
    mov rdi,rax
    mov al,0xc1
    mov ecx,16
    rep stosb
    add rdi,[r15+ILEN]
    mov al,0xc2
    mov ecx,16
    rep stosb
    xor edi,edi
    mov rsi,[r15+IPTR]
    mov rdx,[r15+ILEN]
    call read_exact
    test eax,eax
    jnz infrastructure
    mov rax,[r15+HEAD+8]
    cmp qword ptr [r15+WREADY],0
    je first_workspace
    cmp rax,[r15+WCAP]
    jne contract
    jmp workspace_ready
first_workspace:
    mov [r15+WCAP],rax
    add rax,32
    jc infrastructure
    mov [r15+WMAP],rax
    mov rdi,rax
    call map_rw
    mov [r15+WBASE],rax
    lea rdx,[rax+16]
    mov [r15+WPTR],rdx
    mov rdi,rax
    mov al,0x5a
    mov ecx,16
    rep stosb
    add rdi,[r15+WCAP]
    mov al,0x5b
    mov ecx,16
    rep stosb
    mov qword ptr [r15+WREADY],1
workspace_ready:
    inc qword ptr [r15+REQS]
    mov rdi,[r15+OPTR]
    mov al,0xa7
    mov ecx,64
    rep stosb
invoke:
    inc qword ptr [r15+ENTRIES]
    mov qword ptr [r15+PHASE],0
    call record_entry
    mov rdi,[r15+IPTR]
    mov rsi,[r15+ILEN]
    mov rdx,[r15+OPTR]
    mov ecx,64
    mov r8,[r15+WPTR]
    mov r9,[r15+WCAP]
    call shell_capture_file_entry
    mov eax,eax
    mov [r15+LASTRET],rax
    mov qword ptr [r15+PHASE],1
    call record_entry
    mov eax,[r15+LASTRET]
    cmp eax,0xfffffffd
    je effect
    cmp eax,48
    je result_ok
    cmp eax,0xfffffffe
    je result_refusal
    cmp eax,0xffffffff
    jne contract
result_refusal:
    mov qword ptr [r15+EXTENT],0
    jmp send_result
result_ok:
    mov qword ptr [r15+EXTENT],48
send_result:
    mov rax,[r15+LASTRET]
    mov [r15+RESPONSE],rax
    mov rax,[r15+EXTENT]
    mov [r15+RESPONSE+8],rax
    mov edi,1
    lea rsi,[r15+RESPONSE]
    mov edx,16
    call write_all
    test eax,eax
    jnz infrastructure
    mov edi,1
    mov rsi,[r15+OPTR]
    mov rdx,[r15+EXTENT]
    call write_all
    test eax,eax
    jnz infrastructure
    jmp next_request

effect:
    cmp qword ptr [r15+WCAP],224
    jb contract
    mov rsi,[r15+WPTR]
    add rsi,128
    lea rdi,[r15+SLOT]
    mov ecx,12
    rep movsq
    mov rax,0x3158464643485348 /* HSHCFFX1 */
    cmp [r15+SLOT],rax
    jne contract
    lea rsi,[r15+SLOT+56]
    mov ecx,5
check_issue_zero:
    cmp qword ptr [rsi],0
    jne contract
    add rsi,8
    loop check_issue_zero
    mov rax,[r15+SLOT+16]
    mov [r15+ACTION],rax
    mov qword ptr [r15+PATHPTR],0
    mov qword ptr [r15+PATHLEN],0
    mov qword ptr [r15+FDARG],0
    mov qword ptr [r15+FLAGS],0
    mov qword ptr [r15+MODE],0
    mov qword ptr [r15+RAW],0
    mov qword ptr [r15+ERRNO],0
    mov qword ptr [r15+HANDLE],0
    cmp rax,3
    je prepare_close
    cmp rax,1
    je prepare_open
    cmp rax,2
    jne contract
    cmp qword ptr [r15+SLOT+40],0
    jne contract
    cmp qword ptr [r15+SLOT+48],0
    jne contract
    mov qword ptr [r15+NR],87
    jmp prepare_path
prepare_open:
    cmp qword ptr [r15+SLOT+40],0x80241
    jne contract
    cmp qword ptr [r15+SLOT+48],438
    jne contract
    mov qword ptr [r15+NR],257
    mov qword ptr [r15+FDARG],-100
    mov rax,[r15+SLOT+40]
    mov [r15+FLAGS],rax
    mov rax,[r15+SLOT+48]
    mov [r15+MODE],rax
prepare_path:
    mov rax,[r15+SLOT+24]
    mov rdx,[r15+SLOT+32]
    cmp rax,[r15+WCAP]
    jae contract
    mov rcx,[r15+WCAP]
    sub rcx,rax
    cmp rdx,rcx
    jae contract
    add rax,[r15+WPTR]
    mov [r15+PATHPTR],rax
    mov [r15+PATHLEN],rdx
    cmp byte ptr [rax+rdx],0
    jne contract
    xor ecx,ecx
check_path:
    cmp rcx,rdx
    je dispatch
    cmp byte ptr [rax+rcx],0
    je contract
    inc rcx
    jmp check_path
prepare_close:
    cmp qword ptr [r15+SLOT+32],0
    jne contract
    cmp qword ptr [r15+SLOT+40],0
    jne contract
    cmp qword ptr [r15+SLOT+48],0
    jne contract
    mov rdx,[r15+SLOT+24]
    test rdx,rdx
    jz contract
    mov rax,[r15+TOKENS]
find_owned_token:
    test rax,rax
    jz contract
    cmp [rax+8],rdx
    je found_owned_token
    mov rax,[rax]
    jmp find_owned_token
found_owned_token:
    cmp qword ptr [rax+24],1
    jne contract
    mov [r15+NODE],rax
    mov rax,[rax+16]
    mov [r15+FDARG],rax
    mov qword ptr [r15+NR],3
dispatch:
    inc qword ptr [r15+ISSUED]
    mov qword ptr [r15+PHASE],0
    call record_effect
    cmp qword ptr [r15+ACTION],1
    je perform_open
    cmp qword ptr [r15+ACTION],2
    je perform_unlink
    mov rax,[r15+NODE]
    mov qword ptr [rax+24],0
    inc qword ptr [r15+CLOSED]
    dec qword ptr [r15+LIVE]
    mov rdi,[r15+FDARG]
    mov eax,3
    syscall
    jmp complete_raw
perform_unlink:
    mov rdi,[r15+PATHPTR]
    mov eax,87
    syscall
    jmp complete_raw
perform_open:
    mov rdi,[r15+FDARG]
    mov rsi,[r15+PATHPTR]
    mov rdx,[r15+FLAGS]
    mov r10,[r15+MODE]
    mov eax,257
    syscall
    mov [r15+RAW],rax
    test rax,rax
    js complete_raw
    cmp rax,0x7fffffff
    ja contract
    mov edi,4096
    call map_rw
    mov [r15+NODE],rax
    mov rdx,[r15+TOKENS]
    mov [rax],rdx
    mov rdx,[r15+NEXTTOKEN]
    test rdx,rdx
    jz infrastructure
    mov [rax+8],rdx
    mov [r15+HANDLE],rdx
    inc qword ptr [r15+NEXTTOKEN]
    mov rdx,[r15+RAW]
    mov [rax+16],rdx
    mov qword ptr [rax+24],1
    mov rdx,[r15+REQS]
    mov [rax+32],rdx
    mov rdx,[r15+SLOT+8]
    mov [rax+40],rdx
    mov [r15+TOKENS],rax
    inc qword ptr [r15+MINTED]
    inc qword ptr [r15+LIVE]
    mov rax,[r15+RAW]
complete_raw:
    mov [r15+RAW],rax
    test rax,rax
    jns raw_success
    cmp rax,-4095
    jl contract
    neg rax
    mov [r15+ERRNO],rax
    jmp publish_completion
raw_success:
    cmp qword ptr [r15+ACTION],1
    je publish_completion
    test rax,rax
    jnz contract
publish_completion:
    mov rdx,[r15+WPTR]
    add rdx,128
    mov rax,[r15+RAW]
    mov [rdx+64],rax
    mov rax,[r15+ERRNO]
    mov [rdx+72],rax
    mov rax,[r15+HANDLE]
    mov [rdx+80],rax
    mov qword ptr [rdx+56],1
    inc qword ptr [r15+COMPLETED]
    mov qword ptr [r15+PHASE],1
    call record_effect
    cmp qword ptr [r15+ILEN],16
    jb contract
    mov rax,[r15+IPTR]
    mov qword ptr [rax+8],2
    jmp invoke

/* Header then all three complete buffers with sixteen-byte guards. */
record_entry:
    mov rdi,1
    lea rsi,[r15+TS]
    mov eax,228
    syscall
    test rax,rax
    js infrastructure
    mov rax,0x31304e4546435348 /* HSCFEN01 */
    mov [r15+ENTRYHEAD],rax
    copyq ENTRYHEAD+8,REQS
    copyq ENTRYHEAD+16,ENTRIES
    copyq ENTRYHEAD+24,PHASE
    copyq ENTRYHEAD+32,PID
    copyq ENTRYHEAD+40,TID
    copyq ENTRYHEAD+48,ILEN
    mov qword ptr [r15+ENTRYHEAD+56],64
    copyq ENTRYHEAD+64,WCAP
    xor eax,eax
    cmp qword ptr [r15+PHASE],0
    je entry_return_ready
    mov rax,[r15+LASTRET]
entry_return_ready:
    mov [r15+ENTRYHEAD+72],rax
    mov rax,[r15+TS]
    imul rax,1000000000
    add rax,[r15+TS+8]
    mov [r15+ENTRYHEAD+80],rax
    copyq ENTRYHEAD+88,ISSUED
    copyq ENTRYHEAD+96,COMPLETED
    copyq ENTRYHEAD+104,MINTED
    copyq ENTRYHEAD+112,CLOSED
    copyq ENTRYHEAD+120,LIVE
    audit_write EFD,ENTRYHEAD,128
    mov rdi,[r15+EFD]
    mov rsi,[r15+IBASE]
    mov rdx,[r15+IMAP]
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+EFD]
    mov rsi,[r15+OBASE]
    mov edx,96
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+EFD]
    mov rsi,[r15+WBASE]
    mov rdx,[r15+WMAP]
    call write_all
    test eax,eax
    jnz infrastructure
    ret

/* Header128 + complete effect96 + exact borrowed path bytes. */
record_effect:
    mov rax,0x3130525446435348 /* HSCFTR01 */
    mov [r15+TRACEHEAD],rax
    copyq TRACEHEAD+8,REQS
    copyq TRACEHEAD+16,ENTRIES
    copyq TRACEHEAD+24,SLOT+8
    copyq TRACEHEAD+32,PID
    copyq TRACEHEAD+40,TID
    copyq TRACEHEAD+48,PHASE
    copyq TRACEHEAD+56,NR
    copyq TRACEHEAD+64,FDARG
    copyq TRACEHEAD+72,FLAGS
    copyq TRACEHEAD+80,MODE
    copyq TRACEHEAD+88,RAW
    copyq TRACEHEAD+96,ERRNO
    copyq TRACEHEAD+104,HANDLE
    copyq TRACEHEAD+112,PATHLEN
    audit_write TFD,TRACEHEAD,128
    mov rdi,[r15+TFD]
    mov rsi,[r15+WPTR]
    add rsi,128
    mov edx,96
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+TFD]
    mov rsi,[r15+PATHPTR]
    mov rdx,[r15+PATHLEN]
    call write_all
    test eax,eax
    jnz infrastructure
    ret

normal_exit:
    mov rax,0x3144554146435348 /* HSCFAUD1 */
    mov [r15+FOOTER],rax
    copyq FOOTER+8,PID
    copyq FOOTER+16,REQS
    copyq FOOTER+24,ENTRIES
    copyq FOOTER+32,ISSUED
    copyq FOOTER+40,COMPLETED
    copyq FOOTER+48,MINTED
    copyq FOOTER+56,CLOSED
    copyq FOOTER+64,LIVE
    copyq FOOTER+72,IOERR
    copyq FOOTER+80,BAD
    copyq FOOTER+88,LASTRET
    copyq FOOTER+96,WCAP
    copyq FOOTER+104,TFD
    copyq FOOTER+112,EFD
    audit_write TFD,FOOTER,128
    audit_write EFD,FOOTER,128
    mov edi,1
    lea rsi,[r15+FOOTER]
    mov edx,128
    call write_all
    test eax,eax
    jnz infrastructure
    xor edi,edi
    jmp exit_group

/* Only transport retries EINTR; owner effects above each perform one syscall. */
read_exact:
    mov r8,rdx
read_loop:
    test rdx,rdx
    jz io_ok
    xor eax,eax
    syscall
    cmp rax,-4
    je read_loop
    test rax,rax
    js io_bad
    jz read_eof
    add rsi,rax
    sub rdx,rax
    jmp read_loop
read_eof:
    cmp rdx,r8
    jne io_bad
    mov eax,1
    ret
write_all:
    test rdx,rdx
    jz io_ok
write_loop:
    mov eax,1
    syscall
    cmp rax,-4
    je write_loop
    test rax,rax
    jle io_bad
    add rsi,rax
    sub rdx,rax
    jnz write_loop
io_ok:
    xor eax,eax
    ret
io_bad:
    mov eax,-1
    ret
map_rw:
    mov rsi,rdi
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    js infrastructure
    ret
/* Audit FDs alone are normalized. The actual create FD is never changed. */
normalize_audit_fd:
    cmp rax,3
    jae normalized
    push rbx
    mov rbx,rax
    mov rdi,rax
    mov esi,1030
    mov edx,3
    mov eax,72
    syscall
    test rax,rax
    js infrastructure
    push rax
    mov rdi,rbx
    mov eax,3
    syscall
    pop rax
    pop rbx
normalized:
    ret
equal_cstring:
    mov al,[rdi]
    cmp al,[rsi]
    jne unequal
    test al,al
    jz equal
    inc rdi
    inc rsi
    jmp equal_cstring
equal:
    mov eax,1
    ret
unequal:
    xor eax,eax
    ret
usage:
    mov edi,64
    jmp exit_group
infrastructure:
    mov qword ptr [r15+IOERR],1
    mov edi,74
    jmp exit_group
contract:
    mov qword ptr [r15+BAD],1
    mov edi,78
exit_group:
    mov eax,231
    syscall
    ud2
option_name: .asciz "--capture-file-fixture"
effects_name: .asciz "effects.bin"
entries_name: .asciz "entries.bin"
.size _start, .-_start
.balign 16,0
shell_capture_file_entry:
    int3
