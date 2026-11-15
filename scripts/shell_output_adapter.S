/* Fixed Linux primitives for the private HIA foreground-output owner.
 * Ordering, retries, allocation policy, cancellation and Result tags are HIA.
 * This standalone fixture prepares two owned files and exposes no raw-FD input.
 * Scheduling gates are explicit fixture controls; they never replace a syscall.
 */
.intel_syntax noprefix
.section .text
.global _start
.equ E,256
.equ WLEN,0
.equ DIRFD,8
.equ OUTFD,16
.equ ERRFD,24
.equ TRACEFD,32
.equ READFD,40
.equ HANDLE,48
.equ SEQ,56
.equ ACTION,64
.equ RAW,72
.equ ERROR,80
.equ RESULT,88
.equ AUDITFD,96
.equ PAYPTR,104
.equ PAYLEN,112
.equ PAYKIND,120
.equ MODE,128
.equ ADMITTED,136
.equ SERIAL,152
.equ ISSUES,160
.equ COMPLETIONS,168
.equ TRACEERR,176
.equ IOERR,184
.equ PID,192
.equ RECORDS,200
.equ PATHMAP,208
.equ OUTPATH,216
.equ ERRPATH,224
.equ TRACEPATH,232
.equ OUTLEN,240
.equ ERRLEN,248
.equ A0,256
.equ A1,264
.equ A2,272
.equ PHASE,280
.equ EXITCODE,288
.equ FRAME,304
.equ STATBUF,336
.equ READY,512
.equ GATE,576
.equ RECORD,640
.equ SIGACT,816
.equ FOOTER,896
.equ ABORTMASK,1040
.equ OLDABORTMASK,1048

_start:
    cld
    mov rbp,rsp
    mov rax,[rbp]
    cmp rax,3
    jb usage
    cmp rax,5
    ja usage
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
    mov qword ptr [r12+DIRFD],-1
    mov qword ptr [r12+OUTFD],-1
    mov qword ptr [r12+ERRFD],-1
    mov qword ptr [r12+TRACEFD],-1
    mov qword ptr [r12+READFD],-1
    mov qword ptr [r12+AUDITFD],-1
    mov eax,39
    syscall
    mov [r12+PID],rax
    cmp qword ptr [rbp],3
    je options_done
    mov ebx,3
option_loop:
    mov rdi,[rbp+rbx*8+8]
    lea rsi,[rip+step_option]
    call equal_string
    test eax,eax
    jz option_interrupt
    or qword ptr [r12+MODE],1
    jmp option_next
option_interrupt:
    mov rdi,[rbp+rbx*8+8]
    lea rsi,[rip+interrupt_option]
    call equal_string
    test eax,eax
    jz usage
    or qword ptr [r12+MODE],2
option_next:
    inc rbx
    cmp rbx,[rbp]
    jb option_loop
options_done:
    mov qword ptr [r12+SIGACT],1
    mov edi,13
    lea rsi,[r12+SIGACT]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    js startup_error
    test qword ptr [r12+MODE],2
    jz signals_done
    lea rax,[rip+signal_handler]
    mov [r12+SIGACT],rax
    mov qword ptr [r12+SIGACT+8],0x04000000
    lea rax,[rip+signal_return]
    mov [r12+SIGACT+16],rax
    mov qword ptr [r12+SIGACT+24],0
    mov edi,10
    lea rsi,[r12+SIGACT]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    js startup_error
signals_done:
    mov esi,4096
    call allocate
    cmp rax,-4095
    jae exit_alloc
    mov r13,rax
    mov esi,8192
    call allocate
    cmp rax,-4095
    jae exit_alloc
    mov r14,rax
    mov qword ptr [r12+WLEN],8192
    mov esi,4096
    call allocate
    cmp rax,-4095
    jae exit_alloc
    mov r15,rax
    mov rdi,[rbp+24]
    call string_length
    mov rbx,rax
    lea rsi,[rax+64]
    imul rsi,rsi,3
    jo exit_alloc
    call allocate
    cmp rax,-4095
    jae exit_alloc
    mov [r12+PATHMAP],rax
    mov [r12+OUTPATH],rax
    lea rcx,[rax+rbx+64]
    mov [r12+ERRPATH],rcx
    lea rcx,[rcx+rbx+64]
    mov [r12+TRACEPATH],rcx
    mov rdi,[r12+OUTPATH]
    mov rsi,[rbp+24]
    lea rdx,[rip+stdout_suffix]
    call make_path
    mov [r12+OUTLEN],rax
    mov rdi,[r12+ERRPATH]
    mov rsi,[rbp+24]
    lea rdx,[rip+stderr_suffix]
    call make_path
    mov [r12+ERRLEN],rax
    mov rdi,[r12+TRACEPATH]
    mov rsi,[rbp+24]
    lea rdx,[rip+trace_suffix]
    call make_path

    mov rdi,-100
    mov rsi,[rbp+24]
    mov edx,0xb0000
    xor r10d,r10d
    mov eax,257
    syscall
    call normalize_fd
    test rax,rax
    js startup_error
    mov [r12+DIRFD],rax
    mov rsi,[r12+OUTPATH]
    call create_file
    test rax,rax
    js startup_error
    mov [r12+OUTFD],rax
    mov rsi,[r12+ERRPATH]
    call create_file
    test rax,rax
    js startup_error
    mov [r12+ERRFD],rax
    mov rsi,[r12+TRACEPATH]
    call create_file
    test rax,rax
    js startup_error
    mov [r12+TRACEFD],rax

    mov rax,[rip+ready_magic]
    mov [r12+READY],rax
    mov qword ptr [r12+READY+8],1
    mov rax,[r12+PID]
    mov [r12+READY+16],rax
    mov rax,[r12+OUTFD]
    mov [r12+READY+24],rax
    mov rax,[r12+ERRFD]
    mov [r12+READY+32],rax
    mov rax,[r12+MODE]
    mov [r12+READY+56],rax
    mov rdi,[r12+OUTFD]
    xor ebx,ebx
    call observe_capture
    mov rax,[r12+STATBUF+8]
    mov [r12+READY+40],rax
    mov rdi,[r12+ERRFD]
    mov ebx,1
    call observe_capture
    mov rax,[r12+STATBUF+8]
    mov [r12+READY+48],rax
    mov edi,1
    lea rsi,[r12+READY]
    mov edx,64
    call write_all
    test rax,rax
    js startup_error
    xor edi,edi
    mov rsi,r13
    mov edx,40
    call read_exact
    cmp eax,1
    jne startup_error

owner_next:
    mov rdi,r13
    mov esi,40
    mov rdx,r15
    mov ecx,64
    mov r8,r14
    mov r9,[r12+WLEN]
    call .Lowner_image
    mov rdx,rax
    shr rdx,32
    jnz contract
    cmp eax,0xfffffff0
    je effect_pending
    cmp eax,64
    je completed
    test eax,eax
    jz contract
    mov [r12+FRAME],rax
    mov qword ptr [r12+FRAME+8],0
    mov qword ptr [r12+EXITCODE],2
    cmp eax,0xfffffffe
    jne refusal_contract
    mov qword ptr [r12+EXITCODE],75
refusal_contract:
    cmp eax,0xfffffff9
    jne publish_refusal
    mov qword ptr [r12+EXITCODE],78
publish_refusal:
    call cleanup
    call footer
    mov edi,1
    lea rsi,[r12+FRAME]
    mov edx,16
    call write_all
    jmp finish

effect_pending:
    mov rax,[rip+effect_magic]
    cmp [r14+E],rax
    jne contract
    mov rax,[r12+SEQ]
    inc rax
    jz contract
    cmp [r14+E+8],rax
    jne contract
    mov [r12+SEQ],rax
    mov rax,[r14+E+48]
    or rax,[r14+E+56]
    or rax,[r14+E+64]
    or rax,[r14+E+72]
    or rax,[r14+E+80]
    or rax,[r14+E+88]
    jnz contract
    mov rax,[r14+E+16]
    cmp rax,1
    jb contract
    cmp rax,11
    ja contract
    mov [r12+ACTION],rax
    mov rax,[r14+E+24]
    mov [r12+A0],rax
    mov rax,[r14+E+32]
    mov [r12+A1],rax
    mov rax,[r14+E+40]
    mov [r12+A2],rax
    test qword ptr [r12+MODE],1
    jz dispatch
    mov rax,[rip+gate_magic]
    mov [r12+GATE],rax
    mov rax,[r12+SEQ]
    mov [r12+GATE+8],rax
    mov rax,[r12+ACTION]
    mov [r12+GATE+16],rax
    mov rax,[r12+A0]
    mov [r12+GATE+24],rax
    mov rax,[r12+A1]
    mov [r12+GATE+32],rax
    mov rax,[r12+A2]
    mov [r12+GATE+40],rax
    mov qword ptr [r12+GATE+48],0
    mov qword ptr [r12+GATE+56],0
    mov edi,1
    lea rsi,[r12+GATE]
    mov edx,64
    call write_all
    test rax,rax
    js startup_error
    xor edi,edi
    mov rsi,r13
    mov edx,40
    call read_exact
    cmp eax,1
    jne startup_error
    mov rdi,r13
    mov esi,40
    mov rdx,r15
    mov ecx,64
    mov r8,r14
    mov r9,[r12+WLEN]
    call .Lowner_image
    mov rdx,rax
    shr rdx,32
    jnz contract
    cmp eax,0xfffffff0
    jne contract
    mov rax,[r14+E+8]
    cmp rax,[r12+SEQ]
    jne contract
    mov rax,[r14+E+16]
    cmp rax,[r12+ACTION]
    jne contract
    mov rax,[r14+E+24]
    cmp rax,[r12+A0]
    jne contract
    mov rax,[r14+E+32]
    cmp rax,[r12+A1]
    jne contract
    mov rax,[r14+E+40]
    cmp rax,[r12+A2]
    jne contract
dispatch:
    mov qword ptr [r12+RAW],0
    mov qword ptr [r12+ERROR],0
    mov qword ptr [r12+RESULT],0
    mov qword ptr [r12+PAYPTR],0
    mov qword ptr [r12+PAYLEN],0
    mov qword ptr [r12+PAYKIND],0
    mov rax,[r12+READFD]
    mov [r12+AUDITFD],rax
    mov rax,[r12+ACTION]
    cmp rax,10
    je diagnostic_issue
    cmp rax,11
    jne not_abort_issue
    mov qword ptr [r12+AUDITFD],-1
not_abort_issue:
    cmp rax,2
    je path_issue
    cmp rax,8
    je path_issue
    jmp ordinary_issue
diagnostic_issue:
    cmp qword ptr [r12+A2],0
    jne contract
    mov rdi,[r12+A0]
    mov rsi,[r12+A1]
    test rsi,rsi
    jz contract
    cmp rdi,1024
    jb contract
    mov rax,rdi
    add rax,rsi
    jc contract
    cmp rax,1280
    ja contract
    call span
    mov rax,[r12+A0]
    add rax,r14
    mov [r12+PAYPTR],rax
    mov rax,[r12+A1]
    mov [r12+PAYLEN],rax
    mov qword ptr [r12+PAYKIND],4
    mov qword ptr [r12+AUDITFD],2
    jmp ordinary_issue
path_issue:
    call capture_path
    mov [r12+PAYPTR],rsi
    mov [r12+PAYLEN],rdx
    mov qword ptr [r12+PAYKIND],1
ordinary_issue:
    mov qword ptr [r12+PHASE],0
    call trace_record
    mov qword ptr [r12+PAYPTR],0
    mov qword ptr [r12+PAYLEN],0
    mov qword ptr [r12+PAYKIND],0
    mov rax,[r12+ACTION]
    cmp rax,1
    je admit
    cmp qword ptr [r12+ADMITTED],1
    jne contract
    cmp rax,2
    je open_read
    cmp rax,3
    je metadata_statx
    cmp rax,4
    je metadata_fstat
    cmp rax,5
    je read_file
    cmp rax,6
    je close_read
    cmp rax,7
    je grow_work
    cmp rax,8
    je unlink_file
    cmp rax,9
    je statx_probe
    cmp rax,10
    je diagnostic_write
    cmp rax,11
    je abort_self
    jmp contract
admit:
    cmp qword ptr [r12+ADMITTED],0
    jne contract
    cmp qword ptr [r12+A0],1
    jne contract
    call zero_last
    mov qword ptr [r12+ADMITTED],1
    xor eax,eax
    jmp acknowledge
open_read:
    cmp qword ptr [r12+READFD],-1
    jne contract
    call capture_path
    mov rdi,-100
    mov edx,0x80000
    xor r10d,r10d
    mov eax,257
    syscall
    mov [r12+RAW],rax
    call normalize_fd
    test rax,rax
    js error_return
    mov [r12+READFD],rax
    mov [r12+AUDITFD],rax
    inc qword ptr [r12+SERIAL]
    jz contract
    mov rax,[r12+SERIAL]
    mov [r12+HANDLE],rax
    mov [r12+RESULT],rax
    jmp acknowledged
metadata_statx:
    call owned_handle
    cmp qword ptr [r12+A1],384
    jne contract
    cmp qword ptr [r12+A2],256
    jne contract
    lea rdi,[r14+384]
    mov ecx,256
    xor eax,eax
    rep stosb
    mov rdi,[r12+READFD]
    lea rsi,[rip+empty_path]
    mov edx,0x1000
    mov r10d,0xfff
    lea r8,[r14+384]
    mov eax,332
    syscall
    mov [r12+RAW],rax
    test rax,rax
    js error_return
    lea rax,[r14+384]
    mov [r12+PAYPTR],rax
    mov qword ptr [r12+PAYLEN],256
    mov qword ptr [r12+PAYKIND],3
    xor eax,eax
    jmp acknowledge
metadata_fstat:
    call owned_handle
    cmp qword ptr [r12+A1],640
    jne contract
    cmp qword ptr [r12+A2],144
    jne contract
    mov rdi,[r12+READFD]
    lea rsi,[r14+640]
    mov eax,5
    syscall
    mov [r12+RAW],rax
    test rax,rax
    js error_return
    lea rax,[r14+640]
    mov [r12+PAYPTR],rax
    mov qword ptr [r12+PAYLEN],144
    mov qword ptr [r12+PAYKIND],3
    xor eax,eax
    jmp acknowledge
statx_probe:
    mov rax,[r12+A0]
    or rax,[r12+A1]
    or rax,[r12+A2]
    jnz contract
    xor edi,edi
    xor esi,esi
    xor edx,edx
    mov r10d,0xfff
    xor r8d,r8d
    mov eax,332
    syscall
    mov [r12+RAW],rax
    test rax,rax
    js error_return
    jmp acknowledge
read_file:
    call owned_handle
    mov rdi,[r12+A1]
    mov rsi,[r12+A2]
    call span
    cmp qword ptr [r12+A1],800
    jne read_data_span
    cmp qword ptr [r12+A2],32
    jne contract
    jmp read_span_ready
read_data_span:
    cmp qword ptr [r12+A1],4208
    jb contract
read_span_ready:
    mov rdi,[r12+READFD]
    mov rsi,[r12+A1]
    add rsi,r14
    mov rdx,[r12+A2]
    test rdx,rdx
    jz contract
    xor eax,eax
    syscall
    mov [r12+RAW],rax
    test rax,rax
    js error_return
    mov [r12+RESULT],rax
    mov [r12+PAYLEN],rax
    mov rax,[r12+A1]
    add rax,r14
    mov [r12+PAYPTR],rax
    mov qword ptr [r12+PAYKIND],2
    jmp acknowledged
close_read:
    call owned_handle
    call zero_last
    mov rdi,[r12+READFD]
    mov eax,3
    syscall
    mov [r12+RAW],rax
    mov qword ptr [r12+READFD],-1
    mov qword ptr [r12+HANDLE],0
    test rax,rax
    js error_return
    jmp acknowledge
grow_work:
    call zero_last
    mov rdx,[r12+A0]
    cmp rdx,[r12+WLEN]
    jbe contract
    add rdx,4095
    jc contract
    and rdx,-4096
    mov rbp,rdx
    mov rdi,r14
    mov rsi,[r12+WLEN]
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    mov [r12+RAW],rax
    cmp rax,-4095
    jae error_return
    mov r14,rax
    mov [r12+WLEN],rbp
    mov [r12+RESULT],rbp
    jmp acknowledged
unlink_file:
    call capture_path
    mov rdi,rsi
    mov eax,87
    syscall
    mov [r12+RAW],rax
    test rax,rax
    js error_return
    jmp acknowledge
diagnostic_write:
    mov edi,2
    mov rsi,[r12+A0]
    add rsi,r14
    mov rdx,[r12+A1]
    mov eax,1
    syscall
    test rax,rax
    js error_return
    jmp acknowledge
abort_self:
    mov rax,[r12+A0]
    or rax,[r12+A1]
    or rax,[r12+A2]
    jnz contract
    /* Fixed libc-compatible raise(SIGABRT), then forced-default fallback.
     * This intrinsic does not choose whether a failure is fatal: HIA did. */
    mov qword ptr [r12+ABORTMASK],-1
    xor edi,edi
    lea rsi,[r12+ABORTMASK]
    lea rdx,[r12+OLDABORTMASK]
    mov r10d,8
    mov eax,14
    syscall
    mov eax,186
    syscall
    mov rsi,rax
    mov rdi,[r12+PID]
    mov edx,6
    mov eax,234
    syscall
    mov edi,2
    lea rsi,[r12+OLDABORTMASK]
    xor edx,edx
    mov r10d,8
    mov eax,14
    syscall
    xor edi,edi
    lea rsi,[r12+ABORTMASK]
    xor edx,edx
    mov r10d,8
    mov eax,14
    syscall
    mov qword ptr [r12+SIGACT],0
    mov qword ptr [r12+SIGACT+8],0
    mov qword ptr [r12+SIGACT+16],0
    mov qword ptr [r12+SIGACT+24],-1
    mov edi,6
    lea rsi,[r12+SIGACT]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    mov eax,186
    syscall
    mov rsi,rax
    mov rdi,[r12+PID]
    mov edx,6
    mov eax,234
    syscall
    mov qword ptr [r12+ABORTMASK],32
    mov edi,1
    lea rsi,[r12+ABORTMASK]
    xor edx,edx
    mov r10d,8
    mov eax,14
    syscall
    hlt
    mov edi,127
    mov eax,231
    syscall
acknowledge:
    mov [r12+RAW],rax
    mov [r12+RESULT],rax
    jmp acknowledged
error_return:
    mov [r12+RAW],rax
    neg rax
    cmp rax,4095
    ja contract
    mov [r12+ERROR],rax
    mov qword ptr [r12+RESULT],0
acknowledged:
    mov qword ptr [r12+PHASE],1
    call trace_record
    mov rax,[r12+RESULT]
    mov [r14+E+56],rax
    mov rax,[r12+ERROR]
    mov [r14+E+64],rax
    mov qword ptr [r14+E+80],1
    mov qword ptr [r13+8],2
    jmp owner_next

completed:
    mov rax,[rip+descriptor_magic]
    cmp [r15],rax
    jne contract
    cmp qword ptr [r15+16],1
    jne contract
    mov rdi,[r15+24]
    mov rsi,[r15+32]
    call span
    mov rax,[r15+40]
    or rax,[r15+48]
    or rax,[r15+56]
    jnz contract
    mov rax,[r15+8]
    cmp rax,1
    je ordinary_complete
    cmp rax,2
    jne contract
    mov rax,[r15+24]
    or rax,[r15+32]
    jnz contract
ordinary_complete:
    cmp qword ptr [r12+READFD],-1
    jne contract
    mov qword ptr [r12+FRAME],64
    mov rax,[r15+32]
    add rax,64
    jc contract
    mov [r12+FRAME+8],rax
    call cleanup
    call footer
    mov edi,1
    lea rsi,[r12+FRAME]
    mov edx,16
    call write_all
    test rax,rax
    js output_error
    mov edi,1
    mov rsi,r15
    mov edx,64
    call write_all
    test rax,rax
    js output_error
    mov edi,1
    mov rsi,[r15+24]
    add rsi,r14
    mov rdx,[r15+32]
    call write_all
    test rax,rax
    js output_error
    jmp finish

owned_handle:
    cmp qword ptr [r12+READFD],2
    jbe contract
    mov rax,[r12+A0]
    test rax,rax
    jz contract
    cmp rax,[r12+HANDLE]
    jne contract
    ret
zero_last:
    mov rax,[r12+A1]
    or rax,[r12+A2]
    jnz contract
    ret
span:
    cmp rdi,[r12+WLEN]
    ja contract
    mov rax,[r12+WLEN]
    sub rax,rdi
    cmp rsi,rax
    ja contract
    ret
capture_path:
    cmp qword ptr [r12+A0],1
    jne contract
    cmp qword ptr [r12+A2],0
    jne contract
    mov rax,[r12+A1]
    cmp rax,1
    ja contract
    test rax,rax
    jnz path_stderr
    mov rsi,[r12+OUTPATH]
    mov rdx,[r12+OUTLEN]
    ret
path_stderr:
    mov rsi,[r12+ERRPATH]
    mov rdx,[r12+ERRLEN]
    ret

observe_capture:
    mov [r12+AUDITFD],rdi
    mov [r12+A0],rbx
    mov qword ptr [r12+A1],0
    mov qword ptr [r12+A2],0
    mov qword ptr [r12+ACTION],0
    mov qword ptr [r12+PHASE],1
    lea rsi,[r12+STATBUF]
    mov eax,5
    syscall
    mov [r12+RAW],rax
    test rax,rax
    js startup_error
    mov qword ptr [r12+ERROR],0
    lea rax,[r12+STATBUF]
    mov [r12+PAYPTR],rax
    mov qword ptr [r12+PAYLEN],144
    mov qword ptr [r12+PAYKIND],3
    call trace_record
    ret

trace_record:
    cmp qword ptr [r12+TRACEFD],2
    jbe trace_done
    mov rax,[rip+trace_magic]
    mov [r12+RECORD],rax
    mov rax,[r12+SEQ]
    mov [r12+RECORD+8],rax
    mov rax,[r12+ACTION]
    mov [r12+RECORD+16],rax
    mov rax,[r12+PHASE]
    mov [r12+RECORD+24],rax
    mov rax,[r12+PID]
    mov [r12+RECORD+32],rax
    mov eax,186
    syscall
    mov [r12+RECORD+40],rax
    mov qword ptr [r12+RECORD+48],1
    mov rax,[r12+AUDITFD]
    mov [r12+RECORD+56],rax
    mov rax,[r12+A0]
    mov [r12+RECORD+64],rax
    mov rax,[r12+A1]
    mov [r12+RECORD+72],rax
    mov rax,[r12+A2]
    mov [r12+RECORD+80],rax
    mov rax,[r12+RAW]
    mov [r12+RECORD+88],rax
    mov rax,[r12+ERROR]
    mov [r12+RECORD+96],rax
    mov rax,[r12+PAYKIND]
    mov [r12+RECORD+104],rax
    mov rax,[r12+PAYLEN]
    mov [r12+RECORD+112],rax
    mov qword ptr [r12+RECORD+120],0
    inc qword ptr [r12+RECORDS]
    cmp qword ptr [r12+ACTION],0
    je trace_write
    cmp qword ptr [r12+PHASE],0
    jne trace_completion
    inc qword ptr [r12+ISSUES]
    jmp trace_write
trace_completion:
    inc qword ptr [r12+COMPLETIONS]
trace_write:
    mov rdi,[r12+TRACEFD]
    lea rsi,[r12+RECORD]
    mov edx,128
    call write_all
    test rax,rax
    js trace_failed
    mov rdi,[r12+TRACEFD]
    mov rsi,[r12+PAYPTR]
    mov rdx,[r12+PAYLEN]
    call write_all
    test rax,rax
    js trace_failed
trace_done:
    ret
trace_failed:
    mov [r12+TRACEERR],rax
    ret
footer:
    cmp qword ptr [r12+TRACEFD],2
    jbe footer_done
    lea rdi,[r12+FOOTER]
    mov ecx,128
    xor eax,eax
    rep stosb
    mov rax,[rip+footer_magic]
    mov [r12+FOOTER],rax
    mov rax,[r12+PID]
    mov [r12+FOOTER+8],rax
    mov rax,[r12+RECORDS]
    mov [r12+FOOTER+16],rax
    mov rax,[r12+ISSUES]
    mov [r12+FOOTER+24],rax
    mov rax,[r12+COMPLETIONS]
    mov [r12+FOOTER+32],rax
    mov rax,[r12+TRACEERR]
    mov [r12+FOOTER+40],rax
    mov rax,[r12+IOERR]
    mov [r12+FOOTER+48],rax
    mov rax,[r12+READFD]
    mov [r12+FOOTER+56],rax
    mov rax,[r12+OUTFD]
    mov [r12+FOOTER+64],rax
    mov rax,[r12+ERRFD]
    mov [r12+FOOTER+72],rax
    mov rax,[r12+EXITCODE]
    mov [r12+FOOTER+80],rax
    mov rax,[r12+MODE]
    mov [r12+FOOTER+88],rax
    mov rdi,[r12+TRACEFD]
    lea rsi,[r12+FOOTER]
    mov edx,128
    call write_all
    test rax,rax
    jns footer_done
    mov [r12+TRACEERR],rax
footer_done:
    ret

cleanup:
    mov rdi,[r12+READFD]
    call close_if_owned
    mov qword ptr [r12+READFD],-1
    mov qword ptr [r12+HANDLE],0
    mov rdi,[r12+OUTFD]
    call close_if_owned
    mov qword ptr [r12+OUTFD],-1
    mov rdi,[r12+ERRFD]
    call close_if_owned
    mov qword ptr [r12+ERRFD],-1
    mov rdi,[r12+DIRFD]
    call close_if_owned
    mov qword ptr [r12+DIRFD],-1
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
finish:
    mov rdi,[r12+TRACEFD]
    call close_if_owned
    mov rdi,[r12+EXITCODE]
    cmp qword ptr [r12+TRACEERR],0
    jne failure_exit
    cmp qword ptr [r12+IOERR],0
    je exit_code
failure_exit:
    mov edi,74
exit_code:
    mov eax,60
    syscall
output_error:
    mov [r12+IOERR],rax
    jmp finish
startup_error:
    mov [r12+IOERR],rax
    mov qword ptr [r12+EXITCODE],74
    call cleanup
    call footer
    jmp finish
contract:
    mov qword ptr [r12+EXITCODE],78
    call cleanup
    call footer
    jmp finish
usage:
    mov edi,64
    mov eax,60
    syscall
exit_alloc:
    mov edi,75
    mov eax,60
    syscall

allocate:
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    ret
create_file:
    mov rdi,-100
    mov edx,0xa00c1
    mov r10d,0x180
    mov eax,257
    syscall
    jmp normalize_fd
normalize_fd:
    cmp rax,-4095
    jae normalized
    cmp rax,2
    ja normalized
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
normalized:
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
string_equal_loop:
    mov cl,[rdi]
    cmp cl,[rsi]
    jne string_equal_done
    test cl,cl
    jz string_equal_yes
    inc rdi
    inc rsi
    jmp string_equal_loop
string_equal_yes:
    mov eax,1
string_equal_done:
    ret
string_length:
    xor eax,eax
string_length_loop:
    cmp byte ptr [rdi+rax],0
    je string_length_done
    inc rax
    jmp string_length_loop
string_length_done:
    ret
make_path:
    mov r8,rdi
make_prefix:
    mov al,[rsi]
    test al,al
    jz make_suffix
    mov [rdi],al
    inc rdi
    inc rsi
    jmp make_prefix
make_suffix:
    mov al,[rdx]
    mov [rdi],al
    inc rdi
    inc rdx
    test al,al
    jnz make_suffix
    mov rax,rdi
    sub rax,r8
    ret
signal_handler:
    ret
signal_return:
    mov eax,15
    syscall

fixture_option: .asciz "--output-fixture"
step_option: .asciz "--step-effects"
interrupt_option: .asciz "--interruptible"
stdout_suffix: .asciz "/stdout.log"
stderr_suffix: .asciz "/stderr.log"
trace_suffix: .asciz "/effects.bin"
empty_path: .byte 0
ready_magic: .ascii "HSHOIRD1"
gate_magic: .ascii "HSHOIGT1"
effect_magic: .ascii "HSHOIFX1"
descriptor_magic: .ascii "HSHOID01"
trace_magic: .ascii "HSHOITR1"
footer_magic: .ascii "HSHOIAU1"
.p2align 4,0x90
.Lowner_image:
.byte 0
