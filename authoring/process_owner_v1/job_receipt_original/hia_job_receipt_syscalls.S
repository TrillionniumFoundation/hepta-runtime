/* Linux x86-64 adapter for job_receipt.hepta.
 * fd 0: sealed input; fd 1: job registry directory; fd 2: result receipt.
 * HIA constructs the names and selects each effect from its prior result.
 */
.intel_syntax noprefix
.text
.global _start
_start:
 xor ebp,ebp
 and rsp,-16
 sub rsp,5152
 mov rbp,rsp
 /* Put the descriptor observation and HIA state after the stat buffer. */
 lea rdi,[rbp+144]
 xor eax,eax
 mov ecx,626
 rep stosq
 mov edi,1
 mov esi,9
 xor edx,edx
 xor r10d,r10d
 xor r8d,r8d
 mov eax,157
 syscall
 test rax,rax
 js refusal
 mov eax,110
 syscall
 mov [rbp+160],rax
 xor edi,edi
 mov esi,1034
 mov eax,72
 syscall
 test rax,rax
 js refusal
 and eax,15
 cmp eax,15
 jne refusal
 xor edi,edi
 mov rsi,rbp
 mov eax,5
 syscall
 test rax,rax
 js refusal
 mov r13,[rbp+48]
 cmp r13,35
 jb refusal
 cmp r13,4194464
 ja refusal
 xor edi,edi
 mov rsi,r13
 mov edx,1
 mov r10d,2
 xor r8d,r8d
 xor r9d,r9d
 mov eax,9
 syscall
 test rax,rax
 js refusal
 mov r12,rax
next:
 mov rdi,r12
 mov rsi,r13
 lea rdx,[rbp+192]
 mov ecx,4960
 lea r8,[rbp+144]
 mov r9d,48
 .byte 0xe8
policy_call_hole:
 .long 0
 cmp eax,1
 je stage
 cmp eax,2
 je write_record
 cmp eax,3
 je sync_file
 cmp eax,4
 je close_file
 cmp eax,5
 je publish
 cmp eax,6
 je sync_directory
 cmp eax,7
 je emit
 cmp eax,8
 je close_checked
 cmp eax,9
 je write_cancel_record
 cmp eax,10
 je signal_frozen_supervisor
 cmp eax,11
 je open_group_status
 cmp eax,12
 je read_group_status
 cmp eax,13
 je signal_original_group
 cmp eax,14
 je observe_owner_fd
 cmp eax,15
 je acquire_owner_fd
 cmp eax,16
 je observe_owner_marker
 cmp eax,17
 je observe_handoff_peer
 cmp eax,18
 je open_custody_lock
 cmp eax,19
 je observe_custody_lock
 cmp eax,20
 je acquire_custody_lock
 cmp eax,21
 je send_custody_lock
 jmp refusal

stage:
 mov edi,1
 lea rsi,[rbp+384]
 mov edx,0xa00c1
 mov r10d,384
 mov eax,257
 syscall
 mov r14,rax
 jmp observed

write_record:
 mov rbx,[rbp+216]
 lea r15,[r12+rbx]
 mov r10,r13
 sub r10,rbx
 jmp write_next
write_cancel_record:
 lea r15,[rbp+544]
 mov r10,[rbp+216]
write_next:
 mov rdx,r10
 test rdx,rdx
 jz write_complete
 mov rdi,r14
 mov rsi,r15
 mov eax,1
 syscall
 cmp rax,-4
 je write_next
 test rax,rax
 js observed
 jz short_write
 add r15,rax
 sub r10,rax
 jmp write_next
write_complete:
 xor eax,eax
 jmp observed
short_write:
 mov rax,-5
 jmp observed

sync_file:
 mov rdi,r14
 mov eax,74
 syscall
 cmp rax,-4
 je sync_file
 jmp observed

close_file:
 mov rdi,r14
 mov eax,3
 syscall
 /* The original owner closes only after fsync, and does not retry close. */
 xor eax,eax
 jmp observed

close_checked:
 mov rdi,r14
 mov eax,3
 syscall
 jmp observed

publish:
 mov edi,1
 lea rsi,[rbp+384]
 mov edx,1
 lea r10,[rbp+224]
 mov eax,264
 syscall
 jmp observed

sync_directory:
 mov edi,1
 mov eax,74
 syscall
 cmp rax,-4
 je sync_directory
 jmp observed

signal_frozen_supervisor:
 mov rdi,[rbp+168]
 mov esi,15                 /* SIGTERM to the original inherited pidfd only */
 xor edx,edx
 xor r10d,r10d
 mov eax,424                /* pidfd_send_signal */
 syscall
 jmp observed

open_group_status:
 mov edi,-100
 lea rsi,[rbp+224]
 mov edx,0xa0000             /* O_CLOEXEC | O_NOFOLLOW */
 xor r10d,r10d
 mov eax,257
 syscall
 test rax,rax
 js observed
 mov r14,rax
 mov rdi,r14
 mov rsi,rbp
 mov eax,138                 /* fstatfs on the pinned proc descriptor */
 syscall
 test rax,rax
 js close_group_status
 cmp qword ptr [rbp],0x9fa0  /* PROC_SUPER_MAGIC */
 je observed
 mov rax,-74
 jmp close_group_status

read_group_status:
 mov rdi,r14
 lea rsi,[rbp+1056]
 mov edx,4096
 xor eax,eax
 syscall
 cmp rax,-4
 je read_group_status
close_group_status:
 mov r15,rax
 mov rdi,r14
 mov eax,3
 syscall
 test rax,rax
 js observed
 mov rax,r15
 jmp observed

signal_original_group:
 /* HIA accepted the live original child and chose TERM or KILL.
  * The calling supervisor still holds its unreaped group leader. */
 mov rdi,[rbp+168]
 neg edi
 mov esi,[rbp+176]
 mov eax,62
 syscall

observed:
 mov [rbp+152],rax
 jmp next

/* Observe fd 1. HIA checks the expected private lock or registry directory
 * before selecting its next kernel operation. */
observe_owner_fd:
 mov edi,1
observe_selected_fd:
 mov rsi,rbp
 mov eax,5                    /* fstat */
 syscall
 test rax,rax
 js observed
 mov rax,[rbp]
 mov [rbp+168],rax             /* device */
 mov rax,[rbp+8]
 mov [rbp+176],rax             /* inode */
 mov eax,[rbp+24]
 mov [rbp+184],rax             /* mode */
 mov rax,[rbp+16]
 mov [rbp+192],rax             /* link count */
 mov eax,[rbp+28]
 mov [rbp+200],rax             /* owner uid */
 mov eax,107                   /* geteuid */
 syscall
 mov [rbp+208],rax
 xor eax,eax
 jmp observed

acquire_owner_fd:
 mov edi,1
acquire_selected_fd:
 mov esi,6                    /* LOCK_EX | LOCK_NB */
 mov eax,73                   /* flock */
 syscall
 cmp rax,-4
 je acquire_selected_fd
 jmp observed

observe_owner_marker:
 mov edi,1                    /* pinned private registry directory */
 lea rsi,[rbp+384]            /* fixed name constructed by HIA */
 mov rdx,rbp
 mov r10d,256                 /* AT_SYMLINK_NOFOLLOW */
 mov eax,262                   /* newfstatat */
 syscall
 cmp rax,-4
 je observe_owner_marker
 jmp observed

observe_handoff_peer:
 mov edi,[r12+32]
 mov esi,1                    /* SOL_SOCKET */
 mov edx,17                   /* SO_PEERCRED */
 lea r10,[rbp+640]
 lea r8,[rbp+656]
 mov DWORD PTR [r8],12
 mov eax,55                   /* getsockopt */
 syscall
 test rax,rax
 js observed
 cmp DWORD PTR [rbp+656],12
 jne refusal
 mov eax,[rbp+640]
 mov [rbp+216],rax             /* socket creator PID */
 mov eax,[rbp+644]
 mov [rbp+224],rax             /* socket creator UID */
 xor eax,eax
 jmp observed

open_custody_lock:
 mov edi,1
 lea rsi,[rbp+384]
 mov edx,0xa0042               /* O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC */
 mov r10d,384                 /* 0600, constrained by inherited umask */
 mov eax,257                  /* openat */
 syscall
 cmp rax,-4
 je open_custody_lock
 mov r14,rax
 jmp observed

observe_custody_lock:
 mov edi,r14d
 jmp observe_selected_fd

acquire_custody_lock:
 mov edi,r14d
 jmp acquire_selected_fd

send_custody_lock:
 /* One byte and one SCM_RIGHTS descriptor to the verified peer socket.
  * The receiver obtains the same locked open file description. */
 lea rdi,[rbp+640]
 xor eax,eax
 mov ecx,19
 rep stosq
 lea rax,[rbp+704]
 mov [rbp+656],rax             /* msg_iov */
 mov QWORD PTR [rbp+664],1    /* msg_iovlen */
 lea rax,[rbp+736]
 mov [rbp+672],rax             /* msg_control */
 mov QWORD PTR [rbp+680],24   /* CMSG_SPACE(sizeof(int)) */
 lea rax,[rbp+784]
 mov [rbp+704],rax
 mov QWORD PTR [rbp+712],1
 mov QWORD PTR [rbp+736],20   /* CMSG_LEN(sizeof(int)) */
 mov DWORD PTR [rbp+744],1    /* SOL_SOCKET */
 mov DWORD PTR [rbp+748],1    /* SCM_RIGHTS */
 mov [rbp+752],r14d
 mov BYTE PTR [rbp+784],76    /* 'L' */
send_custody_message:
 mov edi,[r12+32]
 lea rsi,[rbp+640]
 mov edx,0x4040                /* MSG_NOSIGNAL|MSG_DONTWAIT */
 mov eax,46                   /* sendmsg */
 syscall
 cmp rax,-4
 je send_custody_message
 jmp observed

emit:
 lea rbx,[rbp+192]
 lea r15,[rbx+24]
emit_next:
 mov edi,2
 mov rsi,rbx
 mov rdx,r15
 sub rdx,rbx
 jz success
 mov eax,1
 syscall
 cmp rax,-4
 je emit_next
 test rax,rax
 jle refusal
 add rbx,rax
 jmp emit_next

success:
 xor edi,edi
 jmp exit
refusal:
 mov edi,65
exit:
 mov eax,231
 syscall
 ud2

 .ascii "HIAOWNID"

 /* Copied from the sealed writer into its caller's RX mapping. These effects
  * must execute in the original supervisor, never in the receipt subprocess.
  * Positive PID only; observe holds custody and reap returns the raw status. */
 .ascii "HIAWABI1"
child_wait:
 mov rax,-22                  /* EINVAL */
 cmp rdi,2147483647
 ja .return_wait
 test edi,edi
 jz .return_wait
 cmp rsi,1
 ja .return_wait
 mov r9d,edi
 test esi,esi
 jnz .reap_child

 sub rsp,128                 /* zero Linux siginfo_t before the nonblocking wait */
 mov rdi,rsp
 xor eax,eax
 mov ecx,16
 cld
 rep stosq
 mov edi,1                   /* P_PID */
 mov esi,r9d
 mov rdx,rsp
 mov r10d,0x01000005          /* WEXITED | WNOHANG | WNOWAIT */
 xor r8d,r8d
.observe_again:
 mov eax,247                  /* waitid */
 syscall
 cmp rax,-4
 je .observe_again
 test rax,rax
 js .observed_wait
 mov ecx,[rsp+16]             /* siginfo_t.si_pid (Linux x86-64) */
 test ecx,ecx
 jz .observed_wait
 mov rax,-71                  /* EPROTO: a different PID was returned */
 cmp ecx,r9d
 jne .observed_wait
 mov eax,1
.observed_wait:
 add rsp,128
 ret

.reap_child:
 sub rsp,8
 mov qword ptr [rsp],0
 mov rsi,rsp
 mov edx,1                   /* WNOHANG */
 xor r10d,r10d                /* no resource accounting */
.reap_again:
 mov eax,61                  /* wait4 */
 syscall
 cmp rax,-4
 je .reap_again
 test rax,rax
 jle .reaped_wait
 cmp rax,r9
 mov rax,-71
 jne .reaped_wait
 mov eax,[rsp]
 bts rax,32                  /* distinguishes status zero from no progress */
.reaped_wait:
 add rsp,8
.return_wait:
 ret
 .ascii "HIAWEND1"
 .ascii "HIASPAWN"

 /* One original capture pipe / append-log descriptor, never a path. Result:
  * errno in the high word, monotonically transferred bytes in the low word. */
 .ascii "HIAKABI1"
capture_io:
 xor r9d,r9d
 cmp rdi,2147483647
 ja .capture_invalid
 cmp rdx,65536
 ja .capture_invalid
 cmp rcx,1
 je .capture_sync
 test rsi,rsi
 jz .capture_invalid
 test rdx,rdx
 jz .capture_invalid
 cmp rcx,2
 je .capture_read
 test rcx,rcx
 jnz .capture_invalid

.capture_write:
 mov eax,1                  /* write */
 syscall
 cmp rax,-4
 je .capture_write
 test rax,rax
 js .capture_error
 jz .capture_progress
 cmp rax,rdx
 ja .capture_progress
 add r9,rax
 add rsi,rax
 sub rdx,rax
 jnz .capture_write
 mov rax,r9
 ret

.capture_read:
 xor eax,eax                /* read */
 syscall
 cmp rax,-4
 je .capture_read
 test rax,rax
 js .capture_error
 cmp rax,rdx
 ja .capture_progress
 ret

.capture_sync:
 or rsi,rdx
 jnz .capture_invalid
.capture_sync_again:
 mov eax,74                 /* fsync */
 syscall
 cmp rax,-4
 je .capture_sync_again
 test rax,rax
 js .capture_error
 ret

.capture_progress:
 mov eax,8192               /* original "invalid progress" diagnostic */
 jmp .capture_status
.capture_invalid:
 mov eax,22
 jmp .capture_status
.capture_error:
 neg eax
.capture_status:
 shl rax,32
 or rax,r9
 ret
 .ascii "HIAKEND1"

 /* The HIA packer appends f0 and its related functions immediately here. */
 .ascii "HIAJPOL1"
