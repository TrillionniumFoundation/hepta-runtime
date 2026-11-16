/* Private scenario initialization; never linked into the public transport.
 * HBCNEW02 + raw-root-length:u64 + exact raw root constructs one fresh Session.
 * This fixture does not chdir, canonicalize or reinterpret the PathBuf bytes.
 * Global History/locks stay alive; original comparisons use this only while
 * initializing each fresh per-scenario process, before any public request. */
.intel_syntax noprefix
.section .text
fs_fixture_batch_observe:
    cmp qword ptr [r12 + 88], 0
    jne fs_fixture_failure
    mov rdi, [r12 + 72]
    call runtime_batch_fixture_observe
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_next

fs_fixture_new_session:
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 88]
    cmp rsi, 16
    jb fs_fixture_failure
    mov rax, 0x323057454e434248 /* HBCNEW02 */
    cmp [rdi], rax
    jne fs_fixture_failure
    sub rsi, 16
    cmp [rdi + 8], rsi
    jne fs_fixture_failure
    mov rdx, rsi
    add rdx, 32
    jc fs_fixture_failure
    mov [r12 + 40], rdx
    cmp rdx, [r12 + 32]
    jbe fs_fixture_new_root_room
    add rdx, 4095
    jc fs_fixture_failure
    and rdx, -4096
    call fs_fixture_grow
fs_fixture_new_root_room:
    mov rcx, [r12 + 40]
    sub rcx, 32
    test rcx, rcx
    jz fs_fixture_new_root_moved
    mov rsi, [r12 + 24]
    lea rdi, [rsi + rcx + 31]
    lea rsi, [rsi + rcx + 15]
    std
    rep movsb
    cld
fs_fixture_new_root_moved:
    mov rdx, [r12 + 24]
    mov rax, 0x3230305157535248 /* HRSWQ002 */
    mov [rdx], rax
    mov qword ptr [rdx + 8], 1
    mov rax, [r12 + 40]
    sub rax, 32
    mov [rdx + 16], rax
    mov qword ptr [rdx + 24], 0
    mov r13, [r12 + 72]
    call runtime_grow_batch_release
    test rax, rax
    jnz fs_fixture_failure
    call runtime_grow_fence_release
    test rax, rax
    jnz fs_fixture_failure
    call runtime_grow_view_release
    test rax, rax
    jnz fs_fixture_failure
    call runtime_grow_destroy
    test rax, rax
    jnz fs_fixture_failure
    mov qword ptr [r12 + r13 * 8], 0
    lea rdi, [rip + grow_fixture_images]
    mov rsi, [r12 + 504]
    call runtime_grow_create
    cmp rax, -4095
    jae fs_fixture_failure
    mov [r12 + r13 * 8], rax
    mov r15, rax
    mov qword ptr [r15 + 80], 3
    mov rdi, [r12 + 16]
    call runtime_filesystem_hub_bind
    test rax, rax
    jnz fs_fixture_failure
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 40]
    mov r8d, 6
    call runtime_grow_owned
    cmp rax, 32
    jne fs_fixture_failure
    mov rdx, [r15 + 8]
    lea rbx, [rdx + 6 * 64]
    cmp qword ptr [rbx + 56], 32
    jne fs_fixture_failure
    mov rdx, [rbx + 32]
    mov rax, 0x3230305257535248 /* HRSWR002 */
    cmp [rdx], rax
    jne fs_fixture_failure
    mov rax, [rdx + 8]
    or rax, [rdx + 16]
    or rax, [rdx + 24]
    jnz fs_fixture_failure
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae fs_fixture_failure
    btr qword ptr [r12 + 56], r13
    mov rax, 0x3230525846534648 /* HFSFXR02 */
    mov [r12 + 192], rax
    mov [r12 + 200], r13
    mov qword ptr [r12 + 208], 36
    mov qword ptr [r12 + 216], 32
    mov qword ptr [r12 + 224], 32
    xor ecx, ecx
fs_fixture_new_counter:
    mov rax, [r15 + rcx * 8 + 128]
    mov [r12 + rcx * 8 + 232], rax
    inc ecx
    cmp ecx, 6
    jb fs_fixture_new_counter
    mov rdx, [r15 + 8]
    lea rbx, [rdx + 6 * 64]
    mov rax, [rbx + 16]
    mov [r12 + 280], rax
    mov rax, [rbx + 40]
    mov [r12 + 288], rax
    mov edi, 1
    lea rsi, [r12 + 192]
    mov edx, 104
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [rbx + 32]
    mov edx, 32
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_next
