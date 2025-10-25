.intel_syntax noprefix
.text

.globl MyNtOpenProcess
.globl MyOpenProcess
.globl MyZwReadVirtualMemory
.globl MyReadProcessMemory
.globl MyNtWriteVirtualMemory
.globl MyNtAllocateVirtualMemory
.globl MyNtFreeVirtualMemory
.globl MyNtCreateSection
.globl MyNtMapViewOfSection
.globl MyNtUnmapViewOfSection
.globl MyNtClose
.globl MyNtQueueApcThread

MyNtOpenProcess:
    mov     r10, rcx
    mov     eax, 0x26     # NtOpenProcess 的系统调用号
    syscall
    ret


# MyOpenProcess: 使用直接系统调用来自定义实现 OpenProcess
MyOpenProcess:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x68

    # 在栈上准备 OBJECT_ATTRIBUTES 和 CLIENT_ID 结构体
    mov     qword ptr [rbp - 0x40], 0
    lea     r9, [rbp - 0x48]         # r9 = &CLIENT_ID
    movsxd  rax, r8d                 # r8d = ProcessId (来自第3个 C++ 参数)
    mov     qword ptr [rbp - 0x48], rax # CLIENT_ID.UniqueProcess = ProcessId
    mov     qword ptr [rbp - 0x40], 0   # CLIENT_ID.UniqueThread = 0

    # 准备 OBJECT_ATTRIBUTES
    lea     r8, [rbp - 0x38]         # r8 = &OBJECT_ATTRIBUTES
    mov     qword ptr [rbp - 0x38], 0x30 # .Length
    mov     qword ptr [rbp - 0x30], 0   # .RootDirectory
    mov     qword ptr [rbp - 0x28], 0   # .ObjectName
    mov     qword ptr [rbp - 0x20], 0   # .Attributes
    mov     qword ptr [rbp - 0x18], 0   # .SecurityDescriptor
    mov     qword ptr [rbp - 0x10], 0   # .SecurityQualityOfService

    # 准备 NtOpenProcess 的其他参数
    mov     edx, ecx                 # edx = DesiredAccess (来自第1个 C++ 参数)
    lea     rcx, [rbp + 0x10]        # rcx = &ProcessHandle (输出缓冲区)

    # 执行直接系统调用
    call    MyNtOpenProcess

    # 返回句柄
    mov     rax, [rbp + 0x10]
    add     rsp, 0x68
    pop     rbp
    ret


# MyZwReadVirtualMemory: NtReadVirtualMemory 的直接系统调用封装
MyZwReadVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x3F     # NtReadVirtualMemory 的系统调用号
    syscall
    ret


# MyReadProcessMemory: 自定义实现 ReadProcessMemory
MyReadProcessMemory:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x30  # 为局部变量和栈对齐分配空间

    # 为 MyZwReadVirtualMemory 的第5个参数 (PSIZE_T NumberOfBytesRead) 准备一个指针
    # 我们在自己的栈上创建一个临时变量来接收这个值
    lea     rax, [rbp - 8]      # rax = 地址 of [rbp - 8]
    mov     qword ptr [rsp + 0x20], rax # 将该地址放到栈上，作为 syscall 的第5个参数

    # 调用 syscall (前4个参数 rcx, rdx, r8, r9 已由调用者设置好)
    call    MyZwReadVirtualMemory

    # 检查返回的 NTSTATUS 值 (在 rax 中)
    test    rax, rax
    jnz     _L_RPM_FAIL         # 如果 rax 不为 0 (非 STATUS_SUCCESS), 跳转到失败处理

    # 从我们的函数参数中获取 lpNumberOfBytesRead 指针 (第5个参数在 [rbp + 0x30])
    mov     rcx, [rbp + 0x30]
    
    # 安全检查：如果调用者传入 NULL，则不进行写入
    test    rcx, rcx
    jz      _L_RPM_SET_SUCCESS_RET

    # 从我们的临时变量中获取 syscall 返回的字节数
    mov     rdx, [rbp - 8]
    
    # 将字节数写入调用者提供的地址
    mov     [rcx], rdx

_L_RPM_SET_SUCCESS_RET:
    # 设置返回值为 1 (TRUE)
    mov     eax, 1
    jmp     _L_RPM_END

# --- 失败路径 ---
_L_RPM_FAIL:
    # 设置返回值为 0 (FALSE)
    xor     eax, eax

# --- 清理并返回 ---
_L_RPM_END:
    add     rsp, 0x30
    pop     rbp
    ret


# MyNtWriteVirtualMemory: NtWriteVirtualMemory 的直接系统调用封装
MyNtWriteVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x3A     # NtWriteVirtualMemory 的系统调用号
    syscall
    ret

MyNtAllocateVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x18
    syscall
    ret

MyNtFreeVirtualMemory:
    mov     r10, rcx
    mov     eax, 0x1E
    syscall
    ret

MyNtCreateSection:
    mov     r10, rcx
    mov     eax, 0x4A
    syscall
    ret

MyNtMapViewOfSection:
    mov     r10, rcx
    mov     eax, 0x28
    syscall
    ret

MyNtUnmapViewOfSection:
    mov     r10, rcx
    mov     eax, 0x2A
    syscall
    ret

MyNtClose:
    mov     r10, rcx
    mov     eax, 0x0F
    syscall
    ret

MyNtQueueApcThread:
    mov     r10, rcx
    mov     eax, 0x45
    syscall
    ret
