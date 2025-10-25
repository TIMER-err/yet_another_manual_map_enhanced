// includes/syscalls.h
#pragma once

#include <windows.h>

// NTSTATUS a.k.a. LONG
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define ObjectTypeNameInformation 2

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    // 后面还有很多字段，但我们不需要它们
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// 使用 extern "C" 来防止 C++ 名称修饰，确保链接器能找到汇编函数
#ifdef __cplusplus
extern "C"
{
#endif

    // 来自 syscalls.s 的函数原型

    HANDLE MyOpenProcess(
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        DWORD dwProcessId);

    BOOL MyReadProcessMemory(
        HANDLE hProcess,
        LPCVOID lpBaseAddress,
        LPVOID lpBuffer,
        SIZE_T nSize,
        PSIZE_T lpNumberOfBytesRead);

    NTSTATUS MyNtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten);

    NTSTATUS MyNtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress, // 这是一个指向指针的指针 (输入/输出)
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, // 这是一个指针 (输入/输出)
        ULONG AllocationType,
        ULONG Protect);

    NTSTATUS MyNtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress, // 指向指针的指针
        PSIZE_T RegionSize, // 指针
        ULONG FreeType);

    NTSTATUS MyNtCreateSection(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, // POBJECT_ATTRIBUTES, but PVOID is fine for NULL
        PLARGE_INTEGER MaximumSize,
        ULONG SectionPageProtection,
        ULONG AllocationAttributes,
        HANDLE FileHandle);

    NTSTATUS MyNtMapViewOfSection(
        HANDLE SectionHandle,
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T CommitSize,
        PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize,
        UINT InheritDisposition, // See SECTION_INHERIT enum
        ULONG AllocationType,
        ULONG Win32Protect);

    NTSTATUS MyNtUnmapViewOfSection(HANDLE, PVOID);

    NTSTATUS MyNtClose(HANDLE Handle);

    NTSTATUS MyNtQueueApcThread(
        HANDLE ThreadHandle,
        PVOID ApcRoutine, // PIO_APC_ROUTINE
        PVOID ApcArgument1,
        PVOID ApcArgument2,
        PVOID ApcArgument3);
#ifdef __cplusplus
}
#endif