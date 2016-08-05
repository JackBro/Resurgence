#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include "native_enums.h"
#include "native_structs.h"
#include "kernel_imports.h"
#include "zw_imports.h"

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED        0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH      0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER      0x00000004

typedef NTSTATUS(NTAPI* tNtTerminateThread)(__in HANDLE ThreadHandle, __in NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI* tNtCreateThreadEx)
(
    __out PHANDLE hThread,
    __in ACCESS_MASK DesiredAccess,
    __in PVOID ObjectAttributes,
    __in HANDLE ProcessHandle,
    __in PVOID lpStartAddress,
    __in PVOID lpParameter,
    __in ULONG Flags,
    __in SIZE_T StackZeroBits,
    __in SIZE_T SizeOfStackCommit,
    __in SIZE_T SizeOfStackReserve,
    __out PVOID lpBytesBuffer
);

typedef NTSTATUS(NTAPI* tNtQueryPerformanceCounter)(
        __out PLARGE_INTEGER PerformanceCounter,
        __out_opt PLARGE_INTEGER PerformanceFrequency
    );

#if defined(_WIN8_) || defined (_WIN7_)

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)
(
    __in HANDLE ProcessHandle,
    __in PVOID* BaseAddress,
    __in SIZE_T* NumberOfBytesToProtect,
    __in ULONG NewAccessProtection,
    __out PULONG OldAccessProtection
    );

NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    __in HANDLE ProcessHandle,
    __in PVOID* BaseAddress,
    __in SIZE_T* NumberOfBytesToProtect,
    __in ULONG NewAccessProtection,
    __out PULONG OldAccessProtection
);


#else
NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    __in HANDLE ProcessHandle,
    __in PVOID* BaseAddress,
    __in SIZE_T* NumberOfBytesToProtect,
    __in ULONG NewAccessProtection,
    __out PULONG OldAccessProtection
);

#endif

NTSTATUS
NTAPI
ZwCreateThreadEx(
    __out PHANDLE hThread,
    __in ACCESS_MASK DesiredAccess,
    __in PVOID ObjectAttributes,
    __in HANDLE ProcessHandle,
    __in PVOID lpStartAddress,
    __in PVOID lpParameter,
    __in ULONG Flags,
    __in SIZE_T StackZeroBits,
    __in SIZE_T SizeOfStackCommit,
    __in SIZE_T SizeOfStackReserve,
    __in PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
);

NTSTATUS
NTAPI
ZwTerminateThread(
    __in HANDLE ThreadHandle,
    __in NTSTATUS ExitStatus
);

NTSTATUS
NTAPI
ZwQueryPerformanceCounter(
    __out PLARGE_INTEGER PerformanceCounter,
    __out_opt PLARGE_INTEGER PerformanceFrequency
);