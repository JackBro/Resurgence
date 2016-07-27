#pragma once

NTKERNELAPI
NTSTATUS 
IoCreateDriver(
    __in PUNICODE_STRING DriverName,
    __in PDRIVER_INITIALIZE InitializationFunction
    );

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    __in PEPROCESS FromProcess,
    __in PVOID FromAddress,
    __in PEPROCESS ToProcess,
    __out PVOID ToAddress,
    __in SIZE_T BufferSize,
    __in KPROCESSOR_MODE PreviousMode,
    __out PSIZE_T NumberOfBytesCopied
    );

NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(
    __in PEPROCESS Process
);

NTKERNELAPI
PVOID
NTAPI
PsGetThreadTeb(
    __in PETHREAD Thread
);

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
    __in PEPROCESS Process
);

NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(
    __in KPROCESSOR_MODE AlertMode
);

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(
    __in PEPROCESS Process
);

NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessThreadByCid(
    __in PCLIENT_ID ClientId,
    __out_opt PEPROCESS *Process,
    __out PETHREAD *Thread
);

NTKERNELAPI
PVOID
NTAPI
PsGetThreadWin32Thread(
    __in PETHREAD Thread
);

typedef VOID(NTAPI *PKNORMAL_ROUTINE)
(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
    );

typedef VOID(NTAPI* PKKERNEL_ROUTINE)
(
    PRKAPC Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2
    );

typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(PRKAPC Apc);

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
    __in PKAPC Apc,
    __in PKTHREAD Thread,
    __in KAPC_ENVIRONMENT ApcStateIndex,
    __in PKKERNEL_ROUTINE KernelRoutine,
    __in PKRUNDOWN_ROUTINE RundownRoutine,
    __in PKNORMAL_ROUTINE NormalRoutine,
    __in KPROCESSOR_MODE ApcMode,
    __in PVOID NormalContext
    );

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
    PKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
    );

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    __in PVOID Base
);

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    PVOID ImageBase,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size
    );