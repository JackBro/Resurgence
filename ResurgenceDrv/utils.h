#pragma once

NTSTATUS RDrvLogToFile(
    __in LPCSTR Format,
    __in_opt ...
);

NTSTATUS RDrvOpenFile(
    __in LPCWSTR FilePath,
    __in BOOLEAN Write,
    __in BOOLEAN Append,
    __out PHANDLE Handle
);

NTSTATUS RDrvWriteToFile(
    __in HANDLE Handle,
    __in LPCSTR Format,
    __in_opt ...
);

NTSTATUS RDrvGetModuleContainingAddress(
    __in ULONG_PTR Address,
    __out PULONG_PTR BaseAddress,
    __out PSIZE_T Size
);

NTSTATUS RDrvGetKernelInfo(
    __out_opt PULONG_PTR BaseAddress,
    __out_opt PSIZE_T Size
);

NTSTATUS RDrvFindPattern(
    __in ULONG_PTR BaseAddress,
    __in SIZE_T Size,
    __in PCUCHAR Pattern,
    __in PCUCHAR Mask,
    __in SIZE_T PatternSize,
    __inout PVOID* Result
);

NTSTATUS RDrvScanModule(
    __in ULONG_PTR BaseAddress,
    __in PCUCHAR Pattern,
    __in PCUCHAR Mask,
    __in SIZE_T PatternSize,
    __inout PVOID* Result
);

NTSTATUS RDrvSleep(
    __in LONG ms
);

NTSTATUS RDrvGetModuleEntry(
    __in PEPROCESS Process,
    __in LPCWSTR ModuleName,
    __out PLDR_DATA_TABLE_ENTRY* LdrEntry
);

NTSTATUS RDrvGetModuleEntry32(
    __in  PEPROCESS Process,
    __in  LPCWSTR ModuleName,
    __out PLDR_DATA_TABLE_ENTRY32* LdrEntry
);