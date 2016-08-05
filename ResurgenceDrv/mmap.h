#pragma once


NTSTATUS RDrvInjectManualMap(
    __in PEPROCESS Process,
    __in PVOID ImageBuffer,
    __in ULONG ImageSize,
    __in BOOLEAN CallEntryPoint,
    __in ULONG_PTR CustomArg,
    __out PULONG_PTR ModuleBase
);