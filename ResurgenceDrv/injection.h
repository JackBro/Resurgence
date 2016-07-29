#pragma once

NTSTATUS RDrvBuildWow64InjectStub(
    __in ULONG_PTR FnLdrLoadDll,
    __in PUNICODE_STRING ModulePath,
    __out PINJECTION_BUFFER* Buffer
);

NTSTATUS RDrvBuildNativeInjectStub(
    __in ULONG_PTR FnLdrLoadDll,
    __in PUNICODE_STRING ModulePath,
    __out PINJECTION_BUFFER* Buffer
);

NTSTATUS RDrvInjectLdrLoadDll(
    __in PEPROCESS Process,
    __in PWCHAR ModulePath,
    __out PULONG_PTR ModuleBase
);

NTSTATUS RDrvInjectManualMap(
    __in PEPROCESS Process,
    __in PWCHAR ModulePath,
    __in BOOLEAN CallEntryPoint,
    __in ULONG_PTR CustomArg,
    __out PULONG_PTR ModuleBase
);
