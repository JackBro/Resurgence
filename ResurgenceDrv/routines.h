#pragma once

#include "internal.h"

NTSTATUS RDrvQueryOSVersion(
    __out PVERSION_INFO Version
);

NTSTATUS RDrvQueyVirtualMemory(
    __inout PVM_QUERY_INFO Params
);

NTSTATUS RDrvVirtualMemoryOperation(
    __inout PVM_OPERATION Params
);

NTSTATUS RDrvReadWriteVirtualMemory(
    __inout PVM_READ_WRITE Params,
    __in BOOLEAN Write
);

NTSTATUS RDrvGrantHandleAccess(
    __inout PGRANT_ACCESS Params
);

NTSTATUS RDrvProtectProcess(
    __in PPROTECT_PROCESS Params
);

NTSTATUS RDrvOpenProcess(
    __inout POPEN_PROCESS Params
); 

NTSTATUS RDrvSetProcessDEP(
    __in PSET_DEP_STATE Params
);

NTSTATUS RDrvOpenThread(
    __inout POPEN_THREAD Params
);

NTSTATUS RDrvInjectModule(
    __inout PINJECT_MODULE Params
);