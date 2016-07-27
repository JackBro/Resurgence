#include "routines.h"

#pragma alloc_text(PAGE, RDrvQueyVirtualMemory)
#pragma alloc_text(PAGE, RDrvVirtualMemoryOperation)
#pragma alloc_text(PAGE, RDrvReadWriteVirtualMemory)

NTSTATUS RDrvQueyVirtualMemory(
    __inout PVM_QUERY_INFO Params
)
{
    if(!Params) return STATUS_INVALID_PARAMETER;

    NTSTATUS                    status;
    KAPC_STATE                  apcState;
    BOOLEAN                     attached = FALSE;
    PEPROCESS                   process = NULL;
    MEMORY_BASIC_INFORMATION    memoryInfo;
    SIZE_T                      cbNeeded = 0;

    __try {
        status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);
        if(NT_SUCCESS(status)) {
            if(process != PsGetCurrentProcess()) {
                KeStackAttachProcess(process, &apcState);
                attached = TRUE;
            }
            status = ZwQueryVirtualMemory(
                ZwCurrentProcess(),
                (PVOID)Params->In.BaseAddress,
                MemoryBasicInformation, &memoryInfo,
                sizeof(memoryInfo), &cbNeeded);
            if(NT_SUCCESS(status)) {
                RtlCopyMemory((PVOID)&Params->Out, (PVOID)&memoryInfo, sizeof(memoryInfo));
            } else {
                PERROR("ZwQueryVirtualMemory", status);
            }
        } else {
            PERROR("PsLookupProcessByProcessId", status);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER)
    {
        PEXCEPTION();
        status = GetExceptionCode();
    }
    if(attached == TRUE)
        KeUnstackDetachProcess(&apcState);
    if(process != NULL)
        ObDereferenceObject(process);
    return status;
}

NTSTATUS RDrvVirtualMemoryOperation(
    __inout PVM_OPERATION Params
)
{
    if(!Params) return STATUS_INVALID_PARAMETER;

    NTSTATUS    status = STATUS_SUCCESS;
    KAPC_STATE  apcState;
    PEPROCESS   process = NULL;
    BOOLEAN     attached = FALSE;
    ULONG       proccessId = Params->In.ProcessId;
    ULONG_PTR   baseAddress = Params->In.BaseAddress;
    ULONG       allocationFlags = Params->In.AllocationFlags;
    ULONG       protectionFlags = Params->In.ProtectionFlags;
    SIZE_T      regionSize = Params->In.RegionSize;
    ULONG       freeType = Params->In.FreeType;
    __try {
        status = PsLookupProcessByProcessId((HANDLE)proccessId, &process);
        if(NT_SUCCESS(status)) {
            if(process != PsGetCurrentProcess()) {
                KeStackAttachProcess(process, &apcState);
                attached = TRUE;
            }

            switch(Params->In.Operation) {
                case VM_OPERATION_ALLOC:
                {
                    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&baseAddress, 0, &regionSize, allocationFlags, protectionFlags);
                    if(NT_SUCCESS(status)) {
                        Params->Out.BaseAddress = baseAddress;
                        Params->Out.RegionSize = regionSize;
                    } else {
                        PERROR("ZwAllocateVirtualMemory", status);
                    }
                    break;
                }
                case VM_OPERATION_FREE:
                {
                    status = ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)&baseAddress, &regionSize, freeType);
                    if(NT_SUCCESS(status)) {
                        Params->Out.BaseAddress = baseAddress;
                        Params->Out.RegionSize = regionSize;
                    } else {
                        PERROR("ZwFreeVirtualMemory", status);
                    }
                    break;
                }
                case VM_OPERATION_PROTECT:
                {
                    ULONG oldProt;
                    status = ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID*)&baseAddress, &regionSize, protectionFlags, &oldProt);
                    if(NT_SUCCESS(status)) {
                        Params->Out.BaseAddress = baseAddress;
                        Params->Out.RegionSize = regionSize;
                        Params->Out.OldProtection = oldProt;
                    } else {
                        PERROR("ZwProtectVirtualMemory", status);
                    }
                    break;
                }
                default:
                    status = STATUS_INVALID_PARAMETER;
                    break;
            }
        } else {
            PERROR("PsLookupProcessByProcessId", status);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER)
    {
        PEXCEPTION();
        status = GetExceptionCode();
    }
    if(attached == TRUE)
        KeUnstackDetachProcess(&apcState);
    if(process != NULL)
        ObDereferenceObject(process);
    return status;
}

NTSTATUS RDrvReadWriteVirtualMemory(
    __inout PVM_READ_WRITE Params,
    __in BOOLEAN Write
)
{
    NTSTATUS    status;
    PEPROCESS   fromProcess;
    ULONG_PTR   fromAddress;
    PEPROCESS   toProcess;
    ULONG_PTR   toAddress;
    SIZE_T      bytesCopied;

    if(Write == TRUE) {
        fromAddress = Params->Buffer;
        fromProcess = PsGetCurrentProcess();
        toAddress = Params->TargetAddress;
        status = PsLookupProcessByProcessId((HANDLE)Params->ProcessId, &toProcess);
    } else {
        fromAddress = Params->TargetAddress;
        status = PsLookupProcessByProcessId((HANDLE)Params->ProcessId, &fromProcess);
        toAddress = Params->Buffer;
        toProcess = PsGetCurrentProcess();
    }
    __try {
        if(NT_SUCCESS(status)) {
            status = MmCopyVirtualMemory(
                fromProcess, (PVOID)fromAddress,
                toProcess, (PVOID)toAddress,
                Params->BufferSize,
                KernelMode,
                &bytesCopied);
            if(!NT_SUCCESS(status))
                PERROR("MmCopyVirtualMemory", status);
        } else {
            PERROR("PsLookupProcessByProcessId", status);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER)
    {
        PEXCEPTION();
        status = GetExceptionCode();
    }
    if(Write == TRUE) {
        if(toProcess != NULL)
            ObDereferenceObject(toProcess);
    } else {
        if(fromProcess != NULL)
            ObDereferenceObject(fromProcess);
    }
    return status;
}

