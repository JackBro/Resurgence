#include "routines.h"

#pragma alloc_text(PAGE, RDrvProtectProcess)
#pragma alloc_text(PAGE, RDrvOpenProcess)

NTSTATUS RDrvProtectProcess(
    __inout PPROTECT_PROCESS Params
)
{
    if(!Params) return STATUS_INVALID_PARAMETER;

    NTSTATUS    status;
    PEPROCESS   process = NULL;

    __try {
        status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);

        if(NT_SUCCESS(status)) {
        #ifdef _WIN10_
            PPS_PROTECTION psProtection = (PPS_PROTECTION)((PUCHAR)process + Off_EProcess_Protection);
            PPEB peb = PsGetProcessPeb(process);
            if(Params->In.ProtectionLevel == PROTECTION_NONE) {
                psProtection->Level = 0;
                peb->IsProtectedProcess = 0;
                peb->IsProtectedProcessLight = 0;
            } else if(Params->In.ProtectionLevel == PROTECTION_LIGHT) {
                psProtection->Flags.Signer = PsProtectedSignerWinTcb;
                psProtection->Flags.Type = PsProtectedTypeProtectedLight;
                peb->IsProtectedProcess = 1;
                peb->IsProtectedProcessLight = 1;
            } else if(Params->In.ProtectionLevel == PROTECTION_FULL) {
                psProtection->Flags.Signer = PsProtectedSignerWinTcb;
                psProtection->Flags.Type = PsProtectedTypeProtected;
                peb->IsProtectedProcess = 1;
                peb->IsProtectedProcessLight = 0;
            } else {
                DPRINT("Invalid ProtectionLevel: %d", Params->In.ProtectionLevel);
                status = STATUS_UNSUCCESSFUL;
            }
        #else
        #error "Unsupported"
        #endif
        } else {
            PERROR("PsLookupProcessByProcessId", status);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER)
    {
        PEXCEPTION();
        status = GetExceptionCode();
    }
    if(process != NULL)
        ObDereferenceObject(process);
    return status;
}

NTSTATUS RDrvOpenProcess(
    __inout POPEN_PROCESS Params
)
{
    if(!Params) return STATUS_INVALID_PARAMETER;

    NTSTATUS    status;
    PEPROCESS   process = NULL;
    PETHREAD    thread = NULL;
    HANDLE      handle = NULL;
    CLIENT_ID   clientId;
    __try {
        if(Params->In.ProcessId != 0) {
            status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);
        } else if(Params->In.ThreadId != 0) {
            clientId.UniqueProcess = 0;
            clientId.UniqueThread = (HANDLE)Params->In.ThreadId;
            status = PsLookupProcessThreadByCid(&clientId, &process, &thread);
            if(NT_SUCCESS(status)) {
                ObDereferenceObject(thread);
            }
        } else {
            status = STATUS_INVALID_CID;
        }
        if(NT_SUCCESS(status)) {
            status = ObOpenObjectByPointer(process, 0, NULL, Params->In.AccessMask, *PsProcessType, KernelMode, &handle);
            if(NT_SUCCESS(status) && handle != NULL) {
                Params->Out.Handle = (ULONG_PTR)handle;
            } else {
                PERROR("ObOpenObjectByPointer", status);
            }
        } else {
            PERROR("PsLookupProcessByProcessId/ThreadByCid", status);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER)
    {
        PEXCEPTION();
        status = GetExceptionCode();
    }
    if(process != NULL)
        ObDereferenceObject(process);
    return status;
}