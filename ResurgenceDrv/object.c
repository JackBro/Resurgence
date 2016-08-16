#include "routines.h"
#include "internal.h"

#pragma alloc_text(PAGE, RDrvGrantHandleAccess)

NTSTATUS RDrvGrantHandleAccess(
    __inout PGRANT_ACCESS Params
)
{
    if(!Params) return STATUS_INVALID_PARAMETER;

    NTSTATUS    status;
    PEPROCESS   process = NULL;

    __try {
        status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);

        if(succeeded(status)) {
            PHANDLE_TABLE objTable = *(PHANDLE_TABLE*)((PUCHAR)process + g_pDriverContext->DynData.Offsets.ObjectTable);
            EXHANDLE exHandle; exHandle.Value = Params->In.Handle;
            PHANDLE_TABLE_ENTRY handleEntry = ExpLookupHandleTableEntry(objTable, exHandle);
            if(ExpIsValidObjectEntry(handleEntry)) {
                Params->Out.OldAccessMask = handleEntry->GrantedAccessBits;
                handleEntry->GrantedAccessBits = Params->In.AccessMask;
            } else {
                DPRINT("Invalid handle: %p", Params->In.Handle);
                status = STATUS_UNSUCCESSFUL;
            }
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
