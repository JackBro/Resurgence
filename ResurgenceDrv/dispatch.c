#include "dispatch.h"
#include "internal.h"
#include "routines.h"

#pragma alloc_text(PAGE, RDrvDispatch)

NTSTATUS RDrvDispatch(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
{
    PIO_STACK_LOCATION ioStack;
    ULONG ioControlCode = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    ioStack = IoGetCurrentIrpStackLocation(Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    PVOID ioBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;

    if(!g_pDriverContext->Initialized) return (Irp->IoStatus.Status = STATUS_INTERNAL_ERROR);

    switch(ioStack->MajorFunction) {
        case IRP_MJ_DEVICE_CONTROL:
        {
            ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
            switch(ioControlCode) {
                case RESURGENCE_QUERY_OSVERSION:
                {
                    if(outputBufferLength == RESURGENCE_QUERY_OSVERSION_SIZE) {
                        VERSION_INFO info;
                        Irp->IoStatus.Status = RDrvQueryOSVersion(&info);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            RtlCopyMemory(ioBuffer, &info, RESURGENCE_QUERY_OSVERSION_SIZE);
                            Irp->IoStatus.Information = RESURGENCE_QUERY_OSVERSION_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_VM_OPERATION:
                {
                    if(inputBufferLength == RESURGENCE_VM_OPERATION_SIZE &&
                        outputBufferLength == RESURGENCE_VM_OPERATION_SIZE) {
                        Irp->IoStatus.Status = RDrvVirtualMemoryOperation((PVM_OPERATION)ioBuffer);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_VM_OPERATION_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_VM_READ:
                {
                    if(inputBufferLength == RESURGENCE_VM_READ_SIZE &&
                        outputBufferLength == RESURGENCE_VM_READ_SIZE) {
                        Irp->IoStatus.Status = RDrvReadWriteVirtualMemory((PVM_READ_WRITE)ioBuffer, FALSE);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_VM_READ_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_VM_WRITE:
                {
                    if(inputBufferLength == RESURGENCE_VM_WRITE_SIZE &&
                        outputBufferLength == RESURGENCE_VM_WRITE_SIZE) {
                        Irp->IoStatus.Status = RDrvReadWriteVirtualMemory((PVM_READ_WRITE)ioBuffer, TRUE);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_VM_WRITE_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_VM_QUERY:
                {
                    if(inputBufferLength == RESURGENCE_VM_QUERY_SIZE &&
                        outputBufferLength == RESURGENCE_VM_QUERY_SIZE) {
                        Irp->IoStatus.Status = RDrvQueyVirtualMemory((PVM_QUERY_INFO)ioBuffer);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_VM_QUERY_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_GRANT_ACCESS:
                {
                    if(inputBufferLength == RESURGENCE_GRANT_ACCESS_SIZE &&
                        outputBufferLength == RESURGENCE_GRANT_ACCESS_SIZE) {
                        Irp->IoStatus.Status = RDrvGrantHandleAccess((PGRANT_ACCESS)ioBuffer);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_VM_QUERY_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_PROTECT_PROCESS:
                {
                    if(inputBufferLength == RESURGENCE_PROTECT_PROCESS_SIZE) {
                        Irp->IoStatus.Status = RDrvProtectProcess((PPROTECT_PROCESS)ioBuffer);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_PROTECT_PROCESS_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_OPEN_PROCESS:
                {
                    if(inputBufferLength == RESURGENCE_OPEN_PROCESS_SIZE &&
                        outputBufferLength == RESURGENCE_OPEN_PROCESS_SIZE) {
                        Irp->IoStatus.Status = RDrvOpenProcess((POPEN_PROCESS)ioBuffer);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_OPEN_PROCESS_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_SET_DEP_STATE:
                {
                    if(inputBufferLength == RESURGENCE_SET_DEP_STATE_SIZE) {
                        Irp->IoStatus.Status = RDrvSetProcessDEP((PSET_DEP_STATE)ioBuffer);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_PROTECT_PROCESS_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                case RESURGENCE_INJECT_MODULE:
                {
                    if(inputBufferLength == RESURGENCE_INJECT_MODULE_SIZE &&
                        outputBufferLength == RESURGENCE_INJECT_MODULE_SIZE) {
                        Irp->IoStatus.Status = RDrvInjectModule((PINJECT_MODULE)ioBuffer);
                        if(NT_SUCCESS(Irp->IoStatus.Status)) {
                            Irp->IoStatus.Information = RESURGENCE_INJECT_MODULE_SIZE;
                        }
                    } else {
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                    }
                    break;
                }
                default:
                    DPRINT("Unknown IRP_MJ_DEVICE_CONTROL 0x%X", ioControlCode);
                    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    break;
            }
            break;
        }
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            Irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        default:
            Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
            break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Irp->IoStatus.Status;
}
