#include "internal.h"
#include "dispatch.h"
#include "routines.h"

PDRIVER_CONTEXT g_pDriverContext = NULL;
PIMAGE_MAP_DATA g_pImageData = NULL;
BOOLEAN         g_bLoadedByTDL;

NTSTATUS DriverEntry(
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
);

NTSTATUS InitializeDriver(
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
);

NTSTATUS DriverContextInit(
    VOID
);

NTSTATUS DriverLoadDynamicData(
    VOID
);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, InitializeDriver)
#pragma alloc_text(PAGE, DriverContextInit)
#pragma alloc_text(PAGE, DriverLoadDynamicData)

/// <summary>
///     Defines the driver entry point
/// </summary>
/// <param name="DriverObject">
///     A pointer to a DRIVER_OBJECT structure. This is the driver's driver object.
/// </param>
/// <param name="RegistryPath">
///     A pointer to a counted Unicode string specifying the path to the driver's registry key.
/// </param>
/// <returns>The status code</returns>
NTSTATUS DriverEntry(
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        status = STATUS_SUCCESS;
    UNICODE_STRING  drvName;

    DPRINT("DriverEntry called!");

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    if(DriverObject != NULL){

        //
        // Magic matches. It was mapped by the TDL shellcode
        //
        if(((PIMAGE_MAP_DATA)DriverObject)->Magic == 0xFF00FF00AABBCCDD) { 
            DPRINT("Creating DriverObject!");
            //
            //Extract the image data that is sent as the first parameter to DriverEntry by the TDL shellcode
            //
            g_pImageData = (PIMAGE_MAP_DATA)DriverObject;
            g_bLoadedByTDL = TRUE;
            RtlInitUnicodeString(&drvName, L"\\Driver\\" RDRV_DRIVER_NAME);
            status = IoCreateDriver(&drvName, &InitializeDriver);
            if(!NT_SUCCESS(status)) {
                DPRINT("IoCreateDriver failed with status %lX", status);
            }
        } 
        //
        // Magic is different. It wasnt mapped by TDL. Do regular initialization
        //
        else {
            g_bLoadedByTDL = FALSE;
            status = InitializeDriver(DriverObject, RegistryPath);
            if(!NT_SUCCESS(status)) {
                DPRINT("InitializeDriver failed with status %lX", status);
            }
        }
    }
    return status;
}

NTSTATUS InitializeDriver(
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        status = STATUS_SUCCESS;
    UNICODE_STRING  usDosDeviceName, usDeviceName;
    PDEVICE_OBJECT  pDevObj = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);
    DPRINT("Initializing driver!", status);
    
    RtlInitUnicodeString(&usDeviceName, RDRV_DEVICE_NAME);
    RtlInitUnicodeString(&usDosDeviceName, RDRV_DOSDEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        sizeof(DRIVER_CONTEXT),
        &usDeviceName,
        RDRV_DEV_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE, &pDevObj);

    if(!NT_SUCCESS(status)) {
        DPRINT("IoCreateDevice failed with status %lX", status);
        return status;
    }

    g_pDriverContext = (PDRIVER_CONTEXT)pDevObj->DeviceExtension;
    RtlZeroMemory(g_pDriverContext, sizeof(DRIVER_CONTEXT));

    status = IoCreateSymbolicLink(&usDosDeviceName, &usDeviceName);

    if(!NT_SUCCESS(status)) {
        DPRINT("IoCreateSymbolicLink failed with status %lX", status);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &RDrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = &RDrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &RDrvDispatch;
    DriverObject->DriverUnload = NULL;

    if(g_bLoadedByTDL) {
        RtlCopyMemory(&g_pDriverContext->ImageData, g_pImageData, sizeof(IMAGE_MAP_DATA));
        ExFreePoolWithTag((PVOID)g_pImageData, 'SldT');
    } else {
        g_pDriverContext->ImageData.ImageBase = (ULONG_PTR)DriverObject->DriverStart;
        g_pDriverContext->ImageData.SizeOfImage = DriverObject->DriverSize;
    }

    status = DriverLoadDynamicData();

    if(!NT_SUCCESS(status)) {
        DPRINT("DriverLoadDynamicData failed with status %lX!", status);
        return status;
    }

    status = DriverContextInit();

    if(!NT_SUCCESS(status)) {
        DPRINT("DriverContextInit failed with status %lX!", status);
        return status;
    }

    pDevObj->Flags |= IO_TYPE;
    pDevObj->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT("Initialization completed!");
    return status;
}

NTSTATUS DriverContextInit(
    VOID
)
{
    ULONG_PTR KernelBase;
    NTSTATUS status = RDrvGetKernelInfo(&KernelBase, NULL);
    if(!NT_SUCCESS(status)) {
        DPRINT("RDrvGetKernelInfo failed with status %lX", status);
        return status;
    }

#ifdef _WIN10_
    CONST UCHAR Pattern_RtlInsertInvertedTable[] = "\x48\x89\x5C\x24\x00\x55\x56\x57\x48\x83\xEC\x30\x8B\xF2";
    CONST UCHAR Mask_RtlInsertInvertedTable[] = "xxxx?xxxxxxxxx";
#endif 
    PUCHAR pResult;

    status = RDrvFindKernelPattern(
        Pattern_RtlInsertInvertedTable,
        Mask_RtlInsertInvertedTable,
        sizeof(Mask_RtlInsertInvertedTable) - 1,
        &pResult);

    if(!NT_SUCCESS(status)) {
        DPRINT("Failed to retrieve RtlInsertInvertedFunctionTable address!");
        return status;
    }

    g_pDriverContext->RtlInsertInvertedFunctionTable = (tRtlInsertInvertedFunctionTable)pResult;
    DPRINT("RtlInsertInvertedFunctionTable: 0x%p", g_pDriverContext->RtlInsertInvertedFunctionTable);

    //g_pDriverContext->RtlInsertInvertedFunctionTable(g_pDriverContext->ImageData.ImageBase, g_pDriverContext->ImageData.SizeOfImage);

    g_pDriverContext->Initialized = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS DriverLoadDynamicData(
    VOID
)
{
    VERSION_INFO version;
    NTSTATUS status = RDrvQueryOSVersion(&version);

    if(!NT_SUCCESS(status)) {
        PERROR("RDrvQueryOSVersion", status);
        return status;
    }

    switch(version.VersionLong) {
        case 0x0A000000: //Win10
            switch(version.BuildNumber) {
                default:
                    DPRINT("Build %d is not known. Values for build %d will be used instead.", version.BuildNumber, 10586);
                case 10586:
                {
                    PDYNAMIC_DATA data = &g_pDriverContext->DynData;
                    data->TargetBuildNumber                     = 10586;
                    data->TargetVersion                         = version.VersionLong;
                    data->SSDTIndexes.CreateThreadEx            = 0x000000B4;
                    data->SSDTIndexes.TerminateThread           = 0x00000053;
                    data->SSDTIndexes.QueryPerformanceCounter   = 0x00000031;
                    data->SSDTIndexes.ProtectMemory             = 0x00000000;
                    data->Offsets.ExecuteOptions                = 0x000001BF;
                    data->Offsets.ObjectTable                   = 0x00000418;
                    data->Offsets.PreviousMode                  = 0x00000232;
                    data->Offsets.Protection                    = 0x000006B2;
                    break;
                }
            }
            break;
        default:
            status = STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}