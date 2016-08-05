#include "internal.h"
#include "dispatch.h"
#include "routines.h"

PDRIVER_CONTEXT g_pDriverContext = NULL;
PIMAGE_MAP_DATA g_pImageData;

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

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, InitializeDriver)
#pragma alloc_text(PAGE, DriverContextInit)

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
    NTSTATUS status = STATUS_SUCCESS;
    DPRINT("DriverEntry called!");

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    if(DriverObject != NULL && ((PIMAGE_MAP_DATA)DriverObject)->Magic == 0xFF00FF00AABBCCDD) {
        DPRINT("Creating DriverObject!");
        //
        //Extract the image data that is sent as the first parameter to DriverEntry by the TDL shellcode
        //
        g_pImageData = (PIMAGE_MAP_DATA)DriverObject;
        UNICODE_STRING  drvName;
        RtlInitUnicodeString(&drvName, L"\\Driver\\" RDRV_DRIVER_NAME);
        status = IoCreateDriver(&drvName, &InitializeDriver);
        if(NT_ERROR(status)) {
            DPRINT("IoCreateDriver failed with status %lX", status);
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

    VERSION_INFO version;
    if(NT_SUCCESS(RDrvQueryOSVersion(&version))) {
        if(version.VersionLong != TARGET_WINVER) {
            DPRINT("OS UNSUPPORTED %X. Target: %X", version.VersionLong, TARGET_WINVER);
            return STATUS_NOT_SUPPORTED;
        }
    }

    RtlInitUnicodeString(&usDeviceName, RDRV_DEVICE_NAME);
    RtlInitUnicodeString(&usDosDeviceName, RDRV_DOSDEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        sizeof(DRIVER_CONTEXT),
        &usDeviceName,
        RDRV_DEV_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE, &pDevObj);

    if(NT_ERROR(status)) {
        DPRINT("IoCreateDevice failed with status %lX", status);
        return status;
    }

    g_pDriverContext = (PDRIVER_CONTEXT)pDevObj->DeviceExtension;
    RtlZeroMemory(g_pDriverContext, sizeof(DRIVER_CONTEXT));

    status = IoCreateSymbolicLink(&usDosDeviceName, &usDeviceName);

    if(NT_ERROR(status)) {
        DPRINT("IoCreateSymbolicLink failed with status %lX", status);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &RDrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = &RDrvDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &RDrvDispatch;
    DriverObject->DriverUnload = NULL;

    RtlCopyMemory(&g_pDriverContext->ImageData, g_pImageData, sizeof(IMAGE_MAP_DATA));
    ExFreePoolWithTag((PVOID)g_pImageData, 'SldT');

    status = DriverContextInit();

    if(NT_ERROR(status)) {
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
    if(NT_ERROR(status)) {
        DPRINT("RDrvGetKernelInfo failed with status %lX", status);
        return status;
    }

#ifdef _WIN10_
    CONST UCHAR Pattern_RtlInsertInvertedTable[] = "\x48\x89\x5C\x24\x00\x55\x56\x57\x48\x83\xEC\x30\x8B\xF2";
    CONST UCHAR Mask_RtlInsertInvertedTable[] = "xxxx?xxxxxxxxx";

    //nt!IopWriteDriverList+0x24
    CONST UCHAR Pattern_PsLoadedModuleList[] = "\x48\x8B\x1D\x00\x00\x00\x00\x4C\x8D\x2D\x00\x00\x00\x00\x45\x33\xE4";
    CONST UCHAR Mask_PsLoadedModuleList[]    = "xxx????xxx????xxx";
    CONST ULONG Offset_PsLoadedModuleList    = 3;
    CONST ULONG Offset_PsLoadedModuleList2   = 7;
#endif 
    PUCHAR pResult;

    status = RDrvFindKernelPattern(
        Pattern_PsLoadedModuleList,
        Mask_PsLoadedModuleList,
        sizeof(Mask_PsLoadedModuleList) - 1,
        &pResult);

    if(NT_ERROR(status)) {
        DPRINT("Failed to retrieve PsLoadedModuleList address!");
        return status;
    }
        
    g_pDriverContext->PsLoadedModuleList = (PLIST_ENTRY)(pResult + *(PULONG)(pResult + Offset_PsLoadedModuleList) + Offset_PsLoadedModuleList2);

    DPRINT("PsLoadedModuleList: 0x%p", g_pDriverContext->PsLoadedModuleList);

    status = RDrvFindKernelPattern(
        Pattern_RtlInsertInvertedTable,
        Mask_RtlInsertInvertedTable,
        sizeof(Mask_RtlInsertInvertedTable) - 1,
        &pResult);

    if(NT_ERROR(status)) {
        DPRINT("Failed to retrieve RtlInsertInvertedFunctionTable address!");
        return status;
    }

    g_pDriverContext->RtlInsertInvertedFunctionTable = (tRtlInsertInvertedFunctionTable)pResult;
    DPRINT("RtlInsertInvertedFunctionTable: 0x%p", g_pDriverContext->RtlInsertInvertedFunctionTable);

    //g_pDriverContext->RtlInsertInvertedFunctionTable(
    //    g_pDriverContext->ImageData.ImageBase, 
    //    g_pDriverContext->ImageData.SizeOfImage);

    g_pDriverContext->Initialized = TRUE;

    return STATUS_SUCCESS;
}