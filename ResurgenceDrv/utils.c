#include "internal.h"
#include "utils.h"

#pragma alloc_text(PAGE, RDrvLogToFile)
#pragma alloc_text(PAGE, RDrvOpenFile)
#pragma alloc_text(PAGE, RDrvWriteToFile)
#pragma alloc_text(PAGE, RDrvGetModuleContainingAddress)
#pragma alloc_text(PAGE, RDrvGetKernelInfo)
#pragma alloc_text(PAGE, RDrvFindPattern)
#pragma alloc_text(PAGE, RDrvScanModule)
#pragma alloc_text(PAGE, RDrvSleep)
#pragma alloc_text(PAGE, RDrvGetModuleEntry)
#pragma alloc_text(PAGE, RDrvGetModuleEntry32)

NTSTATUS RDrvLogToFile(
    __in LPCSTR Format,
    __in_opt ...
)
{
    IO_STATUS_BLOCK     ioStatus;
    HANDLE              hFile;

    if(NT_SUCCESS(RDrvOpenFile(L"\\SystemRoot\\Temp\\Resurgence.log", TRUE, TRUE, &hFile))) {

        CHAR buffer[512];
        RtlZeroMemory(buffer, 512);
        va_list va;
        va_start(va, Format);
        RtlStringCbVPrintfA(buffer, 512, Format, va);
        va_end(va);

        RDrvWriteToFile(hFile, buffer);

        ZwFlushBuffersFile(hFile, &ioStatus);
        ZwClose(hFile);
        return STATUS_SUCCESS;
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS RDrvOpenFile(
    __in LPCWSTR FilePath,
    __in BOOLEAN Write,
    __in BOOLEAN Append,
    __out PHANDLE Handle
)
{
    UNICODE_STRING      wzFilePath;
    OBJECT_ATTRIBUTES   objAttributes;
    IO_STATUS_BLOCK     ioStatus;
    RtlInitUnicodeString(&wzFilePath, FilePath);
    InitializeObjectAttributes(&objAttributes, &wzFilePath, OBJ_KERNEL_HANDLE, NULL, NULL);

    ACCESS_MASK mask = SYNCHRONIZE;

    mask |= Write ? (Append ? FILE_APPEND_DATA : FILE_WRITE_DATA) : FILE_READ_DATA;

    return ZwCreateFile(Handle,
        mask,
        &objAttributes, &ioStatus,
        NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

NTSTATUS RDrvWriteToFile(
    __in HANDLE Handle,
    __in LPCSTR Format,
    __in_opt ...
)
{
    IO_STATUS_BLOCK ioStatus;
    CHAR buffer[1024];
    RtlZeroMemory(buffer, 1024);
    va_list va;
    va_start(va, Format);
    RtlStringCbVPrintfA(buffer, 1024, Format, va);
    va_end(va);

    size_t cb;
    RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
    return ZwWriteFile(Handle, NULL, NULL, NULL, &ioStatus, buffer, (ULONG)cb, NULL, NULL);
}

NTSTATUS RDrvGetModuleContainingAddress(
    __in ULONG_PTR Address,
    __out PULONG_PTR BaseAddress,
    __out PSIZE_T Size
)
{
    NTSTATUS    status = STATUS_SUCCESS;
    ULONG       nRequiredSize = 0;

    if(!Address) return STATUS_INVALID_PARAMETER;
    if(!BaseAddress) return STATUS_INVALID_PARAMETER;
    if(!Size) return STATUS_INVALID_PARAMETER;

    status = ZwQuerySystemInformation(SystemModuleInformation, 0, nRequiredSize, &nRequiredSize);

    if(nRequiredSize == 0) {
        DPRINT("ZwQuerySystemInformation failed. Invalid size!");
        return STATUS_UNSUCCESSFUL;
    }

    PRTL_PROCESS_MODULES systemModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool,
        nRequiredSize,
        RDRV_POOLTAG);

    if(systemModules == NULL) {
        DPRINT("ExAllocatePoolWithTag failed!");
        return STATUS_UNSUCCESSFUL;
    }
    RtlZeroMemory(systemModules, nRequiredSize);

    status = ZwQuerySystemInformation(SystemModuleInformation, systemModules, nRequiredSize, &nRequiredSize);

    if(NT_SUCCESS(status)) {
        status = STATUS_NOT_FOUND;
        for(ULONG i = 0; i < systemModules->NumberOfModules; i++) {
            ULONG_PTR base = (ULONG_PTR)systemModules->Modules[i].ImageBase;
            SIZE_T size = systemModules->Modules[i].ImageSize;
            if(Address >= base && Address < base + size) {
                *BaseAddress = base;
                *Size = size;
                status = STATUS_SUCCESS;
                break;
            }
        }
    } else {
        DPRINT("ZwQuerySystemInformation failed with status %lx!", status);
    }
    if(systemModules)
        ExFreePoolWithTag(systemModules, RDRV_POOLTAG);

    return status;
}

NTSTATUS RDrvGetKernelInfo(
    __out_opt PULONG_PTR BaseAddress,
    __out_opt PSIZE_T Size
)
{
    NTSTATUS status = STATUS_SUCCESS;

    //Already found
    if(g_pDriverContext->KrnlBase != 0) {
        if(BaseAddress)
            *BaseAddress = g_pDriverContext->KrnlBase;
        if(Size)
            *Size = g_pDriverContext->KrnlSize;
        return STATUS_SUCCESS;
    }

    UNICODE_STRING usPsGetProcessPeb;

    RtlInitUnicodeString(&usPsGetProcessPeb, L"PsGetProcessPeb");
    PVOID pFn = MmGetSystemRoutineAddress(&usPsGetProcessPeb);

    if(pFn == NULL) return STATUS_NOT_FOUND;

    status = RDrvGetModuleContainingAddress((ULONG_PTR)pFn, &g_pDriverContext->KrnlBase, &g_pDriverContext->KrnlSize);

    if(NT_SUCCESS(status)) {
        if(BaseAddress)
            *BaseAddress = g_pDriverContext->KrnlBase;
        if(Size)
            *Size = g_pDriverContext->KrnlSize;
    }
    return status;
}

NTSTATUS RDrvFindPattern(
    __in ULONG_PTR BaseAddress,
    __in SIZE_T Size,
    __in PCUCHAR Pattern,
    __in PCUCHAR Mask,
    __in SIZE_T PatternSize,
    __inout PVOID* Result
)
{
    if(!BaseAddress || !Size || !Pattern || !Mask || !Result)
        return STATUS_INVALID_PARAMETER;

    __try {
        PCUCHAR address = (PCUCHAR)BaseAddress;
        PCUCHAR endAddress = (PCUCHAR)BaseAddress + Size - PatternSize;

        while(address < endAddress) {
            BOOLEAN found = TRUE;
            for(SIZE_T i = 0; i < PatternSize; i++) {
                if(Mask[i] != '?' && Pattern[i] != *(address + i)) {
                    found = FALSE;
                    break;
                }
            }
            if(found == TRUE) {
                *Result = (PVOID)address;
                return STATUS_SUCCESS;
            }
            address++;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        PEXCEPTION();
        return GetExceptionCode();
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS RDrvScanModule(
    __in ULONG_PTR BaseAddress,
    __in PCUCHAR Pattern,
    __in PCUCHAR Mask,
    __in SIZE_T PatternSize,
    __inout PVOID* Result
)
{
    if(!BaseAddress) return STATUS_INVALID_PARAMETER;
    if(!Pattern) return STATUS_INVALID_PARAMETER;
    if(!Mask) return STATUS_INVALID_PARAMETER;
    if(!Result) return STATUS_INVALID_PARAMETER;

    PIMAGE_NT_HEADERS ntHdrs = RtlImageNtHeader((PVOID)BaseAddress);
    PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)(ntHdrs + 1);
    for(PIMAGE_SECTION_HEADER section = firstSection;
        section < firstSection + ntHdrs->FileHeader.NumberOfSections;
        section++) 
    {
        if(section->Characteristics & IMAGE_SCN_MEM_NOT_PAGED && 
            section->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            !(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
            (*(PULONG)section->Name != 'TINI') && (*(PULONG)section->Name != 'EGAP')) 
        {
            NTSTATUS status = RDrvFindPattern(
                g_pDriverContext->KrnlBase + section->VirtualAddress,
                section->Misc.VirtualSize,
                Pattern,
                Mask,
                PatternSize,
                Result);
            return status;
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS RDrvSleep(
    __in LONG ms
)
{
    LARGE_INTEGER waitTime = {0};
    waitTime.QuadPart = ((LONGLONG)-ms * 1000 * 1000);
    return KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
}

NTSTATUS RDrvGetModuleEntry(
    __in PEPROCESS Process,
    __in LPCWSTR ModuleName,
    __out PLDR_DATA_TABLE_ENTRY* LdrEntry
)
{
    if(!Process) return STATUS_INVALID_PARAMETER_1;
    //if(!ModuleName) return STATUS_INVALID_PARAMETER_2;
    if(!LdrEntry) return STATUS_INVALID_PARAMETER_3;

    BOOLEAN returnFirstModule = !ModuleName;
    INT waitCount = 0;
    PPEB peb = PsGetProcessPeb(Process);
    if(!peb) {
        DPRINT("PsGetProcessPeb failed");
        return STATUS_UNSUCCESSFUL;
    }

    PPEB_LDR_DATA ldr = peb->Ldr;

    if(!ldr) {
        DPRINT("peb->Ldr is invalid");
        return STATUS_UNSUCCESSFUL;
    }

    if(!ldr->Initialized) {
        while(!ldr->Initialized && waitCount++ < 4)
            RDrvSleep(250);

        if(!ldr->Initialized) {
            DPRINT("ldr->Initialized is 0");
            return STATUS_UNSUCCESSFUL;
        }
    }

    for(PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->InLoadOrderModuleList.Flink;
        listEntry != &ldr->InLoadOrderModuleList; //Stop when it reaches the beginning again
        listEntry = (PLIST_ENTRY)listEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if(returnFirstModule) {
            *LdrEntry = ldrEntry;
            return STATUS_SUCCESS;
        } else {
            if(RtlCompareMemory(ldrEntry->BaseDllName.Buffer, ModuleName, ldrEntry->BaseDllName.Length) == ldrEntry->BaseDllName.Length) {
                *LdrEntry = ldrEntry;
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS RDrvGetModuleEntry32(
    __in PEPROCESS Process,
    __in LPCWSTR ModuleName,
    __out PLDR_DATA_TABLE_ENTRY32* LdrEntry
)
{
    if(!Process) return STATUS_INVALID_PARAMETER_1;
    //if(!ModuleName) return STATUS_INVALID_PARAMETER_2;
    if(!LdrEntry) return STATUS_INVALID_PARAMETER_3;

    BOOLEAN returnFirstModule = !ModuleName;
    PPEB32 wow64Peb = (PPEB32)PsGetProcessWow64Process(Process);
    INT waitCount = 0;
    if(wow64Peb != NULL) {
        PPEB_LDR_DATA32 ldr = (PPEB_LDR_DATA32)wow64Peb->Ldr;

        if(!ldr) {
            DPRINT("wow64Peb->Ldr is invalid");
            return STATUS_UNSUCCESSFUL;
        }

        if(!ldr->Initialized) {
            while(!ldr->Initialized && waitCount++ < 4)
                RDrvSleep(250);

            if(!ldr->Initialized) {
                DPRINT("ldr->Initialized is 0");
                return STATUS_UNSUCCESSFUL;
            }
        }

        for(PLIST_ENTRY32 listEntry = (PLIST_ENTRY32)ldr->InLoadOrderModuleList.Flink;
            listEntry != &ldr->InLoadOrderModuleList;
            listEntry = (PLIST_ENTRY32)listEntry->Flink) {

            PLDR_DATA_TABLE_ENTRY32 ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

            if(returnFirstModule) {
                *LdrEntry = ldrEntry;
                return STATUS_SUCCESS;
            } else {
                if(RtlCompareMemory((PVOID)ldrEntry->BaseDllName.Buffer, ModuleName, ldrEntry->BaseDllName.Length) == ldrEntry->BaseDllName.Length) {
                    *LdrEntry = ldrEntry;
                    return STATUS_SUCCESS;
                }
            }
        }
    } else { //PsGetProcessWow64Process failed. Native process.
        DPRINT("PsGetProcessWow64Process failed");
    }
    return STATUS_NOT_FOUND;
}
