#include "internal.h"
#include "utils.h"

#pragma alloc_text(PAGE, RDrvLogToFile)
#pragma alloc_text(PAGE, RDrvOpenFile)
#pragma alloc_text(PAGE, RDrvGetModuleContainingAddress)
#pragma alloc_text(PAGE, RDrvGetKernelInfo)
#pragma alloc_text(PAGE, RDrvFindPattern)
#pragma alloc_text(PAGE, RDrvScanModule)
#pragma alloc_text(PAGE, RDrvSleep)
#pragma alloc_text(PAGE, RDrvGetModuleEntry)
#pragma alloc_text(PAGE, RDrvGetModuleEntry32)
#pragma alloc_text(PAGE, RDrvGetProcAddress)
#pragma alloc_text(PAGE, RDrvCreateUserThread)
#pragma alloc_text(PAGE, RDrvBuildWow64InjectStub)
#pragma alloc_text(PAGE, RDrvBuildNativeInjectStub)
#pragma alloc_text(PAGE, RDrvInjectLdrLoadDll)
#pragma alloc_text(PAGE, RDrvInjectManualMap)
#pragma alloc_text(PAGE, RDrvStripHeaders)
#pragma alloc_text(PAGE, RDrvHideFromLoadedList)
#pragma alloc_text(PAGE, GetWow64NtHeaders)
#pragma alloc_text(PAGE, GetNtHeaders)
#pragma alloc_text(PAGE, GetSSDTBase)
#pragma alloc_text(PAGE, GetSSDTEntry)

NTSTATUS RDrvLogToFile(
    __in LPCSTR Format,
    __in_opt ...
)
{
    IO_STATUS_BLOCK     ioStatus;
    HANDLE              hFile;
    CHAR                buffer[512];
    size_t              cb;
    NTSTATUS            status;

    status = RDrvOpenFile(L"\\SystemRoot\\Temp\\Resurgence.log", TRUE, TRUE, &hFile);

    if(NT_SUCCESS(status)) {
        RtlZeroMemory(buffer, 512);
        va_list va;
        va_start(va, Format);
        RtlStringCbVPrintfA(buffer, 512, Format, va);
        va_end(va);

        RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
        ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, buffer, (ULONG)cb, NULL, NULL);

        ZwFlushBuffersFile(hFile, &ioStatus);
        ZwClose(hFile);
        return STATUS_SUCCESS;
    }

    return status;
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
            *BaseAddress = (ULONG_PTR)g_pDriverContext->KrnlBase;
        if(Size)
            *Size = g_pDriverContext->KrnlSize;
        return STATUS_SUCCESS;
    }

    UNICODE_STRING usPsGetProcessPeb;

    RtlInitUnicodeString(&usPsGetProcessPeb, L"PsGetProcessPeb");
    PVOID pFn = MmGetSystemRoutineAddress(&usPsGetProcessPeb);

    if(pFn == NULL) return STATUS_NOT_FOUND;

    status = RDrvGetModuleContainingAddress((ULONG_PTR)pFn, (PULONG_PTR)&g_pDriverContext->KrnlBase, &g_pDriverContext->KrnlSize);

    if(NT_SUCCESS(status)) {
        if(BaseAddress)
            *BaseAddress = (ULONG_PTR)g_pDriverContext->KrnlBase;
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
                (ULONG_PTR)g_pDriverContext->KrnlBase + section->VirtualAddress,
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

NTSTATUS RDrvGetProcAddress(
    __in ULONG_PTR ModuleBase,
    __in LPCSTR ProcName,
    __out PULONG_PTR ProcAddress
)
{
    if(!ModuleBase)	    return STATUS_INVALID_PARAMETER_1;
    if(!ProcName)	    return STATUS_INVALID_PARAMETER_2;
    if(!ProcAddress)    return STATUS_INVALID_PARAMETER_3;

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)ModuleBase;

    if(dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_NOT_MZ;

    PIMAGE_NT_HEADERS32 ntHdrs32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + dosHdr->e_lfanew);
    PIMAGE_NT_HEADERS64 ntHdrs64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dosHdr->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exportDir = NULL;
    ULONG exportsSize;

    if(ntHdrs32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + ntHdrs32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        exportsSize = ntHdrs32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else if(ntHdrs64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + ntHdrs64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        exportsSize = ntHdrs64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        //
        // Should never happen
        //
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PULONG	addressOfFunctions  = (PULONG)(exportDir->AddressOfFunctions + (PUCHAR)ModuleBase);
    PULONG	addressOfNames      = (PULONG)(exportDir->AddressOfNames + (PUCHAR)ModuleBase);
    PUSHORT	addressOfOrdinals   = (PUSHORT)(exportDir->AddressOfNameOrdinals + (PUCHAR)ModuleBase);
    ULONG	numberOfNames       = exportDir->NumberOfNames;

    for(ULONG i = 0; i < numberOfNames; i++) {
        PCSTR pszName = (PCSTR)((PUCHAR)ModuleBase + addressOfNames[i]);
        SHORT ordinal = addressOfOrdinals[i];
        if(!strcmp(pszName, ProcName)) {
            *ProcAddress = (ULONG_PTR)(addressOfFunctions[ordinal] + (PUCHAR)ModuleBase);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_PROCEDURE_NOT_FOUND;
}

NTSTATUS RDrvCreateUserThread(
    __in PVOID pStartAddress,
    __in_opt PVOID pArg,
    __in BOOLEAN wait,
    __out_opt PULONG_PTR pThreadExitCode
)
{
    NTSTATUS			        status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES	        objectAttributes;
    HANDLE				        threadHandle = NULL;

    InitializeObjectAttributes(&objectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwCreateThreadEx(
        &threadHandle, THREAD_QUERY_LIMITED_INFORMATION, &objectAttributes,
        ZwCurrentProcess(), pStartAddress, pArg, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
        0, 0x1000, 0x100000, NULL
    );

    if(NT_ERROR(status)) {
        PERROR("ZwCreateThreadEx", status);
    } else {
        if(wait) {
            LARGE_INTEGER timeout = {0};
            timeout.QuadPart = -5000ll * 1000 * 1000;
            status = ZwWaitForSingleObject(threadHandle, TRUE, &timeout);
            if(NT_SUCCESS(status)) {
                THREAD_BASIC_INFORMATION info = {0};
                ULONG bytes = 0;

                status = ZwQueryInformationThread(threadHandle, ThreadBasicInformation, &info, sizeof(info), &bytes);
                if(NT_SUCCESS(status)) {
                    if(pThreadExitCode)
                        *pThreadExitCode = info.ExitStatus;
                } else {
                    PERROR("ZwQueryInformationThread", status);
                }
            } else {
                PERROR("ZwWaitForSingleObject", status);
            }
        }
        ZwClose(threadHandle);
    }

    return status;
}

NTSTATUS RDrvBuildWow64InjectStub(
    __in ULONG_PTR FnLdrLoadDll,
    __in PUNICODE_STRING ModulePath,
    __out PINJECTION_BUFFER* Buffer
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if(!FnLdrLoadDll)	return STATUS_INVALID_PARAMETER_1;
    if(!ModulePath)	    return STATUS_INVALID_PARAMETER_2;
    if(!Buffer)		    return STATUS_INVALID_PARAMETER_3;

    UCHAR pCodeBuffer[] =
    {
        0x55,                      		//push   ebp			// 0x00
        0x89, 0xE5,                   	//mov    ebp,esp		// 0x01
        0x68, 0x00, 0x00, 0x00, 0x00,   //push   pModuleHandle	// 0x03
        0x68, 0x00, 0x00, 0x00, 0x00,   //push   pszModulePath	// 0x08
        0x6A, 0x00,                    	//push   0				// 0x0D
        0x6A, 0x00,                    	//push   0				// 0x0F
        0xE8, 0x00, 0x00, 0x00, 0x00,  	//call   LdrLoadDll		// 0x11
        0x5D,                      		//pop    ebp			// 0x16
        0xC2, 0x04, 0x00             	//ret    4				// 0x17
    };

    SIZE_T regionSize = sizeof(INJECTION_BUFFER);
    PINJECTION_BUFFER buff = NULL;

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&buff, 0, &regionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(NT_SUCCESS(status)) {
        RtlZeroMemory(buff, regionSize);
        RtlCopyMemory(buff, pCodeBuffer, sizeof(pCodeBuffer));

        buff->ModulePath32.Length = ModulePath->Length;
        buff->ModulePath32.MaximumLength = ModulePath->MaximumLength;
        buff->ModulePath32.Buffer = (ULONG)(ULONG_PTR)buff->PathBuffer;

        RtlCopyMemory((PVOID)buff->PathBuffer, ModulePath->Buffer, ModulePath->Length);

        *(ULONG*)((PUCHAR)buff->CodeBuffer + 0x04) = (ULONG)(ULONG_PTR)&buff->ModuleHandle;
        *(ULONG*)((PUCHAR)buff->CodeBuffer + 0x09) = (ULONG)(ULONG_PTR)&buff->ModulePath32;
        *(ULONG*)((PUCHAR)buff->CodeBuffer + 0x12) = (ULONG)(ULONG_PTR)(FnLdrLoadDll - ((ULONG_PTR)buff->CodeBuffer + 0x16));

        *Buffer = buff;
    } else {
        PERROR("ZwAllocateVirtualMemory", status);
    }
    return status;
}

NTSTATUS RDrvBuildNativeInjectStub(
    __in ULONG_PTR FnLdrLoadDll,
    __in PUNICODE_STRING ModulePath,
    __out PINJECTION_BUFFER* Buffer
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if(!FnLdrLoadDll)	return STATUS_INVALID_PARAMETER_1;
    if(!ModulePath)	    return STATUS_INVALID_PARAMETER_2;
    if(!Buffer)		    return STATUS_INVALID_PARAMETER_3;

    UCHAR pCodeBuffer[] =
    {
        0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
        0x48, 0x31, 0xC9,                       // xor rcx, rcx
        0x48, 0x31, 0xD2,                       // xor rdx, rdx
        0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
        0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +20
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
        0xFF, 0xD0,                             // call rax
        0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
        0xC3                                    // ret
    };

    SIZE_T regionSize = sizeof(INJECTION_BUFFER);
    PINJECTION_BUFFER buff = NULL;

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&buff, 0, &regionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(NT_SUCCESS(status)) {
        RtlZeroMemory(buff, regionSize);
        RtlCopyMemory(buff, pCodeBuffer, sizeof(pCodeBuffer));

        buff->ModulePath64.Length = 0;
        buff->ModulePath64.MaximumLength = sizeof(buff->PathBuffer);
        buff->ModulePath64.Buffer = buff->PathBuffer;

        RtlUnicodeStringCopy(&buff->ModulePath64, ModulePath);

        *(ULONG_PTR*)((PUCHAR)buff->CodeBuffer + 0x0C) = (ULONG_PTR)&buff->ModulePath64;
        *(ULONG_PTR*)((PUCHAR)buff->CodeBuffer + 0x16) = (ULONG_PTR)&buff->ModuleHandle;
        *(ULONG_PTR*)((PUCHAR)buff->CodeBuffer + 0x20) = (ULONG_PTR)FnLdrLoadDll;

        *Buffer = buff;
    } else {
        PERROR("ZwAllocateVirtualMemory", status);
    }
    return status;
}

NTSTATUS RDrvInjectLdrLoadDll(
    __in PEPROCESS Process,
    __in PWCHAR ModulePath,
    __out PULONG_PTR ModuleBase
)
{
    NTSTATUS		        status = STATUS_SUCCESS;
    ULONG_PTR               fnLdrLoadDll;
    
    BOOLEAN isWow64 = !!PsGetProcessWow64Process(Process);
    if(isWow64) {
        PLDR_DATA_TABLE_ENTRY32	ntdll;
        RDrvGetModuleEntry32(Process, L"ntdll.dll", &ntdll);
        RDrvGetProcAddress((ULONG_PTR)ntdll->DllBase, "LdrLoadDll", &fnLdrLoadDll);
    } else {
        PLDR_DATA_TABLE_ENTRY   ntdll;
        RDrvGetModuleEntry(Process, L"ntdll.dll", &ntdll);
        RDrvGetProcAddress((ULONG_PTR)ntdll->DllBase, "LdrLoadDll", &fnLdrLoadDll);
    }
    if(fnLdrLoadDll != 0) {
        UNICODE_STRING szModulePath;
        RtlInitUnicodeString(&szModulePath, ModulePath);

        PINJECTION_BUFFER pBuffer = NULL;
        status = isWow64 ? 
            RDrvBuildWow64InjectStub(fnLdrLoadDll, &szModulePath, &pBuffer) : 
            RDrvBuildNativeInjectStub(fnLdrLoadDll, &szModulePath, &pBuffer);

        if(ModuleBase)
            *ModuleBase = 0;

        if(NT_SUCCESS(status)) {
            ULONG_PTR exitCode;
            status = RDrvCreateUserThread((PVOID)pBuffer, NULL, TRUE, &exitCode);
            if(NT_SUCCESS(status)) {
                status = (NTSTATUS)exitCode;
                if(NT_SUCCESS(status)) {
                    if(ModuleBase)
                        *ModuleBase = (ULONG_PTR)pBuffer->ModuleHandle;
                } else {
                    PERROR("LdrLoadDll", status);
                }
            } else
                PERROR("RDrvCreateUserThread", status);
        } else
            PERROR("RDrvBuildWow64InjectStub/RDrvBuildNativeInjectStub", status);
    } else
        PERROR("RDrvGetProcAddress", status);

    return status;
}

NTSTATUS RDrvInjectManualMap(
    __in PEPROCESS Process,
    __in PWCHAR ModulePath,
    __out PULONG_PTR ModuleBase
)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ModulePath);
    UNREFERENCED_PARAMETER(ModuleBase);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS RDrvStripHeaders(
    __in PVOID BaseAddress
)
{
    if(!BaseAddress) return STATUS_INVALID_PARAMETER;

    PIMAGE_NT_HEADERS32 pNtHdrs32 = GetWow64NtHeaders(BaseAddress);
    PIMAGE_NT_HEADERS64 pNtHdrs64 = GetNtHeaders(BaseAddress);

    if(!pNtHdrs32 || !pNtHdrs64) return STATUS_INVALID_IMAGE_FORMAT;

    SIZE_T sizeOfHeaders = 0;

    if(pNtHdrs32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        sizeOfHeaders = pNtHdrs32->OptionalHeader.SizeOfHeaders;
    } else if(pNtHdrs64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        sizeOfHeaders = pNtHdrs64->OptionalHeader.SizeOfHeaders;
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG oldProt = 0;

    NTSTATUS status = ZwProtectVirtualMemory(ZwCurrentProcess(), &BaseAddress, &sizeOfHeaders, PAGE_EXECUTE_READWRITE, &oldProt);
    if(NT_SUCCESS(status)) {
        RtlZeroMemory(BaseAddress, sizeOfHeaders);
        ZwProtectVirtualMemory(ZwCurrentProcess(), &BaseAddress, &sizeOfHeaders, oldProt, &oldProt);
    }
    return status;
}

NTSTATUS RDrvHideFromLoadedList(
    __in PEPROCESS pProcess,
    __in PVOID pBaseAddress
)
{
    if(!pProcess) return STATUS_INVALID_PARAMETER_1;
    if(!pBaseAddress) return STATUS_INVALID_PARAMETER_2;

    PPEB32 pWow64Peb = (PPEB32)PsGetProcessWow64Process(pProcess);
    INT waitCount = 0;
    if(pWow64Peb != NULL) { 
        PPEB_LDR_DATA32 pLdrData = (PPEB_LDR_DATA32)pWow64Peb->Ldr;

        if(!pLdrData) {
            DPRINT("pWow64Peb->Ldr is invalid");
            return STATUS_UNSUCCESSFUL;
        }

        if(!pLdrData->Initialized) {
            while(!pLdrData->Initialized && waitCount++ < 4)
                RDrvSleep(250);

            if(!pLdrData->Initialized) {
                DPRINT("pLdrData->Initialized is 0");
                return STATUS_UNSUCCESSFUL;
            }
        }

        for(PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)pLdrData->InLoadOrderModuleList.Flink;
            pListEntry != &pLdrData->InLoadOrderModuleList;
            pListEntry = (PLIST_ENTRY32)pListEntry->Flink) {

            PLDR_DATA_TABLE_ENTRY32 pEntry = (PLDR_DATA_TABLE_ENTRY32)pListEntry;

            if(pEntry->DllBase == (ULONG)(ULONG_PTR)pBaseAddress) {
                RemoveEntryListUnsafe32(&pEntry->InInitializationOrderLinks);
                RemoveEntryListUnsafe32(&pEntry->InLoadOrderLinks);
                RemoveEntryListUnsafe32(&pEntry->InMemoryOrderLinks);
                RemoveEntryListUnsafe32(&pEntry->HashLinks);
            }
        }
    } else {
        PPEB pPeb = PsGetProcessPeb(pProcess);
        if(!pPeb) {
            DPRINT("pPeb is invalid");
            return STATUS_UNSUCCESSFUL;
        }

        PPEB_LDR_DATA pLdrData = pPeb->Ldr;

        if(!pLdrData) {
            DPRINT("pPeb->Ldr is invalid");
            return STATUS_UNSUCCESSFUL;
        }

        if(!pLdrData->Initialized) {
            while(!pLdrData->Initialized && waitCount++ < 4)
                RDrvSleep(250);

            if(!pLdrData->Initialized) {
                DPRINT("pLdrData->Initialized is 0");
                return STATUS_UNSUCCESSFUL;
            }
        }

        for(PLIST_ENTRY pListEntry = (PLIST_ENTRY)pLdrData->InLoadOrderModuleList.Flink;
            pListEntry != &pLdrData->InLoadOrderModuleList;
            pListEntry = (PLIST_ENTRY)pListEntry->Flink) {
            PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

            if(pEntry->DllBase == pBaseAddress) {
                RemoveEntryListUnsafe(&pEntry->InInitializationOrderLinks);
                RemoveEntryListUnsafe(&pEntry->InLoadOrderLinks);
                RemoveEntryListUnsafe(&pEntry->InMemoryOrderLinks);
                RemoveEntryListUnsafe(&pEntry->HashLinks);
            }
        }
    }
    return STATUS_NOT_FOUND;
}

PIMAGE_NT_HEADERS32 GetWow64NtHeaders(
    __in PVOID ImageBase
)
{
    if(!ImageBase) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;

    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    return (PIMAGE_NT_HEADERS32)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
}

PIMAGE_NT_HEADERS64 GetNtHeaders(
    __in PVOID ImageBase
)
{
    if(!ImageBase) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;

    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    return (PIMAGE_NT_HEADERS64)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
}

BOOLEAN IsProcessWow64Process(
    __in PEPROCESS Process
)
{
    return !!PsGetProcessWow64Process(Process);
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase(
    void
)
{
    PVOID       pFound;
    NTSTATUS    status;
    UCHAR       pattern[] = "\x4C\x8D\x15\x00\x00\x00\x00\x4C\x8D\x1D\x00\x00\x00\x00\xF7\x43";
    UCHAR       mask[] = "xxx????xxx????xx";

    RDrvGetKernelInfo(NULL, NULL);

    // Already found
    if(g_pDriverContext->SSDT != NULL)
        return g_pDriverContext->SSDT;

    status = RDrvScanModule((ULONG_PTR)g_pDriverContext->KrnlBase, pattern, mask, sizeof(mask) - 1, &pFound);
    if(NT_SUCCESS(status)) {
        g_pDriverContext->SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
        return g_pDriverContext->SSDT;
    }

    return NULL;
}

PVOID GetSSDTEntry(
    __in ULONG Index
)
{
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTBase();

    if(pSSDT) {
        if(Index > pSSDT->NumberOfServices)
            return NULL;

        return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[Index] >> 4);
    }

    return NULL;
}
