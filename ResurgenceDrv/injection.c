#include "internal.h"
#include "injection.h"
#include "utils.h"

#pragma alloc_text(PAGE, RDrvBuildWow64InjectStub)
#pragma alloc_text(PAGE, RDrvBuildNativeInjectStub)
#pragma alloc_text(PAGE, RDrvInjectLdrLoadDll)


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
    NTSTATUS	status;
    ULONG_PTR   fnLdrLoadDll;
    BOOLEAN     isWow64;
    KAPC_STATE  apcState;

    DPRINT("Injecting file %ws to process %X", ModulePath, PsGetProcessId(Process));

    isWow64 = !!PsGetProcessWow64Process(Process);
    KeStackAttachProcess(Process, &apcState);
    if(isWow64) {
        PLDR_DATA_TABLE_ENTRY32	ntdll;
        RDrvGetModuleEntry32(Process, L"ntdll.dll", &ntdll);
        status = RDrvGetProcAddress((ULONG_PTR)ntdll->DllBase, "LdrLoadDll", &fnLdrLoadDll);
    } else {
        PLDR_DATA_TABLE_ENTRY ntdll;
        RDrvGetModuleEntry(Process, L"ntdll.dll", &ntdll);
        status = RDrvGetProcAddress((ULONG_PTR)ntdll->DllBase, "LdrLoadDll", &fnLdrLoadDll);
    }
    if(fnLdrLoadDll != 0) {
        DPRINT("LdrLoadDll found at %p", fnLdrLoadDll);

        UNICODE_STRING szModulePath;
        RtlInitUnicodeString(&szModulePath, ModulePath);

        PINJECTION_BUFFER pBuffer = NULL;
        status = isWow64 ?
            RDrvBuildWow64InjectStub(fnLdrLoadDll, &szModulePath, &pBuffer) :
            RDrvBuildNativeInjectStub(fnLdrLoadDll, &szModulePath, &pBuffer);

        DPRINT("Injection stub written to %p", pBuffer);

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

    KeUnstackDetachProcess(&apcState);

    return status;
}

