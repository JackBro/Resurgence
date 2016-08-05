#include <system/driver/driver.hpp>
#include <system/driver/driver_shellcode.hpp>
#include <misc/winnt.hpp>

#include <Shlwapi.h>

#include <system/driver/TDL/TDL.h>

#pragma comment(lib, "Shlwapi.lib")

#define BUFFER_IMAGE_OFFSET (BOOTSTRAP_IMAGE_OFFSET + 0x14)

namespace resurgence
{
    namespace system
    {
        driver::driver(const std::wstring& path)
            : _handle(INVALID_HANDLE_VALUE)
        {
            _path.reserve(MAX_PATH);
            _path = misc::winnt::get_full_path(path);
        }
        driver::~driver()
        {
            if(IsLoaded())
                CloseHandle(_handle);
            _handle = INVALID_HANDLE_VALUE;
        }
        BOOL driver::IsLoaded()
        {
            return _handle != INVALID_HANDLE_VALUE;
        }
        ntstatus_code driver::Load()
        {
            ntstatus_code    status = STATUS_SUCCESS;

            if(IsLoaded()) return STATUS_SUCCESS;

            if(!PathFileExistsW(_path.data()))  return STATUS_FILE_INVALID;

            status = TDLload_driver(_path.data());
            
            if(NT_SUCCESS(status))
                return Open();
            return status;
        }

        ntstatus_code driver::Open()
        {
            ntstatus_code status = STATUS_NO_SUCH_DEVICE;
            int tries = 0;

            while(tries++ < 10) {
                status = misc::winnt::get_driver_device(RDRV_SYMLINK, &_handle);
                if(NT_SUCCESS(status))
                    break;
                Sleep(1000);
            }
            return status;
        }
        ntstatus_code driver::QueryVersionInfo(PVERSION_INFO pVersion)
        {
            if(!pVersion) return set_last_ntstatus(STATUS_INVALID_PARAMETER);
            DWORD ioBytes;
            if(!DeviceIoControl(_handle, RESURGENCE_QUERY_OSVERSION, NULL, 0, pVersion, sizeof(VERSION_INFO), &ioBytes, NULL))
                return get_last_ntstatus();
            return STATUS_SUCCESS;
        }
        ntstatus_code driver::AllocateVirtualMemory(ULONG ProcessId, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationFlags, ULONG ProtectionFlags)
        {
            VM_OPERATION params;
            RtlZeroMemory(&params, sizeof(params));
            params.In.Operation = VM_OPERATION_ALLOC;
            params.In.ProcessId = ProcessId;
            params.In.BaseAddress = *(PULONG_PTR)BaseAddress;
            params.In.RegionSize = *RegionSize;
            params.In.AllocationFlags = AllocationFlags;
            params.In.ProtectionFlags = ProtectionFlags;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_OPERATION, 
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *BaseAddress = (PVOID)params.Out.BaseAddress;
            *RegionSize = params.Out.RegionSize;

            return STATUS_SUCCESS;
        }
        ntstatus_code driver::ProtectVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection)
        {
            VM_OPERATION params;
            RtlZeroMemory(&params, sizeof(params));
            params.In.Operation = VM_OPERATION_PROTECT;
            params.In.ProcessId = ProcessId;
            params.In.BaseAddress = (ULONG_PTR)BaseAddress;
            params.In.RegionSize = RegionSize;
            params.In.ProtectionFlags = NewProtection;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_OPERATION,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            if(OldProtection)
                *OldProtection = params.Out.OldProtection;

            return STATUS_SUCCESS;
        }
        ntstatus_code driver::FreeVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG FreeType)
        {
            VM_OPERATION params;
            RtlZeroMemory(&params, sizeof(params));
            params.In.Operation = VM_OPERATION_FREE;
            params.In.ProcessId = ProcessId;
            params.In.BaseAddress = (ULONG_PTR)BaseAddress;
            params.In.RegionSize = RegionSize;
            params.In.FreeType = FreeType;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_OPERATION,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }
        ntstatus_code driver::QueryVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemInfo)
        {
            if(!MemInfo) return set_last_ntstatus(STATUS_INVALID_PARAMETER);

            VM_QUERY_INFO params;
            params.In.ProcessId = ProcessId;
            params.In.BaseAddress = (ULONG_PTR)BaseAddress;
            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_QUERY,
                &params, RESURGENCE_VM_QUERY_SIZE,
                &params, RESURGENCE_VM_QUERY_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *MemInfo = params.Out;

            return STATUS_SUCCESS;
        }
        ntstatus_code driver::ReadVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize)
        {
            VM_READ_WRITE params;
            params.ProcessId = ProcessId;
            params.TargetAddress = (ULONG_PTR)BaseAddress;
            params.Buffer = (ULONG_PTR)Buffer;
            params.BufferSize = BufferSize;
            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_READ,
                &params, RESURGENCE_VM_READ_SIZE,
                &params, RESURGENCE_VM_READ_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();
            return STATUS_SUCCESS;
        }
        ntstatus_code driver::WriteVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize)
        {
            VM_READ_WRITE params;
            params.ProcessId        = ProcessId;
            params.TargetAddress    = (ULONG_PTR)BaseAddress;
            params.Buffer           = (ULONG_PTR)Buffer;
            params.BufferSize       = BufferSize;
            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_WRITE,
                &params, RESURGENCE_VM_WRITE_SIZE,
                &params, RESURGENCE_VM_WRITE_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();
            return STATUS_SUCCESS;
        }
        ntstatus_code driver::OpenProcess(ULONG ProcessId, ULONG Access, PHANDLE Handle)
        {
            if(!Handle) return set_last_ntstatus(STATUS_INVALID_PARAMETER_3);

            OPEN_PROCESS params;
            params.In.ProcessId = ProcessId;
            params.In.ThreadId = 0;
            params.In.AccessMask = Access;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_OPEN_PROCESS,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *Handle = (HANDLE)params.Out.Handle;
            return STATUS_SUCCESS;
        }
        ntstatus_code driver::OpenProcessWithThread(ULONG ThreadId, ULONG Access, PHANDLE Handle)
        {
            if(!Handle) return set_last_ntstatus(STATUS_INVALID_PARAMETER_3);

            OPEN_PROCESS params;
            params.In.ProcessId = 0;
            params.In.ThreadId = ThreadId;
            params.In.AccessMask = Access;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_OPEN_PROCESS,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *Handle = (HANDLE)params.Out.Handle;
            return STATUS_SUCCESS;
        }
        ntstatus_code driver::OpenThread(ULONG ThreadId, ULONG Access, PHANDLE Handle)
        {
            if(!Handle) return set_last_ntstatus(STATUS_INVALID_PARAMETER_3);

            OPEN_THREAD params;
            params.In.ThreadId = ThreadId;
            params.In.AccessMask = Access;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_OPEN_THREAD,
                &params, RESURGENCE_OPEN_THREAD_SIZE,
                &params, RESURGENCE_OPEN_THREAD_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *Handle = (HANDLE)params.Out.Handle;
            return STATUS_SUCCESS;
        }
        ntstatus_code driver::GrantHandleAccess(ULONG ProcessId, HANDLE Handle, ULONG Access, PULONG OldAccess)
        {
            GRANT_ACCESS params;
            params.In.ProcessId = ProcessId;
            params.In.Handle = (ULONG_PTR)Handle;
            params.In.AccessMask = Access;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_GRANT_ACCESS,
                &params, RESURGENCE_GRANT_ACCESS_SIZE,
                &params, RESURGENCE_GRANT_ACCESS_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();
            if(OldAccess)
                *OldAccess = params.Out.OldAccessMask;
            return STATUS_SUCCESS;
        }
        ntstatus_code driver::SetProcessProtection(ULONG ProcessId, ULONG ProtectionLevel)
        {
            PROTECT_PROCESS params;
            params.In.ProcessId = ProcessId;
            params.In.ProtectionLevel = ProtectionLevel;
            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_PROTECT_PROCESS,
                &params, RESURGENCE_PROTECT_PROCESS_SIZE,
                NULL, 0,
                &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }
        ntstatus_code driver::SetProcessDEP(ULONG ProcessId, BOOLEAN Enable)
        {
            SET_DEP_STATE params;
            params.In.ProcessId = ProcessId;
            params.In.Enabled = Enable;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_SET_DEP_STATE,
                &params, RESURGENCE_SET_DEP_STATE_SIZE,
                NULL, 0,
                &ioBytes, NULL)) 
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }
        ntstatus_code driver::InjectModule(ULONG ProcessId, LPWSTR ModulePath, BOOLEAN EraseHeaders, BOOLEAN HideModule, PULONG_PTR BaseAddress)
        {

            INJECT_MODULE params;
            params.In.ProcessId = ProcessId;
            params.In.InjectionType = InjectLdrLoadDll;
            params.In.ErasePE = EraseHeaders;
            params.In.HideModule = HideModule;
            params.In.ModuleBase = 0;
            params.In.ModuleSize = 0;
            wcscpy_s(params.In.ModulePath, MAX_PATH, ModulePath);

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_INJECT_MODULE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            if(BaseAddress)
                *BaseAddress = params.Out.BaseAddress;

            return STATUS_SUCCESS;
        }
        ntstatus_code driver::MMapModule(ULONG ProcessId, LPVOID ModuleBase, ULONG ModuleSize, BOOLEAN EraseHeaders, BOOLEAN HideModule, PULONG_PTR BaseAddress)
        {

            INJECT_MODULE params;
            params.In.ProcessId = ProcessId;
            params.In.InjectionType = InjectManualMap;
            params.In.ErasePE = EraseHeaders;
            params.In.HideModule = HideModule;
            params.In.ModuleBase = (ULONG_PTR)ModuleBase;
            params.In.ModuleSize = ModuleSize;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_INJECT_MODULE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            if(BaseAddress)
                *BaseAddress = params.Out.BaseAddress;

            return STATUS_SUCCESS;
        }
    }
}
