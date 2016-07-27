#include <System/Driver/Driver.hpp>
#include <Shlwapi.h>
#include <Misc/NtHelpers.hpp>
#include <System/Driver/Shellcode.hpp>

#include <System/Driver/TDL/TDL.h>

#pragma comment(lib, "Shlwapi.lib")

#define BUFFER_IMAGE_OFFSET (BOOTSTRAP_IMAGE_OFFSET + 0x14)

namespace Resurgence
{
    namespace System
    {

        Driver::Driver(const std::wstring& path)
            : _handle(INVALID_HANDLE_VALUE)
        {
            _path.reserve(MAX_PATH);
            Misc::NtHelpers::GetFullPath(path.data(), const_cast<LPWSTR>(_path.data()));
        }
        Driver::~Driver()
        {
            if(IsLoaded())
                CloseHandle(_handle);
            _handle = INVALID_HANDLE_VALUE;
        }
        BOOL Driver::IsLoaded()
        {
            return _handle != INVALID_HANDLE_VALUE;
        }
        NTSTATUS Driver::Load()
        {
            NTSTATUS    status = STATUS_SUCCESS;

            if(IsLoaded()) return STATUS_SUCCESS;

            if(!PathFileExistsW(_path.data()))  return STATUS_FILE_INVALID;

            status = TDLLoadDriver(_path.data());
            
            if(NT_SUCCESS(status))
                return Open();
            return status;
        }

        NTSTATUS Driver::Open()
        {
            NTSTATUS status = STATUS_NO_SUCH_DEVICE;
            int tries = 0;

            while(tries++ < 10) {
                status = Misc::NtHelpers::GetDeviceHandle(RDRV_SYMLINK, &_handle);
                if(NT_SUCCESS(status))
                    break;
                Sleep(1000);
            }
            return status;
        }
        NTSTATUS Driver::QueryVersionInfo(PVERSION_INFO pVersion)
        {
            if(!pVersion) return SetLastNtStatus(STATUS_INVALID_PARAMETER);
            DWORD ioBytes;
            if(!DeviceIoControl(_handle, RESURGENCE_QUERY_OSVERSION, NULL, 0, pVersion, sizeof(VERSION_INFO), &ioBytes, NULL))
                return GetLastNtStatus();
            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::AllocateVirtualMemory(ULONG ProcessId, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationFlags, ULONG ProtectionFlags)
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
                return GetLastNtStatus();

            *BaseAddress = (PVOID)params.Out.BaseAddress;
            *RegionSize = params.Out.RegionSize;

            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::ProtectVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection)
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
                return GetLastNtStatus();

            if(OldProtection)
                *OldProtection = params.Out.OldProtection;

            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::FreeVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG FreeType)
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
                return GetLastNtStatus();

            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::QueryVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemInfo)
        {
            if(!MemInfo) return SetLastNtStatus(STATUS_INVALID_PARAMETER);

            VM_QUERY_INFO params;
            params.In.ProcessId = ProcessId;
            params.In.BaseAddress = (ULONG_PTR)BaseAddress;
            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_QUERY,
                &params, RESURGENCE_VM_QUERY_SIZE,
                &params, RESURGENCE_VM_QUERY_SIZE,
                &ioBytes, NULL))
                return GetLastNtStatus();

            *MemInfo = params.Out;

            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::ReadVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize)
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
                return GetLastNtStatus();
            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::WriteVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize)
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
                return GetLastNtStatus();
            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::OpenProcess(ULONG ProcessId, ULONG Access, PHANDLE Handle)
        {
            if(!Handle) return SetLastNtStatus(STATUS_INVALID_PARAMETER_3);

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
                return GetLastNtStatus();

            *Handle = (HANDLE)params.Out.Handle;
            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::OpenProcessWithThread(ULONG ThreadId, ULONG Access, PHANDLE Handle)
        {
            if(!Handle) return SetLastNtStatus(STATUS_INVALID_PARAMETER_3);

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
                return GetLastNtStatus();

            *Handle = (HANDLE)params.Out.Handle;
            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::OpenThread(ULONG ThreadId, ULONG Access, PHANDLE Handle)
        {
            if(!Handle) return SetLastNtStatus(STATUS_INVALID_PARAMETER_3);

            OPEN_THREAD params;
            params.In.ThreadId = ThreadId;
            params.In.AccessMask = Access;

            DWORD ioBytes;
            if(!DeviceIoControl(
                _handle, RESURGENCE_OPEN_THREAD,
                &params, RESURGENCE_OPEN_THREAD_SIZE,
                &params, RESURGENCE_OPEN_THREAD_SIZE,
                &ioBytes, NULL))
                return GetLastNtStatus();

            *Handle = (HANDLE)params.Out.Handle;
            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::GrantHandleAccess(ULONG ProcessId, HANDLE Handle, ULONG Access, PULONG OldAccess)
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
                return GetLastNtStatus();
            if(OldAccess)
                *OldAccess = params.Out.OldAccessMask;
            return STATUS_SUCCESS;
        }
        NTSTATUS Driver::SetProcessProtection(ULONG ProcessId, ULONG ProtectionLevel)
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
                return GetLastNtStatus();

            return STATUS_SUCCESS;
        }
    }
}
