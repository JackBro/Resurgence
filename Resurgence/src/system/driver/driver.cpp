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
        ///<summary>
        /// Constructor. 
        ///</summary>
        ///<param name="path"> The driver path. </param>
        driver::driver(const std::wstring& path)
            : _handle(INVALID_HANDLE_VALUE)
        {
            _path = misc::winnt::get_full_path(path);
        }

        ///<summary>
        /// Destructor. 
        ///</summary>
        driver::~driver()
        {
            if(is_loaded())
                NtClose(_handle);
            _handle = INVALID_HANDLE_VALUE;
        }

        ///<summary>
        /// Check if the driver is already loaded on the system.
        ///</summary>
        ///<returns> 
        /// TRUE if loaded, FALSE otherwise.
        ///</returns>
        BOOL driver::is_loaded()
        {
            open();
            return _handle != INVALID_HANDLE_VALUE;
        }

        ///<summary>
        /// Loads the driver.
        ///</summary>
        ///<param name="method"> The load method. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::load(driver_load_method method)
        {
            NTSTATUS status = STATUS_SUCCESS;

            if(is_loaded()) return STATUS_SUCCESS;

            if(!PathFileExistsW(_path.data()))  return STATUS_FILE_INVALID;

            if(method == Turla) {
                status = TDLload_driver(_path.data());
                if(NT_SUCCESS(status))
                    return open();
            } else {
                status = misc::winnt::load_driver(RDRV_SYMLINK, _path, &_handle);
            }
            return status;
        }

        NTSTATUS driver::open()
        {
            NTSTATUS status = STATUS_NO_SUCH_DEVICE;
            int tries = 0;

            while(tries++ < 10) {
                status = misc::winnt::get_driver_device(RDRV_SYMLINK, &_handle);
                if(NT_SUCCESS(status))
                    break;
                Sleep(1000);
            }
            return status;
        }

        ///<summary>
        /// Query the OS version.
        ///</summary>
        ///<param name="version"> The version info. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::query_version_info(PVERSION_INFO version)
        {
            DWORD ioBytes;

            if(!version)
                return set_last_ntstatus(STATUS_INVALID_PARAMETER);

            if(!DeviceIoControl(_handle, RESURGENCE_QUERY_OSVERSION, NULL, 0, version, sizeof(VERSION_INFO), &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Allocate virtual memory.
        ///</summary>
        ///<param name="pid">         The process id. </param>
        ///<param name="baseAddress"> The allocation base. </param>
        ///<param name="regionSize"> The allocation size. </param>
        ///<param name="allocation"> The allocation flags. </param>
        ///<param name="protection"> The protection flags. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::allocate_virtual_memory(uint32_t pid, uint8_t** baseAddress, size_t* regionSize, uint32_t allocation, uint32_t protection)
        {
            DWORD           ioBytes;
            VM_OPERATION    params;

            RtlZeroMemory(&params, sizeof(params));

            params.In.Operation = VM_OPERATION_ALLOC;
            params.In.ProcessId = pid;
            params.In.BaseAddress = (ULONG_PTR)*baseAddress;
            params.In.RegionSize = *regionSize;
            params.In.AllocationFlags = allocation;
            params.In.ProtectionFlags = protection;

            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_OPERATION,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *baseAddress = (uint8_t*)params.Out.BaseAddress;
            *regionSize = params.Out.RegionSize;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Allocate virtual memory.
        ///</summary>
        ///<param name="pid">           The process id. </param>
        ///<param name="baseAddress">   The start address. </param>
        ///<param name="regionSize">    The region size. </param>
        ///<param name="newProtection"> The new protection. </param>
        ///<param name="oldProtection"> The old protection. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::protect_virtual_memory(uint32_t pid, uint8_t* baseAddress, size_t regionSize, uint32_t newProtection, uint32_t* oldProtection)
        {
            DWORD ioBytes;
            VM_OPERATION params;

            RtlZeroMemory(&params, sizeof(params));

            params.In.Operation = VM_OPERATION_PROTECT;
            params.In.ProcessId = pid;
            params.In.BaseAddress = (ULONG_PTR)baseAddress;
            params.In.RegionSize = regionSize;
            params.In.ProtectionFlags = newProtection;

            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_OPERATION,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            if(oldProtection)
                *oldProtection = params.Out.OldProtection;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Free virtual memory.
        ///</summary>
        ///<param name="pid">         The process id. </param>
        ///<param name="baseAddress"> The start address. </param>
        ///<param name="regionSize">  The region size. </param>
        ///<param name="freeType">    The free type. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::free_virtual_memory(uint32_t pid, uint8_t* baseAddress, size_t regionSize, uint32_t freeType)
        {
            DWORD ioBytes;
            VM_OPERATION params;

            RtlZeroMemory(&params, sizeof(params));

            params.In.Operation = VM_OPERATION_FREE;
            params.In.ProcessId = pid;
            params.In.BaseAddress = (ULONG_PTR)baseAddress;
            params.In.RegionSize = regionSize;
            params.In.FreeType = freeType;

            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_OPERATION,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &params, RESURGENCE_VM_OPERATION_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Query memory information.
        ///</summary>
        ///<param name="pid">         The process id. </param>
        ///<param name="baseAddress"> The base address. </param>
        ///<param name="memoryInfo">  The returned memory information. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::query_virtual_memory(uint32_t pid, uint8_t* baseAddress, PMEMORY_BASIC_INFORMATION memoryInfo)
        {
            if(!memoryInfo) return set_last_ntstatus(STATUS_INVALID_PARAMETER);

            DWORD           ioBytes;
            VM_QUERY_INFO   params;

            params.In.ProcessId = pid;
            params.In.BaseAddress = (ULONG_PTR)baseAddress;

            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_QUERY,
                &params, RESURGENCE_VM_QUERY_SIZE,
                &params, RESURGENCE_VM_QUERY_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *memoryInfo = params.Out;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Read virtual memory.
        ///</summary>
        ///<param name="pid">         The process id. </param>
        ///<param name="baseAddress"> The base address. </param>
        ///<param name="buffer">      The buffer. </param>
        ///<param name="length">      The buffer size. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::read_virtual_memory(uint32_t pid, const uint8_t* baseAddress, uint8_t* buffer, size_t length)
        {
            DWORD           ioBytes;
            VM_READ_WRITE   params;

            params.ProcessId = pid;
            params.TargetAddress = (ULONG_PTR)baseAddress;
            params.Buffer = (ULONG_PTR)buffer;
            params.BufferSize = length;

            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_READ,
                &params, RESURGENCE_VM_READ_SIZE,
                &params, RESURGENCE_VM_READ_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Write virtual memory.
        ///</summary>
        ///<param name="pid">         The process id. </param>
        ///<param name="baseAddress"> The base address. </param>
        ///<param name="buffer">      The buffer. </param>
        ///<param name="length">      The buffer size. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::write_virtual_memory(uint32_t pid, const uint8_t* baseAddress, uint8_t* buffer, size_t length)
        {
            DWORD           ioBytes;
            VM_READ_WRITE   params;

            params.ProcessId = pid;
            params.TargetAddress = (ULONG_PTR)baseAddress;
            params.Buffer = (ULONG_PTR)buffer;
            params.BufferSize = length;

            if(!DeviceIoControl(
                _handle, RESURGENCE_VM_WRITE,
                &params, RESURGENCE_VM_WRITE_SIZE,
                &params, RESURGENCE_VM_WRITE_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Opens a process.
        ///</summary>
        ///<param name="pid">    The process id. </param>
        ///<param name="access"> The desired access. </param>
        ///<param name="handle"> The returned handle. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::open_process(uint32_t pid, uint32_t access, PHANDLE handle)
        {
            DWORD ioBytes;
            OPEN_PROCESS params;

            if(!handle)
                return set_last_ntstatus(STATUS_INVALID_PARAMETER_3);

            params.In.ProcessId = pid;
            params.In.ThreadId = 0;
            params.In.AccessMask = access;

            if(!DeviceIoControl(
                _handle, RESURGENCE_OPEN_PROCESS,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *handle = (HANDLE)params.Out.Handle;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Opens the process that contains the target thread.
        ///</summary>
        ///<param name="tid">    The thread id. </param>
        ///<param name="access"> The desired access. </param>
        ///<param name="handle"> The returned handle. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::open_process_with_thread(uint32_t tid, uint32_t access, PHANDLE handle)
        {
            DWORD ioBytes;
            OPEN_PROCESS params;

            if(!handle) return set_last_ntstatus(STATUS_INVALID_PARAMETER_3);

            params.In.ProcessId = 0;
            params.In.ThreadId = tid;
            params.In.AccessMask = access;

            if(!DeviceIoControl(
                _handle, RESURGENCE_OPEN_PROCESS,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &params, RESURGENCE_OPEN_PROCESS_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *handle = (HANDLE)params.Out.Handle;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Opens a thread.
        ///</summary>
        ///<param name="tid">    The thread id. </param>
        ///<param name="access"> The desired access. </param>
        ///<param name="handle"> The returned handle. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::open_thread(uint32_t tid, uint32_t access, PHANDLE handle)
        {
            DWORD ioBytes;
            OPEN_THREAD params;

            if(!handle) return set_last_ntstatus(STATUS_INVALID_PARAMETER_3);

            params.In.ThreadId = tid;
            params.In.AccessMask = access;

            if(!DeviceIoControl(
                _handle, RESURGENCE_OPEN_THREAD,
                &params, RESURGENCE_OPEN_THREAD_SIZE,
                &params, RESURGENCE_OPEN_THREAD_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            *handle = (HANDLE)params.Out.Handle;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Grants access to a handle.
        ///</summary>
        ///<param name="pid">       The process id (current process on most cases). </param>
        ///<param name="handle">    The target handle. </param>
        ///<param name="access">    The desired access. </param>
        ///<param name="oldAccess"> The old access. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::grant_handle_access(uint32_t pid, HANDLE handle, uint32_t access, uint32_t* oldAccess)
        {
            DWORD           ioBytes;
            GRANT_ACCESS    params;

            params.In.ProcessId = pid;
            params.In.Handle = (ULONG_PTR)handle;
            params.In.AccessMask = access;

            if(!DeviceIoControl(
                _handle, RESURGENCE_GRANT_ACCESS,
                &params, RESURGENCE_GRANT_ACCESS_SIZE,
                &params, RESURGENCE_GRANT_ACCESS_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            if(oldAccess)
                *oldAccess = params.Out.OldAccessMask;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Set process protection.
        ///</summary>
        ///<param name="pid">             The process id. </param>
        ///<param name="protectionLevel"> The protection level (0: None. 1: Light. 2: Full). </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::set_process_protection(uint32_t pid, uint32_t protectionLevel)
        {
            DWORD           ioBytes;
            PROTECT_PROCESS params;

            params.In.ProcessId = pid;
            params.In.ProtectionLevel = protectionLevel;

            if(!DeviceIoControl(
                _handle, RESURGENCE_PROTECT_PROCESS,
                &params, RESURGENCE_PROTECT_PROCESS_SIZE,
                NULL, 0,
                &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Enables or disables DEP.
        ///</summary>
        ///<param name="pid">    The process id. </param>
        ///<param name="enable"> The DEP state. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::set_process_dep(uint32_t pid, bool enable)
        {
            DWORD           ioBytes;
            SET_DEP_STATE   params;

            params.In.ProcessId = pid;
            params.In.Enabled = enable;

            if(!DeviceIoControl(
                _handle, RESURGENCE_SET_DEP_STATE,
                &params, RESURGENCE_SET_DEP_STATE_SIZE,
                NULL, 0,
                &ioBytes, NULL))
                return get_last_ntstatus();

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Injects a module.
        ///</summary>
        ///<param name="pid">          The process id. </param>
        ///<param name="modulePath">   The module path. </param>
        ///<param name="eraseHeaders"> Erase headers. </param>
        ///<param name="hideModule">   Hide module. </param>
        ///<param name="baseAddress">  The returned module base. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::inject_module(uint32_t pid, const std::wstring& modulePath, bool eraseHeaders, bool hideModule, uintptr_t* baseAddress)
        {
            DWORD           ioBytes;
            INJECT_MODULE   params;

            params.In.ProcessId = pid;
            params.In.InjectionType = InjectLdrLoadDll;
            params.In.ErasePE = eraseHeaders;
            params.In.HideModule = hideModule;
            params.In.ModuleBase = 0;
            params.In.ModuleSize = 0;
            wcscpy_s(params.In.ModulePath, MAX_PATH, modulePath.data());

            if(!DeviceIoControl(
                _handle, RESURGENCE_INJECT_MODULE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            if(baseAddress)
                *baseAddress = (uintptr_t)params.Out.BaseAddress;

            return STATUS_SUCCESS;
        }

        ///<summary>
        /// Maps a module to the process.
        ///</summary>
        ///<param name="pid">          The process id. </param>
        ///<param name="moduleBase">   The module base. </param>
        ///<param name="moduleSize">   The module size. </param>
        ///<param name="eraseHeaders"> Erase headers. </param>
        ///<param name="hideModule">   Hide module. </param>
        ///<param name="baseAddress">  The returned module base. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS driver::mmap_module(uint32_t pid, const uint8_t* moduleBase, size_t moduleSize, bool eraseHeaders, bool hideModule, uintptr_t* baseAddress)
        {
            DWORD ioBytes;
            INJECT_MODULE params;

            params.In.ProcessId = pid;
            params.In.InjectionType = InjectManualMap;
            params.In.ErasePE = eraseHeaders;
            params.In.HideModule = hideModule;
            params.In.ModuleBase = (ULONG_PTR)moduleBase;
            params.In.ModuleSize = (ULONG)moduleSize;

            if(!DeviceIoControl(
                _handle, RESURGENCE_INJECT_MODULE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &params, RESURGENCE_INJECT_MODULE_SIZE,
                &ioBytes, NULL))
                return get_last_ntstatus();

            if(baseAddress)
                *baseAddress = (uintptr_t)params.Out.BaseAddress;

            return STATUS_SUCCESS;
        }
    }
}
