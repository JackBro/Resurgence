#include <system/process.hpp>
#include <misc/exceptions.hpp>
#include <misc/native.hpp>

#include <bitset>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

namespace resurgence
{
    namespace system
    {
        process::process()
            : _handle(nullptr),
            _memory(this),
            _modules(this),
            _threads(this),
            _symbols(this)
        {
            RtlZeroMemory(&_info, sizeof(_info));
            _info.pid = (uint32_t)-1;
        }
        process::process(uint32_t pid)
            : _handle(nullptr),
            _memory(this),
            _modules(this),
            _threads(this),
            _symbols(this)
        {
            RtlZeroMemory(&_info, sizeof(_info));

            _info.pid = pid;
            _info.current_process = GetCurrentProcessId() == pid;

            if(!is_system_idle_process()) {
                if(!is_current_process()) {
                    open(PROCESS_DEFAULT_ACCESS);
                } else {
                    _handle = misc::safe_process_handle(GetCurrentProcess());
                }
            }
            get_process_info();

        }
        process::process(const process& rhs)
            : _memory(this),
            _modules(this),
            _threads(this),
            _symbols(this)
        {
            _handle = rhs._handle;
            _info = rhs._info;
        }
        process& process::operator=(const process& rhs)
        {
            _memory = process_memory(this);
            _modules = process_modules(this);
            _threads = process_threads(this);
            _symbols = symbol_system(this);
            _handle = rhs._handle;
            _info = rhs._info;
            return *this;
        }
        void process::get_process_info()
        {
            using namespace misc;

            if(is_system_idle_process()) {
                _info.target_platform = platform_x64;
                _info.parent_pid = 0;
                _info.peb_address = 0;
                _info.wow64peb_address = 0;
                _info.name = L"System Idle Process";
                _info.path = L"N/A";
            } else if(is_system_process()) {
                _info.target_platform = platform_x64;
                _info.parent_pid = 0;
                _info.peb_address = 0;
                _info.wow64peb_address = 0;
                _info.name = L"System Process";
                native::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) {
                    wchar_t processPath[MAX_PATH];
                    ZeroMemory(processPath, sizeof(processPath));
                    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCCH)info->FullPathName, 256, processPath, MAX_PATH);
                    _info.path = native::get_dos_path(processPath);
                    return STATUS_SUCCESS;
                });
            } else {
                auto needDispose = false;
                auto handle = HANDLE{nullptr};

                if(!_handle.is_valid()) {
                    native::open_process(&handle, get_pid(), PROCESS_QUERY_LIMITED_INFORMATION);
                    needDispose = true;
                } else
                    handle = _handle.get();

                if(handle) {
                    PPEB32 peb32;
                    auto basic_info = (PPROCESS_BASIC_INFORMATION)native::query_process_information(handle, ProcessBasicInformation);
                    auto fileName = (PUNICODE_STRING)native::query_process_information(handle, ProcessImageFileName);

                    _info.target_platform   = native::process_is_wow64(handle, &peb32) ? platform_x86 : platform_x64;
                    _info.parent_pid        = static_cast<uint32_t>(basic_info->InheritedFromUniqueProcessId);
                    _info.peb_address       = reinterpret_cast<uintptr_t>(basic_info->PebBaseAddress);
                    _info.path              = native::get_dos_path(std::wstring(fileName->Buffer, fileName->Length / sizeof(wchar_t)));
                    _info.name              = PathFindFileNameW(fileName->Buffer);

                #ifdef _WIN64
                    if(_info.target_platform == platform_x86) {
                        _info.wow64peb_address = reinterpret_cast<uint32_t>(peb32);
                    } else {
                        _info.wow64peb_address = 0;
                    }
                #else
                    if(_info.target_platform == platform_x86) {
                        _info.wow64peb_address  = reinterpret_cast<uint32_t>(peb32);
                        _info.peb_address       = _info.peb_address - PAGE_SIZE;
                    } else {
                        _info.wow64peb_address  = 0;
                        _info.peb_address       = 0;
                    }
                #endif

                    free_local_buffer(basic_info);
                    free_local_buffer(fileName);
                    
                    if(needDispose)
                        NtClose(handle);
                }
            }
        }
        std::vector<process> process::get_processes()
        {
            std::vector<process> processes;

            native::enumerate_processes([&](PSYSTEM_PROCESS_INFORMATION info) -> NTSTATUS {
                processes.push_back(process((uint32_t)info->UniqueProcessId));
                return STATUS_NOT_FOUND;
            });

            return processes;
        }
        process process::get_current_process()
        {
            return process(GetCurrentProcessId());
        }
        std::vector<process> process::get_process_by_name(const std::wstring& name)
        {
            std::vector<process> processes;

            native::enumerate_processes([&](PSYSTEM_PROCESS_INFORMATION info) -> NTSTATUS {
                if(info->ImageName.Length > 0 && !_wcsicmp(std::data(name), info->ImageName.Buffer))
                    processes.emplace_back(static_cast<uint32_t>((ULONG_PTR)info->UniqueProcessId));
                return STATUS_NOT_FOUND;
            });

            return processes;
        }
        bool process::grant_privilege(uint32_t privilege)
        {
            BOOLEAN enabled;
            return NT_SUCCESS(RtlAdjustPrivilege(privilege, TRUE, FALSE, &enabled));
        }
        bool process::revoke_privilege(uint32_t privilege)
        {
            BOOLEAN enabled;
            return NT_SUCCESS(RtlAdjustPrivilege(privilege, FALSE, FALSE, &enabled));
        }

        void process::ensure_access(uint32_t access) const
        {
            if(!_handle.has_access(access))
                throw misc::exception("Handle doesnt have the required access rights");
        }
        const std::wstring& process::get_name() const
        {
            return _info.name;
        }
        const std::wstring& process::get_path() const
        {
            return _info.path;
        }
        uintptr_t process::get_peb_address() const
        {
            return _info.peb_address;
        }
        uint32_t process::get_wow64_peb_address() const
        {
            return _info.wow64peb_address;
        }
        int process::get_pid() const
        {
            return _info.pid;
        }
        platform process::get_platform() const
        {
            return _info.target_platform;
        }
        const misc::safe_process_handle& process::get_handle() const
        {
            return _handle;
        }
        bool process::is_current_process() const
        {
            return _info.current_process;
        }
        bool process::is_system_idle_process() const
        {
            return get_pid() == SYSTEM_IDLE_PROCESS;
        }
        bool process::is_system_process() const
        {
            return get_pid() == SYSTEM_PROCESS;
        }
        bool process::is_valid() const
        {
            return _info.pid != (uint32_t)-1;
        }
        bool process::has_exited() const
        {
            return WaitForSingleObject(_handle.get(), 0) != WAIT_TIMEOUT;
        }
        bool process::is_being_debugged()
        {
            ensure_access(PROCESS_VM_READ);

            return !!memory()->read<BOOLEAN>(PTR_ADD(_info.peb_address, FIELD_OFFSET(PEB, BeingDebugged)));
        }
        bool process::is_protected()
        {
            ensure_access(PROCESS_VM_READ);

            std::bitset<8> bitfield(memory()->read<BOOLEAN>(PTR_ADD(_info.peb_address, FIELD_OFFSET(PEB, BitField))));


            return bitfield.test(1) || bitfield.test(7);
        }
        NTSTATUS process::open(uint32_t access)
        {
            if(is_current_process())
                return STATUS_SUCCESS;

            if(_handle.is_valid()) {
                auto handle_info = (POBJECT_BASIC_INFORMATION)native::query_object_information(_handle.get(), ObjectBasicInformation);

                if(handle_info) {
                    //
                    // Already has the desired access
                    //
                    bool b =
                        handle_info->GrantedAccess == access ||
                        handle_info->GrantedAccess == PROCESS_ALL_ACCESS;

                    free_local_buffer(handle_info);

                    if(b) return STATUS_SUCCESS;
                }
            }

            auto handle = HANDLE{nullptr};
            auto status = native::open_process(&handle, get_pid(), PROCESS_DEFAULT_ACCESS | access);

            if(NT_SUCCESS(status)) {
                _handle = misc::safe_process_handle(handle);
            }

            return status;
        }
        void process::terminate(uint32_t exitCode /*= 0*/)
        {
            ensure_access(PROCESS_TERMINATE);

            native::terminate_process(_handle.get(), exitCode);
        }
        NTSTATUS process::get_exit_code() const
        {
            DWORD exitCode = 0;
            GetExitCodeProcess(_handle.get(), &exitCode);
            return (NTSTATUS)exitCode;
        }
        std::wstring process::get_command_line()
        {
            ensure_access(PROCESS_VM_READ);
            
            if(_info.target_platform == platform_x86) {

                ULONG address;
                RTL_USER_PROCESS_PARAMETERS parameters;

                //
                // Read ProcessParameters address
                // 
                address = memory()->read<ULONG>(
                    PTR_ADD(_info.peb_address,
                        FIELD_OFFSET(PEB, ProcessParameters))
                    );

                parameters = memory()->read<RTL_USER_PROCESS_PARAMETERS>((uint8_t*)address);

                return memory()->read_unicode_string(parameters.CommandLine.Buffer, parameters.CommandLine.Length / sizeof(wchar_t));
            } else {
                ULONGLONG address;
                RTL_USER_PROCESS_PARAMETERS parameters;

                //
                // Read ProcessParameters address
                // 
                address = memory()->read<ULONGLONG>(
                    PTR_ADD(_info.peb_address,
                        FIELD_OFFSET(PEB, ProcessParameters))
                    );

                parameters = memory()->read<RTL_USER_PROCESS_PARAMETERS>((uint8_t*)address);

                return memory()->read_unicode_string(parameters.CommandLine.Buffer, parameters.CommandLine.Length / sizeof(wchar_t));
            }
        }
    }
}