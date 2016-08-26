#include <system/process_modules.hpp>
#include <system/process.hpp>
#include <misc/exceptions.hpp>
#include <misc/winnt.hpp>

#include <algorithm>

namespace resurgence
{
    namespace system
    {
    #define INJECTION_BUFFER_SIZE 0x100

        typedef struct _INJECTION_BUFFER
        {
            UCHAR               CodeBuffer[INJECTION_BUFFER_SIZE];
            PULONG_PTR          ModuleHandle;
            UNICODE_STRING      ModulePath64;
            UNICODE_STRING32    ModulePath32;
            WCHAR               DllPath[MAX_PATH];
        } INJECTION_BUFFER, *PINJECTION_BUFFER;

        auto startsWith = [](const std::wstring& str1, const std::wstring& str2, bool ignoreCasing) {
            if(ignoreCasing) {
                std::wstring copy1 = str1, copy2 = str2;
                std::transform(copy1.begin(), copy1.end(), copy1.begin(), ::tolower);
                std::transform(copy2.begin(), copy2.end(), copy2.begin(), ::tolower);
                return copy1.compare(0, copy2.size(), copy2) == 0;
            } else {
                return str1.compare(0, str2.size(), str2) == 0;
            }
        };

        process_module::process_module()
        {
            RtlZeroMemory(this, sizeof(*this));
        }
        process_module::process_module(process* proc, PLDR_DATA_TABLE_ENTRY entry)
        {
            _process = proc;
            if(proc->is_current_process()) {
                _base = (uint8_t*)entry->DllBase;
                _size = (size_t)entry->SizeOfImage;
                _name = entry->BaseDllName.Buffer;
                _path = entry->FullDllName.Buffer;
            } else {
                _base = (uint8_t*)entry->DllBase;
                _size = (size_t)entry->SizeOfImage;
                _name = proc->memory()->read_unicode_string(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
                _path = proc->memory()->read_unicode_string(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t));
            }
        }
        process_module::process_module(process* proc, PLDR_DATA_TABLE_ENTRY32 entry)
        {
            _process = proc;
            _base = (uint8_t*)entry->DllBase;
            _size = (size_t)entry->SizeOfImage;
            _name = proc->memory()->read_unicode_string(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
            _path = proc->memory()->read_unicode_string(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t));

            auto system32 = std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\System32";
            auto syswow64 = std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\SysWOW64";
            if(startsWith(_path, std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\System32", TRUE)) {
                _path = _path.replace(0, system32.size(), syswow64);
            }
        }
        process_module::process_module(process* proc, PRTL_PROCESS_MODULE_INFORMATION entry)
        {
            wchar_t path[MAX_PATH] = {NULL};
            MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (const char*)entry->FullPathName, 256, path, MAX_PATH);

            _process = proc;
            _base = (uint8_t*)entry->ImageBase;
            _size = (size_t)entry->ImageSize;
            _name = (path + entry->OffsetToFileName);
            _path = misc::winnt::get_dos_path(path);
        }
        const portable_executable&  process_module::get_pe()
        {
            if(!_pe.is_valid())
                _pe = portable_executable::load_from_file(_path);

            return _pe;
        }
        uintptr_t process_module::get_proc_address(const std::string& name)
        {
            IMAGE_EXPORT_DIRECTORY exports;

            if(_process->is_system_idle_process()) {
                return 0;
            }

            if(_process->is_system_process()) {
                //
                // We can use the driver here. Just return 0 for now.
                // 
                return 0;
            }

            //Read the PE 
            _pe = get_pe();

            auto exportDirVA = _pe.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress;
            auto status = _process->memory()->read_bytes(_base + exportDirVA, (uint8_t*)&exports, sizeof(IMAGE_EXPORT_DIRECTORY));

            if(!NT_SUCCESS(status)) return 0;

            ULONG	 numberOfNames = exports.NumberOfNames;

            std::vector<ULONG>  addressOfFunctions(numberOfNames);
            std::vector<ULONG>  addressOfNames(numberOfNames);
            std::vector<USHORT> addressOfOrdinals(numberOfNames);

            _process->memory()->read_bytes(_base + exports.AddressOfFunctions, (uint8_t*)addressOfFunctions.data(), numberOfNames * sizeof(ULONG));
            _process->memory()->read_bytes(_base + exports.AddressOfNames, (uint8_t*)addressOfNames.data(), numberOfNames * sizeof(ULONG));
            _process->memory()->read_bytes(_base + exports.AddressOfNameOrdinals, (uint8_t*)addressOfOrdinals.data(), numberOfNames * sizeof(USHORT));

            for(ULONG i = 0; i < numberOfNames; i++) {
                std::string szName = _process->memory()->read_string(_base + addressOfNames[i], 64);
                SHORT ordinal = addressOfOrdinals[i];

                //
                //Compare it to the name we are looking for
                // 
                if(szName == name) {
                    return (uintptr_t)(_base + addressOfFunctions[ordinal]);
                }
            }

            return 0;
        }
        process_modules::process_modules(process* proc)
            : _process(proc)
        {
        }
        process_modules::process_modules()
            : _process(nullptr)
        {

        }
        std::vector<process_module> process_modules::get_all_modules()
        {
            using namespace misc;

            std::vector<process_module> modules;
            auto id = _process->get_pid();
            auto handle = _process->get_handle();

        #ifndef _WIN64
            //
            // Cannot retrieve x64 modules from x86
            // 
            if(_process->get_platform() == platform_x64) {
                set_last_ntstatus(STATUS_ACCESS_DENIED);
                return modules;
            }
        #endif

            if(!_process->is_system_idle_process()) {
                if(_process->is_system_process()) {
                    winnt::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) {
                        modules.emplace_back(_process, info);
                        return STATUS_NOT_FOUND;
                    });
                } else if(handle.is_valid()) {
                    winnt::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                        modules.emplace_back(_process, entry);
                        return STATUS_NOT_FOUND;
                    });

                #ifdef _WIN64
                    if(_process->get_platform() == platform_x86) {
                        std::vector<process_module> modules32;
                        winnt::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
                            modules32.emplace_back(_process, entry);
                            return STATUS_NOT_FOUND;
                        });
                        if(modules32.size() > 1) {
                            auto begin = ++std::begin(modules32);
                            auto end = std::end(modules32);
                            modules.insert(std::end(modules), begin, end);
                        }
                    }
                #endif
                } else {
                    //
                    // Handle was invalid, this is probably caused by the process being protected
                    // 
                    set_last_ntstatus(STATUS_ACCESS_DENIED);
                }
            }
            return modules;
        }
        process_module process_modules::get_main_module()
        {
            return get_module_by_load_order(0);
        }
        process_module process_modules::get_module_by_name(const std::wstring& name)
        {
            using namespace misc;

            process_module mod;
            auto id = _process->get_pid();
            auto handle = _process->get_handle();

        #ifndef _WIN64
            //
            // Cannot retrieve x64 modules from x86
            // 
            if(_process->get_platform() == platform_x64) {
                set_last_ntstatus(STATUS_ACCESS_DENIED);
                return modules;
            }
        #endif

            if(!_process->is_system_idle_process()) {
                if(_process->is_system_process()) {
                    winnt::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) {

                        wchar_t dllname[MAX_PATH] = {NULL};
                        MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (const char*)(info->FullPathName + info->OffsetToFileName), 256, dllname, MAX_PATH);

                        if(_wcsicmp(std::data(dllname), std::data(name)) == 0) {
                            mod = process_module(_process, info);
                            return STATUS_SUCCESS;
                        }
                        return STATUS_NOT_FOUND;
                    });
                } else if(handle.is_valid()) {
                #ifdef _WIN64
                    if(_process->get_platform() == platform_x86) {
                        std::vector<process_module> modules32;
                        winnt::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
                            auto buffer
                                = _process->memory()->read_unicode_string(
                                    entry->BaseDllName.Buffer,
                                    entry->BaseDllName.Length / sizeof(wchar_t));
                            if(_wcsicmp(std::data(buffer), std::data(name)) == 0) {
                                mod = process_module(_process, entry);
                                return STATUS_SUCCESS;
                            }
                            return STATUS_NOT_FOUND;
                        });
                    } else {
                        winnt::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                            auto buffer
                                = _process->memory()->read_unicode_string(
                                    entry->BaseDllName.Buffer,
                                    entry->BaseDllName.Length / sizeof(wchar_t));
                            if(_wcsicmp(std::data(buffer), std::data(name)) == 0) {
                                mod = process_module(_process, entry);
                                return STATUS_SUCCESS;
                            }
                            return STATUS_NOT_FOUND;
                        });
                    }
                #endif
                } else {
                    //
                    // Handle was invalid, this is probably caused by the process being protected
                    // 
                    set_last_ntstatus(STATUS_ACCESS_DENIED);
                }
            }
            return mod;
        }
        process_module process_modules::get_module_by_address(const std::uint8_t* address)
        {
            using namespace misc;

            process_module mod;
            auto id = _process->get_pid();
            auto handle = _process->get_handle();

        #ifndef _WIN64
            //
            // Cannot retrieve x64 modules from x86
            // 
            if(_process->get_platform() == platform_x64) {
                set_last_ntstatus(STATUS_ACCESS_DENIED);
                return modules;
            }
        #endif

            if(!_process->is_system_idle_process()) {
                if(_process->is_system_process()) {
                    winnt::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION entry) {
                        if(address >= entry->ImageBase && address <= PTR_ADD(entry->ImageBase, entry->ImageSize)) {
                            mod = process_module(_process, entry);
                            return STATUS_SUCCESS;
                        }
                        return STATUS_NOT_FOUND;
                    });
                } else if(handle.is_valid()) {
                    winnt::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                        if(address >= entry->DllBase && address <= PTR_ADD(entry->DllBase, entry->SizeOfImage)) {
                            mod = process_module(_process, entry);
                            return STATUS_SUCCESS;
                        }
                        return STATUS_NOT_FOUND;
                    });

                #ifdef _WIN64
                    if(_process->get_platform() == platform_x86) {
                        std::vector<process_module> modules32;
                        winnt::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
                            if((ULONG)address >= entry->DllBase && (ULONG)address <= entry->DllBase + entry->SizeOfImage) {
                                mod = process_module(_process, entry);
                                return STATUS_SUCCESS;
                            }
                            return STATUS_NOT_FOUND;
                        });
                    }
                #endif
                } else {
                    //
                    // Handle was invalid, this is probably caused by the process being protected
                    // 
                    set_last_ntstatus(STATUS_ACCESS_DENIED);
                }
            }
            return mod;
        }
        process_module process_modules::get_module_by_load_order(uint32_t i)
        {
            process_module mod;
            uint32_t current = 0;

        #ifdef _WIN64
            if(_process->get_platform() == platform_x86) {
                misc::winnt::enumerate_process_modules32(_process->get_handle().get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
                    if(current++ == i) {
                        mod = process_module(_process, entry);
                        return STATUS_SUCCESS;
                    }
                    return STATUS_NOT_FOUND;
                });
                return mod;
            } else {
            #endif
                misc::winnt::enumerate_process_modules(_process->get_handle().get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                    if(current++ == i) {
                        mod = process_module(_process, entry);
                        return STATUS_SUCCESS;
                    }
                    return STATUS_NOT_FOUND;
                });
                return mod;
            #ifdef _WIN64
            }
        #endif
        }
        NTSTATUS process_modules::inject_module(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module /*= nullptr*/)
        {
            _process->ensure_access(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD);

            switch(_process->get_platform()) {
                case platform_x86:
                    return inject_module32(path, injectionType, flags, module);
                case platform_x64:
                    return inject_module64(path, injectionType, flags, module);
            }
            return STATUS_UNSUCCESSFUL;
        }
        NTSTATUS process_modules::inject_module32(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module)
        {
            switch(injectionType) {
                case INJECTION_TYPE_LDRLOADLL:
                    goto LDRLOADLL_INJECTION;
                case INJECTION_TYPE_LOADLIBRARY:
                    goto LOADLIBRARY_INJECTION;
                default:
                    return STATUS_INVALID_PARAMETER_2;
            }
        LOADLIBRARY_INJECTION:
            {
            auto fnLoadLibraryW = get_module_by_name(L"kernel32.dll").get_proc_address("LoadLibraryW");
            if(!fnLoadLibraryW) return STATUS_PROCEDURE_NOT_FOUND;

                PINJECTION_BUFFER remoteBuffer = nullptr;

                uint8_t codeBuffer[] =
                {
                    0x55,                               //push ebp                         |
                    0x89, 0xE5,                         //mov  ebp,esp                     |
                    0x68, 0x00, 0x00, 0x00, 0x00,       //push ModulePath                  | offset 0x04
                    0xE8, 0x00, 0x00, 0x00, 0x00,       //call LoadLibraryW                | offset 0x09
                    0xA3, 0x00, 0x00, 0x00, 0x00,       //mov  ModuleHandle, eax           | offset 0x0E
                    0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, //mov  eax, large fs:18h           |
                    0x8B, 0x40, 0x34,                   //mov  eax, dword ptr[eax + 34h]   |
                    0x5D,                               //pop  ebp                         |
                    0xC2, 0x04, 0x00                    //ret  0x4                         |
                };

                auto status = _process->memory()->allocate_ex((uint8_t**)&remoteBuffer, sizeof(INJECTION_BUFFER), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                if(!NT_SUCCESS(status)) return status;

                *(ULONG*)((PUCHAR)codeBuffer + 0x04) = (ULONG)(ULONG_PTR)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, DllPath);
                *(ULONG*)((PUCHAR)codeBuffer + 0x09) = (ULONG)(ULONG_PTR)(fnLoadLibraryW - ((ULONG_PTR)remoteBuffer + 0x0D));
                *(ULONG*)((PUCHAR)codeBuffer + 0x0E) = (ULONG)(ULONG_PTR)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle);

                _process->memory()->write_bytes((uint8_t*)remoteBuffer, codeBuffer, sizeof(INJECTION_BUFFER));
                _process->memory()->write_bytes((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, DllPath), (uint8_t*)std::data(path), (path.size() + 1) * sizeof(wchar_t));

                auto ret = misc::winnt::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

                if(NT_SUCCESS(ret) && module) {
                    ULONG handle = _process->memory()->read<ULONG>((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle));

                    *module = get_module_by_address((uint8_t*)handle);
                }
                return ret;
            }
        LDRLOADLL_INJECTION:
            {
                auto fnLdrLoadDll = get_module_by_name(L"ntdll.dll").get_proc_address("LdrLoadDll");
                if(!fnLdrLoadDll) return STATUS_PROCEDURE_NOT_FOUND;

                PINJECTION_BUFFER remoteBuffer = nullptr;
                UNICODE_STRING32 usModulePath32;
                uint8_t codeBuffer[] =
                {
                    0x55,                      		//push   ebp            | 
                    0x89, 0xE5,                   	//mov    ebp,esp        | 
                    0x68, 0x00, 0x00, 0x00, 0x00,   //push   ModuleHandle   | offset 0x04
                    0x68, 0x00, 0x00, 0x00, 0x00,   //push   ModulePath     | offset 0x09
                    0x6A, 0x00,                    	//push   0              | 
                    0x6A, 0x00,                    	//push   0              | 
                    0xE8, 0x00, 0x00, 0x00, 0x00,  	//call   LdrLoadDll     | offset 0x12
                    0x5D,                      		//pop    ebp            | 
                    0xC2, 0x04, 0x00             	//ret    4              | 
                };

                auto status = _process->memory()->allocate_ex((uint8_t**)&remoteBuffer, sizeof(INJECTION_BUFFER), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                if(!NT_SUCCESS(status)) return status;

                *(ULONG*)((PUCHAR)codeBuffer + 0x04) = (ULONG)(ULONG_PTR)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle);
                *(ULONG*)((PUCHAR)codeBuffer + 0x09) = (ULONG)(ULONG_PTR)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModulePath32);
                *(ULONG*)((PUCHAR)codeBuffer + 0x12) = (ULONG)(ULONG_PTR)(fnLdrLoadDll - ((ULONG_PTR)remoteBuffer + 0x16));

                usModulePath32.Length = (USHORT)(path.size() * sizeof(wchar_t));
                usModulePath32.MaximumLength = MAX_PATH * sizeof(wchar_t);
                usModulePath32.Buffer = (ULONG)(ULONG_PTR)remoteBuffer->DllPath;

                _process->memory()->write_bytes((uint8_t*)remoteBuffer, codeBuffer, sizeof(INJECTION_BUFFER));
                _process->memory()->write_bytes((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, DllPath), (uint8_t*)std::data(path), path.size() * sizeof(wchar_t));
                _process->memory()->write_bytes((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModulePath32), (uint8_t*)&usModulePath32, sizeof(UNICODE_STRING32));

                auto ret = misc::winnt::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

                if(NT_SUCCESS(ret) && module) {
                    ULONG handle = _process->memory()->read<ULONG>((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle));

                    *module = get_module_by_address((uint8_t*)handle);
                }
                return ret;
            }
        }
        NTSTATUS process_modules::inject_module64(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module)
        {
            switch(injectionType) {
                case INJECTION_TYPE_LDRLOADLL:
                    goto LDRLOADLL_INJECTION;
                case INJECTION_TYPE_LOADLIBRARY:
                    goto LOADLIBRARY_INJECTION;
                default:
                    return STATUS_INVALID_PARAMETER_2;
            }
        LOADLIBRARY_INJECTION:
            {
                auto fnLoadLibraryW = get_module_by_name(L"kernel32.dll").get_proc_address("LoadLibraryW");
                if(!fnLoadLibraryW) return STATUS_PROCEDURE_NOT_FOUND;

            #ifdef _WIN64
                PINJECTION_BUFFER remoteBuffer = nullptr;
                uint8_t codeBuffer[] =
                {
                    0x48, 0x83, 0xEC, 0x28,									//sub rsp, 0x28		      | 
                    0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,                     //mov rcs, ModulePath	  | offset 0x06
                    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                     //mov rax, LoadLibraryW   | offset 0x10
                    0xFF, 0xD0,                                             //call rax				  |
                    0x48, 0xA3, 0, 0, 0, 0, 0, 0, 0, 0,                     //mov ModuleHandle, rax   | offset 0x1C
                    0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,   //mov rax, gs:30h		  |
                    0x8B, 0x40, 0x68,                                       //mov raxx, [rax + 68h]   |
                    0x48, 0x83, 0xC4, 0x28,									//add rsp, 0x28		      |
                    0xC3													//ret					  | 
                };

                auto status = _process->memory()->allocate_ex((uint8_t**)&remoteBuffer, sizeof(INJECTION_BUFFER), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                if(!NT_SUCCESS(status)) return status;

                *(ULONGLONG*)((PUCHAR)codeBuffer + 0x06) = (ULONGLONG)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, DllPath);
                *(ULONGLONG*)((PUCHAR)codeBuffer + 0x10) = (ULONGLONG)fnLoadLibraryW;
                *(ULONGLONG*)((PUCHAR)codeBuffer + 0x1C) = (ULONGLONG)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle);

                _process->memory()->write_bytes((uint8_t*)remoteBuffer, codeBuffer, sizeof(INJECTION_BUFFER));
                _process->memory()->write_bytes((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, DllPath), (uint8_t*)std::data(path), (path.size() + 1) * sizeof(wchar_t));

                auto ret = misc::winnt::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

                if(NT_SUCCESS(ret) && module) {
                    HANDLE handle = _process->memory()->read<HANDLE>((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle));

                    *module = get_module_by_address((uint8_t*)handle);
                }
                return ret;
            #else
                //
                // Cannot inject into x64 process from wow64
                // 
                return 0;
            #endif
            }
        LDRLOADLL_INJECTION:
            {
                auto fnLdrLoadDll = get_module_by_name(L"ntdll.dll").get_proc_address("LdrLoadDll");
                if(!fnLdrLoadDll) return STATUS_PROCEDURE_NOT_FOUND;

            #ifdef _WIN64
                PINJECTION_BUFFER remoteBuffer = nullptr;
                UNICODE_STRING usModulePath64;
                uint8_t codeBuffer[] =
                {
                    0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28		  |
                    0x48, 0x31, 0xC9,                       // xor rcx, rcx			  |
                    0x48, 0x31, 0xD2,                       // xor rdx, rdx			  |
                    0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle   | offset 0x0C
                    0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName | offset 0x16
                    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll    | offset 0x20
                    0xFF, 0xD0,                             // call rax				  |
                    0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28		  |
                    0xC3                                    // ret					  |
                };

                auto status = _process->memory()->allocate_ex((uint8_t**)&remoteBuffer, sizeof(INJECTION_BUFFER), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                if(!NT_SUCCESS(status)) return status;

                *(ULONGLONG*)((PUCHAR)codeBuffer + 0x0C) = (ULONGLONG)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle);
                *(ULONGLONG*)((PUCHAR)codeBuffer + 0x16) = (ULONGLONG)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModulePath64);
                *(ULONGLONG*)((PUCHAR)codeBuffer + 0x20) = (ULONGLONG)fnLdrLoadDll;

                usModulePath64.Length = (USHORT)(path.size() * sizeof(wchar_t));
                usModulePath64.MaximumLength = MAX_PATH * sizeof(wchar_t);
                usModulePath64.Buffer = remoteBuffer->DllPath;

                _process->memory()->write_bytes((uint8_t*)remoteBuffer, codeBuffer, sizeof(INJECTION_BUFFER));
                _process->memory()->write_bytes((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, DllPath), (uint8_t*)std::data(path), path.size() * sizeof(wchar_t));
                _process->memory()->write_bytes((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModulePath64), (uint8_t*)&usModulePath64, sizeof(UNICODE_STRING));

                auto ret = misc::winnt::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

                if(NT_SUCCESS(ret) && module) {
                    HANDLE handle = _process->memory()->read<HANDLE>((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle));

                    *module = get_module_by_address((uint8_t*)handle);
                }
                return ret;
            #else
                //
                // Cannot inject into x64 process from wow64
                // 
                return 0;
            #endif
            }
        }
    }
}