#include <system/process_modules.hpp>
#include <system/process.hpp>
#include <misc/exceptions.hpp>
#include <misc/native.hpp>

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

        ///<summary>
        /// Default ctor.
        ///</summary>
        process_module::process_module()
        {
            RtlZeroMemory(this, sizeof(*this));
        }

        ///<summary>
        /// x64 module constructor.
        ///</summary>
        ///<param name="proc">  The owner process. </param>
        ///<param name="entry"> The loader table entry. </param>
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

        ///<summary>
        /// x86 module constructor.
        ///</summary>
        ///<param name="proc">  The owner process. </param>
        ///<param name="entry"> The loader table entry. </param>
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

        ///<summary>
        /// System module constructor.
        ///</summary>
        ///<param name="proc">  The owner process. </param>
        ///<param name="entry"> The module information. </param>
        process_module::process_module(process* proc, PRTL_PROCESS_MODULE_INFORMATION entry)
        {
            wchar_t path[MAX_PATH] = {NULL};
            MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (const char*)entry->FullPathName, 256, path, MAX_PATH);

            _process = proc;
            _base = (uint8_t*)entry->ImageBase;
            _size = (size_t)entry->ImageSize;
            _name = (path + entry->OffsetToFileName);
            _path = native::get_dos_path(path);
        }

        ///<summary>
        /// Gets the portable executable linked with this module.
        ///</summary>
        const portable_executable&  process_module::get_pe()
        {
            if(!_pe.is_valid())
                _pe = portable_executable::load_from_file(_path);

            return _pe;
        }

        ///<summary>
        /// Get procedure address.
        ///</summary>
        ///<param name="name">  The function name. </param>
        ///<returns>
        /// The address, 0 on failure.
        ///</returns>
        uintptr_t process_module::get_proc_address(const std::string& name)
        {
            NTSTATUS                status;
            native::mapped_image    image;
            ANSI_STRING             asName;
            PVOID                   address = nullptr;
            RtlInitAnsiString(&asName, std::data(name));

            if(_process->is_system_idle_process()) {
                return 0;
            }

            if(_process->is_current_process()) {
                status = LdrGetProcedureAddress(_base, &asName, 0, &address);
                return reinterpret_cast<uintptr_t>(address);
            }

            status = native::load_mapped_image(_path, image);

            if(NT_SUCCESS(status)) {
                PIMAGE_DATA_DIRECTORY   exportDataDirectory;
                PIMAGE_EXPORT_DIRECTORY exportDir;

                if(image.nt_hdrs32)
                    exportDataDirectory = &image.nt_hdrs32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                else
                    exportDataDirectory = &image.nt_hdrs64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                exportDir 
                    = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
                        native::mapped_image_rva_to_va(image, exportDataDirectory->VirtualAddress)
                        );

                auto name_table     = reinterpret_cast<uint32_t*>(native::mapped_image_rva_to_va(image, exportDir->AddressOfNames));
                auto address_table  = reinterpret_cast<uint32_t*>(native::mapped_image_rva_to_va(image, exportDir->AddressOfFunctions));
                auto ordinal_table  = reinterpret_cast<uint16_t*>(native::mapped_image_rva_to_va(image, exportDir->AddressOfNameOrdinals));

                if(name_table && address_table && ordinal_table) {
                    for(ULONG i = 0; i < exportDir->NumberOfNames; i++) {
                        PCSTR szName = (PCSTR)native::mapped_image_rva_to_va(image, name_table[i]);
                        uint16_t ordinal = ordinal_table[i];

                        if(ordinal >= exportDir->NumberOfFunctions)
                            return STATUS_PROCEDURE_NOT_FOUND;

                        //
                        //Compare it to the name we are looking for
                        // 
                        if(szName == name) {
                            auto rva = address_table[ordinal];
                            if((rva >= exportDataDirectory->VirtualAddress) &&
                                (rva < exportDataDirectory->VirtualAddress + exportDataDirectory->Size)
                                ) {
                                // This is a forwarder
                                set_last_ntstatus(STATUS_NOT_SUPPORTED);
                            } else {
                                address = PTR_ADD(_base, rva);
                            }
                        }
                    }
                } else {
                    set_last_ntstatus(STATUS_UNSUCCESSFUL);
                }

                native::unload_mapped_image(image);
                return reinterpret_cast<uintptr_t>(address);
            }
            return 0;
        }

        //-----------------------------------------------------------------------
        
        ///<summary>
        /// Default ctor.
        ///</summary>
        ///<param name="proc"> The owner process. </param>
        process_modules::process_modules(process* proc)
            : _process(proc)
        {
        }

        ///<summary>
        /// Get process modules.
        ///</summary>
        ///<returns> A vector with all modules loaded by the process. </returns>
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
                    native::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) {
                        modules.emplace_back(_process, info);
                        return STATUS_NOT_FOUND;
                    });
                } else if(handle.is_valid()) {
                    native::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                        modules.emplace_back(_process, entry);
                        return STATUS_NOT_FOUND;
                    });

                #ifdef _WIN64
                    if(_process->get_platform() == platform_x86) {
                        std::vector<process_module> modules32;
                        native::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
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

        ///<summary>
        /// Get main module.
        ///</summary>
        ///<returns> The main module. </returns>
        process_module process_modules::get_main_module()
        {
            return get_module_by_load_order(0);
        }

        ///<summary>
        /// Get module by name.
        ///</summary>
        ///<param name="name"> The name. </param>
        ///<returns> 
        /// The module. 
        ///</returns>
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
                return mod;
            }
        #endif

            if(!_process->is_system_idle_process()) {
                if(_process->is_system_process()) {
                    native::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) {

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
                        native::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
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
                        native::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
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

        ///<summary>
        /// Get the module that contains the target address.
        ///</summary>
        ///<param name="address"> The address. </param>
        ///<returns> 
        /// The module. 
        ///</returns>
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
                return mod;
            }
        #endif

            if(!_process->is_system_idle_process()) {
                if(_process->is_system_process()) {
                    native::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION entry) {
                        if(address >= entry->ImageBase && address <= PTR_ADD(entry->ImageBase, entry->ImageSize)) {
                            mod = process_module(_process, entry);
                            return STATUS_SUCCESS;
                        }
                        return STATUS_NOT_FOUND;
                    });
                } else if(handle.is_valid()) {
                    native::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                        if(address >= entry->DllBase && address <= PTR_ADD(entry->DllBase, entry->SizeOfImage)) {
                            mod = process_module(_process, entry);
                            return STATUS_SUCCESS;
                        }
                        return STATUS_NOT_FOUND;
                    });

                #ifdef _WIN64
                    if(_process->get_platform() == platform_x86) {
                        std::vector<process_module> modules32;
                        native::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
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

        ///<summary>
        /// Get module by load order.
        ///</summary>
        ///<param name="i"> The module number. </param>
        ///<returns> 
        /// The module. 
        ///</returns>
        process_module process_modules::get_module_by_load_order(uint32_t i)
        {
            using namespace misc;

            process_module mod;

            int index   = 0;
            auto id     = _process->get_pid();
            auto handle = _process->get_handle();

        #ifndef _WIN64
            //
            // Cannot retrieve x64 modules from x86
            // 
            if(_process->get_platform() == platform_x64) {
                set_last_ntstatus(STATUS_ACCESS_DENIED);
                return mod;
            }
        #endif

            if(!_process->is_system_idle_process()) {
                if(_process->is_system_process()) {
                    native::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION entry) {
                        if(index++ == i) {
                            mod = process_module(_process, entry);
                            return STATUS_SUCCESS;
                        }
                        return STATUS_NOT_FOUND;
                    });
                } else if(handle.is_valid()) {
                    native::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                        if(index++ == i) {
                            mod = process_module(_process, entry);
                            return STATUS_SUCCESS;
                        }
                        return STATUS_NOT_FOUND;
                    });

                #ifdef _WIN64
                    if(_process->get_platform() == platform_x86) {
                        std::vector<process_module> modules32;
                        native::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
                            if(index++ == i) {
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

        ///<summary>
        /// Injects a module.
        ///</summary>
        ///<param name="path">          The module path. </param>
        ///<param name="injectionType"> The injection type. </param>
        ///<param name="flags">         The injection flags. </param>
        ///<param name="module">        The injected module entry. </param>
        ///<returns> 
        /// The status code. 
        ///</returns>
        NTSTATUS process_modules::inject_module(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module /*= nullptr*/)
        {
            _process->ensure_access(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD);

            NTSTATUS status = STATUS_UNSUCCESSFUL;
            process_module mod;

            switch(_process->get_platform()) {
                case platform_x86:
                    status = inject_module32(path, injectionType, &mod);
                case platform_x64:
                    status = inject_module64(path, injectionType, &mod);
            }
            if(NT_SUCCESS(status)) {
                //
                // TODO: Post injection stuff here
                //
                //if(flags & INJECTION_HIDE_MODULE) {
                //    mod.unlink();
                //}
                //if(flags & INJECTION_ERASE_HEADERS) {
                //    mod.erase_headers();
                //}
            }
            return status;
        }

        ///<summary>
        /// [Internal] Injects a module on a x86 process.
        ///</summary>
        ///<param name="path">          The module path. </param>
        ///<param name="injectionType"> The injection type. </param>
        ///<param name="module">        The injected module entry. </param>
        ///<returns> 
        /// The status code. 
        ///</returns>
        NTSTATUS process_modules::inject_module32(const std::wstring& path, uint32_t injectionType, process_module* module)
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

                auto ret = native::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

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

                auto ret = native::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

                if(NT_SUCCESS(ret) && module) {
                    ULONG handle = _process->memory()->read<ULONG>((uint8_t*)remoteBuffer + FIELD_OFFSET(INJECTION_BUFFER, ModuleHandle));

                    *module = get_module_by_address((uint8_t*)handle);
                }
                return ret;
            }
        }

        ///<summary>
        /// [Internal] Injects a module on a x86 process.
        ///</summary>
        ///<param name="path">          The module path. </param>
        ///<param name="injectionType"> The injection type. </param>
        ///<param name="module">        The injected module entry. </param>
        ///<returns> 
        /// The status code. 
        ///</returns>
        NTSTATUS process_modules::inject_module64(const std::wstring& path, uint32_t injectionType, process_module* module)
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

                auto ret = native::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

                if(NT_SUCCESS(ret)) {
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

                auto ret = native::create_thread(_process->get_handle().get(), remoteBuffer, nullptr, true);

                if(NT_SUCCESS(ret)) {
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