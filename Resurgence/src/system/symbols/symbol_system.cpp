#include <system/symbols/symbol_system.hpp>
#include <system/process.hpp>
#include <misc/exceptions.hpp>
#include <misc/native.hpp>

#include <sstream>
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

namespace resurgence
{
    namespace system
    {
        ULONG_PTR LastFakeHandle = 0;

        bool                    symbol_system::s_Initialized;
        HANDLE                  symbol_system::s_SymbolHandle;
        std::vector<DWORD64>    symbol_system::s_LoadedModules;
        std::mutex              symbol_system::s_LoadedModulesMutex;

        symbol_info::symbol_info(process* proc, PSYMBOL_INFOW info, uintptr_t displacement)
        {
            _process = proc;
            _module = _process->modules()->get_module_by_address(reinterpret_cast<uint8_t*>(info->Address));
            if(info->ModBase != 0) {
                _moduleBase = info->ModBase;
            } else {
                _moduleBase = reinterpret_cast<uintptr_t>(_module.get_base());
            }
            _address = info->Address;
            _disp = displacement;
            build_name(info, displacement);
        }

        void symbol_info::build_name(PSYMBOL_INFOW info, uintptr_t displacement)
        {
            wchar_t buffer[1024];
            auto module = _process->modules()->get_module_by_address(reinterpret_cast<uint8_t*>(info->Address));
            auto moduleName = module.get_name();

            if(moduleName.empty()) {
                //
                // We don't have a module name.
                // Return an address;
                //
                swprintf_s(buffer, L"0x%p", (PVOID)info->Address);
                _name = buffer;
            } else {
                if(info->NameLen == 0) {
                    //
                    // We have a module name but not a symbol name.
                    // Return module+offset;
                    //
                    swprintf_s(buffer, L"%ws+0x%p", std::data(moduleName), (PVOID)(info->Address - (uintptr_t)module.get_base()));
                    _name = buffer;
                } else {
                    //
                    // We have a module AND symbol name.
                    // Return module!symbol+diplacement
                    //
                    if(displacement == 0) {
                        swprintf_s(buffer, L"%ws!%s", std::data(moduleName), info->Name);
                    } else {
                        swprintf_s(buffer, L"%ws!%s+0x%X", std::data(moduleName), info->Name, static_cast<int>(displacement));
                    }
                    _name = buffer;
                }
            }
        }

        symbol_system::symbol_system(process* proc)
            : _process(proc)
        {
        }
        symbol_system::~symbol_system()
        {
        }
        bool symbol_system::is_initialized()
        {
            return s_Initialized;
        }
        void symbol_system::initialize()
        {
            if(s_Initialized) {
                cleanup();
            }
            bool realHandle = false;
            if(!_process->is_system_idle_process()) {
                static ACCESS_MASK accesses[] =
                {
                    STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff, // pre-Vista full access
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    MAXIMUM_ALLOWED
                };

                ULONG i;

                // Try to open the process with many different accesses.
                // This handle will be re-used when walking stacks, and doing various other things.
                for(i = 0; i < sizeof(accesses) / sizeof(ACCESS_MASK); i++) {
                    if(NT_SUCCESS(native::open_process(&s_SymbolHandle, _process->get_pid(), accesses[i]))) {
                        realHandle = true;
                        break;
                    }
                }
            }

            if(!realHandle) {
                HANDLE fakeHandle;

                // Just generate a fake handle.
            #ifdef _WIN64
                fakeHandle = (HANDLE)_InterlockedExchangeAdd64((LONG_PTR*)&LastFakeHandle, 4);
            #else
                fakeHandle = (HANDLE)_InterlockedExchangeAdd((ULONG_PTR*)&LastFakeHandle, 4);
            #endif
                // Add one to make sure it isn't divisible by 4 (so it can't be mistaken for a real handle).
                s_SymbolHandle = (HANDLE)((ULONG_PTR)fakeHandle + 1);
            }

            SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED | SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_UNDNAME);
            s_Initialized = !!SymInitialize(s_SymbolHandle, NULL, FALSE);
        }
        void symbol_system::cleanup()
        {
            if(!s_Initialized) return;

            std::lock_guard<std::mutex> loaded_modules_lock(s_LoadedModulesMutex);
            for(auto& module : s_LoadedModules) {
                SymUnloadModule64(s_SymbolHandle, module);
            }
            s_LoadedModules.clear();
            SymCleanup(s_SymbolHandle);
            s_Initialized = false;
        }
        DWORD64 symbol_system::load_module_from_address(uintptr_t address)
        {
            if(!s_Initialized) return 0;

            auto module = _process->modules()->get_module_by_address(reinterpret_cast<uint8_t*>(address));
            
            if(module.get_base() != 0) {
                auto result = SymLoadModuleExW(
                    s_SymbolHandle,
                    NULL,
                    std::data(module.get_path()),
                    std::data(module.get_name()),
                    (DWORD64)module.get_base(), 
                    (DWORD)module.get_size(),
                    NULL,
                    0);

                if(result != 0) {
                    std::lock_guard<std::mutex> loaded_modules_lock(s_LoadedModulesMutex);

                    if(std::find(std::begin(s_LoadedModules), std::end(s_LoadedModules), result) != std::end(s_LoadedModules)) {
                        s_LoadedModules.emplace_back(result);
                    }

                    IMAGEHLP_MODULEW64 info;
                    info.SizeOfStruct = sizeof(info);
                    SymGetModuleInfoW64(s_SymbolHandle, result, &info);
                }
                return result;
            }
            return 0;
        }
        symbol_info symbol_system::get_symbol_info_from_address(uintptr_t address)
        {
            DWORD64 displacement = 0;
            char buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
            ZeroMemory(buffer, sizeof(buffer));
            PSYMBOL_INFOW symbolBuffer = (PSYMBOL_INFOW)buffer;

            symbolBuffer->SizeOfStruct = sizeof(SYMBOL_INFOW);
            symbolBuffer->MaxNameLen = MAX_PATH;

            auto mod = load_module_from_address(address);

            if(!SymFromAddrW(s_SymbolHandle, address, &displacement, symbolBuffer)) {
                throw misc::win32_exception("SymFromAddr failed", GetLastError());
            }
            return symbol_info{_process, symbolBuffer, (uintptr_t)displacement};
        }
        symbol_info symbol_system::get_symbol_info_from_name(const std::wstring& name)
        {
            char buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
            ZeroMemory(buffer, sizeof(buffer));
            PSYMBOL_INFOW symbolBuffer = (PSYMBOL_INFOW)buffer;

            symbolBuffer->SizeOfStruct = sizeof(SYMBOL_INFOW);
            symbolBuffer->MaxNameLen = MAX_PATH;

            if(!SymFromNameW(s_SymbolHandle, std::data(name), symbolBuffer)) {
                throw misc::win32_exception("SymFromName failed", GetLastError());
            }
            return symbol_info{_process, symbolBuffer, 0};
        }
    }
}