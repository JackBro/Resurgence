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

        //bool                    symbol_system::s_Initialized;
        //HANDLE                  symbol_system::s_SymbolHandle;
        //std::vector<DWORD64>    symbol_system::s_LoadedModules;
        //std::mutex              symbol_system::s_LoadedModulesMutex;

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
                swprintf_s(buffer, L"0x%llX", static_cast<uintptr_t>(info->Address));
                _name = buffer;
            } else {
                if(info->NameLen == 0) {
                    //
                    // We have a module name but not a symbol name.
                    // Return module+offset;
                    //
                    swprintf_s(buffer, L"%ws+0x%lX", std::data(moduleName), static_cast<uint32_t>(info->Address - (uintptr_t)module.get_base()));
                    _name = buffer;
                } else {
                    //
                    // We have a module AND symbol name.
                    // Return module!symbol+diplacement
                    //
                    if(displacement == 0) {
                        swprintf_s(buffer, L"%ws!%s", std::data(moduleName), info->Name);
                    } else {
                        swprintf_s(buffer, L"%ws!%s+0x%lX", std::data(moduleName), info->Name, static_cast<uint32_t>(displacement));
                    }
                    _name = buffer;
                }
            }
        }

        symbol_system::symbol_system(process* proc)
            : _process(proc), _initialized(false), _symbolHandle(nullptr)
        {
        }
        symbol_system::~symbol_system()
        {
            cleanup();
        }
        bool symbol_system::is_initialized()
        {
            return _initialized;
        }
        void symbol_system::initialize()
        {
            if(_initialized) {
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
                    if(NT_SUCCESS(native::open_process(&_symbolHandle, _process->get_pid(), accesses[i]))) {
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
                _symbolHandle = (HANDLE)((ULONG_PTR)fakeHandle + 1);
            }

            SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED | SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_UNDNAME);
            _initialized = !!SymInitialize(_symbolHandle, NULL, FALSE);
        }
        void symbol_system::cleanup()
        {
            if(!_initialized) return;

            for(auto& module : _loadedModules) {
                SymUnloadModule64(_symbolHandle, module);
            }
            _loadedModules.clear();
            SymCleanup(_symbolHandle);
            _initialized = false;
        }
        DWORD64 symbol_system::load_module_from_address(uintptr_t address)
        {
            if(!_initialized) return 0;

            auto module = _process->modules()->get_module_by_address(reinterpret_cast<uint8_t*>(address));
            
            if(module.get_base() != 0) {
                auto result = SymLoadModuleExW(
                    _symbolHandle,
                    NULL,
                    std::data(module.get_path()),
                    std::data(module.get_name()),
                    (DWORD64)module.get_base(), 
                    (DWORD)module.get_size(),
                    NULL,
                    0);

                if(result != 0) {
                    IMAGEHLP_MODULEW64 info;
                    info.SizeOfStruct = sizeof(info);
                    if(SymGetModuleInfoW64(_symbolHandle, result, &info)) {
                        if(std::find(std::begin(_loadedModules), std::end(_loadedModules), result) != std::end(_loadedModules)) {
                            _loadedModules.emplace_back(result);
                        }
                    } else {
                        throw misc::win32_exception("SymGetModuleInfoW64 failed", GetLastError());
                    }
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

            load_module_from_address(address);
            if(!SymFromAddrW(_symbolHandle, address, &displacement, symbolBuffer))
                symbolBuffer->Address = address;

            return symbol_info{_process, symbolBuffer, (uintptr_t)displacement};
        }
        symbol_info symbol_system::get_symbol_info_from_name(const std::wstring& name)
        {
            char buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
            ZeroMemory(buffer, sizeof(buffer));
            PSYMBOL_INFOW symbolBuffer = (PSYMBOL_INFOW)buffer;

            symbolBuffer->SizeOfStruct = sizeof(SYMBOL_INFOW);
            symbolBuffer->MaxNameLen = MAX_PATH;

            SymFromNameW(_symbolHandle, std::data(name), symbolBuffer);

            return symbol_info{_process, symbolBuffer, 0};
        }
    }
}