#pragma once

#include <headers.hpp>
#include <mutex>
#include <string>
#include <vector>

#include "../process_modules.hpp"

typedef struct _SYMBOL_INFOW *PSYMBOL_INFOW;

namespace resurgence
{
    namespace system
    {
        class process;

        class symbol_info
        {
        public:
            symbol_info(process* proc, PSYMBOL_INFOW info, uintptr_t displacement);

            const std::wstring&     get_name() const { return _name; }
            uint64_t                get_address() const { return _address; }
            uint64_t                get_displacement() const { return _disp; }
            uint64_t                get_module_base() const { return _moduleBase; }
            const process_module&   get_module() const { return _module; }

        private:
            void build_name(PSYMBOL_INFOW info, uintptr_t displacement);

        private:
            process*        _process;
            process_module  _module;
            uint64_t        _moduleBase;   // The base of the module where the symbol resides
            uint64_t        _address;      // The symbol address
            std::wstring    _name;         // The symbol's name (e.g nt!LdrLoadDll+0x10)
            uint64_t        _disp;         // The symbol's displacement
        };

        class symbol_system
        {
        public:
            symbol_system(process* proc);
            ~symbol_system();

            bool is_initialized();
            void initialize();
            void cleanup();

            DWORD64     load_module_from_address(uintptr_t address);
            symbol_info get_symbol_info_from_address(uintptr_t address);
            symbol_info get_symbol_info_from_name(const std::wstring& name);

        private:
            process*        _process;

            static bool                 s_Initialized;
            static HANDLE               s_SymbolHandle;
            static std::vector<DWORD64> s_LoadedModules;
            static std::mutex           s_LoadedModulesMutex;
        };
    }
}