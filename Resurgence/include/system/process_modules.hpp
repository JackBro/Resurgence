#pragma once

#include <headers.hpp>
#include <vector>
#include "portable_executable.hpp"

//
// Injection types
// 
#define INJECTION_TYPE_LOADLIBRARY  0x001
#define INJECTION_TYPE_LDRLOADLL    0x002

//
// Injection flags
// 
#define INJECTION_ERASE_HEADERS 0x001
#define INJECTION_HIDE_MODULE   0x002

namespace resurgence
{
    namespace system
    {
        class process;

        class process_module
        {
        public:
            ///<summary>
            /// Default ctor.
            ///<summary>
            process_module();

            ///<summary>
            /// x64 module constructor.
            ///<summary>
            ///<param name="proc">  The owner process. </param>
            ///<param name="entry"> The loader table entry. </param>
            process_module(process* proc, PLDR_DATA_TABLE_ENTRY entry);

            ///<summary>
            /// x86 module constructor.
            ///<summary>
            ///<param name="proc">  The owner process. </param>
            ///<param name="entry"> The loader table entry. </param>
            process_module(process* proc, PLDR_DATA_TABLE_ENTRY32 entry);

            ///<summary>
            /// System module constructor.
            ///<summary>
            ///<param name="proc">  The owner process. </param>
            ///<param name="entry"> The module information. </param>
            process_module(process* proc, PRTL_PROCESS_MODULE_INFORMATION entry);

            ///<summary>
            /// Gets the module base.
            ///<summary>
            const uint8_t* get_base() const { return _base; }

            ///<summary>
            /// Gets the module size.
            ///<summary>
            size_t get_size() const { return _size; }

            ///<summary>
            /// Gets the module name.
            ///<summary>
            const std::wstring& get_name() const { return _name; }

            ///<summary>
            /// Gets the module path.
            ///<summary>
            const std::wstring& get_path() const { return _path; }

            ///<summary>
            /// Checks whether the module is valid.
            ///<summary>
            bool is_valid() const { return _base != nullptr; }

            ///<summary>
            /// Gets the portable executable linked with this module.
            ///<summary>
            const portable_executable& get_pe();

            ///<summary>
            /// Get procedure address.
            ///<summary>
            ///<param name="name">  The function name. </param>
            ///<returns>
            /// The address, 0 on failure.
            ///</returns>
            uintptr_t get_proc_address(const std::string& name);

        private:
            process*            _process;
            uint8_t*            _base;
            size_t              _size;
            std::wstring        _name;
            std::wstring        _path;
            portable_executable _pe;
        };

        class process_modules
        {
            friend class process;
        public:
            process_modules(process* proc);

            std::vector<process_module> get_all_modules();
            process_module              get_main_module();
            process_module              get_module_by_name(const std::wstring& name);
            process_module              get_module_by_address(const std::uint8_t* address);
            process_module              get_module_by_load_order(uint32_t i);

            NTSTATUS                    inject_module(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module = nullptr);
        private:
            NTSTATUS                    inject_module32(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module);
            NTSTATUS                    inject_module64(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module);
            process_modules();

            process* _process;
        };
    }
}
