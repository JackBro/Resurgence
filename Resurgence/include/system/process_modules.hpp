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
            ///<summary>
            /// Default ctor.
            ///<summary>
            ///<param name="proc"> The owner process. </param>
            process_modules(process* proc);

            ///<summary>
            /// Get process modules.
            ///<summary>
            ///<returns> A vector with all modules loaded by the process. </returns>
            std::vector<process_module> get_all_modules();

            ///<summary>
            /// Get main module.
            ///<summary>
            ///<returns> The main module. </returns>
            process_module get_main_module();

            ///<summary>
            /// Get module by name.
            ///<summary>
            ///<param name="name"> The name. </param>
            ///<returns> 
            /// The module. 
            ///</returns>
            process_module get_module_by_name(const std::wstring& name);

            ///<summary>
            /// Get the module that contains the target address.
            ///<summary>
            ///<param name="address"> The address. </param>
            ///<returns> 
            /// The module. 
            ///</returns>
            process_module get_module_by_address(const std::uint8_t* address);

            ///<summary>
            /// Get module by load order.
            ///<summary>
            ///<param name="i"> The module number. </param>
            ///<returns> 
            /// The module. 
            ///</returns>
            process_module get_module_by_load_order(uint32_t i);

            ///<summary>
            /// Injects a module.
            ///<summary>
            ///<param name="path">          The module path. </param>
            ///<param name="injectionType"> The injection type. </param>
            ///<param name="flags">         The injection flags. </param>
            ///<param name="module">        The injected module entry. </param>
            ///<returns> 
            /// The status code. 
            ///</returns>
            NTSTATUS inject_module(const std::wstring& path, uint32_t injectionType, uint32_t flags, process_module* module = nullptr);

        private:

            ///<summary>
            /// [Internal] Injects a module on a x86 process.
            ///<summary>
            ///<param name="path">          The module path. </param>
            ///<param name="injectionType"> The injection type. </param>
            ///<param name="module">        The injected module entry. </param>
            ///<returns> 
            /// The status code. 
            ///</returns>
            NTSTATUS inject_module32(const std::wstring& path, uint32_t injectionType, process_module* module);

            ///<summary>
            /// [Internal] Injects a module on a x86 process.
            ///<summary>
            ///<param name="path">          The module path. </param>
            ///<param name="injectionType"> The injection type. </param>
            ///<param name="module">        The injected module entry. </param>
            ///<returns> 
            /// The status code. 
            ///</returns>
            NTSTATUS inject_module64(const std::wstring& path, uint32_t injectionType, process_module* module);

            ///<summary>
            /// Default ctor.
            ///<summary>
            process_modules();

            process* _process;
        };
    }
}
