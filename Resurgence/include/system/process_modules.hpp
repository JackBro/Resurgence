#pragma once

#include <headers.hpp>

namespace resurgence
{
    namespace system
    {
        class process;

        class module
        {
        public:
            module();
            module(process* proc, PLDR_DATA_TABLE_ENTRY entry);
            module(process* proc, PLDR_DATA_TABLE_ENTRY32 entry);
            module(PRTL_PROCESS_MODULE_INFORMATION entry);

            const uint8_t* get_base() const { return _base; }
            size_t         get_size() const { return _size; }
            const std::wstring& get_name() const { return _name; }
            const std::wstring& get_path() const { return _path; }

            uint8_t*   _base;
            size_t     _size;
            std::wstring    _name;
            std::wstring    _path;
        };

        class process_modules
        {
        public:
            process_modules(process* proc);

            std::vector<module> get_all_modules();
            module              get_module_by_name(const std::wstring& name);
            module              get_module_by_handle(HANDLE handle);
            module              get_module_by_load_order(int i);

        private:
            friend class process;
            process_modules();

            process* _process;
        };
    }
}
