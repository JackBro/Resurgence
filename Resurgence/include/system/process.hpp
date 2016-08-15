#pragma once

#include <headers.hpp>
#include <memory>
#include <vector>
#include <misc/safe_handle.hpp>
#include "process_memory.hpp"
#include "process_modules.hpp"

#define SYSTEM_IDLE_PROCESS_ID  (0)
#define SYSTEM_PROCESS_ID       (4)

namespace resurgence
{
    namespace system
    {
        enum platform
        {
            platform_unknown = 0,
            platform_x86,
            platform_x64
        };

        class process_info
        {
        public:
            process_info()
            {
                pid = parent_pid = 0;
                name = L"";
                path = L"";
                platform = platform_unknown;
                peb_address = 0;
                wow64peb_address = 0;
                is_current_process = false;
            }
            std::uint32_t   pid;
            std::uint32_t   parent_pid;
            std::wstring    name;
            std::wstring    path;
            platform        platform;
            std::uintptr_t  peb_address;
            std::uint32_t   wow64peb_address;
            bool            is_current_process;
        };

        class process
        {
        public:
            process();
            process(std::uint32_t pid);
            process(const process& rhs);
            process& operator=(const process& rhs);

            static std::vector<process>         get_processes();
            static std::vector<process>         get_process_by_name(const std::wstring& name);
            static bool                         grant_privilege(std::uint32_t privilege);
            static bool                         revoke_privilege(std::uint32_t privilege);

            const std::wstring&                 get_name() const;
            const std::wstring&                 get_path() const;
            std::uintptr_t                      get_peb_address() const;
            std::uint32_t                       get_wow64_peb_address() const;
            int                                 get_pid() const;
            platform                            get_platform() const;
            const misc::safe_process_handle&    get_handle() const;
            bool                                is_current_process() const;

            bool                                open(std::uint32_t access);

            process_memory*                     memory() { return &_memory; }
            process_modules*                    modules() { return &_modules; }

        private:
            void                                get_process_info();

        private:
            process_info                _info;
            misc::safe_process_handle   _handle;
            process_memory              _memory;
            process_modules             _modules;
        };
    }
}