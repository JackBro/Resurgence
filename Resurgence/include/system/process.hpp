#pragma once

#include <headers.hpp>
#include <memory>
#include <vector>
#include <misc/safe_handle.hpp>
#include "process_memory.hpp"
#include "process_modules.hpp"
#include "process_threads.hpp"

#define SYSTEM_IDLE_PROCESS     (0)
#define SYSTEM_PROCESS          (4)
#define PROCESS_DEFAULT_ACCESS  SYNCHRONIZE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
#define THREAD_DEFAULT_ACCESS   SYNCHRONIZE | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | \
                                THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE

namespace resurgence
{
    namespace system
    {
        class process_info
        {
        public:
            process_info()
            {
                RtlZeroMemory(this, sizeof(process_info));
            }
            uint32_t        pid;
            uint32_t        parent_pid;
            std::wstring    name;
            std::wstring    path;
            platform        target_platform;
            uintptr_t       peb_address;
            uint32_t        wow64peb_address;
            bool            current_process;
        };

        class process
        {
        public:
            process();
            process(uint32_t pid);
            process(const process& rhs);
            process& operator=(const process& rhs);

            static std::vector<process>         get_processes();
            static process                      get_current_process();
            static std::vector<process>         get_process_by_name(const std::wstring& name);
            static bool                         grant_privilege(uint32_t privilege);
            static bool                         revoke_privilege(uint32_t privilege);

            void                                ensure_access(uint32_t access) const;
            const std::wstring&                 get_name() const;
            const std::wstring&                 get_path() const;
            uintptr_t                           get_peb_address() const;
            uint32_t                            get_wow64_peb_address() const;
            int                                 get_pid() const;
            platform                            get_platform() const;
            const misc::safe_process_handle&    get_handle() const;
            bool                                is_current_process() const;
            bool                                is_system_idle_process() const;
            bool                                is_system_process() const;
            bool                                is_valid() const;
            bool                                has_exited() const;
            bool                                is_being_debugged();
            bool                                is_protected();

            NTSTATUS                            open(uint32_t access);
            void                                terminate(uint32_t exitCode = 0);
            NTSTATUS                            get_exit_code() const;
            std::wstring                        get_command_line();

            process_memory*                     memory() { return &_memory; }
            process_modules*                    modules() { return &_modules; }
            process_threads*                    threads() { return &_threads; }

        private:
            void                                get_process_info();
            
        private:
            process_info                _info;
            misc::safe_process_handle   _handle;
            process_memory              _memory;
            process_modules             _modules;
            process_threads             _threads;
        };
    }
}