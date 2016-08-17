#pragma once

#include <cstdint>
#include <string>
#include <misc/safe_handle.hpp>
#include <headers.hpp>

#include "../../../../ResurgenceDrv/ResurgenceDrv.h"

namespace resurgence
{
    namespace system
    {
        enum driver_load_method
        {
            SCManager,
            Turla
        };

        class driver
        {
        public:
            driver(const std::wstring& path);
            ~driver();

            BOOL        is_loaded();
            error_code  load(driver_load_method method);

            error_code  query_version_info(PVERSION_INFO version);

            //
            // Virtual Memory Management
            //
            error_code  allocate_virtual_memory(uint32_t pid, uint8_t** baseAddress, size_t* regionSize, uint32_t allocation, uint32_t protection);
            error_code  protect_virtual_memory(uint32_t pid, uint8_t* baseAddress, size_t regionSize, uint32_t newProtection, uint32_t* oldProtection);
            error_code  free_virtual_memory(uint32_t pid, uint8_t* baseAddress, size_t regionSize, uint32_t freeType);
            error_code  query_virtual_memory(uint32_t pid, uint8_t* baseAddress, PMEMORY_BASIC_INFORMATION memoryInfo);
            error_code  read_virtual_memory(uint32_t pid, const uint8_t* baseAddress, uint8_t* buffer, size_t length);
            error_code  write_virtual_memory(uint32_t pid, const uint8_t* baseAddress, uint8_t* buffer, size_t length);

            //
            // Process/Thread Management
            //
            error_code  open_process(uint32_t pid, uint32_t access, PHANDLE handle);
            error_code  open_process_with_thread(uint32_t tid, uint32_t access, PHANDLE handle);
            error_code  open_thread(uint32_t tid, uint32_t access, PHANDLE handle);
            error_code  grant_handle_access(uint32_t pid, HANDLE handle, uint32_t access, uint32_t* oldAccess);
            error_code  set_process_protection(uint32_t pid, uint32_t protectionLevel);
            error_code  set_process_dep(uint32_t pid, bool enable);
            error_code  inject_module(uint32_t pid, const std::wstring& modulePath, bool eraseHeaders, bool hideModule, uintptr_t* baseAddress);
            error_code  mmap_module(uint32_t pid, const uint8_t* moduleBase, size_t moduleSize, bool eraseHeaders, bool hideModule, uintptr_t* baseAddress);
        
        private:
            error_code  open();

            std::wstring    _path;
            HANDLE          _handle;
        };
    }
}