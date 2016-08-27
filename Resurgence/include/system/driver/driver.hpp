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
            ///<summary>
            /// Constructor. 
            ///</summary>
            ///<param name="path"> The driver path. </param>
            driver(const std::wstring& path);

            ///<summary>
            /// Destructor. 
            ///</summary>
            ~driver();

            ///<summary>
            /// Check if the driver is already loaded on the system.
            ///</summary>
            ///<returns> 
            /// TRUE if loaded, FALSE otherwise.
            ///</returns>
            BOOL is_loaded();

            ///<summary>
            /// Loads the driver.
            ///</summary>
            ///<param name="method"> The load method. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS load(driver_load_method method);

            ///<summary>
            /// Query the OS version.
            ///</summary>
            ///<param name="version"> The version info. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS query_version_info(PVERSION_INFO version);

            //
            // Virtual Memory Management
            //

            ///<summary>
            /// Allocate virtual memory.
            ///</summary>
            ///<param name="pid">         The process id. </param>
            ///<param name="baseAddress"> The allocation base. </param>
            ///<param name="regionSize"> The allocation size. </param>
            ///<param name="allocation"> The allocation flags. </param>
            ///<param name="protection"> The protection flags. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS  allocate_virtual_memory(uint32_t pid, uint8_t** baseAddress, size_t* regionSize, uint32_t allocation, uint32_t protection);

            ///<summary>
            /// Allocate virtual memory.
            ///</summary>
            ///<param name="pid">           The process id. </param>
            ///<param name="baseAddress">   The start address. </param>
            ///<param name="regionSize">    The region size. </param>
            ///<param name="newProtection"> The new protection. </param>
            ///<param name="oldProtection"> The old protection. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS protect_virtual_memory(uint32_t pid, uint8_t* baseAddress, size_t regionSize, uint32_t newProtection, uint32_t* oldProtection);

            ///<summary>
            /// Free virtual memory.
            ///</summary>
            ///<param name="pid">         The process id. </param>
            ///<param name="baseAddress"> The start address. </param>
            ///<param name="regionSize">  The region size. </param>
            ///<param name="freeType">    The free type. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS free_virtual_memory(uint32_t pid, uint8_t* baseAddress, size_t regionSize, uint32_t freeType);

            ///<summary>
            /// Query memory information.
            ///</summary>
            ///<param name="pid">         The process id. </param>
            ///<param name="baseAddress"> The base address. </param>
            ///<param name="memoryInfo">  The returned memory information. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS query_virtual_memory(uint32_t pid, uint8_t* baseAddress, PMEMORY_BASIC_INFORMATION memoryInfo);

            ///<summary>
            /// Read virtual memory.
            ///</summary>
            ///<param name="pid">         The process id. </param>
            ///<param name="baseAddress"> The base address. </param>
            ///<param name="buffer">      The buffer. </param>
            ///<param name="length">      The buffer size. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS read_virtual_memory(uint32_t pid, const uint8_t* baseAddress, uint8_t* buffer, size_t length);

            ///<summary>
            /// Write virtual memory.
            ///</summary>
            ///<param name="pid">         The process id. </param>
            ///<param name="baseAddress"> The base address. </param>
            ///<param name="buffer">      The buffer. </param>
            ///<param name="length">      The buffer size. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS write_virtual_memory(uint32_t pid, const uint8_t* baseAddress, uint8_t* buffer, size_t length);

            //
            // Process/Thread Management
            //

            ///<summary>
            /// Opens a process.
            ///</summary>
            ///<param name="pid">    The process id. </param>
            ///<param name="access"> The desired access. </param>
            ///<param name="handle"> The returned handle. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS open_process(uint32_t pid, uint32_t access, PHANDLE handle);

            ///<summary>
            /// Opens the process that contains the target thread.
            ///</summary>
            ///<param name="tid">    The thread id. </param>
            ///<param name="access"> The desired access. </param>
            ///<param name="handle"> The returned handle. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS open_process_with_thread(uint32_t tid, uint32_t access, PHANDLE handle);

            ///<summary>
            /// Opens a thread.
            ///</summary>
            ///<param name="tid">    The thread id. </param>
            ///<param name="access"> The desired access. </param>
            ///<param name="handle"> The returned handle. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS  open_thread(uint32_t tid, uint32_t access, PHANDLE handle);

            ///<summary>
            /// Grants access to a handle.
            ///</summary>
            ///<param name="pid">       The process id (current process on most cases). </param>
            ///<param name="handle">    The target handle. </param>
            ///<param name="access">    The desired access. </param>
            ///<param name="oldAccess"> The old access. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS grant_handle_access(uint32_t pid, HANDLE handle, uint32_t access, uint32_t* oldAccess);

            ///<summary>
            /// Set process protection.
            ///</summary>
            ///<param name="pid">             The process id. </param>
            ///<param name="protectionLevel"> The protection level (0: None. 1: Light. 2: Full). </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS set_process_protection(uint32_t pid, uint32_t protectionLevel);

            ///<summary>
            /// Enables or disables DEP.
            ///</summary>
            ///<param name="pid">    The process id. </param>
            ///<param name="enable"> The DEP state. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS set_process_dep(uint32_t pid, bool enable);

            ///<summary>
            /// Injects a module.
            ///</summary>
            ///<param name="pid">          The process id. </param>
            ///<param name="modulePath">   The module path. </param>
            ///<param name="eraseHeaders"> Erase headers. </param>
            ///<param name="hideModule">   Hide module. </param>
            ///<param name="baseAddress">  The returned module base. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS inject_module(uint32_t pid, const std::wstring& modulePath, bool eraseHeaders, bool hideModule, uintptr_t* baseAddress);

            ///<summary>
            /// Maps a module to the process.
            ///</summary>
            ///<param name="pid">          The process id. </param>
            ///<param name="moduleBase">   The module base. </param>
            ///<param name="moduleSize">   The module size. </param>
            ///<param name="eraseHeaders"> Erase headers. </param>
            ///<param name="hideModule">   Hide module. </param>
            ///<param name="baseAddress">  The returned module base. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS mmap_module(uint32_t pid, const uint8_t* moduleBase, size_t moduleSize, bool eraseHeaders, bool hideModule, uintptr_t* baseAddress);


            ///<summary>
            /// Maps a module to the process.
            ///</summary>
            ///<param name="pid">          The process id. </param>
            ///<param name="modulePath">   The module path. </param>
            ///<param name="eraseHeaders"> Erase headers. </param>
            ///<param name="hideModule">   Hide module. </param>
            ///<param name="baseAddress">  The returned module base. </param>
            ///<returns> 
            /// The status code.
            ///</returns>
            NTSTATUS mmap_module(uint32_t pid, const std::wstring& modulePath, bool eraseHeaders, bool hideModule, uintptr_t* baseAddress);

        private:
            NTSTATUS  open();

            std::wstring    _path;
            HANDLE          _handle;
        };
    }
}