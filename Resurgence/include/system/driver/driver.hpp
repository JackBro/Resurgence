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

            BOOL            IsLoaded();
            error_code   Load(driver_load_method method);
            error_code   Open();

            error_code   QueryVersionInfo(PVERSION_INFO pVersion);

            //
            // Virtual Memory Management
            //
            error_code   AllocateVirtualMemory(ULONG ProcessId, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationFlags, ULONG ProtectionFlags);
            error_code   ProtectVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);
            error_code   FreeVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG FreeType);
            error_code   QueryVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemInfo);
            error_code   ReadVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize);
            error_code   WriteVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize);

            //
            // Process/Thread Management
            //
            error_code   OpenProcess(ULONG ProcessId, ULONG Access, PHANDLE Handle);
            error_code   OpenProcessWithThread(ULONG ThreadId, ULONG Access, PHANDLE Handle);
            error_code   OpenThread(ULONG ThreadId, ULONG Access, PHANDLE Handle);
            error_code   GrantHandleAccess(ULONG ProcessId, HANDLE Handle, ULONG Access, PULONG OldAccess);
            error_code   SetProcessProtection(ULONG ProcessId, ULONG ProtectionLevel);
            error_code   SetProcessDEP(ULONG ProcessId, BOOLEAN Enable);
            error_code   InjectModule(ULONG ProcessId, LPWSTR ModulePath, BOOLEAN EraseHeaders, BOOLEAN HideModule, PULONG_PTR BaseAddress);
            error_code   MMapModule(ULONG ProcessId, LPVOID ModuleBase, ULONG ModuleSize, BOOLEAN EraseHeaders, BOOLEAN HideModule, PULONG_PTR BaseAddress);
        
        //private:
            std::wstring    _path;
            HANDLE          _handle;
        };
    }
}