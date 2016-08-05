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
        class driver
        {
        public:
            driver(const std::wstring& path);
            ~driver();

            BOOL            IsLoaded();
            ntstatus_code   Load();
            ntstatus_code   Open();

            ntstatus_code   QueryVersionInfo(PVERSION_INFO pVersion);

            //
            // Virtual Memory Management
            //
            ntstatus_code   AllocateVirtualMemory(ULONG ProcessId, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationFlags, ULONG ProtectionFlags);
            ntstatus_code   ProtectVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);
            ntstatus_code   FreeVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG FreeType);
            ntstatus_code   QueryVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemInfo);
            ntstatus_code   ReadVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize);
            ntstatus_code   WriteVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize);

            //
            // Process/Thread Management
            //
            ntstatus_code   OpenProcess(ULONG ProcessId, ULONG Access, PHANDLE Handle);
            ntstatus_code   OpenProcessWithThread(ULONG ThreadId, ULONG Access, PHANDLE Handle);
            ntstatus_code   OpenThread(ULONG ThreadId, ULONG Access, PHANDLE Handle);
            ntstatus_code   GrantHandleAccess(ULONG ProcessId, HANDLE Handle, ULONG Access, PULONG OldAccess);
            ntstatus_code   SetProcessProtection(ULONG ProcessId, ULONG ProtectionLevel);
            ntstatus_code   SetProcessDEP(ULONG ProcessId, BOOLEAN Enable);
            ntstatus_code   InjectModule(ULONG ProcessId, LPWSTR ModulePath, BOOLEAN EraseHeaders, BOOLEAN HideModule, PULONG_PTR BaseAddress);
            ntstatus_code   MMapModule(ULONG ProcessId, LPVOID ModuleBase, ULONG ModuleSize, BOOLEAN EraseHeaders, BOOLEAN HideModule, PULONG_PTR BaseAddress);
        private:
            std::wstring    _path;
            HANDLE          _handle;
        };
    }
}