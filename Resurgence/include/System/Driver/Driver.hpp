#pragma once

#include <cstdint>
#include <string>
#include <Misc/SafeHandle.hpp>
#include <Headers.hpp>

#include "../../../../ResurgenceDrv/ResurgenceDrv.h"

namespace Resurgence
{
    namespace System
    {
        class Driver
        {
        public:
            Driver(const std::wstring& path);
            ~Driver();

            BOOL            IsLoaded();
            NTSTATUS        Load();
            NTSTATUS        Open();

            NTSTATUS        QueryVersionInfo(PVERSION_INFO pVersion);

            //
            // Virtual Memory Management
            //
            NTSTATUS        AllocateVirtualMemory(ULONG ProcessId, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationFlags, ULONG ProtectionFlags);
            NTSTATUS        ProtectVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);
            NTSTATUS        FreeVirtualMemory(ULONG ProcessId, PVOID BaseAddress, SIZE_T RegionSize, ULONG FreeType);
            NTSTATUS        QueryVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemInfo);
            NTSTATUS        ReadVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize);
            NTSTATUS        WriteVirtualMemory(ULONG ProcessId, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize);

            //
            // Process/Thread Management
            //
            NTSTATUS        OpenProcess(ULONG ProcessId, ULONG Access, PHANDLE Handle);
            NTSTATUS        OpenProcessWithThread(ULONG ThreadId, ULONG Access, PHANDLE Handle);
            NTSTATUS        OpenThread(ULONG ThreadId, ULONG Access, PHANDLE Handle);
            NTSTATUS        GrantHandleAccess(ULONG ProcessId, HANDLE Handle, ULONG Access, PULONG OldAccess);
            NTSTATUS        SetProcessProtection(ULONG ProcessId, ULONG ProtectionLevel);
            NTSTATUS        SetProcessDEP(ULONG ProcessId, BOOLEAN Enable);
        private:
            std::wstring    _path;
            HANDLE          _handle;
        };
    }
}