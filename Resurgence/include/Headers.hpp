#pragma once

#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

typedef long NTSTATUS;
#include <Windows.h>
#include <winioctl.h>
#include <ntstatus.h>
#include <strsafe.h>
#include <NtApi.hpp>
#include <stdint.h>
#include <Misc/Logging.hpp>
#if !defined PAGE_SIZE
#define PAGE_SIZE       0x1000
#endif

#define LAST_STATUS_OFFSET (0x598 + 0x197 * sizeof(void*))

__forceinline NTSTATUS GetLastNtStatus()
{
    return NtCurrentTeb()->LastStatusValue;
}
__forceinline NTSTATUS SetLastNtStatus(NTSTATUS status)
{
    return NtCurrentTeb()->LastStatusValue = status;
}