#pragma once

#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

typedef long NTSTATUS;

#include <cassert>
#include <cstdint>

#include <Windows.h>
#include <winioctl.h>
#include <ntstatus.h>
#include <strsafe.h>
#include <NtApi.hpp>
#include <misc/error.hpp>

#ifndef PTR_ADD
#define PTR_ADD(ptr, off) ((uint8_t*)ptr + off)
#endif

#if !defined PAGE_SIZE
#define PAGE_SIZE       0x1000
#endif

#if !defined(DEFAULT_DRIVER_NAMES)
#define DEFAULT_DRIVER_NAMES
#define DEFAULT_DRIVER_WIN7     TEXT(".\\ResurgenceDrvWin7.sys")
#define DEFAULT_DRIVER_WIN8     TEXT(".\\ResurgenceDrvWin8.sys")
#define DEFAULT_DRIVER_WIN81    TEXT(".\\ResurgenceDrvWin81.sys")
#define DEFAULT_DRIVER_WIN10    TEXT(".\\ResurgenceDrvWin10.sys")
#endif

__forceinline NTSTATUS get_last_ntstatus()
{
    return NtCurrentTeb()->LastStatusValue;
}
__forceinline NTSTATUS set_last_ntstatus(NTSTATUS status)
{
    return NtCurrentTeb()->LastStatusValue = status;
}
