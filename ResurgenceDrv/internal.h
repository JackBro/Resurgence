#pragma once

#ifdef _M_IX86
#error "x86 systems are not supported"
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include "imports.h"
#include "utils.h"
#include "ResurgenceDrv.h"

#define RDRV_DRIVER_NAME L"ResurgenceDrv"
#define RDRV_POOLTAG 'vrDR'
#define IO_TYPE DO_BUFFERED_IO

#define LOG_TO_FILE
#define _DEBUG

#ifdef _DEBUG
#   ifdef LOG_TO_FILE
#       define DPRINT(str, ...) RDrvLogToFile("%ws | %-30s | " str "\r\n", RDRV_DRIVER_NAME, __FUNCTION__, __VA_ARGS__)
#   else
#       define DPRINT(str, ...) DbgPrint("%ws: " str, RDRV_DRIVER_NAME, __VA_ARGS__)
#   endif
#else 
#   define DPRINT(str, ...) 
#endif

#ifndef PERROR
#define PERROR(f, s) DPRINT(f " failed with status %lX", s)
#endif

#ifndef PEXCEPTION
#define PEXCEPTION() DPRINT("Exception: %lX", GetExceptionCode())
#endif



#if defined(_WIN10_)
#   define TARGET_WINVER                0x0A000000
#   define Off_EProcess_ObjectTable     0x00000418
#   define Off_EProcess_Protection      0x000006AA //_PS_PROTECTION 
#elif defined(_WIN81_)
#   error "Unsupported platform"
#elif defined(_WIN8_)
#   error "Unsupported platform"
#elif defined(_WIN7_)
#   define TARGET_WINVER 0x06010100
#else
#   error "Unsupported platform"
#   define TARGET_WINVER 0x00000000
#endif

typedef struct _IMAGE_MAP_DATA
{
    ULONG_PTR   Magic;
    ULONG_PTR   ImageBase;
    ULONG       SizeOfImage;
} IMAGE_MAP_DATA, *PIMAGE_MAP_DATA;

#ifdef _WIN10_
typedef void(NTAPI* tRtlInsertInvertedFunctionTable)(ULONG_PTR ImageBase, ULONG ImageSize);
#else
#pragma error "Unsupported build"
#endif

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

typedef struct _DRIVER_CONTEXT
{
    IMAGE_MAP_DATA  ImageData;

    PLIST_ENTRY     PsLoadedModuleList;

    ULONG_PTR       KrnlBase;

    SIZE_T          KrnlSize;

    //
    // Functions
    // 
    tRtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

extern PDRIVER_CONTEXT g_pDriverContext;

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(
    __in PHANDLE_TABLE HandleTable,
    __in EXHANDLE ExHandle
);