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
#   define TARGET_WINVER                        0x0A000000
#   define Off_EThread_PreviousMode             0x00000232
#   define Off_EProcess_ObjectTable             0x00000418
#   define Off_EProcess_Protection              0x000006B2 //_PS_PROTECTION 
#   define Off_KProcess_ExecuteOptions          0x000001BF //_KEXECUTE_OPTIONS
#   define SSDTEntry_CreateThreadEx             0x000000B4
#   define SSDTEntry_TerminateThread            0x00000053
#   define SSDTEntry_QueryPerformanceCounter    0x00000031
#elif defined(_WIN81_)
#   error "Unsupported platform"
#elif defined(_WIN8_)
#   error "Unsupported platform"
#elif defined(_WIN7_)
#   error "Unsupported platform"
#else
#   error "Unsupported platform"
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
#define INJECTION_BUFFER_SIZE 0x100

#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

typedef struct _DRIVER_CONTEXT
{
    BOOLEAN         Initialized;

    IMAGE_MAP_DATA  ImageData;

    PLIST_ENTRY     PsLoadedModuleList;

    PVOID           KrnlBase;

    SIZE_T          KrnlSize;

    PSYSTEM_SERVICE_DESCRIPTOR_TABLE SSDT;
    //
    // Functions
    // 
    tRtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable;

} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

typedef struct _INJECTION_BUFFER
{
    UCHAR               CodeBuffer[INJECTION_BUFFER_SIZE];
    PULONG_PTR          ModuleHandle;
    UNICODE_STRING      ModulePath64;
    UNICODE_STRING32    ModulePath32;
    WCHAR               PathBuffer[MAX_PATH];
} INJECTION_BUFFER, *PINJECTION_BUFFER;

extern PDRIVER_CONTEXT g_pDriverContext;

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(
    __in PHANDLE_TABLE HandleTable,
    __in EXHANDLE ExHandle
);

FORCEINLINE
BOOLEAN
RemoveEntryListUnsafe32(
    _In_ PLIST_ENTRY32 Entry
)
{
    PLIST_ENTRY32 Blink;
    PLIST_ENTRY32 Flink;

    Flink = (PLIST_ENTRY32)Entry->Flink;
    Blink = (PLIST_ENTRY32)Entry->Blink;
    Blink->Flink = (ULONG)(ULONG_PTR)Flink;
    Flink->Blink = (ULONG)(ULONG_PTR)Blink;
    return (BOOLEAN)(Flink == Blink);
}