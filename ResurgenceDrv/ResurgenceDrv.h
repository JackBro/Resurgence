#pragma once

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((ULONG)&(((type *)0)->field))
#endif

#ifndef FIELD_SIZE
#define FIELD_SIZE(type, field) (sizeof(((type *)0)->field))
#endif

#define RDRV_SYMLINK        L"Resurgence"
#define RDRV_DEVICE_NAME    L"\\Device\\" RDRV_SYMLINK
#define RDRV_DOSDEVICE_NAME L"\\DosDevices\\" RDRV_SYMLINK
#define RDRV_DEV_TYPE       0x8989

#define VM_OPERATION_ALLOC      0x00
#define VM_OPERATION_FREE       0x01
#define VM_OPERATION_PROTECT    0x02
#define PROTECTION_NONE         0x00
#define PROTECTION_LIGHT        0x01
#define PROTECTION_FULL         0x02

#define RESURGENCE_QUERY_OSVERSION      CTL_CODE(RDRV_DEV_TYPE, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_QUERY_OSVERSION_SIZE sizeof(VERSION_INFO)

#define RESURGENCE_VM_OPERATION         CTL_CODE(RDRV_DEV_TYPE, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_VM_OPERATION_SIZE    sizeof(VM_OPERATION)

#define RESURGENCE_VM_READ              CTL_CODE(RDRV_DEV_TYPE, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_VM_WRITE             CTL_CODE(RDRV_DEV_TYPE, 0x8004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_VM_READ_SIZE         sizeof(VM_READ_WRITE)
#define RESURGENCE_VM_WRITE_SIZE        RESURGENCE_VM_READ_SIZE

#define RESURGENCE_VM_QUERY             CTL_CODE(RDRV_DEV_TYPE, 0x8005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_VM_QUERY_SIZE        sizeof(VM_QUERY_INFO)

#define RESURGENCE_GRANT_ACCESS         CTL_CODE(RDRV_DEV_TYPE, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_GRANT_ACCESS_SIZE    sizeof(GRANT_ACCESS)

#define RESURGENCE_PROTECT_PROCESS      CTL_CODE(RDRV_DEV_TYPE, 0x8007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_PROTECT_PROCESS_SIZE sizeof(PROTECT_PROCESS)

#define RESURGENCE_OPEN_PROCESS         CTL_CODE(RDRV_DEV_TYPE, 0x8008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_OPEN_PROCESS_SIZE    sizeof(OPEN_PROCESS)

#define RESURGENCE_OPEN_THREAD          CTL_CODE(RDRV_DEV_TYPE, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_OPEN_THREAD_SIZE     sizeof(OPEN_THREAD)

#define RESURGENCE_SET_DEP_STATE        CTL_CODE(RDRV_DEV_TYPE, 0x800A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESURGENCE_SET_DEP_STATE_SIZE   sizeof(SET_DEP_STATE)
#pragma warning(disable : 4201)

typedef struct _VERSION_INFO
{
    ULONG           MajorVersion;
    ULONG           MinorVersion;
    USHORT          ServicePackMajor;
    USHORT          ServicePackMinor;
    ULONG           BuildNumber;
    ULONG           VersionLong;
} VERSION_INFO, *PVERSION_INFO;

typedef struct _VM_OPERATION
{
    union
    {
        struct
        {
            ULONG       Operation; //Alloc, Free or Protect
            ULONG       ProcessId;
            ULONG_PTR   BaseAddress;
            SIZE_T      RegionSize;
            ULONG       ProtectionFlags;
            ULONG       AllocationFlags;
            ULONG       FreeType;
        } In;
        struct
        {
            ULONG_PTR   BaseAddress;
            SIZE_T      RegionSize;
            ULONG       OldProtection;
        } Out;
    };
} VM_OPERATION, *PVM_OPERATION;

typedef struct _VM_READ_WRITE
{
    ULONG       ProcessId;
    ULONG_PTR   TargetAddress;
    ULONG_PTR   Buffer;
    ULONG_PTR   BufferSize;
} VM_READ_WRITE, *PVM_READ_WRITE;

typedef struct _VM_QUERY_INFO
{
    union
    {
        struct
        {
            ULONG       ProcessId;
            ULONG_PTR   BaseAddress;
        } In;
        MEMORY_BASIC_INFORMATION Out;
    };
} VM_QUERY_INFO, *PVM_QUERY_INFO;

typedef struct _GRANT_ACCESS
{
    union
    {
        struct
        {
            ULONG       ProcessId;
            ULONG_PTR   Handle;
            ULONG       AccessMask;
        } In;
        struct
        {
            ULONG   OldAccessMask;
        } Out;
    };
} GRANT_ACCESS, *PGRANT_ACCESS;

typedef struct _PROTECT_PROCESS
{
    union
    {
        struct
        {
            ULONG   ProcessId;
            ULONG   ProtectionLevel;
        } In;
    };
} PROTECT_PROCESS, *PPROTECT_PROCESS;

typedef struct _OPEN_PROCESS
{
    union
    {
        struct
        {
            ULONG   ProcessId;      // Any of these can be 0, but not both.
            ULONG   ThreadId;       // If ProcessId is 0, we open the process that contains the ThreadId
            ULONG   AccessMask;
        } In;
        struct
        {
            ULONG_PTR Handle;
        } Out;
    };
} OPEN_PROCESS, *POPEN_PROCESS;

typedef struct _OPEN_THREAD
{
    union
    {
        struct
        {
            ULONG   ThreadId;
            ULONG   AccessMask;
        } In;
        struct
        {
            ULONG_PTR Handle;
        } Out;
    };
} OPEN_THREAD, *POPEN_THREAD;

typedef struct _SET_DEP_STATE
{
    union
    {
        struct
        {
            ULONG   ProcessId;
            BOOLEAN Enabled;
        } In;
    };
} SET_DEP_STATE, *PSET_DEP_STATE;

#pragma warning(default : 4201)