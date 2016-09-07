#pragma once

#define IN_REGION(x, Base, size) (((ULONG_PTR)x >= (ULONG_PTR)Base) && ((ULONG_PTR)x <= (ULONG_PTR)Base + (ULONG_PTR)size))
#define ALIGN_DOWN(count,size)   ((ULONG_PTR)(count) & ~((ULONG_PTR)(size) - 1))
#define ALIGN_UP(count,size)     (ALIGN_DOWN( (ULONG_PTR)(count)+(ULONG_PTR)(size)-1, (ULONG_PTR)(size) ))

#define CALLBACK_MODIFY_STATE    0x0001
#define CALLBACK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|CALLBACK_MODIFY_STATE )

#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
                              DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

#define EVENT_QUERY_STATE       0x0001
#define EVENT_MODIFY_STATE      0x0002  
#define EVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 

#define EVENT_PAIR_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)

#define IO_COMPLETION_QUERY_STATE   0x0001
#define IO_COMPLETION_MODIFY_STATE  0x0002  
#define IO_COMPLETION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 

#define KEYEDEVENT_WAIT 0x0001
#define KEYEDEVENT_WAKE 0x0002
#define KEYEDEVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | KEYEDEVENT_WAIT | KEYEDEVENT_WAKE)

#define MUTANT_QUERY_STATE      0x0001

#define PORT_CONNECT (0x0001)
#define PORT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1)

#define PROFILE_CONTROL (0x0001)
#define PROFILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | PROFILE_CONTROL)

#define SEMAPHORE_QUERY_STATE       0x0001
#define SEMAPHORE_MODIFY_STATE      0x0002 
#define SEMAPHORE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

#define SYMBOLIC_LINK_QUERY (0x0001)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define THREAD_ALERT	(0x0004)

#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define OBJECT_TYPE_CREATE (0x0001)
#define OBJECT_TYPE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define WMIGUID_QUERY                 0x0001
#define WMIGUID_SET                   0x0002
#define WMIGUID_NOTIFICATION          0x0004
#define WMIGUID_READ_DESCRIPTION      0x0008
#define WMIGUID_EXECUTE               0x0010
#define TRACELOG_CREATE_REALTIME      0x0020
#define TRACELOG_CREATE_ONDISK        0x0040
#define TRACELOG_GUID_ENABLE          0x0080
#define TRACELOG_ACCESS_KERNEL_LOGGER 0x0100
#define TRACELOG_CREATE_INPROC        0x0200
#define TRACELOG_ACCESS_REALTIME      0x0400
#define TRACELOG_REGISTER_GUIDS       0x0800

//
// Global flags that can be set to control system behavior.
// Flag word is 32 bits.
//
#define FLG_STOP_ON_EXCEPTION           0x00000001      // user and kernel mode
#define FLG_SHOW_LDR_SNAPS              0x00000002      // user and kernel mode
#define FLG_DEBUG_INITIAL_COMMAND       0x00000004      // kernel mode only up until WINLOGON started
#define FLG_STOP_ON_HUNG_GUI            0x00000008      // kernel mode only while running

#define FLG_HEAP_ENABLE_TAIL_CHECK      0x00000010      // user mode only
#define FLG_HEAP_ENABLE_FREE_CHECK      0x00000020      // user mode only
#define FLG_HEAP_VALIDATE_PARAMETERS    0x00000040      // user mode only
#define FLG_HEAP_VALIDATE_ALL           0x00000080      // user mode only

#define FLG_APPLICATION_VERIFIER        0x00000100      // user mode only
#define FLG_POOL_ENABLE_TAGGING         0x00000400      // kernel mode only
#define FLG_HEAP_ENABLE_TAGGING         0x00000800      // user mode only

#define FLG_USER_STACK_TRACE_DB         0x00001000      // x86 user mode only
#define FLG_KERNEL_STACK_TRACE_DB       0x00002000      // x86 kernel mode only at boot time
#define FLG_MAINTAIN_OBJECT_TYPELIST    0x00004000      // kernel mode only at boot time
#define FLG_HEAP_ENABLE_TAG_BY_DLL      0x00008000      // user mode only

#define FLG_DISABLE_STACK_EXTENSION     0x00010000      // user mode only
#define FLG_ENABLE_CSRDEBUG             0x00020000      // kernel mode only at boot time
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD   0x00040000      // kernel mode only
#define FLG_DISABLE_PAGE_KERNEL_STACKS  0x00080000      // kernel mode only at boot time

#define FLG_ENABLE_SYSTEM_CRIT_BREAKS   0x00100000      // user mode only
#define FLG_HEAP_DISABLE_COALESCING     0x00200000      // user mode only
#define FLG_ENABLE_CLOSE_EXCEPTIONS     0x00400000      // kernel mode only
#define FLG_ENABLE_EXCEPTION_LOGGING    0x00800000      // kernel mode only

#define FLG_ENABLE_HANDLE_TYPE_TAGGING  0x01000000      // kernel mode only
#define FLG_HEAP_PAGE_ALLOCS            0x02000000      // user mode only
#define FLG_DEBUG_INITIAL_COMMAND_EX    0x04000000      // kernel mode only up until WINLOGON started
#define FLG_DISABLE_DBGPRINT            0x08000000      // kernel mode only

#define FLG_CRITSEC_EVENT_CREATION      0x10000000      // user mode only, Force early creation of resource events
#define FLG_LDR_TOP_DOWN                0x20000000      // user mode only, win64 only
#define FLG_ENABLE_HANDLE_EXCEPTIONS    0x40000000      // kernel mode only
#define FLG_DISABLE_PROTDLLS            0x80000000      // user mode only (smss/winlogon)

#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define ZwCurrentThread()  NtCurrentThread()

//
// Define special ByteOffset parameters for read and write operations
//
#define FILE_WRITE_TO_END_OF_FILE       0xffffffff
#define FILE_USE_FILE_POINTER_POSITION  0xfffffffe

//
// This is the maximum MaximumLength for a UNICODE_STRING.
//
#define MAXUSHORT   0xffff     
#define MAX_USTRING (sizeof(WCHAR) * (MAXUSHORT/sizeof(WCHAR)))

#ifndef ANSI_NULL
#define ANSI_NULL ((CHAR)0)
#endif

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

typedef enum _SYSTEM_MEMORY_LIST_COMMAND
{
    MemoryCaptureAccessedBits,
    MemoryCaptureAndResetAccessedBits,
    MemoryEmptyWorkingSets,
    MemoryFlushModifiedList,
    MemoryPurgeStandbyList,
    MemoryPurgeLowPriorityStandbyList,
    MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;

typedef enum _THREAD_STATE
{
    StateInitialized,
    StateReady,
    StateRunning,
    StateStandby,
    StateTerminated,
    StateWait,
    StateTransition,
    StateUnknown
} THREAD_STATE;

typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    MaximumWaitReason
} KWAIT_REASON;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessCycleTime = 38,
    ProcessPagePriority = 39,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47,
    ProcessTokenVirtualizationEnabled = 48,
    ProcessOwnerInformation = 49,
    ProcessWindowInformation = 50,
    ProcessHandleInformation = 51,
    ProcessMitigationPolicy = 52,
    ProcessDynamicFunctionTableInformation = 53,
    ProcessHandleCheckingMode = 54,
    ProcessKeepAliveCount = 55,
    ProcessRevokeFileHandles = 56,
    ProcessWorkingSetControl = 57,
    ProcessHandleTable = 58,
    ProcessCheckStackExtentsMode = 59,
    ProcessCommandLineInformation = 60,
    ProcessProtectionInformation = 61,
    MaxProcessInfoClass = 62
} PROCESSINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
    SystemNumaProximityNodeInformation = 101,
    SystemDynamicTimeZoneInformation = 102,
    SystemCodeIntegrityInformation = 103,
    SystemProcessorMicrocodeUpdateInformation = 104,
    SystemProcessorBrandString = 105,
    SystemVirtualAddressInformation = 106,
    SystemLogicalProcessorAndGroupInformation = 107,
    SystemProcessorCycleTimeInformation = 108,
    SystemStoreInformation = 109,
    SystemRegistryAppendString = 110,
    SystemAitSamplingValue = 111,
    SystemVhdBootInformation = 112,
    SystemCpuQuotaInformation = 113,
    SystemNativeBasicInformation = 114,
    SystemErrorPortTimeouts = 115,
    SystemLowPriorityIoInformation = 116,
    SystemBootEntropyInformation = 117,
    SystemVerifierCountersInformation = 118,
    SystemPagedPoolInformationEx = 119,
    SystemSystemPtesInformationEx = 120,
    SystemNodeDistanceInformation = 121,
    SystemAcpiAuditInformation = 122,
    SystemBasicPerformanceInformation = 123,
    SystemQueryPerformanceCounterInformation = 124,
    SystemSessionBigPoolInformation = 125,
    SystemBootGraphicsInformation = 126,
    SystemScrubPhysicalMemoryInformation = 127,
    SystemBadPageInformation = 128,
    SystemProcessorProfileControlArea = 129,
    SystemCombinePhysicalMemoryInformation = 130,
    SystemEntropyInterruptTimingInformation = 131,
    SystemConsoleInformation = 132,
    SystemPlatformBinaryInformation = 133,
    SystemPolicyInformation = 134,
    SystemHypervisorProcessorCountInformation = 135,
    SystemDeviceDataInformation = 136,
    SystemDeviceDataEnumerationInformation = 137,
    SystemMemoryTopologyInformation = 138,
    SystemMemoryChannelInformation = 139,
    SystemBootLogoInformation = 140,
    SystemProcessorPerformanceInformationEx = 141,
    SystemSpare0 = 142,
    SystemSecureBootPolicyInformation = 143,
    SystemPageFileInformationEx = 144,
    SystemSecureBootInformation = 145,
    SystemEntropyInterruptTimingRawInformation = 146,
    SystemPortableWorkspaceEfiLauncherInformation = 147,
    SystemFullProcessInformation = 148,
    SystemKernelDebuggerInformationEx = 149,
    SystemBootMetadataInformation = 150,
    SystemSoftRebootInformation = 151,
    SystemElamCertificateInformation = 152,
    SystemOfflineDumpConfigInformation = 153,
    SystemProcessorFeaturesInformation = 154,
    SystemRegistryReconciliationInformation = 155,
    SystemEdidInformation = 156,
    MaxSystemInfoClass = 157
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _TIMER_TYPE
{
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

typedef enum _TIMER_INFORMATION_CLASS
{
    TimerBasicInformation
} TIMER_INFORMATION_CLASS;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) {   \
            (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
            (p)->RootDirectory = r;                             \
            (p)->Attributes = a;                                \
            (p)->ObjectName = n;                                \
            (p)->SecurityDescriptor = s;                        \
            (p)->SecurityQualityOfService = NULL;               \
        }

//
// Valid values for the Attributes field
//
#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L
#endif

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_point                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsepointnformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

//
// Define the NamedPipeType flags for NtCreateNamedPipeFile
//
#define FILE_PIPE_BYTE_STREAM_TYPE      0x00000000
#define FILE_PIPE_MESSAGE_TYPE          0x00000001

//
// Define the CompletionMode flags for NtCreateNamedPipeFile
//
#define FILE_PIPE_QUEUE_OPERATION       0x00000000
#define FILE_PIPE_COMPLETE_OPERATION    0x00000001

//
// Define the ReadMode flags for NtCreateNamedPipeFile
//
#define FILE_PIPE_BYTE_STREAM_MODE      0x00000000
#define FILE_PIPE_MESSAGE_MODE          0x00000001

//
// Define the NamedPipeConfiguration flags for NtQueryInformation
//
#define FILE_PIPE_INBOUND               0x00000000
#define FILE_PIPE_OUTBOUND              0x00000001
#define FILE_PIPE_FULL_DUPLEX           0x00000002

//
// Define the NamedPipeState flags for NtQueryInformation
//
#define FILE_PIPE_DISCONNECTED_STATE    0x00000001
#define FILE_PIPE_LISTENING_STATE       0x00000002
#define FILE_PIPE_CONNECTED_STATE       0x00000003
#define FILE_PIPE_CLOSING_STATE         0x00000004

//
// Define the NamedPipeEnd flags for NtQueryInformation
//
#define FILE_PIPE_CLIENT_END            0x00000000
#define FILE_PIPE_SERVER_END            0x00000001

//
// Define the flags for NtSet(Query)EaFile service structure entries
//
#define FILE_NEED_EA                    0x00000080

//
// Define EA type values
//
#define FILE_EA_TYPE_BINARY             0xfffe
#define FILE_EA_TYPE_ASCII              0xfffd
#define FILE_EA_TYPE_BITMAP             0xfffb
#define FILE_EA_TYPE_METAFILE           0xfffa
#define FILE_EA_TYPE_ICON               0xfff9
#define FILE_EA_TYPE_EA                 0xffee
#define FILE_EA_TYPE_MVMT               0xffdf
#define FILE_EA_TYPE_MVST               0xffde
#define FILE_EA_TYPE_ASN1               0xffdd
#define FILE_EA_TYPE_FAMILY_IDS         0xff01

typedef enum _SECTION_INFORMATION_CLASS
{
    SectionBasicInformation,
    SectionImageInformation,
    SectionRelocationInformation,
    MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#define SEC_BASED          0x200000
#define SEC_NO_CHANGE      0x400000
#define SEC_FILE           0x800000     
#define SEC_IMAGE         0x1000000     
#define SEC_RESERVE       0x4000000     
#define SEC_COMMIT        0x8000000     
#define SEC_NOCACHE      0x10000000     
#define SEC_GLOBAL       0x20000000
#define SEC_LARGE_PAGES  0x80000000    

#define NUMBER_SERVICE_TABLES 2
#define SERVICE_NUMBER_MASK ((1 << 12) -  1)

#if defined(_WIN64)

#if defined(_AMD64_)

#define SERVICE_TABLE_SHIFT (12 - 4)
#define SERVICE_TABLE_MASK (((1 << 1) - 1) << 4)
#define SERVICE_TABLE_TEST (WIN32K_SERVICE_INDEX << 4)

#else

#define SERVICE_TABLE_SHIFT (12 - 5)
#define SERVICE_TABLE_MASK (((1 << 1) - 1) << 5)
#define SERVICE_TABLE_TEST (WIN32K_SERVICE_INDEX << 5)

#endif

#else

#define SERVICE_TABLE_SHIFT (12 - 4)
#define SERVICE_TABLE_MASK (((1 << 1) - 1) << 4)
#define SERVICE_TABLE_TEST (WIN32K_SERVICE_INDEX << 4)

#endif

typedef enum _MUTANT_INFORMATION_CLASS
{
    MutantBasicInformation
} MUTANT_INFORMATION_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
    IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

typedef enum _EVENT_TYPE
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

// Privileges
#ifndef SE_MIN_WELL_KNOWN_PRIVILEGE
#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

//
// Header flags
//
#define OB_FLAG_NEW_OBJECT              0x01
#define OB_FLAG_KERNEL_OBJECT           0x02
#define OB_FLAG_CREATOR_INFO            0x04
#define OB_FLAG_EXCLUSIVE_OBJECT        0x08
#define OB_FLAG_PERMANENT_OBJECT        0x10
#define OB_FLAG_DEFAULT_SECURITY_QUOTA  0x20
#define OB_FLAG_SINGLE_HANDLE_ENTRY     0x40
#define OB_FLAG_DELETED_INLINE          0x80

//
// InfoMask values
//
#define OB_INFOMASK_PROCESS_INFO	0x10
#define OB_INFOMASK_QUOTA			0x08
#define OB_INFOMASK_HANDLE			0x04
#define OB_INFOMASK_NAME			0x02
#define OB_INFOMASK_CREATOR_INFO	0x01

typedef enum _POOL_TYPE
{
    NonPagedPool = 0,
    NonPagedPoolExecute = 0,
    PagedPool = 1,
    NonPagedPoolMustSucceed = 2,
    DontUseThisType = 3,
    NonPagedPoolCacheAligned = 4,
    PagedPoolCacheAligned = 5,
    NonPagedPoolCacheAlignedMustS = 6,
    MaxPoolType = 7,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = 2,
    NonPagedPoolBaseCacheAligned = 4,
    NonPagedPoolBaseCacheAlignedMustS = 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = 33,
    NonPagedPoolMustSucceedSession = 34,
    DontUseThisTypeSession = 35,
    NonPagedPoolCacheAlignedSession = 36,
    PagedPoolCacheAlignedSession = 37,
    NonPagedPoolCacheAlignedMustSSession = 38,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = 516,
    NonPagedPoolSessionNx = 544
} POOL_TYPE;

#define OBJECT_TO_OBJECT_HEADER(obj) \
        CONTAINING_RECORD( (obj), OBJECT_HEADER, Body )

#define TIMER_TOLERABLE_DELAY_BITS      6
#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5

#define MAXIMUM_VOLUME_LABEL_LENGTH  (32 * sizeof(WCHAR)) // 32 characters

enum _KOBJECTS
{
    EventNotificationObject = 0x0,
    EventSynchronizationObject = 0x1,
    MutantObject = 0x2,
    ProcessObject = 0x3,
    QueueObject = 0x4,
    SemaphoreObject = 0x5,
    ThreadObject = 0x6,
    GateObject = 0x7,
    TimerNotificationObject = 0x8,
    TimerSynchronizationObject = 0x9,
    Spare2Object = 0xa,
    Spare3Object = 0xb,
    Spare4Object = 0xc,
    Spare5Object = 0xd,
    Spare6Object = 0xe,
    Spare7Object = 0xf,
    Spare8Object = 0x10,
    Spare9Object = 0x11,
    ApcObject = 0x12,
    DpcObject = 0x13,
    DeviceQueueObject = 0x14,
    EventPairObject = 0x15,
    InterruptObject = 0x16,
    ProfileObject = 0x17,
    ThreadedDpcObject = 0x18,
    MaximumKernelObject = 0x19,
};

#define DO_VERIFY_VOLUME                0x00000002      // ntddk nthal ntifs wdm
#define DO_BUFFERED_IO                  0x00000004      // ntddk nthal ntifs wdm
#define DO_EXCLUSIVE                    0x00000008      // ntddk nthal ntifs wdm
#define DO_DIRECT_IO                    0x00000010      // ntddk nthal ntifs wdm
#define DO_MAP_IO_BUFFER                0x00000020      // ntddk nthal ntifs wdm
#define DO_DEVICE_HAS_NAME              0x00000040      // ntddk nthal ntifs
#define DO_DEVICE_INITIALIZING          0x00000080      // ntddk nthal ntifs wdm
#define DO_SYSTEM_BOOT_PARTITION        0x00000100      // ntddk nthal ntifs
#define DO_LONG_TERM_REQUESTS           0x00000200      // ntddk nthal ntifs
#define DO_NEVER_LAST_DEVICE            0x00000400      // ntddk nthal ntifs
#define DO_SHUTDOWN_REGISTERED          0x00000800      // ntddk nthal ntifs wdm
#define DO_BUS_ENUMERATED_DEVICE        0x00001000      // ntddk nthal ntifs wdm
#define DO_POWER_PAGABLE                0x00002000      // ntddk nthal ntifs wdm
#define DO_POWER_INRUSH                 0x00004000      // ntddk nthal ntifs wdm
#define DO_POWER_NOOP                   0x00008000
#define DO_LOW_PRIORITY_FILESYSTEM      0x00010000      // ntddk nthal ntifs
#define DO_XIP                          0x00020000

#define FILE_REMOVABLE_MEDIA                        0x00000001
#define FILE_READ_ONLY_DEVICE                       0x00000002
#define FILE_FLOPPY_DISKETTE                        0x00000004
#define FILE_WRITE_ONCE_MEDIA                       0x00000008
#define FILE_REMOTE_DEVICE                          0x00000010
#define FILE_DEVICE_IS_MOUNTED                      0x00000020
#define FILE_VIRTUAL_VOLUME                         0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME              0x00000080
#define FILE_DEVICE_SECURE_OPEN                     0x00000100
#define FILE_CHARACTERISTIC_PNP_DEVICE              0x00000800
#define FILE_CHARACTERISTIC_TS_DEVICE               0x00001000
#define FILE_CHARACTERISTIC_WEBDAV_DEVICE           0x00002000
#define FILE_CHARACTERISTIC_CSV                     0x00010000
#define FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL    0x00020000
#define FILE_PORTABLE_DEVICE                        0x00040000

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated, 
    ThreadLastSystemCall,
    ThreadIoPriority, 
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    ThreadCpuAccountingInformation, // since WIN8
    ThreadSuspendCount, // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, 
    ThreadNameInformation,
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, 
    ThreadActualGroupAffinity,
    MaxThreadInfoClass
} THREADINFOCLASS;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003
#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

#define GDI_MAX_HANDLE_COUNT 0x4000

#define FLS_MAXIMUM_AVAILABLE 128
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

#define GDI_BATCH_BUFFER_SIZE 310

#define LPC_REQUEST             1
#define LPC_REPLY               2
#define LPC_DATAGRAM            3
#define LPC_LOST_REPLY          4
#define LPC_PORT_CLOSED         5
#define LPC_CLIENT_DIED         6
#define LPC_EXCEPTION           7
#define LPC_DEBUG_EVENT         8
#define LPC_ERROR_EVENT         9
#define LPC_CONNECTION_REQUEST 10

#define PORT_VALID_OBJECT_ATTRIBUTES (OBJ_CASE_INSENSITIVE)
#define PORT_MAXIMUM_MESSAGE_LENGTH 256

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

#define PROCESSOR_FEATURE_MAX 64

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign,                 // None == 0 == standard design
    NEC98x86,                       // NEC PC98xx series on X86
    EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

//
// Define Address of User Shared Data
//
#define MM_SHARED_USER_DATA_VA      0x000000007FFE0000
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)MM_SHARED_USER_DATA_VA)