#include "native_structs.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#pragma comment(lib, "ntdll.lib")

    __inline struct _PEB * NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }

    typedef VOID(NTAPI *PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION)(
        _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
        _In_ PVOID Context,
        _In_ OUT BOOLEAN *StopEnumeration
        );

    NTSTATUS NTAPI LdrEnumerateLoadedModules(
        _In_opt_ ULONG Flags,
        _In_     PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION CallbackFunction,
        _In_opt_ PVOID Context
    );

    NTSTATUS NTAPI LdrGetProcedureAddress(
        _In_     PVOID DllHandle,
        _In_opt_ CONST ANSI_STRING* ProcedureName,
        _In_opt_ ULONG ProcedureNumber,
        _Out_    PVOID *ProcedureAddress
    );

    NTSTATUS NTAPI LdrLoadDll(
        _In_opt_ PCWSTR DllPath,
        _In_opt_ PULONG DllCharacteristics,
        _In_     PCUNICODE_STRING DllName,
        _Out_    PVOID *DllHandle
    );

    NTSTATUS NTAPI LdrUnloadDll(
        _In_ PVOID DllHandle
    );

    NTSTATUS NTAPI LdrGetDllHandle(
        _In_opt_ PCWSTR DllPath OPTIONAL,
        _In_opt_ PULONG DllCharacteristics OPTIONAL,
        _In_ PCUNICODE_STRING DllName,
        _Out_ PVOID *DllHandle
    );

    NTSTATUS NTAPI LdrFindResource_U(
        _In_ PVOID DllHandle,
        _In_ CONST ULONG_PTR* ResourceIdPath,
        _In_ ULONG ResourceIdPathLength,
        _Out_ PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry
    );

    NTSTATUS NTAPI LdrAccessResource(
        _In_ PVOID DllHandle,
        _In_ CONST IMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry,
        _Out_opt_ PVOID *Address,
        _Out_opt_ PULONG size
    );

    NTSTATUS NTAPI LdrFindEntryForAddress(
        _In_ PVOID Address,
        _Out_ PLDR_DATA_TABLE_ENTRY *TableEntry
    );

    ULONG NTAPI CsrGetProcessId();

    ULONG NTAPI RtlRandomEx(
        _Inout_ PULONG Seed
    );

    PVOID NTAPI RtlAddVectoredExceptionHandler(
        _In_ ULONG First,
        _In_ PVECTORED_EXCEPTION_HANDLER Handler
    );

    ULONG NTAPI RtlRemoveVectoredExceptionHandler(
        _In_ PVOID Handle
    );

    VOID NTAPI RtlPushFrame(
        _In_ PTEB_ACTIVE_FRAME Frame
    );

    VOID NTAPI RtlPopFrame(
        _In_ PTEB_ACTIVE_FRAME Frame
    );

    PTEB_ACTIVE_FRAME NTAPI RtlGetFrame(
        VOID
    );

    VOID NTAPI RtlInitUnicodeString(
        _Inout_	PUNICODE_STRING DestinationString,
        _In_	PCWSTR SourceString
    );

    BOOLEAN NTAPI RtlEqualUnicodeString(
        _In_ PCUNICODE_STRING String1,
        _In_ PCUNICODE_STRING String2,
        _In_ BOOLEAN CaseInSensitive
    );

    BOOLEAN NTAPI RtlPrefixUnicodeString(
        _In_ PCUNICODE_STRING String1,
        _In_ PCUNICODE_STRING String2,
        _In_ BOOLEAN CaseInSensitive
    );

    NTSTATUS NTAPI RtlGetVersion(
        _Inout_	PRTL_OSVERSIONINFOW lpVersionInformation
    );

    ULONG NTAPI RtlNtStatusToDosError(
        _In_ NTSTATUS Status
    );

    NTSTATUS NTAPI RtlGetOwnerSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PSID *Owner,
        _Out_ PBOOLEAN OwnerDefaulted
    );

    NTSTATUS NTAPI RtlGetGroupSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PSID *Group,
        _Out_ PBOOLEAN GroupDefaulted
    );

    NTSTATUS NTAPI RtlGetDaclSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PBOOLEAN DaclPresent,
        _Out_ PACL *Dacl,
        _Out_ PBOOLEAN DaclDefaulted
    );

    NTSTATUS NTAPI RtlGetSaclSecurityDescriptor(
        _In_  PSECURITY_DESCRIPTOR SecurityDescriptor,
        _Out_ PBOOLEAN SaclPresent,
        _Out_ PACL *Sacl,
        _Out_ PBOOLEAN SaclDefaulted
    );

    ULONG NTAPI RtlLengthSecurityDescriptor(
        _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

    VOID NTAPI RtlMapGenericMask(
        _In_ PACCESS_MASK AccessMask,
        _In_ PGENERIC_MAPPING GenericMapping
    );

    VOID NTAPI RtlInitString(
        PSTRING DestinationString,
        PCSZ SourceString
    );

    NTSTATUS NTAPI RtlExpandEnvironmentStrings_U(
        _In_opt_	PVOID Environment,
        _In_		PCUNICODE_STRING Source,
        _Out_		PUNICODE_STRING Destination,
        _Out_opt_	PULONG ReturnedLength
    );

    VOID NTAPI RtlSetLastWin32Error(
        LONG Win32Error
    );

    PVOID NTAPI RtlAllocateHeap(
        _In_ PVOID HeapHandle,
        _In_ ULONG Flags,
        _In_ SIZE_T size
    );

    BOOLEAN NTAPI RtlFreeHeap(
        _In_ PVOID HeapHandle,
        _In_ ULONG Flags,
        _In_ PVOID BaseAddress
    );

    BOOLEAN NTAPI RtlValidSid(
        PSID Sid
    );

    BOOLEAN NTAPI RtlEqualSid(
        PSID Sid1,
        PSID Sid2
    );

    BOOLEAN NTAPI RtlEqualPrefixSid(
        PSID Sid1,
        PSID Sid2
    );

    ULONG NTAPI RtlLengthRequiredSid(
        ULONG SubAuthorityCount
    );

    PVOID NTAPI RtlFreeSid(
        IN PSID Sid
    );

    NTSTATUS NTAPI RtlAllocateAndInitializeSid(
        IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        IN UCHAR SubAuthorityCount,
        IN ULONG SubAuthority0,
        IN ULONG SubAuthority1,
        IN ULONG SubAuthority2,
        IN ULONG SubAuthority3,
        IN ULONG SubAuthority4,
        IN ULONG SubAuthority5,
        IN ULONG SubAuthority6,
        IN ULONG SubAuthority7,
        OUT PSID *Sid
    );

    NTSTATUS NTAPI RtlInitializeSid(
        PSID Sid,
        PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
        UCHAR SubAuthorityCount
    );

    PSID_IDENTIFIER_AUTHORITY NTAPI RtlIdentifierAuthoritySid(
        PSID Sid
    );

    PULONG NTAPI RtlSubAuthoritySid(
        PSID Sid,
        ULONG SubAuthority
    );

    PUCHAR NTAPI RtlSubAuthorityCountSid(
        PSID Sid
    );

    ULONG NTAPI RtlLengthSid(
        PSID Sid
    );

    NTSTATUS NTAPI RtlCopySid(
        ULONG DestinationSidLength,
        PSID DestinationSid,
        PSID SourceSid
    );

    NTSTATUS NTAPI RtlCopySidAndAttributesArray(
        ULONG ArrayLength,
        PSID_AND_ATTRIBUTES Source,
        ULONG TargetSidBufferSize,
        PSID_AND_ATTRIBUTES TargetArrayElement,
        PSID TargetSid,
        PSID *NextTargetSid,
        PULONG RemainingTargetSidSize
    );

    NTSTATUS NTAPI RtlLengthSidAsUnicodeString(
        PSID Sid,
        PULONG StringLength
    );

    NTSTATUS NTAPI RtlConvertSidToUnicodeString(
        PUNICODE_STRING UnicodeString,
        PSID Sid,
        BOOLEAN AllocateDestinationString
    );

    NTSTATUS NTAPI RtlCreateSecurityDescriptor(
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        ULONG Revision
    );

    NTSTATUS NTAPI RtlSetOwnerSecurityDescriptor(
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        PSID Owner,
        BOOLEAN OwnerDefaulted
    );

    FORCEINLINE LUID NTAPI RtlConvertLongToLuid(
        LONG Long
    )
    {
        LUID TempLuid;
        LARGE_INTEGER TempLi;

        TempLi.QuadPart = Long;
        TempLuid.LowPart = TempLi.LowPart;
        TempLuid.HighPart = TempLi.HighPart;
        return(TempLuid);
    }

    NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(
        _Out_ PUNICODE_STRING CurrentUserKeyPath
    );

    VOID NTAPI RtlFreeUnicodeString(
        PUNICODE_STRING UnicodeString
    );

    VOID NTAPI RtlFreeAnsiString(
        PANSI_STRING AnsiString
    );

    NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
        PUNICODE_STRING DestinationString,
        PCANSI_STRING SourceString,
        BOOLEAN AllocateDestinationString
    );

    BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
        _In_ PCWSTR DosFileName,
        _Out_ PUNICODE_STRING NtFileName,
        _Out_opt_ PWSTR *FilePart,
        PVOID Reserved
    );

    NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(
        _In_ USHORT CompressionFormatAndEngine,
        _Out_ PULONG CompressBufferWorkSpaceSize,
        _Out_ PULONG CompressFragmentWorkSpaceSize
    );

    NTSTATUS NTAPI RtlCompressBuffer(
        _In_ USHORT CompressionFormatAndEngine,
        _In_ PUCHAR UncompressedBuffer,
        _In_ ULONG UncompressedBufferSize,
        _Out_ PUCHAR CompressedBuffer,
        _In_ ULONG CompressedBufferSize,
        _In_ ULONG UncompressedChunkSize,
        _Out_ PULONG FinalCompressedSize,
        _In_ PVOID WorkSpace
    );

    NTSTATUS NTAPI RtlDecompressBuffer(
        _In_ USHORT CompressionFormat,
        _Out_ PUCHAR UncompressedBuffer,
        _In_ ULONG UncompressedBufferSize,
        _In_ PUCHAR CompressedBuffer,
        _In_ ULONG CompressedBufferSize,
        _Out_ PULONG FinalUncompressedSize
    );

    PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
        _In_ PVOID Base
    );

    NTSYSAPI PVOID NTAPI RtlAddressInSectionTable(
        _In_ PIMAGE_NT_HEADERS NtHeaders,
        _In_ PVOID BaseOfImage,
        _In_ ULONG VirtualAddress
    );

    PVOID NTAPI RtlImageDirectoryEntryToData(
        PVOID BaseOfImage,
        BOOLEAN MappedAsImage,
        USHORT DirectoryEntry,
        PULONG size
    );

    VOID NTAPI RtlSecondsSince1970ToTime(
        ULONG ElapsedSeconds,
        PLARGE_INTEGER Time
    );

    VOID NTAPI RtlSecondsSince1980ToTime(
        ULONG ElapsedSeconds,
        PLARGE_INTEGER Time
    );

    BOOLEAN NTAPI RtlTimeToSecondsSince1980(
        PLARGE_INTEGER Time,
        PULONG ElapsedSeconds
    );

    VOID NTAPI RtlTimeToTimeFields(
        _Inout_ PLARGE_INTEGER Time,
        _Inout_ PTIME_FIELDS TimeFields
    );

    BOOLEAN NTAPI RtlTimeFieldsToTime(
        PTIME_FIELDS TimeFields,
        PLARGE_INTEGER Time
    );

    ULONG32 NTAPI RtlComputeCrc32(
        _In_ ULONG32 PartialCrc,
        _In_ PVOID Buffer,
        _In_ ULONG Length
    );

    VOID NTAPI RtlGetNtVersionNumbers(
        _Out_opt_  PULONG MajorVersion,
        _Out_opt_  PULONG MinorVersion,
        _Out_opt_  PULONG BuildNumber
    );

    PPEB NTAPI RtlGetCurrentPeb(
        VOID
    );

    PWSTR NTAPI RtlIpv4AddressToStringW(
        __in const struct in_addr *Addr,
        __out_ecount(16) PWSTR S
    );

    NTSTATUS NTAPI RtlAdjustPrivilege(
        ULONG Privilege,
        BOOLEAN Enable,
        BOOLEAN CurrentThread,
        PBOOLEAN WasEnabled
    );

    ULONG NTAPI DbgPrint(
        _In_ PCH Format,
        ...
    );

    typedef enum _TABLE_SEARCH_RESULT
    {
        TableEmptyTree,
        TableFoundNode,
        TableInsertAsLeft,
        TableInsertAsRight
    } TABLE_SEARCH_RESULT;

    typedef enum _RTL_GENERIC_COMPARE_RESULTS
    {
        GenericLessThan,
        GenericGreaterThan,
        GenericEqual
    } RTL_GENERIC_COMPARE_RESULTS;

    typedef struct _RTL_AVL_TABLE *PRTL_AVL_TABLE;

    typedef RTL_GENERIC_COMPARE_RESULTS(NTAPI *PRTL_AVL_COMPARE_ROUTINE)(
        _In_ PRTL_AVL_TABLE Table,
        _In_ PVOID FirstStruct,
        _In_ PVOID SecondStruct
        );

    typedef PVOID(NTAPI *PRTL_AVL_ALLOCATE_ROUTINE)(
        _In_ PRTL_AVL_TABLE Table,
        _In_ ULONG ByteSize
        );

    typedef VOID(NTAPI *PRTL_AVL_FREE_ROUTINE)(
        _In_  PRTL_AVL_TABLE Table,
        _In_ _Post_invalid_ PVOID Buffer
        );

    typedef NTSTATUS(NTAPI *PRTL_AVL_MATCH_FUNCTION)(
        _In_ PRTL_AVL_TABLE Table,
        _In_ PVOID UserData,
        _In_ PVOID MatchData
        );

    typedef struct _RTL_BALANCED_LINKS
    {
        struct _RTL_BALANCED_LINKS *Parent;
        struct _RTL_BALANCED_LINKS *LeftChild;
        struct _RTL_BALANCED_LINKS *RightChild;
        CHAR Balance;
        UCHAR Reserved[3];
    } RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

    typedef struct _RTL_AVL_TABLE
    {
        RTL_BALANCED_LINKS BalancedRoot;
        PVOID Orderedpointer;
        ULONG WhichOrderedElement;
        ULONG NumberGenericTableElements;
        ULONG DepthOfTree;
        PRTL_BALANCED_LINKS RestartKey;
        ULONG DeleteCount;
        PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
        PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
        PRTL_AVL_FREE_ROUTINE FreeRoutine;
        PVOID TableContext;
    } RTL_AVL_TABLE, *PRTL_AVL_TABLE;

    VOID NTAPI RtlInitializeGenericTableAvl(
        _Out_ PRTL_AVL_TABLE Table,
        _In_ PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
        _In_ PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
        _In_ PRTL_AVL_FREE_ROUTINE FreeRoutine,
        _In_opt_ PVOID TableContext
    );

    PVOID NTAPI RtlInsertElementGenericTableAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ CLONG BufferSize,
        _Out_opt_ PBOOLEAN NewElement
    );

    PVOID NTAPI RtlInsertElementGenericTableFullAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ CLONG BufferSize,
        _Out_opt_ PBOOLEAN NewElement,
        _In_ PVOID NodeOrParent,
        _In_ TABLE_SEARCH_RESULT SearchResult
    );

    BOOLEAN NTAPI RtlDeleteElementGenericTableAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_ PVOID Buffer
    );

    PVOID NTAPI RtlLookupElementGenericTableAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_ PVOID Buffer
    );

    PVOID NTAPI RtlLookupElementGenericTableFullAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_ PVOID Buffer,
        _Out_ PVOID *NodeOrParent,
        _Out_ TABLE_SEARCH_RESULT *SearchResult
    );

    PVOID NTAPI RtlEnumerateGenericTableAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_ BOOLEAN Restart
    );

    PVOID NTAPI RtlEnumerateGenericTableWithoutSplayingAvl(
        _In_ PRTL_AVL_TABLE Table,
        _Inout_ PVOID *RestartKey
    );

    PVOID NTAPI RtlLookupFirstMatchingElementGenericTableAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_ PVOID Buffer,
        _Out_ PVOID *RestartKey
    );

    PVOID NTAPI RtlEnumerateGenericTableLikeADirectory(
        _In_ PRTL_AVL_TABLE Table,
        _In_opt_ PRTL_AVL_MATCH_FUNCTION MatchFunction,
        _In_opt_ PVOID MatchData,
        _In_ ULONG NextFlag,
        _Inout_ PVOID *RestartKey,
        _Inout_ PULONG DeleteCount,
        _In_ PVOID Buffer
    );

    PVOID NTAPI RtlGetElementGenericTableAvl(
        _In_ PRTL_AVL_TABLE Table,
        _In_ ULONG I
    );

    ULONG NTAPI RtlNumberGenericTableElementsAvl(
        _In_ PRTL_AVL_TABLE Table
    );

    BOOLEAN NTAPI RtlIsGenericTableEmptyAvl(
        _In_ PRTL_AVL_TABLE Table
    );

    /*
    ** Generic Avl END
    */

    /*
    ** Critical Section START
    */
#define LOGICAL ULONG

    NTSTATUS NTAPI RtlEnterCriticalSection(
        PRTL_CRITICAL_SECTION CriticalSection
    );

    NTSTATUS NTAPI RtlLeaveCriticalSection(
        PRTL_CRITICAL_SECTION CriticalSection
    );

    LOGICAL NTAPI RtlIsCriticalSectionLocked(
        IN PRTL_CRITICAL_SECTION CriticalSection
    );

    LOGICAL NTAPI RtlIsCriticalSectionLockedByThread(
        IN PRTL_CRITICAL_SECTION CriticalSection
    );

    ULONG NTAPI RtlGetCriticalSectionRecursionCount(
        IN PRTL_CRITICAL_SECTION CriticalSection
    );

    LOGICAL NTAPI RtlTryEnterCriticalSection(
        PRTL_CRITICAL_SECTION CriticalSection
    );

    NTSTATUS NTAPI RtlInitializeCriticalSection(
        PRTL_CRITICAL_SECTION CriticalSection
    );

    VOID NTAPI RtlEnableEarlyCriticalSectionEventCreation(
        VOID
    );

    NTSTATUS NTAPI RtlInitializeCriticalSectionAndSpinCount(
        PRTL_CRITICAL_SECTION CriticalSection,
        ULONG SpinCount
    );

    ULONG NTAPI RtlSetCriticalSectionSpinCount(
        PRTL_CRITICAL_SECTION CriticalSection,
        ULONG SpinCount
    );

    NTSTATUS NTAPI RtlDeleteCriticalSection(
        PRTL_CRITICAL_SECTION CriticalSection
    );

    /*
    ** Critical Section END
    */


    /*
    ** Loader API START
    */

    NTSTATUS NTAPI LdrGetProcedureAddress(
        _In_ PVOID DllHandle,
        _In_opt_ CONST ANSI_STRING* ProcedureName,
        _In_opt_ ULONG ProcedureNumber,
        _Out_ PVOID *ProcedureAddress
    );

    /*
    ** Loader API END
    */

    /*
    ** Native API START
    */

    NTSTATUS NTAPI NtClose(
        _In_ HANDLE Handle
    );

    NTSTATUS NTAPI NtOpenDirectoryObject(
        _Out_  PHANDLE				DirectoryHandle,
        _In_   ACCESS_MASK			DesiredAccess,
        _In_   POBJECT_ATTRIBUTES	ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryDirectoryObject(
        _In_       HANDLE DirectoryHandle,
        _Out_opt_  PVOID Buffer,
        _In_       ULONG Length,
        _In_       BOOLEAN ReturnSingleEntry,
        _In_       BOOLEAN RestartScan,
        _Inout_    PULONG Context,
        PULONG ReturnLength
    );

    NTSTATUS NTAPI NtQueryObject(
        _In_opt_   HANDLE Handle,
        _In_       OBJECT_INFORMATION_CLASS ObjectInformationClass,
        _Out_opt_  PVOID ObjectInformation,
        _In_       ULONG ObjectInformationLength,
        _Out_opt_  PULONG ReturnLength
    );

    NTSTATUS WINAPI NtQuerySystemInformation(
        _In_       SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Inout_    PVOID SystemInformation,
        _In_       ULONG SystemInformationLength,
        _Out_opt_  PULONG ReturnLength
    );

    NTSTATUS NTAPI NtCreateMutant(
        _Out_		PHANDLE MutantHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
        _In_		BOOLEAN InitialOwner
    );

    NTSTATUS NTAPI NtOpenMutant(
        _Out_	PHANDLE MutantHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryMutant(
        _In_		HANDLE MutantHandle,
        _In_		MUTANT_INFORMATION_CLASS MutantInformationClass,
        _Out_		PVOID MutantInformation,
        _In_		ULONG MutantInformationLength,
        _Out_opt_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtReleaseMutant(
        _In_		HANDLE MutantHandle,
        _Out_opt_	PLONG PreviousCount
    );

    NTSTATUS NTAPI NtCreateTimer(
        _In_		PHANDLE TimerHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
        _In_		TIMER_TYPE TimerType
    );

    NTSTATUS NtSetTimer(
        _In_		HANDLE TimerHandle,
        _In_		PLARGE_INTEGER DueTime,
        _In_opt_	PTIMER_APC_ROUTINE TimerApcRoutine,
        _In_opt_	PVOID TimerContext,
        _In_		BOOLEAN WakeTimer,
        _In_opt_	LONG Period,
        _Out_opt_	PBOOLEAN PreviousState
    );

    NTSTATUS NTAPI NtOpenTimer(
        _In_	PHANDLE TimerHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryTimer(
        _In_       HANDLE TimerHandle,
        _In_       TIMER_INFORMATION_CLASS TimerInformationClass,
        _Out_      PVOID TimerInformation,
        _In_       ULONG TimerInformationLength,
        _Out_opt_  PULONG ReturnLength
    );

    NTSTATUS NTAPI NtCreateSymbolicLinkObject(
        _Out_   PHANDLE LinkHandle,
        _In_    ACCESS_MASK DesiredAccess,
        _In_    POBJECT_ATTRIBUTES ObjectAttributes,
        _In_    PUNICODE_STRING LinkTarget
    );

    NTSTATUS WINAPI NtOpenSymbolicLinkObject(
        _Out_	PHANDLE LinkHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQuerySymbolicLinkObject(
        _In_		HANDLE LinkHandle,
        _Inout_		PUNICODE_STRING LinkTarget,
        _Out_opt_	PULONG  ReturnedLength
    );

    NTSTATUS NTAPI NtQuerySemaphore(
        _In_		HANDLE SemaphoreHandle,
        _In_		SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
        _Out_		PVOID SemaphoreInformation,
        _In_		ULONG SemaphoreInformationLength,
        _Out_opt_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtQueryDirectoryFile(
        _In_		HANDLE FileHandle,
        _In_opt_	HANDLE Event,
        _In_opt_	PIO_APC_ROUTINE ApcRoutine,
        _In_opt_	PVOID ApcContext,
        _Out_		PIO_STATUS_BLOCK IoStatusBlock,
        _Out_		PVOID FileInformation,
        _In_		ULONG Length,
        _In_		FILE_INFORMATION_CLASS FileInformationClass,
        _In_		BOOLEAN ReturnSingleEntry,
        _In_opt_	PUNICODE_STRING FileName,
        _In_		BOOLEAN RestartScan
    );

    NTSTATUS NTAPI NtQuerySection(
        _In_		HANDLE SectionHandle,
        _In_		SECTION_INFORMATION_CLASS SectionInformationClass,
        _Out_		PVOID SectionInformation,
        _In_		SIZE_T SectionInformationLength,
        _Out_opt_	PSIZE_T ReturnLength
    );

    NTSTATUS NtOpenSection(
        _Out_	PHANDLE SectionHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtCreateSection(
        _Out_		PHANDLE SectionHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_	PLARGE_INTEGER MaximumSize,
        _In_		ULONG SectionPageProtection,
        _In_		ULONG AllocationAttributes,
        _In_opt_	HANDLE FileHandle
    );

    NTSTATUS NTAPI NtMapViewOfSection(
        _In_		HANDLE SectionHandle,
        _In_		HANDLE ProcessHandle,
        __inout		PVOID *BaseAddress,
        _In_		ULONG_PTR ZeroBits,
        _In_		SIZE_T CommitSize,
        _Inout_opt_ PLARGE_INTEGER SectionOffset,
        _Inout_		PSIZE_T ViewSize,
        _In_		SECTION_INHERIT InheritDisposition,
        _In_		ULONG AllocationType,
        _In_		ULONG Win32Protect
    );

    NTSTATUS NTAPI NtUnmapViewOfSection(
        _In_	HANDLE ProcessHandle,
        _In_	PVOID BaseAddress
    );

    NTSTATUS NTAPI NtOpenProcessToken(
        _In_	HANDLE ProcessHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _Out_	PHANDLE TokenHandle
    );


    NTSTATUS NTAPI NtOpenThreadTokenEx(
        _In_       HANDLE ThreadHandle,
        _In_       ACCESS_MASK DesiredAccess,
        _In_       BOOLEAN OpenAsSelf,
        _In_       ULONG HandleAttributes,
        _Out_      PHANDLE TokenHandle
    );

    NTSTATUS NTAPI NtAdjustPrivilegesToken(
        _In_		HANDLE TokenHandle,
        _In_		BOOLEAN DisableAllPrivileges,
        _In_opt_	PTOKEN_PRIVILEGES NewState,
        _In_opt_	ULONG BufferLength,
        _Out_opt_	PTOKEN_PRIVILEGES PreviousState,
        _Out_opt_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtQueryInformationToken(
        _In_	HANDLE TokenHandle,
        _In_	TOKEN_INFORMATION_CLASS TokenInformationClass,
        _Out_	PVOID TokenInformation,
        _In_	ULONG TokenInformationLength,
        _Out_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtOpenKey(
        _Out_	PHANDLE KeyHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtDeleteKey(
        _In_       HANDLE KeyHandle
    );

    NTSTATUS NTAPI NtDeleteValueKey(
        _In_       HANDLE KeyHandle,
        _In_       PUNICODE_STRING ValueName
    );

    NTSTATUS NTAPI NtOpenJobObject(
        _Out_	PHANDLE JobHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryInformationJobObject(
        _In_opt_	HANDLE JobHandle,
        _In_		JOBOBJECTINFOCLASS JobObjectInformationClass,
        _Out_		PVOID JobObjectInformation,
        _In_		ULONG JobObjectInformationLength,
        _Out_opt_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtOpenIoCompletion(
        _Out_	PHANDLE IoCompletionHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryIoCompletion(
        _In_		HANDLE IoCompletionHandle,
        _In_		IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
        _Out_		PVOID IoCompletionInformation,
        _In_		ULONG IoCompletionInformationLength,
        _Out_opt_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtQueryInformationFile(
        _In_	HANDLE FileHandle,
        _Out_	PIO_STATUS_BLOCK IoStatusBlock,
        _Out_	PVOID FileInformation,
        _In_	ULONG Length,
        _In_	FILE_INFORMATION_CLASS FileInformationClass
    );

    NTSTATUS NTAPI NtFsControlFile(
        _In_     HANDLE FileHandle,
        _In_opt_ HANDLE Event,
        _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID ApcContext,
        _Out_    PIO_STATUS_BLOCK IoStatusBlock,
        _In_     ULONG FsControlCode,
        _In_     PVOID InputBuffer,
        _In_     ULONG InputBufferLength,
        _Out_    PVOID OutputBuffer,
        _In_     ULONG OutputBufferLength
    );

    NTSTATUS NTAPI NtQueryDirectoryFile(
        _In_      HANDLE FileHandle,
        _In_opt_  HANDLE Event,
        _In_opt_  PIO_APC_ROUTINE ApcRoutine,
        _In_opt_  PVOID ApcContext,
        _Out_     PIO_STATUS_BLOCK IoStatusBlock,
        _Out_     PVOID FileInformation,
        _In_      ULONG Length,
        _In_      FILE_INFORMATION_CLASS FileInformationClass,
        _In_      BOOLEAN ReturnSingleEntry,
        _In_opt_  PUNICODE_STRING FileName,
        _In_      BOOLEAN RestartScan
    );

    NTSTATUS NTAPI NtQueryEaFile(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        __out_bcount(Length) PVOID Buffer,
        _In_ ULONG Length,
        _In_ BOOLEAN ReturnSingleEntry,
        __in_bcount_opt(EaListLength) PVOID EaList,
        _In_ ULONG EaListLength,
        _In_opt_ PULONG EaIndex,
        _In_ BOOLEAN RestartScan
    );

    NTSTATUS NTAPI NtSetEaFile(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        __in_bcount(Length) PVOID Buffer,
        _In_ ULONG Length
    );

    NTSTATUS NTAPI NtQueryVolumeInformationFile(
        _In_    HANDLE FileHandle,
        _Out_   PIO_STATUS_BLOCK IoStatusBlock,
        _Out_   PVOID FsInformation,
        _In_    ULONG Length,
        _In_    FS_INFORMATION_CLASS FsInformationClass
    );

    NTSTATUS NTAPI NtOpenFile(
        _Out_	PHANDLE FileHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_	PIO_STATUS_BLOCK IoStatusBlock,
        _In_	ULONG ShareAccess,
        _In_	ULONG OpenOptions
    );

    NTSTATUS NTAPI NtReadFile(
        _In_     HANDLE FileHandle,
        _In_opt_ HANDLE Event,
        _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID ApcContext,
        _Out_    PIO_STATUS_BLOCK IoStatusBlock,
        __out_bcount(Length) PVOID Buffer,
        _In_     ULONG Length,
        _In_opt_ PLARGE_INTEGER ByteOffset,
        _In_opt_ PULONG Key
    );

    NTSTATUS NTAPI NtWriteFile(
        _In_ HANDLE FileHandle,
        _In_opt_ HANDLE Event,
        _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID ApcContext,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_ PVOID Buffer,
        _In_ ULONG Length,
        _In_opt_ PLARGE_INTEGER ByteOffset,
        _In_opt_ PULONG Key
    );

    NTSTATUS NTAPI NtFlushBuffersFile(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

    NTSTATUS NTAPI NtSetInformationFile(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        __in_bcount(Length) PVOID FileInformation,
        _In_ ULONG Length,
        _In_ FILE_INFORMATION_CLASS FileInformationClass
    );

    NTSTATUS NTAPI NtDeleteFile(
        _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtOpenEvent(
        _Out_	PHANDLE EventHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtOpenKeyedEvent(
        _Out_	PHANDLE KeyedEventHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtOpenSemaphore(
        _Out_	PHANDLE SemaphoreHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSTATUS NTAPI NtQueryEvent(
        _In_		HANDLE EventHandle,
        _In_		EVENT_INFORMATION_CLASS EventInformationClass,
        _Out_		PVOID EventInformation,
        _In_		ULONG EventInformationLength,
        _Out_opt_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtOpenEventPair(
        _Out_	PHANDLE EventPairHandle,
        _In_	ACCESS_MASK DesiredAccess,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes
    );

    //TmTx
    NTSTATUS NTAPI NtCreateTransaction(
        _Out_     PHANDLE TransactionHandle,
        _In_      ACCESS_MASK DesiredAccess,
        _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_  LPGUID Uow,
        _In_opt_  HANDLE TmHandle,
        _In_opt_  ULONG CreateOptions,
        _In_opt_  ULONG IsolationLevel,
        _In_opt_  ULONG IsolationFlags,
        _In_opt_  PLARGE_INTEGER Timeout,
        _In_opt_  PUNICODE_STRING Description
    );

    //TmRm
    NTSTATUS NTAPINtCreateResourceManager(
        _Out_     PHANDLE ResourceManagerHandle,
        _In_      ACCESS_MASK DesiredAccess,
        _In_      HANDLE TmHandle,
        _In_opt_  LPGUID ResourceManagerGuid,
        _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_  ULONG CreateOptions,
        _In_opt_  PUNICODE_STRING Description
    );

    //TmEn
    NTSTATUS NTAPI NtCreateEnlistment(
        _Out_     PHANDLE EnlistmentHandle,
        _In_      ACCESS_MASK DesiredAccess,
        _In_      HANDLE ResourceManagerHandle,
        _In_      HANDLE TransactionHandle,
        _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_  ULONG CreateOptions,
        _In_      NOTIFICATION_MASK NotificationMask,
        _In_opt_  PVOID EnlistmentKey
    );

    //TmTm
    NTSTATUS NTAPI NtCreateTransactionManager(
        _Out_     PHANDLE TmHandle,
        _In_      ACCESS_MASK DesiredAccess,
        _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_  PUNICODE_STRING LogFileName,
        _In_opt_  ULONG CreateOptions,
        _In_opt_  ULONG CommitStrength
    );

    NTSTATUS NTAPI NtCreateFile(
        _Out_		PHANDLE FileHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_		POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_		PIO_STATUS_BLOCK IoStatusBlock,
        _In_opt_	PLARGE_INTEGER AllocationSize,
        _In_		ULONG FileAttributes,
        _In_		ULONG ShareAccess,
        _In_		ULONG CreateDisposition,
        _In_		ULONG CreateOptions,
        _In_opt_	PVOID EaBuffer,
        _In_		ULONG EaLength
    );

    NTSTATUS NTAPI NtOpenProcess(
        _Out_		PHANDLE ProcessHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_		POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_	PCLIENT_ID ClientId
    );

    NTSTATUS NTAPI NtTerminateProcess(
        _In_opt_	HANDLE ProcessHandle,
        _In_		NTSTATUS ExitStatus
    );

    NTSTATUS NTAPI NtSuspendThread(
        _In_		HANDLE ThreadHandle,
        _Out_opt_	PULONG PreviousSuspendCount
    );

    NTSTATUS NTAPI NtResumeThread(
        _In_		HANDLE ThreadHandle,
        _Out_opt_	PULONG PreviousSuspendCount
    );

    NTSTATUS NTAPI NtOpenThread(
        _Out_       PHANDLE ThreadHandle,
        _In_        ACCESS_MASK DesiredAccess,
        _In_        POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_    PCLIENT_ID ClientId
    );

    NTSTATUS NTAPI NtImpersonateThread(
        _In_        HANDLE ServerThreadHandle,
        _In_        HANDLE ClientThreadHandle,
        _In_        PSECURITY_QUALITY_OF_SERVICE SecurityQos
    );

    NTSTATUS NTAPI NtSetContextThread(
        _In_        HANDLE ThreadHandle,
        _In_        PCONTEXT ThreadContext
    );

    NTSTATUS NTAPI NtGetContextThread(
        _In_        HANDLE ThreadHandle,
        _Inout_     PCONTEXT ThreadContext
    );

    NTSTATUS NTAPI NtQueryInformationProcess(
        _In_		HANDLE ProcessHandle,
        _In_		PROCESS_INFORMATION_CLASSEX ProcessInformationClass,
        _Out_		PVOID ProcessInformation,
        _In_		ULONG ProcessInformationLength,
        _Out_opt_	PULONG ReturnLength
    );

    NTSTATUS NTAPI NtDuplicateObject(
        _In_		HANDLE SourceProcessHandle,
        _In_		HANDLE SourceHandle,
        _In_opt_	HANDLE TargetProcessHandle,
        _Out_		PHANDLE TargetHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_		ULONG HandleAttributes,
        _In_		ULONG Options
    );

    NTSTATUS NTAPI NtSetSecurityObject(
        _In_	HANDLE Handle,
        _In_	SECURITY_INFORMATION SecurityInformation,
        _In_	PSECURITY_DESCRIPTOR SecurityDescriptor
    );

    NTSTATUS NTAPI NtQuerySecurityObject(
        _In_	HANDLE Handle,
        _In_	SECURITY_INFORMATION SecurityInformation,
        _Out_	PSECURITY_DESCRIPTOR SecurityDescriptor,
        _In_	ULONG Length,
        _Out_	PULONG LengthNeeded
    );

    NTSTATUS NtCreateIoCompletion(
        _Out_		PHANDLE IoCompletionHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_	ULONG Count
    );

    NTSTATUS NTAPI NtCreateEvent(
        _Out_		PHANDLE EventHandle,
        _In_		ACCESS_MASK DesiredAccess,
        _In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
        _In_		EVENT_TYPE EventType,
        _In_		BOOLEAN InitialState
    );

    NTSTATUS NTAPI NtAllocateVirtualMemory(
        _In_        HANDLE ProcessHandle,
        _Inout_     PVOID *BaseAddress,
        _In_        ULONG_PTR ZeroBits,
        _Inout_     PSIZE_T RegionSize,
        _In_        ULONG AllocationType,
        _In_        ULONG Protect
    );

    NTSTATUS NTAPI NtFreeVirtualMemory(
        _In_       HANDLE ProcessHandle,
        _Inout_    PVOID *BaseAddress,
        _Inout_    PSIZE_T RegionSize,
        _In_       ULONG FreeType
    );

    NTSTATUS NTAPI NtQueryVirtualMemory(
        _In_		HANDLE ProcessHandle,
        _In_		PVOID BaseAddress,
        _In_		MEMORY_INFORMATION_CLASS MemoryInformationClass,
        _Out_		PVOID MemoryInformation,
        _In_		SIZE_T MemoryInformationLength,
        _Out_opt_	PSIZE_T ReturnLength
    );

    NTSTATUS NTAPI NtReadVirtualMemory(
        _In_		HANDLE ProcessHandle,
        _In_opt_	PVOID BaseAddress,
        _Out_		PVOID Buffer,
        _In_		SIZE_T BufferSize,
        _Out_opt_	PSIZE_T NumberOfBytesRead
    );

    NTSTATUS NTAPI NtWow64AllocateVirtualMemory64(
        _In_        HANDLE ProcessHandle,
        _Inout_     PVOID *BaseAddress,
        _In_        ULONG_PTR ZeroBits,
        _Inout_     PSIZE_T RegionSize,
        _In_        ULONG AllocationType,
        _In_        ULONG Protect
    );

    NTSTATUS NTAPI NtWow64ReadVirtualMemory64(
        _In_	    HANDLE ProcessHandle,
        _In_opt_	PVOID BaseAddress,
        _Out_		PVOID Buffer,
        _In_		SIZE_T BufferSize,
        _Out_opt_	PSIZE_T NumberOfBytesRead
    );

    NTSTATUS NTAPI NtWow64WriteVirtualMemory64(
        _In_		HANDLE ProcessHandle,
        _In_opt_	PVOID BaseAddress,
        _Out_		PVOID Buffer,
        _In_		SIZE_T BufferSize,
        _Out_opt_	PSIZE_T NumberOfBytesWritten
    );
    NTSTATUS NTAPI NtWriteVirtualMemory(
        _In_        HANDLE ProcessHandle,
        _In_opt_    PVOID BaseAddress,
        _In_        VOID *Buffer,
        _In_        SIZE_T BufferSize,
        _Out_opt_   PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS NTAPI NtProtectVirtualMemory(
        _In_        HANDLE ProcessHandle,
        _Inout_     PVOID *BaseAddress,
        _Inout_     PSIZE_T RegionSize,
        _In_        ULONG NewProtect,
        _Out_       PULONG OldProtect
    );
    
    NTSTATUS NTAPI NtCreatePort(
        _Out_	PHANDLE PortHandle,
        _In_	POBJECT_ATTRIBUTES ObjectAttributes,
        _In_	ULONG MaxConnectionInfoLength,
        _In_	ULONG MaxMessageLength,
        _In_	ULONG MaxPoolUsage
    );

    NTSTATUS NTAPI NtCompleteConnectPort(
        _In_	HANDLE PortHandle
    );

    NTSTATUS NTAPI NtListenPort(
        _In_	HANDLE PortHandle,
        _Out_	PPORT_MESSAGE ConnectionRequest
    );

    NTSTATUS NTAPI NtReplyPort(
        _In_	HANDLE PortHandle,
        _In_	PPORT_MESSAGE ReplyMessage
    );

    NTSTATUS NTAPI NtReplyWaitReplyPort(
        _In_	HANDLE PortHandle,
        _Inout_	PPORT_MESSAGE ReplyMessage
    );

    NTSTATUS NTAPI NtRequestPort(
        _In_	HANDLE PortHandle,
        _In_	PPORT_MESSAGE RequestMessage
    );

    NTSTATUS NTAPI NtRequestWaitReplyPort(
        _In_	HANDLE PortHandle,
        _In_	PPORT_MESSAGE RequestMessage,
        _Out_	PPORT_MESSAGE ReplyMessage
    );

    NTSTATUS NTAPI NtClosePort(
        _In_	HANDLE PortHandle
    );

    NTSTATUS NTAPI NtReplyWaitReceivePort(
        _In_		HANDLE PortHandle,
        _Out_opt_	PVOID *PortContext,
        _In_opt_	PPORT_MESSAGE ReplyMessage,
        _Out_		PPORT_MESSAGE ReceiveMessage
    );

    NTSTATUS NTAPI NtWriteRequestData(
        _In_		HANDLE PortHandle,
        _In_		PPORT_MESSAGE Message,
        _In_		ULONG DataEntryIndex,
        _In_		PVOID Buffer,
        _In_		ULONG BufferSize,
        _Out_opt_	PULONG NumberOfBytesWritten
    );

    NTSTATUS NTAPI NtReadRequestData(
        _In_		HANDLE PortHandle,
        _In_		PPORT_MESSAGE Message,
        _In_		ULONG DataEntryIndex,
        _Out_		PVOID Buffer,
        _In_		ULONG BufferSize,
        _Out_opt_	PULONG NumberOfBytesRead
    );

    NTSTATUS NTAPI NtConnectPort(
        _Out_		PHANDLE PortHandle,
        _In_		PUNICODE_STRING PortName,
        _In_		PSECURITY_QUALITY_OF_SERVICE SecurityQos,
        _Inout_opt_	PPORT_VIEW ClientView,
        _Out_opt_	PREMOTE_PORT_VIEW ServerView,
        _Out_opt_	PULONG MaxMessageLength,
        _Inout_opt_	PVOID ConnectionInformation,
        _Inout_opt_	PULONG ConnectionInformationLength
    );

    NTSTATUS NTAPI NtAcceptConnectPort(
        _Out_		PHANDLE PortHandle,
        _In_opt_	PVOID PortContext,
        _In_		PPORT_MESSAGE ConnectionRequest,
        _In_		BOOLEAN AcceptConnection,
        _Inout_opt_	PPORT_VIEW ServerView,
        _Out_opt_	PREMOTE_PORT_VIEW ClientView
    );

#ifdef __cplusplus
}
#endif