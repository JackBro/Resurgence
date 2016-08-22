#pragma once

typedef struct _INJECTION_BUFFER *PINJECTION_BUFFER;

NTSTATUS RDrvLogToFile(
	__in LPCSTR Format,
	__in_opt ...
);

NTSTATUS RDrvOpenFile(
	__in LPCWSTR FilePath,
	__in BOOLEAN Write,
	__in BOOLEAN Append,
	__out PHANDLE Handle
);

NTSTATUS RDrvGetKernelInfo(
	__out_opt PULONG_PTR BaseAddress,
	__out_opt PSIZE_T Size
);

NTSTATUS RDrvFindPattern(
	__in ULONG_PTR BaseAddress,
	__in SIZE_T Size,
	__in PCUCHAR Pattern,
	__in PCUCHAR Mask,
	__in SIZE_T PatternSize,
	__inout PVOID* Result
);

NTSTATUS RDrvFindKernelPattern(
	__in PCUCHAR Pattern,
	__in PCUCHAR Mask,
	__in SIZE_T PatternSize,
	__inout PVOID* Result
);

NTSTATUS RDrvSleep(
	__in LONG ms
);

NTSTATUS RDrvGetModuleEntry(
	__in PEPROCESS Process,
	__in LPCWSTR ModuleName,
	__out PLDR_DATA_TABLE_ENTRY* LdrEntry
);

NTSTATUS RDrvGetModuleEntry32(
	__in  PEPROCESS Process,
	__in  LPCWSTR ModuleName,
	__out PLDR_DATA_TABLE_ENTRY32* LdrEntry
);

NTSTATUS RDrvGetProcAddress(
	__in ULONG_PTR ModuleBase,
	__in LPCSTR ProcName,
	__out PULONG_PTR ProcAddress
);

NTSTATUS RDrvCreateUserThread(
	__in PVOID pStartAddress,
	__in_opt PVOID pArg,
	__in BOOLEAN wait,
	__out_opt PULONG_PTR pThreadExitCode
);

NTSTATUS RDrvStripHeaders(
	__in PVOID BaseAddress
);

NTSTATUS RDrvHideFromLoadedList(
	__in PEPROCESS pProcess,
	__in PVOID pBaseAddress
);

PIMAGE_NT_HEADERS32 GetWow64NtHeaders(
	__in PVOID ImageBase
);

PIMAGE_NT_HEADERS64 GetNtHeaders(
	__in PVOID ImageBase
);

BOOLEAN IsProcessWow64Process(
	__in PEPROCESS Process
);

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase(
	void
);

PVOID GetSSDTEntry(
	__in ULONG Index
);

NTSTATUS RDrvLoadImageFromFile(
	__in PWCHAR ModulePath,
	__out PVOID* ImageBase,
	__out PULONG ImageSize
);

NTSTATUS RDrvLoadImageFromMemory(
	__in PVOID UserBuffer,
	__out PVOID* ImageBase,
	__out PULONG ImageSize
);

NTSTATUS RDrvGenerateRandomString(
	__in ULONG Length,
	__out PWSTR String
);