#include "internal.h"
#include "zw_imports.h"

#if defined(_WIN8_) || defined (_WIN7_)

NTSTATUS
NTAPI
ZwProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
)
{
	NTSTATUS status = STATUS_SUCCESS;

	fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)(ULONG_PTR)GetSSDTEntry(g_pDriverContext->DynData.SSDTIndexes.ProtectMemory);
	if(NtProtectVirtualMemory) {
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_pDriverContext->DynData.Offsets.PreviousMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

		*pPrevMode = prevMode;
	} else
		status = STATUS_NOT_FOUND;

	return status;
}
#endif

NTSTATUS
NTAPI
ZwCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
)
{
	NTSTATUS status = STATUS_SUCCESS;

	tNtCreateThreadEx NtCreateThreadEx = (tNtCreateThreadEx)(ULONG_PTR)GetSSDTEntry(g_pDriverContext->DynData.SSDTIndexes.CreateThreadEx);
	if(NtCreateThreadEx) {
		//
		// If previous mode is UserMode, addresses passed into ZwCreateThreadEx must be in user-mode space
		// Switching to KernelMode allows usage of kernel-mode addresses
		//
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_pDriverContext->DynData.Offsets.PreviousMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = NtCreateThreadEx(
			hThread, DesiredAccess, ObjectAttributes,
			ProcessHandle, lpStartAddress, lpParameter,
			Flags, StackZeroBits, SizeOfStackCommit,
			SizeOfStackReserve, AttributeList
		);

		*pPrevMode = prevMode;
	} else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI ZwTerminateThread(IN HANDLE ThreadHandle, IN NTSTATUS ExitStatus)
{
	NTSTATUS status = STATUS_SUCCESS;

	tNtTerminateThread NtTerminateThread = (tNtTerminateThread)(ULONG_PTR)GetSSDTEntry(g_pDriverContext->DynData.SSDTIndexes.TerminateThread);
	if(NtTerminateThread) {
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_pDriverContext->DynData.Offsets.PreviousMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = NtTerminateThread(ThreadHandle, ExitStatus);
		*pPrevMode = prevMode;
	} else
		status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS
NTAPI
ZwQueryPerformanceCounter(
	__out PLARGE_INTEGER PerformanceCounter,
	__out_opt PLARGE_INTEGER PerformanceFrequency
)
{
	NTSTATUS status = STATUS_SUCCESS;

	tNtQueryPerformanceCounter NtQueryPerformanceCounter
		= (tNtQueryPerformanceCounter)(ULONG_PTR)GetSSDTEntry(g_pDriverContext->DynData.SSDTIndexes.QueryPerformanceCounter);
	if(NtQueryPerformanceCounter) {
		PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_pDriverContext->DynData.Offsets.PreviousMode;
		UCHAR prevMode = *pPrevMode;
		*pPrevMode = KernelMode;

		status = NtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);

		*pPrevMode = prevMode;
	} else {
		status = STATUS_NOT_FOUND;
	}
	return status;
}