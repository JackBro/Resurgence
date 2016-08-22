#include "routines.h"

#pragma alloc_text(PAGE, RDrvOpenThread)

NTSTATUS RDrvOpenThread(
	__inout POPEN_THREAD Params
)
{
	if(!Params) return STATUS_INVALID_PARAMETER;

	NTSTATUS    status;
	PETHREAD    thread = NULL;
	HANDLE      handle = NULL;

	__try {
		status = PsLookupThreadByThreadId((HANDLE)Params->In.ThreadId, &thread);
		if(NT_SUCCESS(status)) {
			status = ObOpenObjectByPointer(thread, 0, NULL, Params->In.AccessMask, *PsThreadType, KernelMode, &handle);
			if(NT_SUCCESS(status) && handle != NULL) {
				Params->Out.Handle = (ULONG_PTR)handle;
			} else {
				PERROR("ObOpenObjectByPointer", status);
			}
		} else {
			PERROR("PsLookupThreadByThreadId", status);
		}
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
		PEXCEPTION();
		status = GetExceptionCode();
	}
	if(thread != NULL)
		ObDereferenceObject(thread);
	return status;
}