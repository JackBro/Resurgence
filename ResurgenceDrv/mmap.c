#include "internal.h"
#include "mmap.h"
#include "utils.h"

#pragma alloc_text(PAGE, RDrvInjectManualMap)


NTSTATUS RDrvInjectManualMap(
	__in PEPROCESS Process,
	__in PVOID ImageBuffer,
	__in ULONG ImageSize,
	__in BOOLEAN CallEntryPoint,
	__in ULONG_PTR CustomArg,
	__out PULONG_PTR ModuleBase
)
{
	//NTSTATUS    status;

	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ImageBuffer);
	UNREFERENCED_PARAMETER(ImageSize);
	UNREFERENCED_PARAMETER(CallEntryPoint);
	UNREFERENCED_PARAMETER(CustomArg);
	UNREFERENCED_PARAMETER(ModuleBase);
	//
	// Can't pass if both are null
	//
	//if(ImageBuffer == NULL) return STATUS_INVALID_PARAMETER;
	//
	//if(NT_SUCCESS(status)) {
	//
	//} else {
	//    DPRINT("Failed to load the image to the system buffer. Status: %lX", status);
	//}
	return STATUS_SUCCESS;
}