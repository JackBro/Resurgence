#include "routines.h"
#include "injection.h"
#include "mmap.h"

#pragma alloc_text(PAGE, RDrvProtectProcess)
#pragma alloc_text(PAGE, RDrvOpenProcess)
#pragma alloc_text(PAGE, RDrvSetProcessDEP)

NTSTATUS RDrvProtectProcess(
	__inout PPROTECT_PROCESS Params
)
{
	if(!Params) return STATUS_INVALID_PARAMETER;

	NTSTATUS    status;
	PEPROCESS   process = NULL;
	KAPC_STATE  apcState;
	__try {
		status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);

		if(NT_SUCCESS(status)) {
		#ifdef _WIN10_
			PPS_PROTECTION psProtection = (PPS_PROTECTION)((PUCHAR)process + g_pDriverContext->DynData.Offsets.Protection);
			if(psProtection != NULL) {
				KeStackAttachProcess(process, &apcState);
				PPEB peb = PsGetProcessPeb(process);
				if(Params->In.ProtectionLevel == PROTECTION_NONE) {
					psProtection->Level = 0;
					peb->IsProtectedProcess = 0;
					peb->IsProtectedProcessLight = 0;
				} else if(Params->In.ProtectionLevel == PROTECTION_LIGHT) {
					psProtection->Flags.Signer = PsProtectedSignerWinTcb;
					psProtection->Flags.Type = PsProtectedTypeProtectedLight;
					peb->IsProtectedProcess = 1;
					peb->IsProtectedProcessLight = 1;
				} else if(Params->In.ProtectionLevel == PROTECTION_FULL) {
					psProtection->Flags.Signer = PsProtectedSignerWinTcb;
					psProtection->Flags.Type = PsProtectedTypeProtected;
					peb->IsProtectedProcess = 1;
					peb->IsProtectedProcessLight = 0;
				} else {
					DPRINT("Invalid ProtectionLevel: %d", Params->In.ProtectionLevel);
					status = STATUS_UNSUCCESSFUL;
				}
				KeUnstackDetachProcess(&apcState);
			} else {
				DPRINT("PsProtection is invalid");
				status = STATUS_UNSUCCESSFUL;
			}
		#else
		#error "Unsupported"
		#endif
		} else {
			PERROR("PsLookupProcessByProcessId", status);
		}
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
		PEXCEPTION();
		status = GetExceptionCode();
	}
	if(process != NULL)
		ObDereferenceObject(process);
	return status;
}

NTSTATUS RDrvOpenProcess(
	__inout POPEN_PROCESS Params
)
{
	if(!Params) return STATUS_INVALID_PARAMETER;

	NTSTATUS    status;
	PEPROCESS   process = NULL;
	PETHREAD    thread = NULL;
	HANDLE      handle = NULL;
	CLIENT_ID   clientId;

	__try {
		if(Params->In.ProcessId != 0) {
			status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);
		} else if(Params->In.ThreadId != 0) {
			clientId.UniqueProcess = 0;
			clientId.UniqueThread = (HANDLE)Params->In.ThreadId;
			status = PsLookupProcessThreadByCid(&clientId, &process, &thread);
			if(NT_SUCCESS(status)) {
				ObDereferenceObject(thread);
			}
		} else {
			status = STATUS_INVALID_CID;
		}
		if(NT_SUCCESS(status)) {
			status = ObOpenObjectByPointer(process, 0, NULL, Params->In.AccessMask, *PsProcessType, KernelMode, &handle);
			if(NT_SUCCESS(status) && handle != NULL) {
				Params->Out.Handle = (ULONG_PTR)handle;
			} else {
				PERROR("ObOpenObjectByPointer", status);
			}
		} else {
			PERROR("PsLookupProcessByProcessId/ThreadByCid", status);
		}
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
		PEXCEPTION();
		status = GetExceptionCode();
	}
	if(process != NULL)
		ObDereferenceObject(process);
	return status;
}

NTSTATUS RDrvSetProcessDEP(
	__in PSET_DEP_STATE Params
)
{
	if(!Params) return STATUS_INVALID_PARAMETER;

	NTSTATUS            status;
	PEPROCESS           process = NULL;

	__try {
		status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);

		if(NT_SUCCESS(status)) {
		#ifdef _WIN10_
			PKEXECUTE_OPTIONS executeOptions = (PKEXECUTE_OPTIONS)((PUCHAR)process + g_pDriverContext->DynData.Offsets.ExecuteOptions);
			if(Params->In.Enabled == FALSE) {
				executeOptions->ExecuteOptions = 0;

				executeOptions->Flags.ExecuteDisable = 1;
				executeOptions->Flags.ImageDispatchEnable = 1;
				executeOptions->Flags.ExecuteDispatchEnable = 1;
			} else {
				executeOptions->ExecuteOptions = 0;

				executeOptions->Flags.ExecuteEnable = 1;
				executeOptions->Flags.Permanent = 1;
			}
		#else
		#error "Unsupported"
		#endif
		} else {
			PERROR("PsLookupProcessByProcessId", status);
		}
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
		PEXCEPTION();
		status = GetExceptionCode();
	}
	if(process != NULL)
		ObDereferenceObject(process);
	return status;
}

NTSTATUS RDrvInjectModule(
	__inout PINJECT_MODULE Params
)
{

	NTSTATUS    status = STATUS_SUCCESS;
	PEPROCESS   process = NULL;
	KAPC_STATE  apcState;
	ULONG_PTR   base = 0;
	SIZE_T      pathSize = 0;

	if(!Params) return STATUS_INVALID_PARAMETER;

	RtlStringCbLengthW(Params->In.ModulePath, MAX_PATH, &pathSize);

	//
	// Cant continue if ModuleBase and Path are invalid
	//
	if(!Params->In.ModuleBase && pathSize == 0) return STATUS_INVALID_PARAMETER;

	__try {
		status = PsLookupProcessByProcessId((HANDLE)Params->In.ProcessId, &process);
		if(NT_SUCCESS(status)) {

			if(Params->In.InjectionType == InjectLdrLoadDll) {
				status = RDrvInjectLdrLoadDll(process, Params->In.ModulePath, &base);
			} else if(Params->In.InjectionType == InjectManualMap) {
				//PVOID systemBuffer;
				//ULONG imageSize;
				//if(Params->In.ModuleBase != 0) {
				//    status = RDrvLoadImageFromMemory(Params->In.ModuleBase, &systemBuffer, &imageSize);
				//} else {
				//    RDrvLoadImageFromFile(Params->In.ModulePath, &systemBuffer, &imageSize);
				//}
				//status = RDrvInjectManualMap(process, systemBuffer, imageSize, Params->In.ModulePath, Params->In.CallEntryPoint, Params->In.CustomParameter, &base);
			}
			if(NT_SUCCESS(status)) {
				KeStackAttachProcess(process, &apcState);
				if(Params->In.ErasePE == TRUE) {
					if(!NT_SUCCESS(status = RDrvStripHeaders((PVOID)base)))
						PERROR("RDrvStripHeaders", status);
				}
				if(Params->In.HideModule == TRUE) {
					if(!NT_SUCCESS(status = RDrvHideFromLoadedList(process, (PVOID)base)))
						PERROR("RDrvHideFromLoadedList", status);
				}
				KeUnstackDetachProcess(&apcState);
			}

			Params->Out.BaseAddress = base;

		} else
			PERROR("PsLookupProcessByProcessId", status);
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
		PEXCEPTION();
		status = GetExceptionCode();
	}
	if(process)
		ObDereferenceObject(process);

	return status;
}
