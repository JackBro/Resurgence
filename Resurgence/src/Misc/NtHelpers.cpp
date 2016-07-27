#include <Misc/NtHelpers.hpp>
#include <Misc/SafeHandle.hpp>

#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace Resurgence
{
    namespace Misc
    {
        std::wstring NtHelpers::GetSystemErrorMessage(
            IN NTSTATUS status)
        {
            HMODULE ntdll = GetModuleHandle(L"ntdll.dll");

            WCHAR buffer[260];

            FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
                ntdll, status,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buffer, 260, NULL);

            return std::wstring(buffer);
        }
        NTSTATUS NtHelpers::EnumSystemModules(
            IN ENUM_MODULES_CALLBACK fnCallback)
        {
            if(!fnCallback) return STATUS_INVALID_PARAMETER_1;

            PVOID       pInfoBuffer = NULL;
            ULONG       cb          = 0;
            NTSTATUS    status      = STATUS_SUCCESS;
            
            do {
                status = NtQuerySystemInformation(SystemModuleInformation, pInfoBuffer, cb, &cb);
                if(!NT_SUCCESS(status)) {
                    if(status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pInfoBuffer != NULL)
                            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
                        pInfoBuffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, cb);
                        continue;
                    }
                    break;
                } else {
                    auto pSysModules = (PRTL_PROCESS_MODULES)pInfoBuffer;
                    for(ULONG i = 0; i < pSysModules->NumberOfModules; i++) {
                        status = fnCallback(&pSysModules->Modules[i]);
                        if(NT_SUCCESS(status))
                            break;
                    }
                    break;
                }
            } while(true);
            if(pInfoBuffer != NULL)
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
            return status;
        }
        NTSTATUS NtHelpers::EnumSystemObjects(
            IN LPCWSTR szRootDir,
            IN ENUM_OBJECTS_CALLBACK fnCallback)
        {
            if(!szRootDir) return STATUS_INVALID_PARAMETER_1;
            if(!fnCallback) return STATUS_INVALID_PARAMETER_2;
            
            OBJECT_ATTRIBUTES   objAttr;
            UNICODE_STRING      usDirectoryName;
            NTSTATUS            status;
            HANDLE              hDirectory;
            ULONG               uEnumCtx    = 0;
            ULONG               uBufferSize = 0;
            PVOID               pObjBuffer  = NULL;

            RtlSecureZeroMemory(&usDirectoryName, sizeof(usDirectoryName));
            RtlInitUnicodeString(&usDirectoryName, szRootDir);
            InitializeObjectAttributes(&objAttr, &usDirectoryName, OBJ_CASE_INSENSITIVE, NULL, NULL);

            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);
            if(!NT_SUCCESS(status) || !hDirectory) {
                return status;
            }

            do {
                status = NtQueryDirectoryObject(hDirectory, pObjBuffer, uBufferSize, TRUE, FALSE, &uEnumCtx, &uBufferSize);
                if(!NT_SUCCESS(status)) {
                    if(status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pObjBuffer != NULL)
                            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pObjBuffer);
                        uBufferSize = uBufferSize * 2;
                        pObjBuffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, uBufferSize);
                        continue;
                    } 
                    break;
                }

                if(!pObjBuffer) break;

                status = fnCallback((POBJECT_DIRECTORY_INFORMATION)pObjBuffer);
                if(NT_SUCCESS(status))
                    break;
            } while(true);

            if(pObjBuffer != NULL)
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pObjBuffer);

            NtClose(hDirectory);
            return status;
        }
        NTSTATUS NtHelpers::EnumSystemProcesses(
            IN ENUM_PROCESSES_CALLBACK fnCallback)
        {
            if(!fnCallback) return STATUS_INVALID_PARAMETER_1;

            PVOID       pInfoBuffer = NULL;
            ULONG       cb = 0;
            NTSTATUS    status = STATUS_SUCCESS;

            do {
                status = NtQuerySystemInformation(SystemProcessInformation, pInfoBuffer, cb, &cb);
                if(!NT_SUCCESS(status)) {
                    if(status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pInfoBuffer != NULL)
                            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
                        pInfoBuffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, cb);
                        continue;
                    }
                    break;
                } else {
                    auto pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)pInfoBuffer;
                    while(pProcessEntry->NextEntryDelta) {
                        status = fnCallback((PSYSTEM_PROCESSES_INFORMATION)pProcessEntry);
                        if(NT_SUCCESS(status))
                            break;
                        pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)((PUCHAR)pProcessEntry + pProcessEntry->NextEntryDelta);
                    }
                    break;
                }
            } while(true);
            if(pInfoBuffer != NULL)
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
            return status;
        }
        NTSTATUS NtHelpers::SystemObjectExists(
            IN LPCWSTR szRootDir,
            IN LPCWSTR szObjectName,
            OUT PBOOL bFound /*= NULL*/)
        {
            UNICODE_STRING uName;
            RtlInitUnicodeString(&uName, szObjectName);
            BOOL found = FALSE;
            NTSTATUS status = EnumSystemObjects(szRootDir, [&](POBJECT_DIRECTORY_INFORMATION entry) -> NTSTATUS {
                if(RtlEqualUnicodeString(&uName, &entry->Name, TRUE)) {
                    found = TRUE;
                    return STATUS_SUCCESS;
                }
                return STATUS_NOT_FOUND;
            });
            if(bFound)
                *bFound = found;
            return status;
        }
        NTSTATUS NtHelpers::GetSystemModuleInfo(
            IN LPCSTR szModuleName,
            OUT PRTL_PROCESS_MODULE_INFORMATION pInformation)
        {
            if(!pInformation) return STATUS_INVALID_PARAMETER;

            NTSTATUS status = EnumSystemModules([&](PRTL_PROCESS_MODULE_INFORMATION info) -> NTSTATUS {
                if(!strcmp(szModuleName, (char*)(info->FullPathName + info->OffsetToFileName))) {
                    RtlCopyMemory(pInformation, info, sizeof(RTL_PROCESS_MODULE_INFORMATION));
                    return STATUS_SUCCESS;
                }
                return STATUS_NOT_FOUND;
            });
            return status;
        }
        NTSTATUS NtHelpers::WriteBufferToFile(
            IN LPCWSTR szFilePath,
            IN LPVOID lpBuffer,
            IN DWORD nSize)
        {
            auto handle = SafeGenericHandle(CreateFile(szFilePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL));

            if(!handle.IsValid())
                return GetLastNtStatus();

            DWORD nBytesWritten = 0;
            return WriteFile(handle.Get(), lpBuffer, nSize, &nBytesWritten, NULL) && nBytesWritten != nSize;
        }
        NTSTATUS NtHelpers::CopyFile(
            IN LPCWSTR szOldPath,
            IN LPCWSTR szNewPath)
        {
            if(!::CopyFileW(szOldPath, szNewPath, FALSE))
                return GetLastNtStatus();
            return STATUS_SUCCESS;
        }
        NTSTATUS NtHelpers::GetFullPath(
            IN LPCWSTR szPath,
            OUT LPWSTR szFullPath)
        {
            if(!GetFullPathNameW(szPath, MAX_PATH, szFullPath, NULL))
                return GetLastNtStatus();
            return STATUS_SUCCESS;
        }
        NTSTATUS NtHelpers::CreateDriverService(
            IN SC_HANDLE hSCManager,
            IN LPCWSTR szDriverName,
            IN LPCWSTR szExePath)
        {
            SC_HANDLE schService;

            schService = CreateServiceW(hSCManager, 
                szDriverName,                       
                szDriverName,                       
                SERVICE_ALL_ACCESS,                 
                SERVICE_KERNEL_DRIVER,              
                SERVICE_DEMAND_START,               
                SERVICE_ERROR_NORMAL,               
                szExePath,                          
                NULL,                               
                NULL,                               
                NULL,                               
                NULL,                               
                NULL                                
            );
            if(!schService) {
                return GetLastNtStatus();
            }

            CloseServiceHandle(schService);
            return STATUS_SUCCESS;
        }
        NTSTATUS NtHelpers::StartDriver(
            IN SC_HANDLE hSCManager,
            IN LPCWSTR szDriverName)
        {
            SC_HANDLE  schService;

            schService = OpenService(hSCManager,
                szDriverName,
                SERVICE_ALL_ACCESS
            );
            if(!schService)
                return GetLastNtStatus();

            BOOL success = (StartService(schService, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);

            CloseServiceHandle(schService);

            return success ? STATUS_SUCCESS : GetLastNtStatus();
        }
        NTSTATUS NtHelpers::StopDriver(
            IN SC_HANDLE hSCManager,
            IN LPCWSTR szDriverName)
        {
            INT             iRetryCount;
            SC_HANDLE       schService;
            SERVICE_STATUS  serviceStatus;

            schService = OpenService(hSCManager, szDriverName, SERVICE_ALL_ACCESS);
            if(!schService) {
                return GetLastNtStatus();
            }

            iRetryCount = 5;
            do {
                if(ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus))
                    break;

                if(GetLastError() != ERROR_DEPENDENT_SERVICES_RUNNING)
                    break;

                Sleep(1000);
                iRetryCount--;
            } while(iRetryCount);

            CloseServiceHandle(schService);

            if(iRetryCount == 0)
                return GetLastNtStatus();
            return STATUS_SUCCESS;
        }
        NTSTATUS NtHelpers::GetDeviceHandle(
            IN LPCWSTR szDriverName,
            OUT PHANDLE phDevice)
        {
            WCHAR    szDeviceName[MAX_PATH];
            HANDLE   hDevice;

            if(!szDriverName || !phDevice) return STATUS_INVALID_PARAMETER;

            RtlSecureZeroMemory(szDeviceName, sizeof(szDeviceName));
            wsprintf(szDeviceName, TEXT("\\\\.\\%s"), szDriverName);

            hDevice = CreateFile(szDeviceName,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if(hDevice == INVALID_HANDLE_VALUE)
                return GetLastNtStatus();

            *phDevice = hDevice;

            return STATUS_SUCCESS;
        }
        NTSTATUS NtHelpers::DeleteDriverService(
            IN SC_HANDLE hSCManager,
            IN LPCWSTR szDriverName)
        {
            SC_HANDLE  schService;
            schService = OpenService(hSCManager,
                szDriverName,
                DELETE
            );

            if(!schService) {
                return GetLastNtStatus();
            }

            BOOL success = DeleteService(schService);

            CloseServiceHandle(schService);

            return success ? STATUS_SUCCESS : GetLastNtStatus();
        }
        NTSTATUS NtHelpers::LoadDriver(
            IN LPCWSTR szDriverName,
            IN LPCWSTR szPath,
            OUT PHANDLE phDevice)
        {
            SC_HANDLE	schSCManager;
            BOOL		bResult = FALSE;

            if(!szDriverName || !szPath || !phDevice)
                return STATUS_INVALID_PARAMETER;

            schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if(schSCManager) {
                DeleteDriverService(schSCManager, szDriverName);
                CreateDriverService(schSCManager, szDriverName, szPath);
                StartDriver(schSCManager, szDriverName);
                GetDeviceHandle(szDriverName, phDevice);
                CloseServiceHandle(schSCManager);
            }
            return bResult;
        }
        NTSTATUS NtHelpers::UnloadDriver(
            IN LPCWSTR szDriverName)
        {
            SC_HANDLE	schSCManager;
            NTSTATUS    status;
            if(!szDriverName) {
                return STATUS_INVALID_PARAMETER;
            }

            schSCManager = OpenSCManager(NULL,
                NULL,
                SC_MANAGER_ALL_ACCESS
            );
            if(schSCManager) {
                status = StopDriver(schSCManager, szDriverName);
                if(NT_SUCCESS(status))
                    status = DeleteDriverService(schSCManager, szDriverName);
                CloseServiceHandle(schSCManager);
            }
            return status;
        }

    }
}
