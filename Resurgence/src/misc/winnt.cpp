#include <misc/winnt.hpp>
#include <misc/safe_handle.hpp>

#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace resurgence
{
    namespace misc
    {
        std::wstring winnt::get_status_message(ntstatus_code status)
        {
            HMODULE ntdll = GetModuleHandle(L"ntdll.dll");

            WCHAR buffer[260];

            FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
                ntdll, status,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buffer, 260, nullptr);

            return std::wstring(buffer);
        }
        ntstatus_code winnt::enumerate_system_modules(module_enumeration_callback callback)
        {
            if(!callback) return STATUS_INVALID_PARAMETER_1;

            PVOID           pInfoBuffer = nullptr;
            ULONG           cb          = 0;
            ntstatus_code   status      = STATUS_SUCCESS;
            
            do {
                status = NtQuerySystemInformation(SystemModuleInformation, pInfoBuffer, cb, &cb);
                if(!NT_SUCCESS(status)) {
                    if(status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pInfoBuffer != nullptr)
                            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
                        pInfoBuffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, cb);
                        continue;
                    }
                    break;
                } else {
                    auto pSysModules = (PRTL_PROCESS_MODULES)pInfoBuffer;
                    for(ULONG i = 0; i < pSysModules->NumberOfModules; i++) {
                        status = callback(&pSysModules->Modules[i]);
                        if(NT_SUCCESS(status))
                            break;
                    }
                    break;
                }
            } while(true);
            if(pInfoBuffer != nullptr)
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
            return status;
        }
        ntstatus_code winnt::enumerate_system_objects(const std::wstring& root, object_enumeration_callback callback)
        {
            if(root.empty()) return STATUS_INVALID_PARAMETER_1;
            if(!callback)    return STATUS_INVALID_PARAMETER_2;
            
            OBJECT_ATTRIBUTES   objAttr;
            UNICODE_STRING      usDirectoryName;
            ntstatus_code       status;
            HANDLE              hDirectory;
            ULONG               uEnumCtx    = 0;
            ULONG               uBufferSize = 0;
            PVOID               pObjBuffer  = nullptr;

            RtlSecureZeroMemory(&usDirectoryName, sizeof(usDirectoryName));
            RtlInitUnicodeString(&usDirectoryName, std::data(root));
            InitializeObjectAttributes(&objAttr, &usDirectoryName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);
            if(!NT_SUCCESS(status) || !hDirectory) {
                return status;
            }

            do {
                status = NtQueryDirectoryObject(hDirectory, pObjBuffer, uBufferSize, TRUE, FALSE, &uEnumCtx, &uBufferSize);
                if(!NT_SUCCESS(status)) {
                    if(status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pObjBuffer != nullptr)
                            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pObjBuffer);
                        uBufferSize = uBufferSize * 2;
                        pObjBuffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, uBufferSize);
                        continue;
                    } 
                    break;
                }

                if(!pObjBuffer) break;

                status = callback((POBJECT_DIRECTORY_INFORMATION)pObjBuffer);
                if(NT_SUCCESS(status))
                    break;
            } while(true);

            if(pObjBuffer != nullptr)
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pObjBuffer);

            NtClose(hDirectory);
            return status;
        }
        ntstatus_code winnt::enumerate_processes(process_enumeration_callback callback)
        {
            if(!callback) return STATUS_INVALID_PARAMETER_1;

            PVOID           pInfoBuffer = nullptr;
            ULONG           cb          = 0;
            ntstatus_code   status      = STATUS_SUCCESS;

            do {
                status = NtQuerySystemInformation(SystemProcessInformation, pInfoBuffer, cb, &cb);
                if(!NT_SUCCESS(status)) {
                    if(status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pInfoBuffer != nullptr)
                            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
                        pInfoBuffer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, cb);
                        continue;
                    }
                    break;
                } else {
                    auto pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)pInfoBuffer;
                    while(pProcessEntry->NextEntryDelta) {
                        status = callback((PSYSTEM_PROCESSES_INFORMATION)pProcessEntry);
                        if(NT_SUCCESS(status))
                            break;
                        pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)((PUCHAR)pProcessEntry + pProcessEntry->NextEntryDelta);
                    }
                    break;
                }
            } while(true);
            if(pInfoBuffer != nullptr)
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pInfoBuffer);
            return status;
        }
        ntstatus_code winnt::object_exists(const std::wstring& root, const std::wstring& object, bool* found /*= nullptr*/)
        {
            UNICODE_STRING uName;
            RtlInitUnicodeString(&uName, std::data(object));
            bool _found = false;
            ntstatus_code status = enumerate_system_objects(root, [&](POBJECT_DIRECTORY_INFORMATION entry) -> ntstatus_code {
                if(RtlEqualUnicodeString(&uName, &entry->Name, TRUE)) {
                    _found = true;
                    return STATUS_SUCCESS;
                }
                return STATUS_NOT_FOUND;
            });
            if(found)
                *found = _found;
            return status;
        }
        ntstatus_code winnt::get_system_module_info(const std::string& module, PRTL_PROCESS_MODULE_INFORMATION moduleInfo)
        {
            if(!moduleInfo) return STATUS_INVALID_PARAMETER;

            ntstatus_code status = enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) -> ntstatus_code {
                if(!strcmp(std::data(module), (char*)(info->FullPathName + info->OffsetToFileName))) {
                    RtlCopyMemory(moduleInfo, info, sizeof(RTL_PROCESS_MODULE_INFORMATION));
                    return STATUS_SUCCESS;
                }
                return STATUS_NOT_FOUND;
            });
            return status;
        }
        ntstatus_code winnt::write_file(const std::wstring& path, std::uint8_t* buffer, std::size_t length)
        {
            auto handle = SafeGenericHandle(CreateFile(std::data(path), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr));

            if(!handle.IsValid())
                return get_last_ntstatus();

            decltype(length) nBytesWritten = 0;
            return WriteFile(handle.Get(), buffer, (DWORD)length, (PDWORD)&nBytesWritten, nullptr) && nBytesWritten != length;
        }
        ntstatus_code winnt::copy_file(const std::wstring& oldPath, const std::wstring& newPath)
        {
            if(!::CopyFileW(std::data(oldPath), std::data(newPath), FALSE))
                return get_last_ntstatus();
            return STATUS_SUCCESS;
        }
        std::wstring winnt::get_full_path(const std::wstring& path)
        {
            std::wstring fullpath;
            fullpath.reserve(MAX_PATH);
            if(!GetFullPathNameW(std::data(path), MAX_PATH, const_cast<wchar_t*>(std::data(fullpath)), nullptr))
                return L"";
            
            return fullpath;
        }
        ntstatus_code winnt::create_service(SC_HANDLE manager, const std::wstring& driverName, const std::wstring& driverPath)
        {
            SC_HANDLE schService;

            schService = CreateServiceW(manager,
                std::data(driverName),                       
                std::data(driverName),                       
                SERVICE_ALL_ACCESS,                 
                SERVICE_KERNEL_DRIVER,              
                SERVICE_DEMAND_START,               
                SERVICE_ERROR_NORMAL,               
                std::data(driverPath),
                nullptr,                               
                nullptr,                               
                nullptr,                               
                nullptr,                               
                nullptr                                
            );
            if(!schService) {
                return get_last_ntstatus();
            }

            CloseServiceHandle(schService);
            return STATUS_SUCCESS;
        }
        ntstatus_code winnt::start_driver(SC_HANDLE manager, const std::wstring& driverName)
        {
            SC_HANDLE  schService;

            schService = OpenService(manager,
                std::data(driverName),
                SERVICE_ALL_ACCESS
            );
            if(!schService)
                return get_last_ntstatus();

            BOOL success = (StartService(schService, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);

            CloseServiceHandle(schService);

            return success ? STATUS_SUCCESS : get_last_ntstatus();
        }
        ntstatus_code winnt::stop_driver(SC_HANDLE manager, const std::wstring& driverName)
        {
            INT             iRetryCount;
            SC_HANDLE       schService;
            SERVICE_STATUS  serviceStatus;

            schService = OpenService(manager, std::data(driverName), SERVICE_ALL_ACCESS);
            if(!schService) {
                return get_last_ntstatus();
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
                return get_last_ntstatus();
            return STATUS_SUCCESS;
        }
        ntstatus_code winnt::get_driver_device(const std::wstring& driver, PHANDLE deviceHandle)
        {
            WCHAR    szDeviceName[MAX_PATH];
            HANDLE   hDevice;

            if(driver.empty() || !deviceHandle) return STATUS_INVALID_PARAMETER;

            RtlSecureZeroMemory(szDeviceName, sizeof(szDeviceName));
            wsprintf(szDeviceName, L"\\\\.\\%ws", std::data(driver));

            hDevice = CreateFile(szDeviceName,
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
            if(hDevice == INVALID_HANDLE_VALUE)
                return get_last_ntstatus();

            *deviceHandle = hDevice;

            return STATUS_SUCCESS;
        }
        ntstatus_code winnt::delete_service(SC_HANDLE manager, const std::wstring& driverName)
        {
            SC_HANDLE  schService;
            schService = OpenService(manager,
                std::data(driverName),
                DELETE
            );

            if(!schService)
                return get_last_ntstatus();

            BOOL success = DeleteService(schService);

            CloseServiceHandle(schService);

            return success ? STATUS_SUCCESS : get_last_ntstatus();
        }
        ntstatus_code winnt::load_driver(const std::wstring& driverName, const std::wstring& driverPath, PHANDLE deviceHandle)
        {
            SC_HANDLE	schSCManager;
            BOOL		bResult = FALSE;

            if(driverName.empty() || driverPath.empty() || !deviceHandle)
                return STATUS_INVALID_PARAMETER;

            schSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if(schSCManager) {
                delete_service(schSCManager, driverName);
                create_service(schSCManager, driverName, driverPath);
                start_driver(schSCManager, driverName);
                get_driver_device(driverName, deviceHandle);
                CloseServiceHandle(schSCManager);
            }
            return bResult;
        }
        ntstatus_code winnt::unload_driver(const std::wstring& driverName)
        {
            SC_HANDLE	      schSCManager;
            ntstatus_code   status;

            if(driverName.empty()) return STATUS_INVALID_PARAMETER;

            schSCManager = OpenSCManager(nullptr,
                nullptr,
                SC_MANAGER_ALL_ACCESS
            );
            if(schSCManager) {
                status = stop_driver(schSCManager, driverName);
                if(NT_SUCCESS(status))
                    status = delete_service(schSCManager, driverName);
                CloseServiceHandle(schSCManager);
            }
            return status;
        }

    }
}
