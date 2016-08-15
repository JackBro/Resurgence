#include <misc/winnt.hpp>
#include <misc/safe_handle.hpp>
#include <misc/exceptions.hpp>
#include <system/process.hpp>

#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace resurgence
{
    namespace misc
    {
        std::wstring winnt::get_status_message(NTSTATUS status)
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
        std::size_t winnt::query_required_size(SYSTEM_INFORMATION_CLASS information)
        {
            ULONG cb;

            ntstatus_code status = NtQuerySystemInformation(information, nullptr, 0, (PULONG)&cb);
            if(status != STATUS_INFO_LENGTH_MISMATCH)
                return 0;

            return cb;
        }
        std::size_t winnt::query_required_size(PROCESS_INFORMATION_CLASSEX information)
        {
            switch(information) {
                case ProcessBasicInformation:
                    return sizeof(PROCESS_BASIC_INFORMATION);
                case ProcessQuotaLimits:
                    return sizeof(QUOTA_LIMITS_EX);
                case ProcessIoCounters:
                    return sizeof(IO_COUNTERS);
                case ProcessVmCounters:
                    return sizeof(VM_COUNTERS);
                case ProcessTimes:
                    return sizeof(KERNEL_USER_TIMES);
                case ProcessPriorityClass:
                    return sizeof(PROCESS_PRIORITY_CLASS);
                case ProcessHandleCount:
                    return sizeof(ULONG);
                case ProcessSessionInformation:
                    return sizeof(PROCESS_SESSION_INFORMATION);
                case ProcessWow64Information:
                    return sizeof(ULONG_PTR);
                case ProcessImageFileName:
                    return sizeof(UNICODE_STRING) + MAX_PATH * sizeof(WCHAR);
                case ProcessImageFileNameWin32:
                    return sizeof(UNICODE_STRING) + MAX_PATH * sizeof(WCHAR);
                case ProcessExecuteFlags:
                    return sizeof(ULONG);
                case ProcessImageInformation:
                    return sizeof(SECTION_IMAGE_INFORMATION);
                default:
                    throw;
            }
        }
        std::size_t winnt::query_required_size(OBJECT_INFORMATION_CLASS information)
        {
            switch(information) {
                case ObjectBasicInformation:
                    return sizeof(OBJECT_BASIC_INFORMATION);
                case ObjectNameInformation:
                    return PAGE_SIZE;       // Can be lower
                case ObjectTypeInformation:
                    return PAGE_SIZE;       // Can be lower
                default:
                    throw;
            }
        }
        std::uint8_t* winnt::query_system_information(SYSTEM_INFORMATION_CLASS information)
        {
            std::uint8_t*   buffer  = nullptr;
            ntstatus_code   status  = STATUS_SUCCESS;
            std::size_t     cb      = query_required_size(information);

            status = allocate_local_buffer(&buffer, &cb);
            
            if(!NT_SUCCESS(status)) return nullptr;

            do {
                status = NtQuerySystemInformation(information, buffer, (ULONG)cb, (PULONG)&cb);
                if(NT_SUCCESS(status)) {
                    return buffer;
                } else {
                    if(status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(buffer != nullptr)
                            free_local_buffer(&buffer);
                        status = allocate_local_buffer(&buffer, &cb);
                        continue;
                    }
                    return nullptr;
                }
            } while(true);
        }
        std::uint8_t* winnt::query_process_information(HANDLE handle, PROCESS_INFORMATION_CLASSEX information)
        {
            std::uint8_t*   buffer      = nullptr;
            ntstatus_code   status      = STATUS_SUCCESS;
            std::size_t     cb          = query_required_size(information);
            std::size_t     sizeNeeded  = cb;

            status = allocate_local_buffer(&buffer, &sizeNeeded);
            
            if(!NT_SUCCESS(status)) return nullptr;

            status = NtQueryInformationProcess(handle, information, buffer, (ULONG)cb, (PULONG)&sizeNeeded);
            if(NT_SUCCESS(status)) {
                return buffer;
            } else {
                if(buffer != nullptr)
                    free_local_buffer(&buffer);
                return nullptr;
            }
        }
        std::uint8_t* winnt::query_object_information(HANDLE handle, OBJECT_INFORMATION_CLASS information)
        {
            std::uint8_t*   buffer      = nullptr;
            ntstatus_code   status      = STATUS_SUCCESS;
            std::size_t     cb = query_required_size(information);

            status = allocate_local_buffer(&buffer, &cb);

            if(!NT_SUCCESS(status)) return nullptr;

            status = NtQueryObject(handle, information, buffer, (ULONG)cb, nullptr);
            if(NT_SUCCESS(status)) {
                return buffer;
            } else {
                return nullptr;
            }
        }
        ntstatus_code winnt::enumerate_system_modules(system_module_enumeration_callback callback)
        {
            if(!callback) return STATUS_INVALID_PARAMETER_1;

            std::uint8_t*   buffer = nullptr;
            ntstatus_code   status = STATUS_SUCCESS;

            buffer = query_system_information(SystemModuleInformation);
            if(buffer) {
                auto pSysModules = (PRTL_PROCESS_MODULES)buffer;
                for(ULONG i = 0; i < pSysModules->NumberOfModules; i++) {
                    status = callback(&pSysModules->Modules[i]);
                    if(NT_SUCCESS(status))
                        break;
                }
                free_local_buffer(&buffer);
            }
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
            std::size_t         uBufferSize = 0;
            PVOID               pObjBuffer  = nullptr;

            RtlSecureZeroMemory(&usDirectoryName, sizeof(usDirectoryName));
            RtlInitUnicodeString(&usDirectoryName, std::data(root));
            InitializeObjectAttributes(&objAttr, &usDirectoryName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);
            if(!NT_SUCCESS(status) || !hDirectory) {
                return status;
            }

            do {
                status = NtQueryDirectoryObject(hDirectory, pObjBuffer, (ULONG)uBufferSize, TRUE, FALSE, &uEnumCtx, (PULONG)&uBufferSize);
                if(!NT_SUCCESS(status)) {
                    if(status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pObjBuffer != nullptr)
                            free_local_buffer(&pObjBuffer);
                        uBufferSize = uBufferSize * 2;
                        allocate_local_buffer(&pObjBuffer, &uBufferSize);
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
                free_local_buffer(&pObjBuffer);

            NtClose(hDirectory);
            return status;
        }
        ntstatus_code winnt::enumerate_processes(process_enumeration_callback callback)
        {
            if(!callback) return STATUS_INVALID_PARAMETER_1;

            std::uint8_t*   buffer = nullptr;
            ntstatus_code   status = STATUS_SUCCESS;

            buffer = query_system_information(SystemProcessInformation);
            if(buffer) {
                auto pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)buffer;
                while(pProcessEntry->NextEntryDelta) {
                    status = callback((PSYSTEM_PROCESSES_INFORMATION)pProcessEntry);
                    if(NT_SUCCESS(status))
                        break;
                    pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)((PUCHAR)pProcessEntry + pProcessEntry->NextEntryDelta);
                }
                free_local_buffer(&buffer);
            }
            return status;
        }
        ntstatus_code winnt::enumerate_process_modules(HANDLE process, module_enumeration_callback callback)
        {
            PPEB_LDR_DATA           ldr;
            PEB_LDR_DATA            ldrData;
            PLIST_ENTRY             startLink;
            PLIST_ENTRY             currentLink;
            LDR_DATA_TABLE_ENTRY    currentEntry;

            auto basic_info = (PPROCESS_BASIC_INFORMATION)winnt::query_process_information(process, ProcessBasicInformation);

            ntstatus_code status = read_memory(
                process,
                PTR_ADD(basic_info->PebBaseAddress, FIELD_OFFSET(PEB, Ldr)),
                &ldr,
                sizeof(ldr)
            );

            if(!NT_SUCCESS(status)) {
                free_local_buffer(&basic_info);
                return status;
            }

            status = read_memory(process, ldr, &ldrData, sizeof(ldrData));
            if(!NT_SUCCESS(status)) {
                free_local_buffer(&basic_info);
                return status;
            }

            if(!ldrData.Initialized) return STATUS_UNSUCCESSFUL;

            startLink = (PLIST_ENTRY)PTR_ADD(ldr, FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));
            currentLink = ldrData.InLoadOrderModuleList.Flink;
                
            while(currentLink != startLink) {
                PVOID addressOfEntry = CONTAINING_RECORD(currentLink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                status = read_memory(
                    process,
                    addressOfEntry,
                    &currentEntry,
                    sizeof(LDR_DATA_TABLE_ENTRY)
                );

                if(!NT_SUCCESS(status)) {
                    free_local_buffer(&basic_info);
                    return status;
                }

                if(currentEntry.DllBase != 0) {
                    status = callback(&currentEntry);

                    if(NT_SUCCESS(status)) {
                        free_local_buffer(&basic_info);
                        return status;
                    }
                }
                currentLink = currentEntry.InLoadOrderLinks.Flink;
            }
            free_local_buffer(&basic_info);
            return STATUS_SUCCESS;
        }
        ntstatus_code winnt::enumerate_process_modules32(HANDLE process, module_enumeration_callback32 callback)
        {
            auto basic_info = (PPROCESS_BASIC_INFORMATION)winnt::query_process_information(process, ProcessBasicInformation);

            ULONG                   ldr;
            PEB_LDR_DATA32          ldrData;
            ULONG                   startLink;
            ULONG                   currentLink;
            LDR_DATA_TABLE_ENTRY32  currentEntry;
            ULONG                   wow64Peb = (ULONG)((PUCHAR)basic_info->PebBaseAddress + PAGE_SIZE);

            ntstatus_code status = read_memory(
                process,
                PTR_ADD((ULONG_PTR)wow64Peb, FIELD_OFFSET(PEB32, Ldr)),
                &ldr,
                sizeof(ldr)
            );

            if(!NT_SUCCESS(status)) {
                free_local_buffer(&basic_info);
                return status;
            }

            status = read_memory(process, (PVOID)ldr, &ldrData, sizeof(ldrData));
            if(!NT_SUCCESS(status)) {
                free_local_buffer(&basic_info);
                return status;
            }

            if(!ldrData.Initialized) return STATUS_UNSUCCESSFUL;

            startLink = (ULONG)PTR_ADD((ULONG_PTR)ldr, FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList));
            currentLink = (ULONG)ldrData.InLoadOrderModuleList.Flink;

            while(currentLink != startLink) {
                PVOID addressOfEntry = CONTAINING_RECORD((ULONG_PTR)currentLink, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

                status = read_memory(
                    process,
                    addressOfEntry,
                    &currentEntry,
                    sizeof(LDR_DATA_TABLE_ENTRY32)
                );

                if(!NT_SUCCESS(status)) {
                    free_local_buffer(&basic_info);
                    return status;
                }

                if(currentEntry.DllBase != 0) {
                    status = callback(&currentEntry);

                    if(NT_SUCCESS(status)) {
                        free_local_buffer(&basic_info);
                        return status;
                    }
                }

                currentLink = (ULONG)currentEntry.InLoadOrderLinks.Flink;
            }
            free_local_buffer(&basic_info);
            return STATUS_SUCCESS;
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
            auto handle = safe_generic_handle(CreateFile(std::data(path), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr));

            if(!handle.is_valid())
                return get_last_ntstatus();

            decltype(length) nBytesWritten = 0;
            return WriteFile(handle.get(), buffer, (DWORD)length, (PDWORD)&nBytesWritten, nullptr) && nBytesWritten != length;
        }
        ntstatus_code winnt::copy_file(const std::wstring& oldPath, const std::wstring& newPath)
        {
            if(!::CopyFileW(std::data(oldPath), std::data(newPath), FALSE))
                return get_last_ntstatus();
            return STATUS_SUCCESS;
        }
        std::wstring winnt::get_full_path(const std::wstring& path)
        {
            WCHAR fullpath[MAX_PATH];

            if(!GetFullPathNameW(std::data(path), MAX_PATH, const_cast<wchar_t*>(std::data(fullpath)), nullptr))
                return L"";
            
            return fullpath;
        }
        std::wstring winnt::get_dos_path(const std::wstring& path)
        {
            auto startsWith = [](const std::wstring& str1, const std::wstring& str2, bool ignoreCasing) {
                if(ignoreCasing) {
                    std::wstring copy1 = str1, copy2 = str2;
                    std::transform(copy1.begin(), copy1.end(), copy1.begin(), ::tolower);
                    std::transform(copy2.begin(), copy2.end(), copy2.begin(), ::tolower);
                    return copy1.compare(0, copy2.size(), copy2) == 0;
                } else {
                    return str1.compare(0, str2.size(), str2) == 0;
                }
            };

            auto idx = path.find(L"\\??\\");
            if(startsWith(path, L"\\??\\", false)) {
                return path.substr(idx + 4);
            } else if(startsWith(path, L"\\SystemRoot", true)) {
                return std::wstring(USER_SHARED_DATA->NtSystemRoot) + path.substr(11);
            } else if(startsWith(path, L"system32\\", true)) {
                return std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\system32" + path.substr(8);
            } 
            return path;
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
            SC_HANDLE	  schSCManager;
            NTSTATUS    status;

            if(driverName.empty()) 
                return STATUS_INVALID_PARAMETER_1;
            if(driverPath.empty())
                return STATUS_INVALID_PARAMETER_2;
            if(!deviceHandle) 
                return STATUS_INVALID_PARAMETER_3;
                

            schSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if(schSCManager) {
                delete_service(schSCManager, driverName);
                status = create_service(schSCManager, driverName, driverPath);
                if(!NT_SUCCESS(status))
                    LOG(DEBUG) << "create_service returned " << std::hex << status;
                status = start_driver(schSCManager, driverName);
                if(!NT_SUCCESS(status))
                    LOG(DEBUG) << "start_driver returned " << std::hex << status;
                status = get_driver_device(driverName, deviceHandle);
                if(!NT_SUCCESS(status))
                    LOG(DEBUG) << "get_driver_device returned " << std::hex << status;
                CloseServiceHandle(schSCManager);
            }
            return status;
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
        HANDLE winnt::open_process(std::uint32_t pid, std::uint32_t access)
        {
            return OpenProcess(access, FALSE, pid);
        }
        bool winnt::process_is_wow64(HANDLE process)
        {
            PULONG_PTR buffer = (PULONG_PTR)query_process_information(process, ProcessWow64Information);
            bool iswow64 = *buffer != 0;
            free_local_buffer(&buffer);
            return iswow64;
        }
        ntstatus_code winnt::allocate_memory(HANDLE process, void* start, std::size_t* size, std::uint32_t allocation, std::uint32_t protection)
        {
            return NtAllocateVirtualMemory(process, (PVOID*)start, 0, (PSIZE_T)size, allocation, protection);
        }
        ntstatus_code winnt::protect_memory(HANDLE process, void* start, std::size_t* size, std::uint32_t protection, std::uint32_t& oldProtection)
        {
            return NtProtectVirtualMemory(process, (PVOID*)start, (PSIZE_T)size, protection, (PULONG)&oldProtection);
        }
        ntstatus_code winnt::free_memory(HANDLE process, void* start, std::size_t size, std::uint32_t free)
        {
            return NtFreeVirtualMemory(process, (PVOID*)start, (PSIZE_T)&size, free);
        }
        ntstatus_code winnt::read_memory(HANDLE process, void* address, void* buffer, std::size_t size)
        {
            if(process == GetCurrentProcess()) {
                memcpy((PVOID)buffer, (PVOID)address, size);
                return STATUS_SUCCESS;
            } else {
                return NtReadVirtualMemory(process, address, buffer, size, nullptr);
            }
        }
        ntstatus_code winnt::write_memory(HANDLE process, void* address, void* buffer, std::size_t size)
        {
            if(process == GetCurrentProcess()) {
                memcpy(address, buffer, size);
                return STATUS_SUCCESS;
            } else {
                return NtWriteVirtualMemory(process, address, buffer, size, nullptr);
            }
        }
    }
}
