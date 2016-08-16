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
        std::wstring winnt::get_status_message(error_code status)
        {
            HMODULE ntdll = GetModuleHandle(L"ntdll.dll");

            wchar_t buffer[MAX_PATH] = {0};

            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
                ntdll, status,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buffer, 260, nullptr);

            return std::wstring(buffer);
        }
        size_t winnt::query_required_size(SYSTEM_INFORMATION_CLASS information)
        {
            ULONG cb;

            error_code status = NtQuerySystemInformation(information, nullptr, 0, (PULONG)&cb);
            if(status != STATUS_INFO_LENGTH_MISMATCH)
                return 0;

            return cb;
        }
        size_t winnt::query_required_size(PROCESS_INFORMATION_CLASSEX information)
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
                    return sizeof(UNICODE_STRING) + MAX_PATH * sizeof(wchar_t);
                case ProcessImageFileNameWin32:
                    return sizeof(UNICODE_STRING) + MAX_PATH * sizeof(wchar_t);
                case ProcessExecuteFlags:
                    return sizeof(ULONG);
                case ProcessImageInformation:
                    return sizeof(SECTION_IMAGE_INFORMATION);
                default:
                    throw;
            }
        }
        size_t winnt::query_required_size(OBJECT_INFORMATION_CLASS information)
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
        uint8_t* winnt::query_system_information(SYSTEM_INFORMATION_CLASS information)
        {
            uint8_t*        buffer  = nullptr;
            error_code   status  = STATUS_SUCCESS;
            size_t          cb      = query_required_size(information);

            status = allocate_local_buffer(&buffer, &cb);
            
            if(!succeeded(status)) return nullptr;

            do {
                status = NtQuerySystemInformation(information, buffer, (ULONG)cb, (PULONG)&cb);
                if(succeeded(status)) {
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
        uint8_t* winnt::query_process_information(HANDLE handle, PROCESS_INFORMATION_CLASSEX information)
        {
            uint8_t*        buffer      = nullptr;
            error_code   status      = STATUS_SUCCESS;
            size_t          cb          = query_required_size(information);
            size_t          sizeNeeded  = cb;

            status = allocate_local_buffer(&buffer, &sizeNeeded);
            
            if(!succeeded(status)) return nullptr;

            status = NtQueryInformationProcess(handle, information, buffer, (ULONG)cb, (PULONG)&sizeNeeded);
            if(succeeded(status)) {
                return buffer;
            } else {
                if(buffer != nullptr)
                    free_local_buffer(&buffer);
                return nullptr;
            }
        }
        uint8_t* winnt::query_object_information(HANDLE handle, OBJECT_INFORMATION_CLASS information)
        {
            uint8_t*        buffer      = nullptr;
            error_code   status      = STATUS_SUCCESS;
            size_t          cb = query_required_size(information);

            status = allocate_local_buffer(&buffer, &cb);

            if(!succeeded(status)) return nullptr;

            status = NtQueryObject(handle, information, buffer, (ULONG)cb, nullptr);
            if(succeeded(status)) {
                return buffer;
            } else {
                return nullptr;
            }
        }
        error_code winnt::enumerate_system_modules(system_module_enumeration_callback callback)
        {
            if(!callback) return STATUS_INVALID_PARAMETER_1;

            uint8_t*        buffer = nullptr;
            error_code   status = STATUS_SUCCESS;

            buffer = query_system_information(SystemModuleInformation);
            if(buffer) {
                auto pSysModules = (PRTL_PROCESS_MODULES)buffer;
                for(ULONG i = 0; i < pSysModules->NumberOfModules; i++) {
                    status = callback(&pSysModules->Modules[i]);
                    if(succeeded(status))
                        break;
                }
                free_local_buffer(&buffer);
            }
            return status;
        }
        error_code winnt::enumerate_system_objects(const std::wstring& root, object_enumeration_callback callback)
        {
            if(root.empty()) return STATUS_INVALID_PARAMETER_1;
            if(!callback)    return STATUS_INVALID_PARAMETER_2;
            
            OBJECT_ATTRIBUTES   objAttr;
            UNICODE_STRING      usDirectoryName;
            error_code       status;
            HANDLE              hDirectory;
            ULONG               uEnumCtx    = 0;
            size_t              uBufferSize = 0x100;
            POBJECT_DIRECTORY_INFORMATION   pObjBuffer  = nullptr;

            RtlSecureZeroMemory(&usDirectoryName, sizeof(usDirectoryName));
            RtlInitUnicodeString(&usDirectoryName, std::data(root));
            InitializeObjectAttributes(&objAttr, &usDirectoryName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);
            
            if(!succeeded(status) || !hDirectory) {
                return status;
            }

            pObjBuffer = (POBJECT_DIRECTORY_INFORMATION)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, uBufferSize);

            do {
                status = NtQueryDirectoryObject(hDirectory, pObjBuffer, (ULONG)uBufferSize, TRUE, FALSE, &uEnumCtx, (PULONG)&uBufferSize);
                if(!succeeded(status)) {
                    if(status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
                        if(pObjBuffer != nullptr)
                            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pObjBuffer);
                        uBufferSize = uBufferSize * 2;
                        pObjBuffer = (POBJECT_DIRECTORY_INFORMATION)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, uBufferSize);
                        continue;
                    } 
                    break;
                }

                if(!pObjBuffer) break;

                status = callback(pObjBuffer);
                if(succeeded(status))
                    break;
            } while(true);

            if(pObjBuffer != nullptr)
                RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pObjBuffer);

            NtClose(hDirectory);
            return status;
        }
        error_code winnt::enumerate_processes(process_enumeration_callback callback)
        {
            if(!callback) return STATUS_INVALID_PARAMETER_1;

            uint8_t*   buffer = nullptr;
            error_code   status = STATUS_SUCCESS;

            buffer = query_system_information(SystemProcessInformation);
            if(buffer) {
                auto pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)buffer;
                while(pProcessEntry->NextEntryDelta) {
                    status = callback((PSYSTEM_PROCESSES_INFORMATION)pProcessEntry);
                    if(succeeded(status))
                        break;
                    pProcessEntry = (PSYSTEM_PROCESSES_INFORMATION)((PUCHAR)pProcessEntry + pProcessEntry->NextEntryDelta);
                }
                free_local_buffer(&buffer);
            }
            return status;
        }
        error_code winnt::enumerate_process_modules(HANDLE process, module_enumeration_callback callback)
        {
            PPEB_LDR_DATA           ldr;
            PEB_LDR_DATA            ldrData;
            PLIST_ENTRY             startLink;
            PLIST_ENTRY             currentLink;
            LDR_DATA_TABLE_ENTRY    currentEntry;

            auto basic_info = (PPROCESS_BASIC_INFORMATION)winnt::query_process_information(process, ProcessBasicInformation);

            if(!basic_info)
                return STATUS_UNSUCCESSFUL;

            //
            // PEB will be invalid when trying to access a x64 process from WOW64
            // 
            if(basic_info->PebBaseAddress == 0) {
                free_local_buffer(&basic_info);
                return STATUS_ACCESS_DENIED;
            }

            error_code status = read_memory(
                process,
                PTR_ADD(basic_info->PebBaseAddress, FIELD_OFFSET(PEB, Ldr)),
                &ldr,
                sizeof(ldr)
            );

            if(!succeeded(status)) {
                free_local_buffer(&basic_info);
                return status;
            }

            status = read_memory(process, ldr, &ldrData, sizeof(ldrData));
            if(!succeeded(status)) {
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

                if(!succeeded(status)) {
                    free_local_buffer(&basic_info);
                    return status;
                }

                if(currentEntry.DllBase != 0) {
                    status = callback(&currentEntry);

                    if(succeeded(status)) {
                        free_local_buffer(&basic_info);
                        return status;
                    }
                }
                currentLink = currentEntry.InLoadOrderLinks.Flink;
            }
            free_local_buffer(&basic_info);
            return STATUS_SUCCESS;
        }
        error_code winnt::enumerate_process_modules32(HANDLE process, module_enumeration_callback32 callback)
        {
            auto basic_info = (PPROCESS_BASIC_INFORMATION)winnt::query_process_information(process, ProcessBasicInformation);

            ULONG                   ldr;
            PEB_LDR_DATA32          ldrData;
            ULONG                   startLink;
            ULONG                   currentLink;
            LDR_DATA_TABLE_ENTRY32  currentEntry;
            ULONG                   wow64Peb = (ULONG)((PUCHAR)basic_info->PebBaseAddress + PAGE_SIZE);

            error_code status = read_memory(
                process,
                PTR_ADD((ULONG_PTR)wow64Peb, FIELD_OFFSET(PEB32, Ldr)),
                &ldr,
                sizeof(ldr)
            );

            if(!succeeded(status)) {
                free_local_buffer(&basic_info);
                return status;
            }

            status = read_memory(process, (PVOID)ldr, &ldrData, sizeof(ldrData));
            if(!succeeded(status)) {
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

                if(!succeeded(status)) {
                    free_local_buffer(&basic_info);
                    return status;
                }

                if(currentEntry.DllBase != 0) {
                    status = callback(&currentEntry);

                    if(succeeded(status)) {
                        free_local_buffer(&basic_info);
                        return status;
                    }
                }

                currentLink = (ULONG)currentEntry.InLoadOrderLinks.Flink;
            }
            free_local_buffer(&basic_info);
            return STATUS_SUCCESS;
        }
        error_code winnt::object_exists(const std::wstring& root, const std::wstring& object, bool* found /*= nullptr*/)
        {
            UNICODE_STRING uName;
            RtlInitUnicodeString(&uName, std::data(object));
            bool _found = false;
            error_code status = enumerate_system_objects(root, [&](POBJECT_DIRECTORY_INFORMATION entry) -> error_code {
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
        error_code winnt::get_system_module_info(const std::string& module, PRTL_PROCESS_MODULE_INFORMATION moduleInfo)
        {
            if(!moduleInfo) return STATUS_INVALID_PARAMETER;

            error_code status = enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) -> error_code {
                if(!strcmp(std::data(module), (char*)(info->FullPathName + info->OffsetToFileName))) {
                    RtlCopyMemory(moduleInfo, info, sizeof(RTL_PROCESS_MODULE_INFORMATION));
                    return STATUS_SUCCESS;
                }
                return STATUS_NOT_FOUND;
            });
            return status;
        }
        error_code winnt::write_file(const std::wstring& path, uint8_t* buffer, size_t length)
        {
            auto handle = safe_generic_handle(CreateFile(std::data(path), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr));

            if(!handle.is_valid())
                return get_last_ntstatus();

            decltype(length) nBytesWritten = 0;
            return WriteFile(handle.get(), buffer, (DWORD)length, (PDWORD)&nBytesWritten, nullptr) && nBytesWritten != length;
        }
        error_code winnt::copy_file(const std::wstring& oldPath, const std::wstring& newPath)
        {
            if(!::CopyFileW(std::data(oldPath), std::data(newPath), FALSE))
                return get_last_ntstatus();
            return STATUS_SUCCESS;
        }
        std::wstring winnt::get_full_path(const std::wstring& path)
        {
            wchar_t fullpath[MAX_PATH];

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

            std::wstring dosPath = path;

            auto idx = dosPath.find(L"\\??\\");
            if(startsWith(dosPath, L"\\??\\", false)) {
                return dosPath.substr(idx + 4);
            } else if(startsWith(dosPath, L"\\SystemRoot", true)) {
                return std::wstring(USER_SHARED_DATA->NtSystemRoot) + dosPath.substr(11);
            } else if(startsWith(dosPath, L"system32\\", true)) {
                return std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\system32" + dosPath.substr(8);
            } else if(startsWith(dosPath, L"\\Device", true)) {
                std::vector<std::wstring> drives;
                query_mounted_drives(drives);
                for(auto& drive : drives) {
                    std::wstring sym;
                    get_symbolic_link_from_drive(drive, sym);
                    if(startsWith(dosPath, sym, false)) {
                        dosPath.replace(0, sym.size(), drive);
                        break;
                    }
                }
            }
            return dosPath;
        }
        error_code winnt::query_mounted_drives(std::vector<std::wstring>& letters)
        {
            // Required size:
            // 26 letters * 2 * sizeof(WCHAR) = 104
            // C:\

            wchar_t     buffer[MAX_PATH] = {0};
            uint32_t    length;
            
            letters.reserve(MAX_PATH);

            if(!!(length = GetLogicalDriveStrings(MAX_PATH, buffer))) {
                for(wchar_t* current = buffer; current < &buffer[length]; ) {
                    letters.push_back(std::wstring(current, 2));
                    current += 4;
                }
                return STATUS_SUCCESS;
            } else {
                return get_last_ntstatus();
            }
        }
        error_code winnt::get_symbolic_link_from_drive(const std::wstring& drive, std::wstring& deviceLink)
        {
            HANDLE linkHandle;
            OBJECT_ATTRIBUTES oa;
            UNICODE_STRING deviceName;
            UNICODE_STRING devicePrefix;

            wchar_t deviceNameBuffer[] = L"\\??\\ :";

            deviceNameBuffer[4] = drive[0];

            deviceName.Buffer           = deviceNameBuffer;
            deviceName.Length           = 6 * sizeof(wchar_t);
            deviceName.MaximumLength    = 7 * sizeof(wchar_t);

            InitializeObjectAttributes(
                &oa,
                &deviceName,
                OBJ_CASE_INSENSITIVE,
                NULL,
                NULL
            );

            devicePrefix.Length = MAX_PATH * sizeof(WCHAR);
            devicePrefix.MaximumLength = MAX_PATH * sizeof(WCHAR);
            devicePrefix.Buffer = (PWSTR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR));

            auto status = NtOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &oa);
            if(succeeded(status)) {
                status = NtQuerySymbolicLinkObject(linkHandle, &devicePrefix, NULL);
                if(succeeded(status)) {
                    deviceLink = std::wstring(devicePrefix.Buffer, devicePrefix.Length / sizeof(wchar_t));
                }
                NtClose(linkHandle);
            }
            RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, devicePrefix.Buffer);
            return status;
        }
        error_code winnt::create_service(SC_HANDLE manager, const std::wstring& driverName, const std::wstring& driverPath)
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
        error_code winnt::start_driver(SC_HANDLE manager, const std::wstring& driverName)
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
        error_code winnt::stop_driver(SC_HANDLE manager, const std::wstring& driverName)
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
        error_code winnt::get_driver_device(const std::wstring& driver, PHANDLE deviceHandle)
        {
            wchar_t    szDeviceName[MAX_PATH];
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
        error_code winnt::delete_service(SC_HANDLE manager, const std::wstring& driverName)
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
        error_code winnt::load_driver(const std::wstring& driverName, const std::wstring& driverPath, PHANDLE deviceHandle)
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
                if(!succeeded(status))
                    LOG(DEBUG) << "create_service returned " << std::hex << status;
                status = start_driver(schSCManager, driverName);
                if(!succeeded(status))
                    LOG(DEBUG) << "start_driver returned " << std::hex << status;
                status = get_driver_device(driverName, deviceHandle);
                if(!succeeded(status))
                    LOG(DEBUG) << "get_driver_device returned " << std::hex << status;
                CloseServiceHandle(schSCManager);
            }
            return status;
        }
        error_code winnt::unload_driver(const std::wstring& driverName)
        {
            SC_HANDLE	      schSCManager;
            error_code   status;

            if(driverName.empty()) return STATUS_INVALID_PARAMETER;

            schSCManager = OpenSCManager(nullptr,
                nullptr,
                SC_MANAGER_ALL_ACCESS
            );
            if(schSCManager) {
                status = stop_driver(schSCManager, driverName);
                if(succeeded(status))
                    status = delete_service(schSCManager, driverName);
                CloseServiceHandle(schSCManager);
            }
            return status;
        }
        error_code winnt::open_process(PHANDLE handle, uint32_t pid, uint32_t access)
        {
            OBJECT_ATTRIBUTES objAttr;

            InitializeObjectAttributes(&objAttr, NULL, NULL, NULL, NULL);
            CLIENT_ID cid;
            cid.UniqueProcess   = reinterpret_cast<HANDLE>(pid);
            cid.UniqueThread    = 0;

            auto status = NtOpenProcess(handle, access, &objAttr, &cid);

            return status;
        }
        bool winnt::process_is_wow64(HANDLE process)
        {
            PULONG_PTR buffer = (PULONG_PTR)query_process_information(process, ProcessWow64Information);
            bool iswow64 = *buffer != 0;
            free_local_buffer(&buffer);
            return iswow64;
        }
        error_code winnt::allocate_memory(HANDLE process, void* start, size_t* size, uint32_t allocation, uint32_t protection)
        {
            return NtAllocateVirtualMemory(process, (PVOID*)start, 0, (PSIZE_T)size, allocation, protection);
        }
        error_code winnt::protect_memory(HANDLE process, void* start, size_t* size, uint32_t protection, uint32_t& oldProtection)
        {
            return NtProtectVirtualMemory(process, (PVOID*)start, (PSIZE_T)size, protection, (PULONG)&oldProtection);
        }
        error_code winnt::free_memory(HANDLE process, void* start, size_t size, uint32_t free)
        {
            return NtFreeVirtualMemory(process, (PVOID*)start, (PSIZE_T)&size, free);
        }
        error_code winnt::read_memory(HANDLE process, void* address, void* buffer, size_t size)
        {
            if(process == GetCurrentProcess()) {
                memcpy((PVOID)buffer, (PVOID)address, size);
                return STATUS_SUCCESS;
            } else {
                return NtReadVirtualMemory(process, address, buffer, size, nullptr);
            }
        }
        error_code winnt::write_memory(HANDLE process, void* address, void* buffer, size_t size)
        {
            if(process == GetCurrentProcess()) {
                memcpy(const_cast<void*>(address), buffer, size);
                return STATUS_SUCCESS;
            } else {
                return NtWriteVirtualMemory(process, address, buffer, size, nullptr);
            }
        }
    }
}
