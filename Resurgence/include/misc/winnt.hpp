#pragma once

#include <headers.hpp>
#include <functional>

typedef struct _OBJECT_DIRECTORY_INFORMATION* POBJECT_DIRECTORY_INFORMATION;

namespace resurgence
{
    namespace misc
    {
        typedef std::function<ntstatus_code(POBJECT_DIRECTORY_INFORMATION)>     object_enumeration_callback;
        typedef std::function<ntstatus_code(PSYSTEM_PROCESSES_INFORMATION)>     process_enumeration_callback;
        typedef std::function<ntstatus_code(PRTL_PROCESS_MODULE_INFORMATION)>   module_enumeration_callback;

        class winnt
        {
        public:
            static std::wstring get_status_message(ntstatus_code status);

            //-----------------------------------------------
            // system routines
            //-----------------------------------------------
            static ntstatus_code enumerate_system_modules(module_enumeration_callback callback);
            static ntstatus_code enumerate_system_objects(const std::wstring& root, object_enumeration_callback callback);
            static ntstatus_code enumerate_processes(process_enumeration_callback callback);
            static ntstatus_code object_exists(const std::wstring& root, const std::wstring& object, bool* found = nullptr);
            static ntstatus_code get_system_module_info(const std::string& module, PRTL_PROCESS_MODULE_INFORMATION info);

            //-----------------------------------------------
            // File routines
            //-----------------------------------------------
            static ntstatus_code write_file(const std::wstring& path, std::uint8_t* buffer, std::size_t length);
            static ntstatus_code copy_file(const std::wstring& oldPath, const std::wstring& newPath);
            static std::wstring  get_full_path(const std::wstring& path);

            //-----------------------------------------------
            // driver related routines
            //-----------------------------------------------
            static ntstatus_code create_service(SC_HANDLE manager, const std::wstring& driverName, const std::wstring& driverPath);
            static ntstatus_code start_driver(SC_HANDLE manager, const std::wstring& driverName);
            static ntstatus_code stop_driver(SC_HANDLE manager, const std::wstring& driverName);
            static ntstatus_code get_driver_device(const std::wstring& driver, PHANDLE deviceHandle);
            static ntstatus_code delete_service(SC_HANDLE manager, const std::wstring& driverName);
            static ntstatus_code load_driver(const std::wstring& driverName, const std::wstring& driverPath, PHANDLE deviceHandle);
            static ntstatus_code unload_driver(const std::wstring& driverName);
        };
    }
}
