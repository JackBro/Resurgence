#pragma once

#include <headers.hpp>
#include <functional>

typedef struct _OBJECT_DIRECTORY_INFORMATION* POBJECT_DIRECTORY_INFORMATION;

namespace resurgence
{
    namespace system
    {
        class process;
    }

    namespace misc
    {
        typedef std::function<error_code(POBJECT_DIRECTORY_INFORMATION)>     object_enumeration_callback;
        typedef std::function<error_code(PSYSTEM_PROCESSES_INFORMATION)>     process_enumeration_callback;
        typedef std::function<error_code(PRTL_PROCESS_MODULE_INFORMATION)>   system_module_enumeration_callback;
        typedef std::function<error_code(PLDR_DATA_TABLE_ENTRY)>             module_enumeration_callback;
        typedef std::function<error_code(PLDR_DATA_TABLE_ENTRY32)>           module_enumeration_callback32;

        class winnt
        {
        public:
            static std::wstring     get_status_message(error_code status);

            //-----------------------------------------------
            // system routines
            //-----------------------------------------------
            static size_t           query_required_size(SYSTEM_INFORMATION_CLASS information);
            static size_t           query_required_size(PROCESS_INFORMATION_CLASSEX information);
            static size_t           query_required_size(OBJECT_INFORMATION_CLASS information);
            static uint8_t*         query_system_information(SYSTEM_INFORMATION_CLASS information);
            static uint8_t*         query_process_information(HANDLE handle, PROCESS_INFORMATION_CLASSEX information);
            static uint8_t*         query_object_information(HANDLE handle, OBJECT_INFORMATION_CLASS information);
            static error_code    enumerate_system_modules(system_module_enumeration_callback callback);
            static error_code    enumerate_system_objects(const std::wstring& root, object_enumeration_callback callback);
            static error_code    enumerate_processes(process_enumeration_callback callback);
            static error_code    enumerate_process_modules(HANDLE process, module_enumeration_callback callback);
            static error_code    enumerate_process_modules32(HANDLE process, module_enumeration_callback32 callback);
            static error_code    object_exists(const std::wstring& root, const std::wstring& object, bool* found = nullptr);
            static error_code    get_system_module_info(const std::string& module, PRTL_PROCESS_MODULE_INFORMATION info);

            //-----------------------------------------------
            // File routines
            //-----------------------------------------------
            static error_code    write_file(const std::wstring& path, uint8_t* buffer, size_t length);
            static error_code    copy_file(const std::wstring& oldPath, const std::wstring& newPath);
            static std::wstring     get_full_path(const std::wstring& path);
            static std::wstring     get_dos_path(const std::wstring& path);
            static error_code    query_mounted_drives(std::vector<std::wstring>& letters);
            static error_code    get_symbolic_link_from_drive(const std::wstring& drive, std::wstring& deviceLink);

            //-----------------------------------------------
            // Driver related routines
            //-----------------------------------------------
            static error_code    create_service(SC_HANDLE manager, const std::wstring& driverName, const std::wstring& driverPath);
            static error_code    start_driver(SC_HANDLE manager, const std::wstring& driverName);
            static error_code    stop_driver(SC_HANDLE manager, const std::wstring& driverName);
            static error_code    get_driver_device(const std::wstring& driver, PHANDLE deviceHandle);
            static error_code    delete_service(SC_HANDLE manager, const std::wstring& driverName);
            static error_code    load_driver(const std::wstring& driverName, const std::wstring& driverPath, PHANDLE deviceHandle);
            static error_code    unload_driver(const std::wstring& driverName);

            //-----------------------------------------------
            // Memory routines
            //-----------------------------------------------
            static error_code    allocate_memory(HANDLE process, void* start, size_t* size, uint32_t allocation, uint32_t protection);
            static error_code    protect_memory(HANDLE process, void* start, size_t* size, uint32_t protection, uint32_t& oldProtection);
            static error_code    free_memory(HANDLE process, void* start, size_t size, uint32_t free);
            static error_code    read_memory(HANDLE process, void* address, void* buffer, size_t size);
            static error_code    write_memory(HANDLE process, void* address, void* buffer, size_t size);
            
            //-----------------------------------------------
            // Process routines
            //-----------------------------------------------
            static error_code    open_process(PHANDLE handle, uint32_t pid, uint32_t access);
            static bool             process_is_wow64(HANDLE process);
        };
    }
}

#define allocate_local_buffer(buffer, size) resurgence::misc::winnt::allocate_memory(GetCurrentProcess(), buffer, size, MEM_COMMIT, PAGE_READWRITE)
#define free_local_buffer(buffer)           resurgence::misc::winnt::free_memory(GetCurrentProcess(), buffer, 0, MEM_RELEASE)