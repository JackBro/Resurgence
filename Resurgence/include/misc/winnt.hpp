#pragma once

#include <headers.hpp>
#include <functional>
#include <vector>

typedef struct _OBJECT_DIRECTORY_INFORMATION* POBJECT_DIRECTORY_INFORMATION;

namespace resurgence
{
	namespace system
	{
		class process;
	}

	namespace misc
	{
		typedef std::function<NTSTATUS(POBJECT_DIRECTORY_INFORMATION)>     object_enumeration_callback;
		typedef std::function<NTSTATUS(PSYSTEM_PROCESSES_INFORMATION)>     process_enumeration_callback;
		typedef std::function<NTSTATUS(PRTL_PROCESS_MODULE_INFORMATION)>   system_module_enumeration_callback;
		typedef std::function<NTSTATUS(PLDR_DATA_TABLE_ENTRY)>             module_enumeration_callback;
		typedef std::function<NTSTATUS(PLDR_DATA_TABLE_ENTRY32)>           module_enumeration_callback32;

		class winnt
		{
		public:
			static std::wstring     get_status_message(NTSTATUS status);

			//-----------------------------------------------
			// system routines
			//-----------------------------------------------
			static size_t           query_required_size(SYSTEM_INFORMATION_CLASS information);
			static size_t           query_required_size(PROCESS_INFORMATION_CLASSEX information);
			static size_t           query_required_size(OBJECT_INFORMATION_CLASS information);
			static uint8_t*         query_system_information(SYSTEM_INFORMATION_CLASS information);
			static uint8_t*         query_process_information(HANDLE handle, PROCESS_INFORMATION_CLASSEX information);
			static uint8_t*         query_object_information(HANDLE handle, OBJECT_INFORMATION_CLASS information);
			static NTSTATUS         enumerate_system_modules(system_module_enumeration_callback callback);
			static NTSTATUS         enumerate_system_objects(const std::wstring& root, object_enumeration_callback callback);
			static NTSTATUS         enumerate_processes(process_enumeration_callback callback);
			static NTSTATUS         enumerate_process_modules(HANDLE process, module_enumeration_callback callback);
			static NTSTATUS         enumerate_process_modules32(HANDLE process, module_enumeration_callback32 callback);
			static NTSTATUS         object_exists(const std::wstring& root, const std::wstring& object, bool* found = nullptr);
			static NTSTATUS         get_system_module_info(const std::string& module, PRTL_PROCESS_MODULE_INFORMATION info);

			//-----------------------------------------------
			// File routines
			//-----------------------------------------------
			static NTSTATUS         write_file(const std::wstring& path, uint8_t* buffer, size_t length);
			static NTSTATUS         copy_file(const std::wstring& oldPath, const std::wstring& newPath);
			static std::wstring     get_full_path(const std::wstring& path);
			static std::wstring     get_dos_path(const std::wstring& path);
			static NTSTATUS         query_mounted_drives(std::vector<std::wstring>& letters);
			static NTSTATUS         get_symbolic_link_from_drive(const std::wstring& drive, std::wstring& deviceLink);

			//-----------------------------------------------
			// Driver related routines
			//-----------------------------------------------
			static NTSTATUS         create_service(SC_HANDLE manager, const std::wstring& driverName, const std::wstring& driverPath);
			static NTSTATUS         start_driver(SC_HANDLE manager, const std::wstring& driverName);
			static NTSTATUS         stop_driver(SC_HANDLE manager, const std::wstring& driverName);
			static NTSTATUS         get_driver_device(const std::wstring& driver, PHANDLE deviceHandle);
			static NTSTATUS         delete_service(SC_HANDLE manager, const std::wstring& driverName);
			static NTSTATUS         load_driver(const std::wstring& driverName, const std::wstring& driverPath, PHANDLE deviceHandle);
			static NTSTATUS         unload_driver(const std::wstring& driverName);

			//-----------------------------------------------
			// Memory routines
			//-----------------------------------------------
			static NTSTATUS         allocate_memory(HANDLE process, PVOID*  start, size_t* size, uint32_t allocation, uint32_t protection);
			static NTSTATUS         protect_memory(HANDLE process, PVOID*  start, size_t* size, uint32_t protection, uint32_t* oldProtection);
			static NTSTATUS         free_memory(HANDLE process, PVOID* start, size_t size, uint32_t free);
			static NTSTATUS         read_memory(HANDLE process, void* address, void* buffer, size_t size);
			static NTSTATUS         write_memory(HANDLE process, void* address, void* buffer, size_t size);

			//-----------------------------------------------
			// Process routines
			//-----------------------------------------------
			static NTSTATUS         open_process(PHANDLE handle, uint32_t pid, uint32_t access);
			static bool             process_is_wow64(HANDLE process);
		};
	}
}

#define allocate_local_buffer(buffer, size)  \
    do { \
        size_t _uid_size_ = size; \
        resurgence::misc::winnt::allocate_memory(GetCurrentProcess(), (void**)buffer, &_uid_size_, MEM_COMMIT, PAGE_READWRITE); \
    } while(0)

#define free_local_buffer(buffer) resurgence::misc::winnt::free_memory(GetCurrentProcess(), (void**)buffer, 0, MEM_RELEASE)