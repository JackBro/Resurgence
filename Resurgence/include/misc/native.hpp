#pragma once

#include <headers.hpp>
#include <functional>
#include <vector>

typedef struct _OBJECT_DIRECTORY_INFORMATION* POBJECT_DIRECTORY_INFORMATION;

namespace resurgence
{
    namespace native
    {
        typedef struct
        {
            union
            {
                uintptr_t           view_base;
                uintptr_t           image_base;
                PIMAGE_DOS_HEADER   dos_hdr;
            };
            union
            {
                size_t      view_size;
                size_t      image_size;
            };

            PIMAGE_NT_HEADERS32     nt_hdrs32;
            PIMAGE_NT_HEADERS64     nt_hdrs64;
            IMAGE_SECTION_HEADER*   sections;
            ULONG                   section_count;
        } mapped_image;

        typedef std::function<NTSTATUS(POBJECT_DIRECTORY_INFORMATION)>          object_enumeration_callback;
        typedef std::function<NTSTATUS(PSYSTEM_PROCESS_INFORMATION)>            process_enumeration_callback;
        typedef std::function<NTSTATUS(PRTL_PROCESS_MODULE_INFORMATION)>        system_module_enumeration_callback;
        typedef std::function<NTSTATUS(PLDR_DATA_TABLE_ENTRY)>                  module_enumeration_callback;
        typedef std::function<NTSTATUS(PSYSTEM_EXTENDED_THREAD_INFORMATION)>    thread_enumeration_callback;
        typedef std::function<NTSTATUS(PLDR_DATA_TABLE_ENTRY32)>                module_enumeration_callback32;

        ///<summary>
        /// Gets the message associated with a status value.
        ///</summary>
        ///<param name="status"> The status code. </param>
        ///<returns> 
        /// A string containing the message.
        ///</returns>
        std::wstring get_status_message(NTSTATUS status);

        //-----------------------------------------------
        // System routines
        //-----------------------------------------------

        ///<summary>
        /// Gets the required size needed for a NtQuerySystemInformation call.
        ///</summary>
        ///<param name="information"> The information class. </param>
        ///<returns> 
        /// The required buffer size.
        ///</returns>
        size_t query_required_size(SYSTEM_INFORMATION_CLASS information);

        ///<summary>
        /// Gets the required size needed for a NtQueryInformationProcess call.
        ///</summary>
        ///<param name="information"> The information class. </param>
        ///<returns> 
        /// The required buffer size.
        ///</returns>
        size_t query_required_size(PROCESSINFOCLASS information);

        ///<summary>
        /// Gets the required size needed for a NtQueryObject call.
        ///</summary>
        ///<param name="information"> The information class. </param>
        ///<returns> 
        /// The required buffer size.
        ///</returns>
        size_t query_required_size(OBJECT_INFORMATION_CLASS information);

        ///<summary>
        /// Query system information.
        ///</summary>
        ///<param name="information"> The information class. </param>
        ///<returns> 
        /// A buffer with the requested information or nullptr on failure.
        ///</returns>
        ///<remarks>
        /// The returned buffer, if not null, must be freed with free_local_buffer.
        ///</remarks>
        uint8_t* query_system_information(SYSTEM_INFORMATION_CLASS information);

        ///<summary>
        /// Query process information.
        ///</summary>
        ///<param name="information"> The information class. </param>
        ///<returns> 
        /// A buffer with the requested information or nullptr on failure.
        ///</returns>
        ///<remarks>
        /// The returned buffer, if not null, must be freed with free_local_buffer.
        ///</remarks>
        uint8_t* query_process_information(HANDLE handle, PROCESSINFOCLASS information);

        ///<summary>
        /// Query object information.
        ///</summary>
        ///<param name="information"> The information class. </param>
        ///<returns> 
        /// A buffer with the requested information or nullptr on failure.
        ///</returns>
        ///<remarks>
        /// The returned buffer, if not null, must be freed with free_local_buffer.
        ///</remarks>
        uint8_t* query_object_information(HANDLE handle, OBJECT_INFORMATION_CLASS information);

        ///<summary>
        /// Enumerates system modules (drivers).
        ///</summary>
        ///<param name="callback"> 
        /// The callback that will be called for each module. 
        /// Enumeration stops if the callback returns STATUS_SUCCESS. 
        ///</param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS enumerate_system_modules(system_module_enumeration_callback callback);

        ///<summary>
        /// Enumerates system objects.
        ///</summary>
        ///<param name="root"> 
        /// The root folder for the enumeration.
        ///</param>
        ///<param name="callback"> 
        /// The callback that will be called for each objects. 
        /// Enumeration stops if the callback returns STATUS_SUCCESS. 
        ///</param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS enumerate_system_objects(const std::wstring& root, object_enumeration_callback callback);

        ///<summary>
        /// Enumerates running processes.
        ///</summary>
        ///<param name="callback"> 
        /// The callback that will be called for each process. 
        /// Enumeration stops if the callback returns STATUS_SUCCESS. 
        ///</param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS enumerate_processes(process_enumeration_callback callback);

        ///<summary>
        /// Enumerates process' threads.
        ///</summary>
        ///<param name="pid"> 
        /// Id of the process. 
        ///</param>
        ///<param name="callback"> 
        /// The callback that will be called for each thread. 
        /// Enumeration stops if the callback returns STATUS_SUCCESS. 
        ///</param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS enumerate_process_threads(uint32_t pid, thread_enumeration_callback callback);

        ///<summary>
        /// Enumerates process' x64 modules.
        ///</summary>
        ///<param name="process"> 
        /// Handle to the process. Must have read and query information access. 
        ///</param>
        ///<param name="callback"> 
        /// The callback that will be called for each module. 
        /// Enumeration stops if the callback returns STATUS_SUCCESS. 
        ///</param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS enumerate_process_modules(HANDLE process, module_enumeration_callback callback);

        ///<summary>
        /// Enumerates process' x86 modules.
        ///</summary>
        ///<param name="process"> 
        /// Handle to the process. Must have read and query information access. 
        ///</param>
        ///<param name="callback"> 
        /// The callback that will be called for each module. 
        /// Enumeration stops if the callback returns STATUS_SUCCESS. 
        ///</param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS enumerate_process_modules32(HANDLE process, module_enumeration_callback32 callback);

        ///<summary>
        /// Checks if a object exists on the system.
        ///</summary>
        ///<param name="root">   The folder to check. </param>
        ///<param name="object"> The object name. </param>
        ///<param name="found">  Pointer to a variable that will hold the result. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS object_exists(const std::wstring& root, const std::wstring& object, bool* found);

        ///<summary>
        /// Queries information about a system module.
        ///</summary>
        ///<param name="module"> The module name. </param>
        ///<param name="info">   The returned information. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS get_system_module_info(const std::string& module, PRTL_PROCESS_MODULE_INFORMATION info);

        //-----------------------------------------------
        // File routines
        //-----------------------------------------------

        ///<summary>
        /// Opens an existing file.
        ///</summary>
        ///<param name="path">        The file path. </param>
        ///<param name="accessFlags"> The desired access. </param>
        ///<param name="handle">      The returned handle. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS open_file(const std::wstring& path, uint32_t accessFlags, PHANDLE handle);

        ///<summary>
        /// Writes to a file.
        ///</summary>
        ///<param name="path">   The file path. </param>
        ///<param name="buffer"> The buffer to write. </param>
        ///<param name="length"> The size of the buffer. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS write_file(const std::wstring& path, uint8_t* buffer, size_t length);

        ///<summary>
        /// Queries the size of a file.
        ///</summary>
        ///<param name="handle"> The file handle. </param>
        ///<param name="size">   The returned size. </param>
        ///<param name="li">     The returned size. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS get_file_size(HANDLE handle, size_t* size, LARGE_INTEGER* li);

        ///<summary>
        /// Copy a file.
        ///</summary>
        ///<param name="oldPath"> The old path. </param>
        ///<param name="newPath"> The new path. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS copy_file(const std::wstring& oldPath, const std::wstring& newPath);

        ///<summary>
        /// Translates a relative path to full path.
        ///</summary>
        ///<param name="path"> The path. </param>
        ///<returns> 
        /// The full path.
        ///</returns>
        std::wstring get_full_path(const std::wstring& path);

        ///<summary>
        /// Translates a NT path to DOS path.
        ///</summary>
        ///<param name="path"> The NT path (i.e "\SystemRoot\system32\ntoskrnl.exe"). </param>
        ///<returns> 
        /// The DOS path (i.e "C:\Windows\system32\ntoskrnl.exe").
        ///</returns>
        std::wstring get_dos_path(const std::wstring& path);

        ///<summary>
        /// Query mounted devices (i.e C:\, D:\ etc).
        ///</summary>
        ///<param name="letters"> A vector containing the mounted driver letters. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS query_mounted_drives(std::vector<std::wstring>& letters);

        ///<summary>
        /// Gets the symbolic device link from a driver letter.
        ///</summary>
        ///<param name="drive">      The drive letter. </param>
        ///<param name="deviceLink"> The returned device link. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS get_symbolic_link_from_drive(const std::wstring& drive, std::wstring& deviceLink);

        //-----------------------------------------------
        // Driver related routines
        //-----------------------------------------------

        ///<summary>
        /// Adds a service to the database.
        ///</summary>
        ///<param name="manager">    Handle to the service database. </param>
        ///<param name="driverName"> The driver name. </param>
        ///<param name="driverPath"> The driver path. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS create_service(SC_HANDLE manager, const std::wstring& driverName, const std::wstring& driverPath);

        ///<summary>
        /// Starts a driver service.
        ///</summary>
        ///<param name="manager">    Handle to the service database. </param>
        ///<param name="driverName"> The driver name. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS start_driver(SC_HANDLE manager, const std::wstring& driverName);

        ///<summary>
        /// Stops a driver service.
        ///</summary>
        ///<param name="manager">    Handle to the service database. </param>
        ///<param name="driverName"> The driver name. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS stop_driver(SC_HANDLE manager, const std::wstring& driverName);

        ///<summary>
        /// Gets a driver device handle.
        ///</summary>
        ///<param name="driver">       The driver name. </param>
        ///<param name="deviceHandle"> The device handle. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS get_driver_device(const std::wstring& driver, PHANDLE deviceHandle);

        ///<summary>
        /// Removes a service from the database.
        ///</summary>
        ///<param name="manager">    Handle to the service database. </param>
        ///<param name="driverName"> The driver name. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS delete_service(SC_HANDLE manager, const std::wstring& driverName);

        ///<summary>
        /// Loads a driver.
        ///</summary>
        ///<param name="driverName">   The driver name. </param>
        ///<param name="driverPath">   The driver path. </param>
        ///<param name="deviceHandle"> The returned device handle. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS load_driver(const std::wstring& driverName, const std::wstring& driverPath, PHANDLE deviceHandle);

        ///<summary>
        /// Unloads a driver.
        ///</summary>
        ///<param name="driverName">   The driver name. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS unload_driver(const std::wstring& driverName);

        //-----------------------------------------------
        // Memory routines
        //-----------------------------------------------

        ///<summary>
        /// Allocates virtual memory.
        ///</summary>
        ///<param name="process">    The target process. </param>
        ///<param name="start">      The allocation start address. </param>
        ///<param name="size">       The allocation size. </param>
        ///<param name="allocation"> The allocation flags. </param>
        ///<param name="protection"> The memory protection flags. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS allocate_memory(HANDLE process, PVOID* start, size_t* size, uint32_t allocation, uint32_t protection);

        ///<summary>
        /// Change virtual memory protection.
        ///</summary>
        ///<param name="process">       The target process. </param>
        ///<param name="start">         The start address. </param>
        ///<param name="size">          The region size. </param>
        ///<param name="protection">    The new protection flags. </param>
        ///<param name="oldProtection"> The old protection flags. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS protect_memory(HANDLE process, PVOID* start, size_t* size, uint32_t protection, uint32_t* oldProtection);

        ///<summary>
        /// Frees virtual memory.
        ///</summary>
        ///<param name="process"> The target process. </param>
        ///<param name="start">   The start address. </param>
        ///<param name="size">    The region size. </param>
        ///<param name="free">    The free flag. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS free_memory(HANDLE process, PVOID* start, size_t size, uint32_t free);

        ///<summary>
        /// Read virtual memory.
        ///</summary>
        ///<param name="process"> The target process. </param>
        ///<param name="address"> The start address. </param>
        ///<param name="buffer">  The buffer. </param>
        ///<param name="size">    The buffer size. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS read_memory(HANDLE process, LPVOID address, LPVOID buffer, size_t size);

        ///<summary>
        /// Write virtual memory.
        ///</summary>
        ///<param name="process"> The target process. </param>
        ///<param name="address"> The start address. </param>
        ///<param name="buffer">  The buffer. </param>
        ///<param name="size">    The buffer size. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS write_memory(HANDLE process, LPVOID address, LPVOID buffer, size_t size);

        //-----------------------------------------------
        // Process routines
        //-----------------------------------------------

        ///<summary>
        /// Opens a process.
        ///</summary>
        ///<param name="handle"> The returned handle. </param>
        ///<param name="pid">    The process id. </param>
        ///<param name="access"> The desired access flags. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS open_process(PHANDLE handle, uint32_t pid, uint32_t access);

        ///<summary>
        /// Checks if the process is running under WOW64.
        ///</summary>
        ///<param name="process"> The target process. </param>
        ///<param name="pebAddress"> The address of the x86 PEB. </param>
        ///<returns> 
        /// True if the process is a wow64 process.
        ///</returns>
        bool process_is_wow64(HANDLE process, PPEB32* pebAddress = nullptr);

        ///<summary>
        /// Creates a thread.
        ///</summary>
        ///<param name="process">        The target process. </param>
        ///<param name="startAddress">   The thread start address. </param>
        ///<param name="startParameter"> The thread start parameter. </param>
        ///<param name="wait">           Blocks and wait for the thread to finish running. </param>
        ///<returns> 
        /// On success the thread exit status if wait is true. 0 if wait is false.
        /// On failure the status code.
        ///</returns>
        ULONG create_thread(HANDLE process, LPVOID startAddress, LPVOID startParameter, bool wait);

        ///<summary>
        /// Terminate a process.
        ///</summary>
        ///<param name="process">  The target process. </param>
        ///<param name="exitCode"> The exit code. </param>
        void terminate_process(HANDLE process, uint32_t exitCode);

        ///<summary>
        /// Maps an image to the current process. This does not call the entry point.
        ///</summary>
        ///<param name="path">  The target image path. </param>
        ///<param name="image"> The loaded image. </param>
        ///<returns> 
        /// The status code.
        ///</returns>
        NTSTATUS load_mapped_image(const std::wstring& path, mapped_image& image);

        ///<summary>
        /// Unloads a previously mapped image
        ///</summary>
        ///<param name="image"> The image base. </param>
        void unload_mapped_image(const mapped_image& image);

        PIMAGE_SECTION_HEADER mapped_image_rva_to_section(const mapped_image& image, ULONG rva);
        uintptr_t mapped_image_rva_to_va(const mapped_image& image, ULONG rva);
    }
}
#define allocate_local_buffer(buffer, size)  \
    do { \
        size_t _uid_size_ = size; \
        resurgence::native::allocate_memory(GetCurrentProcess(), (void**)buffer, &_uid_size_, MEM_COMMIT, PAGE_READWRITE); \
    } while(0)

#define free_local_buffer(buffer) resurgence::native::free_memory(GetCurrentProcess(), (void**)&buffer, 0, MEM_RELEASE)