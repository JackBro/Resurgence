#include <system/portable_executable.hpp>
#include <system/process.hpp>
#include <misc/winnt.hpp>

namespace resurgence
{
    namespace system
    {
        portable_executable::portable_executable()
            : _dosHdr(nullptr), _ntHdr32(nullptr), _ntHdr64(nullptr)
        {

        }
        portable_executable portable_executable::load_from_file(const std::wstring& file)
        {
            HANDLE              fileHandle;
            HANDLE              fileMapping;
            uint8_t*            fileBase;

            UNICODE_STRING      usFileName;
            std::wstring        qualifiedPath;
            OBJECT_ATTRIBUTES   objAttr;
            IO_STATUS_BLOCK     ioStatus;
            NTSTATUS          status;
            portable_executable pe;

            qualifiedPath = L"\\??\\";
            qualifiedPath.append(file);

            RtlInitUnicodeString(&usFileName, std::data(qualifiedPath));
            InitializeObjectAttributes(&objAttr, &usFileName, NULL, NULL, NULL);

            status = NtCreateFile(
                &fileHandle, FILE_GENERIC_READ, 
                &objAttr, &ioStatus, 
                NULL, FILE_ATTRIBUTE_NORMAL, 
                FILE_SHARE_READ | FILE_SHARE_WRITE, 
                FILE_OPEN, 
                FILE_SYNCHRONOUS_IO_NONALERT, 
                NULL, 0);
            
            if(NT_SUCCESS(status)) {
                fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
                if(fileMapping) {
                    fileBase = (uint8_t*)MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
                    if(fileBase) {
                        pe = load_from_memory(nullptr, fileBase);
                        UnmapViewOfFile(fileBase);
                    } else {
                        set_last_ntstatus(STATUS_UNSUCCESSFUL);
                    }
                    NtClose(fileMapping);
                } else {
                    set_last_ntstatus(STATUS_UNSUCCESSFUL);
                }
                NtClose(fileHandle);
            }
            return pe;
        }
        portable_executable portable_executable::load_from_memory(process* proc, const std::uint8_t* base)
        {
            throw;
            //PIMAGE_DOS_HEADER dosHdr;
            //
            ////
            //// Use the current process if one isnt provided
            ////
            //if(proc == nullptr)                        
            //    *proc = process::get_current_process();
            //
            //allocate_local_buffer(&dosHdr, )
        }
    }
}