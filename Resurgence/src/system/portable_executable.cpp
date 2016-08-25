#include <system/portable_executable.hpp>
#include <system/process.hpp>
#include <misc/winnt.hpp>

#define GET_NT_HEADER_FIELD(field) _is32Bit ? _ntHdr32.field : _ntHdr64.field

namespace resurgence
{
    namespace system
    {
        portable_executable::portable_executable()
            : _process(nullptr), _dosHdr(), _ntHdr32(), _ntHdr64(), _secHdr(), _is32Bit(false)
        {
        }
        portable_executable::portable_executable(process* proc, PIMAGE_DOS_HEADER dosHdr, PIMAGE_NT_HEADERS32 ntHdrs, PIMAGE_SECTION_HEADER secHdr)
            : _process(proc), _dosHdr(*dosHdr), _ntHdr32(*ntHdrs), _ntHdr64(), _is32Bit(true)
        {
            RtlCopyMemory(_secHdr, secHdr, MAX_SECTION_COUNT * sizeof(IMAGE_SECTION_HEADER));
        }
        portable_executable::portable_executable(process* proc, PIMAGE_DOS_HEADER dosHdr, PIMAGE_NT_HEADERS64 ntHdrs, PIMAGE_SECTION_HEADER secHdr)
            : _process(proc), _dosHdr(*dosHdr), _ntHdr32(), _ntHdr64(*ntHdrs), _is32Bit(false)
        {
            RtlCopyMemory(_secHdr, secHdr, MAX_SECTION_COUNT * sizeof(IMAGE_SECTION_HEADER));
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
            NTSTATUS            status;
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
                        auto targetProcess = process::get_current_process();
                        pe = load_from_memory(&targetProcess, fileBase);
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
            portable_executable     pe;
            PIMAGE_DOS_HEADER       dosHdr = nullptr;
            PIMAGE_NT_HEADERS32     ntHdrs32 = nullptr;
            PIMAGE_NT_HEADERS64     ntHdrs64 = nullptr;
            PIMAGE_SECTION_HEADER   secHdr = nullptr;
            WORD ntHdrsMagic;

            allocate_local_buffer(&dosHdr, sizeof(IMAGE_DOS_HEADER));
            if(!dosHdr)
                goto FAIL_3;

            auto status = proc->memory()->read_bytes(base, (uint8_t*)dosHdr, sizeof(IMAGE_DOS_HEADER));

            if(!NT_SUCCESS(status))
                goto FAIL_2;

            if(dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
                set_last_ntstatus(STATUS_INVALID_IMAGE_NOT_MZ);
                goto FAIL_2;
            }

            auto ntHdrsBase = PTR_ADD(base, dosHdr->e_lfanew);
            auto ntHdrsMagicAddress = PTR_ADD(ntHdrsBase, FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader));

            status = proc->memory()->read_bytes(ntHdrsMagicAddress, (uint8_t*)&ntHdrsMagic, sizeof(WORD));

            if(!NT_SUCCESS(status))
                goto FAIL_2;

            //
            // 32bit image
            // 
            if(ntHdrsMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                allocate_local_buffer(&ntHdrs32, sizeof(IMAGE_NT_HEADERS32));

                if(!ntHdrs32)
                    goto FAIL_1;

                status = proc->memory()->read_bytes(ntHdrsBase, (uint8_t*)ntHdrs32, sizeof(IMAGE_NT_HEADERS32));

                if(!NT_SUCCESS(status))
                    goto FAIL_1;

                allocate_local_buffer(&secHdr, MAX_SECTION_COUNT * sizeof(IMAGE_SECTION_HEADER));

                if(!secHdr)
                    goto FAIL_1;

                RtlZeroMemory(secHdr, MAX_SECTION_COUNT * sizeof(IMAGE_SECTION_HEADER));

                status = proc->memory()->read_bytes(PTR_ADD(ntHdrsBase, sizeof(IMAGE_NT_HEADERS32)), (uint8_t*)secHdr, sizeof(IMAGE_SECTION_HEADER) * ntHdrs32->FileHeader.NumberOfSections);

                if(!NT_SUCCESS(status))
                    goto FAIL_1;

                pe = portable_executable(proc, dosHdr, ntHdrs32, secHdr);
            }
            //
            // 64bit image
            // 
            else {
                allocate_local_buffer(&ntHdrs64, sizeof(IMAGE_NT_HEADERS64));

                if(!ntHdrs64)
                    goto FAIL_1;

                status = proc->memory()->read_bytes(ntHdrsBase, (uint8_t*)ntHdrs64, sizeof(IMAGE_NT_HEADERS64));

                if(!NT_SUCCESS(status))
                    goto FAIL_1;

                allocate_local_buffer(&secHdr, MAX_SECTION_COUNT * sizeof(IMAGE_SECTION_HEADER));

                if(!secHdr)
                    goto FAIL_1;

                RtlZeroMemory(secHdr, MAX_SECTION_COUNT * sizeof(IMAGE_SECTION_HEADER));

                status = proc->memory()->read_bytes(PTR_ADD(ntHdrsBase, sizeof(IMAGE_NT_HEADERS64)), (uint8_t*)secHdr, sizeof(IMAGE_SECTION_HEADER) * ntHdrs64->FileHeader.NumberOfSections);

                if(!NT_SUCCESS(status))
                    goto FAIL_1;

                pe = portable_executable(proc, dosHdr, ntHdrs64, secHdr);
            }

        FAIL_1: // Failed after allocating all buffers
            if(ntHdrs32)    free_local_buffer(&ntHdrs32);
            if(ntHdrs64)    free_local_buffer(&ntHdrs64);
            if(secHdr)      free_local_buffer(&secHdr);
        FAIL_2: // Failed after allocating only the dos header
            free_local_buffer(&dosHdr);
        FAIL_3:
            return pe;
        }
        const IMAGE_DOS_HEADER* portable_executable::get_dos_header() const
        {
            return &_dosHdr;
        }
        const IMAGE_NT_HEADERS32* portable_executable::get_nt_headers32() const
        {
            return &_ntHdr32;
        }
        const IMAGE_NT_HEADERS64* portable_executable::get_nt_headers64() const
        {
            return &_ntHdr64;
        }
        IMAGE_DATA_DIRECTORY portable_executable::get_data_directory(int entry) const
        {
            return _is32Bit ? _ntHdr32.OptionalHeader.DataDirectory[entry] : _ntHdr64.OptionalHeader.DataDirectory[entry];
        }
        const IMAGE_SECTION_HEADER* portable_executable::get_section_header() const
        {
            return _secHdr;
        }
        bool portable_executable::is_valid() const
        {
            return _dosHdr.e_magic == IMAGE_DOS_SIGNATURE;
        }
        platform portable_executable::get_platform() const
        {
            return _is32Bit ? platform_x86 : platform_x64;
        }
        uint16_t portable_executable::get_size_opt_header() const
        {
            return GET_NT_HEADER_FIELD(FileHeader.SizeOfOptionalHeader);
        }
        uint16_t portable_executable::get_number_of_sections() const
        {
            return GET_NT_HEADER_FIELD(FileHeader.NumberOfSections);
        }
        uint16_t portable_executable::get_file_characteristics() const
        {
            return GET_NT_HEADER_FIELD(FileHeader.Characteristics);
        }
        uint16_t portable_executable::get_dll_characteristics() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.DllCharacteristics);
        }
        uint32_t portable_executable::get_base_of_code() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.BaseOfCode);
        }
        uint32_t portable_executable::get_size_of_code() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.SizeOfCode);
        }
        uint32_t portable_executable::get_size_of_image() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.SizeOfImage);
        }
        uint32_t portable_executable::get_size_of_headers() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.SizeOfHeaders);
        }
        uintptr_t portable_executable::get_entry_point_address() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.AddressOfEntryPoint);
        }
        uintptr_t portable_executable::get_image_base() const
        {
            return static_cast<uintptr_t>(GET_NT_HEADER_FIELD(OptionalHeader.ImageBase));
        }
        uint32_t portable_executable::get_section_alignment() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.SectionAlignment);
        }
        uint32_t portable_executable::get_file_alignment() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.FileAlignment);
        }
        uint32_t portable_executable::get_checksum() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.CheckSum);
        }
        uint16_t portable_executable::get_subsystem() const
        {
            return GET_NT_HEADER_FIELD(OptionalHeader.Subsystem);
        }
    }
}