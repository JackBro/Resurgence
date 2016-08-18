#pragma once

#include <headers.hpp>
#include <string>

namespace resurgence
{
    namespace system
    {
        class process;

        enum platform
        {
            platform_unknown = 0,
            platform_x86,
            platform_x64
        };

        class portable_executable
        {
        public:
            portable_executable();
            portable_executable(process* proc, PIMAGE_DOS_HEADER dosHdr, PIMAGE_NT_HEADERS32 ntHdrs);
            portable_executable(process* proc, PIMAGE_DOS_HEADER dosHdr, PIMAGE_NT_HEADERS64 ntHdrs);

            static portable_executable  load_from_file(const std::wstring& file);
            static portable_executable  load_from_memory(process* proc, const std::uint8_t* base);
            
            const IMAGE_DOS_HEADER*     get_dos_header() const;
            const IMAGE_NT_HEADERS32*   get_nt_headers32() const;
            const IMAGE_NT_HEADERS64*   get_nt_headers64() const;
            const IMAGE_DATA_DIRECTORY* get_data_directory() const;
            const IMAGE_SECTION_HEADER* get_section_header() const;

            bool                        is_valid() const;
            platform                    get_platform() const;

            uint16_t                    get_size_opt_header() const;
            uint16_t                    get_file_characteristics() const;
            uint16_t                    get_dll_characteristics() const;

            uint32_t                    get_base_of_code() const;
            uint32_t                    get_size_of_code() const;
            uint32_t                    get_size_of_image() const;
            uint32_t                    get_size_of_headers() const;
            uintptr_t                   get_entry_point_address() const;
            uintptr_t                   get_image_base() const;
            uint32_t                    get_section_alignment() const;
            uint32_t                    get_file_alignment() const;
            uint32_t                    get_checksum() const;
            uint16_t                    get_subsystem() const;

        private:
            process*            _process;
            IMAGE_DOS_HEADER    _dosHdr;
            IMAGE_NT_HEADERS32  _ntHdr32;
            IMAGE_NT_HEADERS64  _ntHdr64;
            bool                _is32Bit;
        };
    }
}
