#pragma once

#include <headers.hpp>
#include <string>

namespace resurgence
{
    namespace system
    {
        class process;

        class portable_executable
        {
        public:
            portable_executable();

            static portable_executable load_from_file(const std::wstring& file);
            static portable_executable load_from_memory(process* proc, const std::uint8_t* base);

            bool is_valid() { return !!_dosHdr && _dosHdr->e_magic == IMAGE_DOS_SIGNATURE; }

        private:
            PIMAGE_DOS_HEADER   _dosHdr;
            PIMAGE_NT_HEADERS32 _ntHdr32;
            PIMAGE_NT_HEADERS64 _ntHdr64;
        };
    }
}
