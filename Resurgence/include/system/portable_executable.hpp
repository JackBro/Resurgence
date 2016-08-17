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
            static portable_executable load_from_file(const std::wstring& file);
            static portable_executable load_from_memory(process* proc, const std::uint8_t* base);

            bool is_valid() { return _dosHdr.e_magic == IMAGE_DOS_SIGNATURE; }

        private:
            IMAGE_DOS_HEADER    _dosHdr;
            IMAGE_NT_HEADERS32  _ntHdr32;
            IMAGE_NT_HEADERS64  _ntHdr64;
        };
    }
}
