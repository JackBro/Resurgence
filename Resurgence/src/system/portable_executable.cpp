#include <system/portable_executable.hpp>

namespace resurgence
{
    namespace system
    {

        portable_executable portable_executable::load_from_file(const std::wstring& file)
        {
            throw;
        }
        portable_executable portable_executable::load_from_memory(process* proc, const std::uint8_t* base)
        {
            throw;
        }
    }
}