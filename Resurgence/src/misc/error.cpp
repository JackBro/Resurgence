#include <headers.hpp>
#include <misc/error.hpp>
#include <misc/winnt.hpp>

namespace resurgence
{
    error_code::error_code()
        : _status(STATUS_SUCCESS)
    {
    }

    error_code::error_code(NTSTATUS status)
        : _status(status)
    {
    }

    std::wstring error_code::get_message() const
    {
        return misc::winnt::get_status_message(_status);
    }
}