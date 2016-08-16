#pragma once

namespace resurgence
{
    class error_code
    {
    public:
        error_code();
        error_code(NTSTATUS status);


        NTSTATUS get_status() const
        {
            return _status;
        }

        __forceinline operator NTSTATUS&()
        {
            return _status;
        }
        __forceinline error_code& operator=(const NTSTATUS& rhs)
        {
            _status = rhs;
            return *this;
        }

        std::wstring get_message() const;

    private:
        NTSTATUS _status;
    };
}

//
// Ideally I would want these to be macros, but that generates some conflicts with std files
//
__forceinline bool succeeded(resurgence::error_code error)  { return (NTSTATUS)error >= 0; }
__forceinline bool failed(resurgence::error_code error)     { return (NTSTATUS)error < 0; }