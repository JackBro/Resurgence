#include <misc/safe_handle.hpp>

namespace resurgence
{
    namespace misc
    {
        namespace detail
        {
            safe_handle::safe_handle(HANDLE invalidValue)
                : _value(invalidValue),
                _invalid(invalidValue)
            {
            }
            safe_handle::safe_handle(HANDLE value, HANDLE invalidValue)
                : _value(value),
                _invalid(invalidValue)
            {
            }
            safe_handle::safe_handle(const safe_handle& rhs)
                : _value(rhs._invalid),
                _invalid(rhs._invalid)
            {
                rhs.Duplicate(*this);
            }
            safe_handle::~safe_handle()
            {
                if(IsValid())
                    Close();
            }
            safe_handle& safe_handle::operator=(const safe_handle& rhs)
            {
                rhs.Duplicate(*this); return *this;
            }
            void safe_handle::Duplicate(safe_handle& other) const
            {
                DuplicateHandle(
                    GetCurrentProcess(), _value,
                    GetCurrentProcess(), &other._value,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS);
            }
            HANDLE safe_handle::Get() const
            {
                return _value;
            }
            void safe_handle::Set(HANDLE value)
            {
                if(IsValid()) Close();
                _value = value;
            }
            void safe_handle::Close()
            {
                CloseHandle(_value);
            }
            bool safe_handle::IsValid() const
            {
                return _value != _invalid;
            }
        }
        safe_process_handle::safe_process_handle()
            : safe_handle(NULL)
        {
        }
        safe_process_handle::safe_process_handle(HANDLE value)
            : safe_handle(value, NULL)
        {
        }
        safe_process_handle::safe_process_handle(const safe_process_handle& rhs)
            : safe_handle(rhs)
        {
        }

        safe_generic_handle::safe_generic_handle()
            : safe_handle(INVALID_HANDLE_VALUE)
        {
        }
        safe_generic_handle::safe_generic_handle(HANDLE value)
            : safe_handle(value, INVALID_HANDLE_VALUE)
        {
        }
        safe_generic_handle::safe_generic_handle(const safe_generic_handle& rhs)
            : safe_handle(rhs)
        {
        }
    }
}