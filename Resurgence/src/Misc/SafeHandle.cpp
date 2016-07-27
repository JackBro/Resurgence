#include <Misc/SafeHandle.hpp>

namespace Resurgence
{
    namespace Misc
    {
        SafeHandle::SafeHandle(HANDLE invalidValue)
            : _value(invalidValue),
            _invalid(invalidValue)
        {
        }
        SafeHandle::SafeHandle(HANDLE value, HANDLE invalidValue)
            : _value(value),
            _invalid(invalidValue)
        {
        }
        SafeHandle::SafeHandle(const SafeHandle& rhs)
            : _value(rhs._invalid),
            _invalid(rhs._invalid)
        {
            rhs.Duplicate(*this);
        }
        SafeHandle::~SafeHandle()
        {
            if(IsValid())
                Close();
        }
        SafeHandle& SafeHandle::operator=(const SafeHandle& rhs)
        {
            rhs.Duplicate(*this); return *this;
        }
        void SafeHandle::Duplicate(SafeHandle& other) const
        {
            DuplicateHandle(
                GetCurrentProcess(), _value,
                GetCurrentProcess(), &other._value,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS);
        }

        SafeProcessHandle::SafeProcessHandle()
            : SafeHandle(NULL)
        {
        }
        SafeProcessHandle::SafeProcessHandle(HANDLE value)
            : SafeHandle(value, NULL)
        {
        }
        SafeProcessHandle::SafeProcessHandle(const SafeProcessHandle& rhs)
            : SafeHandle(rhs)
        {
        }

        SafeGenericHandle::SafeGenericHandle()
            : SafeHandle(INVALID_HANDLE_VALUE)
        {
        }
        SafeGenericHandle::SafeGenericHandle(HANDLE value)
            : SafeHandle(value, INVALID_HANDLE_VALUE)
        {
        }
        SafeGenericHandle::SafeGenericHandle(const SafeGenericHandle& rhs)
            : SafeHandle(rhs)
        {
        }
    }
}