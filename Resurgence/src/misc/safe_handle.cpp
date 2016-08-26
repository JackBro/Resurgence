#include <misc/safe_handle.hpp>
#include <misc/winnt.hpp>

namespace resurgence
{
    namespace misc
    {
        namespace detail
        {
            safe_handle::safe_handle(HANDLE invalidValue)
                : _value(invalidValue),
                _invalid(invalidValue),
                _grantedBits(0)
            {
            }
            safe_handle::safe_handle(HANDLE value, HANDLE invalidValue)
                : _value(value),
                _invalid(invalidValue)
            {
                update_access();
            }
            safe_handle::safe_handle(const safe_handle& rhs)
                : _value(rhs._invalid),
                _invalid(rhs._invalid)
            {
                rhs.duplicate(*this);
                update_access();
            }
            safe_handle::~safe_handle()
            {
                if(is_valid())
                    close();
            }
            safe_handle& safe_handle::operator=(const safe_handle& rhs)
            {
                rhs.duplicate(*this);
                update_access();
                return *this;
            }
            void safe_handle::duplicate(safe_handle& other) const
            {
                DuplicateHandle(
                    GetCurrentProcess(), _value,
                    GetCurrentProcess(), &other._value,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS);
                return;
            }
            HANDLE safe_handle::get() const
            {
                return _value;
            }
            void safe_handle::set(HANDLE value)
            {
                if(is_valid()) close();
                _value = value;
                update_access();
            }
            void safe_handle::close()
            {
                CloseHandle(_value);
            }
            bool safe_handle::is_valid() const
            {
                return _value != _invalid;
            }
            uint32_t safe_handle::access_mask() const
            {
                return _grantedBits;
            }
            void safe_handle::update_access()
            {
                _grantedBits = 0;

                auto basic_info = (POBJECT_BASIC_INFORMATION)winnt::query_object_information(_value, ObjectBasicInformation);

                if(basic_info) {
                    _grantedBits = basic_info->GrantedAccess;
                    free_local_buffer(basic_info);
                }
            }
            bool safe_handle::has_access(uint32_t access) const
            {
                return (_grantedBits & access) == access;
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