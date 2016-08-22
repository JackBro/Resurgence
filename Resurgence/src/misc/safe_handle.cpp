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
				rhs.duplicate(*this);
			}
			safe_handle::~safe_handle()
			{
				if(is_valid())
					close();
			}
			safe_handle& safe_handle::operator=(const safe_handle& rhs)
			{
				rhs.duplicate(*this); return *this;
			}
			void safe_handle::duplicate(safe_handle& other) const
			{
				DuplicateHandle(
					GetCurrentProcess(), _value,
					GetCurrentProcess(), &other._value,
					0,
					FALSE,
					DUPLICATE_SAME_ACCESS);
			}
			HANDLE safe_handle::get() const
			{
				return _value;
			}
			void safe_handle::set(HANDLE value)
			{
				if(is_valid()) close();
				_value = value;
			}
			void safe_handle::close()
			{
				CloseHandle(_value);
			}
			bool safe_handle::is_valid() const
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