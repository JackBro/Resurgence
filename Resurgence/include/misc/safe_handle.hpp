#pragma once

#include <headers.hpp>

namespace resurgence
{
    namespace misc
    {
        namespace detail
        {
            class safe_handle
            {
            public:
                safe_handle(HANDLE invalidValue);
                safe_handle(HANDLE value, HANDLE invalidValue);
                safe_handle(const safe_handle& rhs);
                virtual ~safe_handle();

                HANDLE  Get() const;
                void    Set(HANDLE value);
                void    Close();
                bool    IsValid() const;

                safe_handle& operator=(const safe_handle& rhs);

            protected:
                void Duplicate(safe_handle& other) const;

                HANDLE _value;
                HANDLE _invalid;
            };
        }

        class safe_process_handle
            : public detail::safe_handle
        {
        public:
            safe_process_handle();
            safe_process_handle(HANDLE value);
            safe_process_handle(const safe_process_handle& rhs);
            virtual ~safe_process_handle() {}
        };

        class safe_generic_handle
            : public detail::safe_handle
        {
        public:
            safe_generic_handle();
            safe_generic_handle(HANDLE value);
            safe_generic_handle(const safe_generic_handle& rhs);
            virtual ~safe_generic_handle() {}
        };
    }
}