#pragma once

#include <headers.hpp>
#include "pointer.hpp"

namespace resurgence
{
    namespace misc
    {
        class SafeHandle
        {
        public:
            SafeHandle(HANDLE invalidValue);
            SafeHandle(HANDLE value, HANDLE invalidValue);
            SafeHandle(const SafeHandle& rhs);
            virtual ~SafeHandle();

            inline HANDLE  Get() const;
            inline void    Set(HANDLE value);
            inline void    Close();
            inline bool    IsValid() const;

            SafeHandle& operator=(const SafeHandle& rhs);

        protected:
            void Duplicate(SafeHandle& other) const;

            HANDLE _value;
            HANDLE _invalid;
        };

        inline HANDLE SafeHandle::Get() const
        {
            return _value;
        }
        inline void SafeHandle::Set(HANDLE value)
        {
            if(IsValid()) Close();
            _value = value;
        }
        inline void SafeHandle::Close()
        {
            CloseHandle(_value);
        }
        inline bool SafeHandle::IsValid() const
        {
            return _value != _invalid;
        }

        class SafeProcessHandle
            : public SafeHandle
        {
        public:
            SafeProcessHandle();
            SafeProcessHandle(HANDLE value);
            SafeProcessHandle(const SafeProcessHandle& rhs);
            virtual ~SafeProcessHandle() {}
        };

        class SafeGenericHandle
            : public SafeHandle
        {
        public:
            SafeGenericHandle();
            SafeGenericHandle(HANDLE value);
            SafeGenericHandle(const SafeGenericHandle& rhs);
            virtual ~SafeGenericHandle() {}
        };
    }
}