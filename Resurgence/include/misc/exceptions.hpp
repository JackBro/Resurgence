#pragma once

#include <headers.hpp>
#include <string>
#include <locale>
#include <codecvt>

#ifdef GetMessage
#undef GetMessage
#endif

namespace resurgence
{
    namespace misc
    {
        class exception
        {
        public:
            exception()
                : _message(L"")
            {
            }

            exception(std::wstring msg)
                : _message(std::move(msg))
            {
            }
            exception(std::string msg)
            {
                std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
                _message = converter.from_bytes(msg);
            }
            virtual ~exception()
            {
            }
            virtual const std::wstring& get_message() const
            {
                return _message;
            }

        protected:
            std::wstring _message;
        };

        class file_not_found_exception
            : public exception
        {
        public:
            file_not_found_exception()
                : exception()
            {
            }
            file_not_found_exception(std::wstring msg)
                : exception(msg)
            {
            }
            file_not_found_exception(std::string msg)
                : exception(msg)
            {
            }
        };

        class win32_exception
            : public exception
        {
        public:
            win32_exception(NTSTATUS status)
                : exception(L"A Win32 routine !NT_SUCCESS."), _status(status)
            {

            }
            win32_exception(std::wstring msg, NTSTATUS status)
                : exception(msg), _status(status)
            {

            }
            win32_exception(std::string msg, NTSTATUS status)
                : exception(msg), _status(status)
            {

            }

            NTSTATUS get_status() const
            {
                return _status;
            }

        protected:
            NTSTATUS _status;
        };
    }
}
