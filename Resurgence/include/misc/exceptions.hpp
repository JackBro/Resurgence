#pragma once

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
        
            const std::wstring& GetMessage() const
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
            win32_exception()
                : exception(L"A Win32 routine failed.")
            {

            }
            win32_exception(std::wstring routine)
                : exception(std::wstring(L"A Win32 routine failed. ") + routine)
            {

            }
            win32_exception(std::string routine)
                : exception(std::string("A Win32 routine failed. ") + routine)
            {

            }
        };
    }
}
