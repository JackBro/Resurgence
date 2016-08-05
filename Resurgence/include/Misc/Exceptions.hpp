#pragma once

#include <string>

#ifdef GetMessage
#undef GetMessage
#endif

namespace resurgence
{
    namespace misc
    {
        class Exception
        {
        public:
            Exception()
                : _message(L"")
            {
                SetType(L"Exception");
            }

            Exception(std::wstring msg)
                : _message(std::move(msg))
            {
                SetType(L"Exception");
            }

            virtual const std::wstring& GetType() const
            {
                return _type;
            }

            const std::wstring& GetMessage() const
            {
                return _message;
            }
        protected:
            void SetType(std::wstring str)
            {
                _type = std::move(str);
            }

            std::wstring _message;
            std::wstring _type;
        };

        class FileNotFoundException
            : public Exception
        {
        public:
            FileNotFoundException()
                : Exception()
            {
                SetType(L"FileNotFoundException");
            }

            FileNotFoundException(std::wstring msg)
                : Exception(msg)
            {
                SetType(L"FileNotFoundException");
            }
        };
    }
}
