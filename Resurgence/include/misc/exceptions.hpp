#pragma once

#include <string>

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
        };
    }
}
