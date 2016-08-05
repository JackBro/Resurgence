#pragma once

#define ELPP_DISABLE_LOGS
#include <easylogging++.h>

namespace resurgence
{
    namespace misc
    {
        enum log_output
        {
            LogNone,
            LogStdOut,
            LogFile
        };
        class logger
        {
        public:
            static void enable();
            static void disable();
            static void set_output(log_output mode, const std::string& fileName = "");
            static void set_format(const std::string& format);
        };
    }
}