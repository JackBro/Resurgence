#pragma once

#define ELPP_DISABLE_LOGS
#include <easylogging++.h>

namespace resurgence
{
    namespace misc
    {
        enum LogOutputMode
        {
            LogNone,
            LogStdOut,
            LogFile
        };
        class Logging
        {
        public:
            static void Enable();
            static void Disable();
            static void SetOutputMode(LogOutputMode mode, const std::string& fileName = "");
            static void SetFormat(const std::string& format);
        };
    }
}