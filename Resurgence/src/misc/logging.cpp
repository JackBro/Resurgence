#include <misc/logging.hpp>

namespace resurgence
{
    namespace misc
    {
        void Logging::Enable()
        {
            el::Configurations default;
            default.setGlobally(el::ConfigurationType::Enabled, "true");
            el::Loggers::reconfigureLogger("default", default);
        }
        void Logging::Disable()
        {
            el::Configurations default;
            default.setGlobally(el::ConfigurationType::Enabled, "false");
            el::Loggers::reconfigureLogger("default", default);
        }
        void Logging::SetOutputMode(LogOutputMode mode, const std::string& fileName /*= ""*/)
        {
            el::Configurations default;
            default.setGlobally(el::ConfigurationType::ToStandardOutput, (mode & LogStdOut) != 0 ? "true" : "false");
            if(mode & LogFile) {
                default.setGlobally(el::ConfigurationType::ToFile, "true");
                default.setGlobally(el::ConfigurationType::Filename, fileName);
            } else {
                default.setGlobally(el::ConfigurationType::ToFile, "false");
            }
            el::Loggers::reconfigureLogger("default", default);
        }
        void Logging::SetFormat(const std::string& format)
        {
            el::Configurations default;
            default.setGlobally(el::ConfigurationType::Format, format);
            el::Loggers::reconfigureLogger("default", default);
        }
    }
}