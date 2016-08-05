#include <misc/logging.hpp>

namespace resurgence
{
    namespace misc
    {
        void logger::enable()
        {
            el::Configurations default;
            default.setGlobally(el::ConfigurationType::Enabled, "true");
            el::Loggers::reconfigureLogger("default", default);
        }
        void logger::disable()
        {
            el::Configurations default;
            default.setGlobally(el::ConfigurationType::Enabled, "false");
            el::Loggers::reconfigureLogger("default", default);
        }
        void logger::set_output(log_output mode, const std::string& fileName /*= ""*/)
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
        void logger::set_format(const std::string& format)
        {
            el::Configurations default;
            default.setGlobally(el::ConfigurationType::Format, format);
            el::Loggers::reconfigureLogger("default", default);
        }
    }
}