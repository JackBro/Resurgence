#include <Resurgence.hpp>

INITIALIZE_EASYLOGGINGPP

void SetLoggingFormat(const std::string& format)
{
    el::Configurations conf;

    conf.setGlobally(el::ConfigurationType::Format, format);
}