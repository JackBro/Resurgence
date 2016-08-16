#include <system/process_memory.hpp>
#include <system/process.hpp>
#include <misc/exceptions.hpp>
#include <misc/winnt.hpp>

namespace resurgence
{
    namespace system
    {
        process_memory::process_memory(process* proc)
            : _process(proc)
        {
        }
        process_memory::process_memory()
            : _process(nullptr)
        {

        }
        ntstatus_code process_memory::read_bytes(const uint8_t* address, uint8_t* buffer, size_t size)
        {
            return misc::winnt::read_memory(_process->get_handle().get(), (void*)address, buffer, size);
        }
        ntstatus_code process_memory::write_bytes(const uint8_t* address, uint8_t* buffer, size_t size)
        {
            return misc::winnt::write_memory(_process->get_handle().get(), (void*)address, buffer, size);
        }
    }
}