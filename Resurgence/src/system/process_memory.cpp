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
        void process_memory::read_bytes(uint8_t* address, uint8_t* buffer, size_t size)
        {
            auto status = misc::winnt::read_memory(_process->get_handle().get(), address, buffer, size);
            if(!NT_SUCCESS(status))
                throw misc::exception(misc::winnt::get_status_message(status));
        }
        void process_memory::write_bytes(uint8_t* address, uint8_t* buffer, size_t size)
        {

            auto status = misc::winnt::write_memory(_process->get_handle().get(), address, buffer, size);
            if(!NT_SUCCESS(status))
                throw misc::exception(misc::winnt::get_status_message(status));
        }
    }
}