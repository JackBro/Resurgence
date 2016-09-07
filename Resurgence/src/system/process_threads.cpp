#include <system/process_threads.hpp>
#include <system/process.hpp>

#include <misc/native.hpp>

namespace resurgence
{
    namespace system
    {
        process_thread::process_thread(process* owner, PSYSTEM_EXTENDED_THREAD_INFORMATION exThread)
            : _process(owner)
        {
            if(_process->get_platform() == platform_x86)
                _startAddress = reinterpret_cast<uintptr_t>(exThread->Win32StartAddress);
            else
                _startAddress = reinterpret_cast<uintptr_t>(exThread->StartAddress);

            _id = reinterpret_cast<uint32_t>(exThread->ClientId.UniqueThread);
        }

        process_threads::process_threads(process* proc)
            : _process(proc)
        {
        }

        std::vector<process_thread> process_threads::get_all_threads()
        {
            std::vector<process_thread> threads;
            native::enumerate_process_threads(_process->get_pid(), [&](PSYSTEM_EXTENDED_THREAD_INFORMATION entry) {
                threads.emplace_back(_process, entry);
                return STATUS_NOT_FOUND;
            });
            return threads;
        }
    }
}