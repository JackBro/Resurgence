#include <system/process_threads.hpp>
#include <system/process.hpp>

#include <misc/winnt.hpp>

namespace resurgence
{
    namespace system
    {
        process_thread::process_thread(process* owner, PSYSTEM_EXTENDED_THREAD_INFORMATION exThread)
            : _process(owner)
        {
        }

        process_threads::process_threads(process* proc)
            : _process(proc)
        {
        }

        std::vector<process_thread> process_threads::get_all_threads()
        {
            std::vector<process_thread> threads;
            misc::winnt::enumerate_processes([&](PSYSTEM_PROCESS_INFORMATION entry) {
                if(reinterpret_cast<uint32_t>(entry->UniqueProcessId) == _process->get_pid()) {
                    for(auto i = 0ul; i < entry->ThreadCount; i++) {
                        PSYSTEM_EXTENDED_THREAD_INFORMATION thread_info = (PSYSTEM_EXTENDED_THREAD_INFORMATION)&entry->Threads[i];
                        threads.emplace_back(_process, thread_info);
                    }
                    return STATUS_SUCCESS;
                }
                return STATUS_NOT_FOUND;
            });
            return threads;
        }
    }
}