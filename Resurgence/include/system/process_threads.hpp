#pragma once

#include <headers.hpp>
#include <vector>

namespace resurgence
{
    namespace system
    {
        class process;

        class process_thread
        {
        public:
            process_thread(process* owner, PSYSTEM_EXTENDED_THREAD_INFORMATION exThread);

        private:
            process* _process;
        };

        class process_threads
        {
        public:
            process_threads(process* proc);

            std::vector<process_thread> get_all_threads();

        private:
            process* _process;
        };
    }
}