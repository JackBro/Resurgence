#pragma once

#include <headers.hpp>

namespace resurgence
{
    namespace Internal
    {
        extern uint32_t g_pVulnerableDriverData[17072];
        extern uint8_t g_pLoaderCode[463];

    #define SHELLCODE_VULNERABLE_DRIVER_SIZE (17072 * 4)
    #define SHELLCODE_VULNERABLE_DRIVER ((PBYTE)resurgence::Internal::g_pVulnerableDriverData)
    #define SHELLCODE_LOADER ((PBYTE)resurgence::Internal::g_pLoaderCode)
    #define SHELLCODE_LOADER_SIZE (463)

    #define BOOTSTRAP_IMAGE_OFFSET 0x200
    }
}