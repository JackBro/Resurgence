#pragma once

#include <headers.hpp>

#ifdef __cplusplus
extern "C" {
#endif

    long __stdcall TDLload_driver(
        LPCWSTR lpDriverFullName
    );

#ifdef __cplusplus
}
#endif
