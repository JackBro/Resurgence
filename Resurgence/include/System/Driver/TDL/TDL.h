#pragma once

#include <Headers.hpp>

#ifdef __cplusplus
extern "C" {
#endif

long __stdcall TDLLoadDriver(
    LPCWSTR lpDriverFullName
);

#ifdef __cplusplus
}
#endif
