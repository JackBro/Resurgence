#include "routines.h"
#include "utils.h"
#include "internal.h"

#pragma alloc_text(PAGE, RDrvQueryOSVersion)

NTSTATUS RDrvQueryOSVersion(
    __out PVERSION_INFO Version
)
{
    NTSTATUS                status;
    RTL_OSVERSIONINFOEXW    versionInfo;

    if(!Version) return STATUS_INVALID_PARAMETER;

    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    status = RtlGetVersion((PRTL_OSVERSIONINFOW)&versionInfo);
    if(NT_SUCCESS(status)) {
        Version->BuildNumber = versionInfo.dwBuildNumber;
        Version->MajorVersion = versionInfo.dwMajorVersion;
        Version->MinorVersion = versionInfo.dwMinorVersion;
        Version->ServicePackMajor = versionInfo.wServicePackMajor;
        Version->ServicePackMinor = versionInfo.wServicePackMinor;
        Version->VersionLong =
            (versionInfo.dwMajorVersion << 24) |
            (versionInfo.dwMinorVersion << 16) |
            (versionInfo.wServicePackMajor << 8) |
            versionInfo.wServicePackMinor;
    } else {
        PERROR("RtlGetVersion", status);
    }
    return status;
}