#pragma once

#include <Headers.hpp>
#include <functional>

#ifdef CopyFile
#undef CopyFile
#endif

typedef struct _OBJECT_DIRECTORY_INFORMATION* POBJECT_DIRECTORY_INFORMATION;

typedef std::function<NTSTATUS(POBJECT_DIRECTORY_INFORMATION)> ENUM_OBJECTS_CALLBACK;
typedef std::function<NTSTATUS(PSYSTEM_PROCESSES_INFORMATION)> ENUM_PROCESSES_CALLBACK;
typedef std::function<NTSTATUS(PRTL_PROCESS_MODULE_INFORMATION)> ENUM_MODULES_CALLBACK;

namespace Resurgence
{
    namespace Misc
    {
        class NtHelpers
        {
        public:

            /// <summary>
            ///  Gets a NTSTATUS error message.
            /// </summary>
            /// <param name="status">    [In] The status. </param>
            /// <param name="szMessage"> [In, Out] The message buffer. </param>
            /// <param name="uSize">     [In] The buffer size. </param>
            /// <returns>
            ///  The message string.
            /// </returns>
            static std::wstring GetSystemErrorMessage(
                IN NTSTATUS status);

            //-----------------------------------------------
            // System routines
            //-----------------------------------------------
            
            /// <summary>
            ///  Enumerates system modules (drivers).
            /// </summary>
            /// <param name="fnCallback"> [In] The enumeration callback. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS EnumSystemModules(
                IN ENUM_MODULES_CALLBACK fnCallback);

            /// <summary>
            ///  Enumerates system objects.
            /// </summary>
            /// <param name="szRootDir">  [In] The root directory. </param>
            /// <param name="fnCallback"> [In] The enumeration callback. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS EnumSystemObjects(
                IN LPCWSTR szRootDir,
                IN ENUM_OBJECTS_CALLBACK fnCallback);

            /// <summary>
            ///  Enumerates system processes.
            /// </summary>
            /// <param name="fnCallback"> [In] The enumeration callback. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS EnumSystemProcesses(
                IN ENUM_PROCESSES_CALLBACK fnCallback);

            /// <summary>
            ///  Queries if a given system object exists.
            /// </summary>
            /// <param name="szRootDir">    [In] The root dir. </param>
            /// <param name="szObjectName"> [In] Name of the object. </param>
            /// <param name="bFound">       [Out, Optional] Was it found. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS SystemObjectExists(
                IN LPCWSTR szRootDir,
                IN LPCWSTR szObjectName,
                OUT PBOOL bFound = NULL);

            /// <summary>
            ///  Gets a system module information.
            /// </summary>
            /// <param name="szModuleName"> [In] Name of the module. </param>
            /// <param name="pInformation"> [Out] The information. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS GetSystemModuleInfo(
                IN LPCSTR szModuleName,
                OUT PRTL_PROCESS_MODULE_INFORMATION pInformation);

            //-----------------------------------------------
            // File routines
            //-----------------------------------------------
            
            /// <summary>
            ///  Writes a buffer to file.
            /// </summary>
            /// <param name="szFilePath"> [In] Full pathname of the file. </param>
            /// <param name="lpBuffer">   [In] The buffer. </param>
            /// <param name="nSize">      [In] The size. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS WriteBufferToFile(
                IN LPCWSTR  szFilePath, 
                IN LPVOID   lpBuffer, 
                IN DWORD    nSize);

            /// <summary>
            ///  Copies a file.
            /// </summary>
            /// <param name="szOldPath"> [In] Full pathname of the old file. </param>
            /// <param name="szNewPath"> [In] Full pathname of the new file. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS CopyFile(
                IN LPCWSTR szOldPath, 
                IN LPCWSTR szNewPath);

            /// <summary>
            ///  Gets full path of a file. 
            /// </summary>
            /// <param name="szPath">     [In] Pathname of the file. </param>
            /// <param name="szFullPath"> [Out] Full pathname of the full file. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS GetFullPath(
                IN LPCWSTR szPath,
                OUT LPWSTR szFullPath);


            //-----------------------------------------------
            // Driver related routines
            //-----------------------------------------------
            
            /// <summary>
            ///  Adds a service to the SCM database.
            /// </summary>
            /// <param name="hSCManager">   [In] Handle to the Service Control Manager. </param>
            /// <param name="szDriverName"> [In] Name of the driver. </param>
            /// <param name="szExePath">    [In] Full pathname of the driver's executable file. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS CreateDriverService(
                IN SC_HANDLE hSCManager, 
                IN LPCWSTR szDriverName,
                IN LPCWSTR szExePath);

            /// <summary>
            ///  Starts a driver.
            /// </summary>
            /// <param name="hSCManager">   [In] Handle to the Service Control Manager. </param>
            /// <param name="szDriverName"> [In] Name of the driver. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS StartDriver(
                IN SC_HANDLE hSCManager, 
                IN LPCWSTR szDriverName);

            /// <summary>
            ///  Stops a driver.
            /// </summary>
            /// <param name="hSCManager">   [In] Handle to the Service Control Manager. </param>
            /// <param name="szDriverName"> [In] Name of the driver. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS StopDriver(
                IN SC_HANDLE hSCManager, 
                IN LPCWSTR szDriverName);

            /// <summary>
            ///  Opens a handle to a driver's device
            /// </summary>
            /// <param name="szDriverName"> [In]  Name of the driver. </param>
            /// <param name="phDevice">     [Out] Pointer to store the handle. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS GetDeviceHandle(
                IN LPCWSTR szDriverName, 
                OUT PHANDLE phDevice);

            /// <summary>
            ///  Deletes the driver service from the database.
            /// </summary>
            /// <param name="hSCManager">   Handle to the Service Control Manager. </param>
            /// <param name="szDriverName"> Name of the driver. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS DeleteDriverService(
                IN SC_HANDLE hSCManager, 
                IN LPCWSTR szDriverName);

            /// <summary>
            ///  Wrapper for driver loading. Calls CreateDriverService and StartDriver.
            /// </summary>
            /// <param name="szDriverName"> [In] The driver name. </param>
            /// <param name="szPath">       [In] Full pathname of the file. </param>
            /// <param name="phDevice">     [Out] Handle to the device. </param>
            /// <returns>
            ///  The device driver.
            /// </returns>
            static NTSTATUS LoadDriver(
                IN LPCWSTR szDriverName, 
                IN LPCWSTR szPath,
                OUT PHANDLE phDevice);

            /// <summary>
            ///  Unload driver.
            /// </summary>
            /// <param name="szDriverName"> [In] The driver name. </param>
            /// <returns>
            ///  The status code.
            /// </returns>
            static NTSTATUS UnloadDriver(
                IN LPCWSTR szDriverName);
        };
    }
}
