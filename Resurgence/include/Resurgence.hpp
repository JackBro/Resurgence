#pragma once

#define DEFAULT_DRIVER_WIN7 TEXT(".\\ResurgenceDrvWin10.sys")
#define DEFAULT_DRIVER_WIN8 TEXT(".\\ResurgenceDrvWin10.sys")
#define DEFAULT_DRIVER_WIN81 TEXT(".\\ResurgenceDrvWin10.sys")
#define DEFAULT_DRIVER_WIN10 TEXT(".\\ResurgenceDrvWin10.sys")

#include <misc/exceptions.hpp>
#include <misc/pointer.hpp>
#include <misc/winnt.hpp>
#include <misc/safe_handle.hpp>
#include <misc/logging.hpp>

#include <system/driver/driver.hpp>

