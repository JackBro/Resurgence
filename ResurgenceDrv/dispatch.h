#pragma once

#include "Internal.h"

/// <summary>
///     The drivers I/O dispatcher
/// </summary>
/// <param name="DeviceObject">
///     The device to which the request was sent.
///     A single driver cna have multiple devices
/// </param>
/// <param name="Irp">The I/O Request Packet sent by the I/O Manager</param>
/// <returns></returns>
NTSTATUS RDrvDispatch(
	__in PDEVICE_OBJECT DeviceObject,
	__in PIRP Irp
);
