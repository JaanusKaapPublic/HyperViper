#include"DevIoCtrlHandler.h"
#include"Hypercall.h"
#include"VMbusPipe.h"

NTSTATUS DevIoCtrlHandler::hypercallSend(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(HV_X64_HYPERCALL_INPUT))
		return STATUS_NDIS_INVALID_LENGTH;
	if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HV_X64_HYPERCALL_OUTPUT))
		return STATUS_BUFFER_OVERFLOW;
	if (((PHV_X64_HYPERCALL_INPUT)Irp->AssociatedIrp.SystemBuffer)->IsFast && pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != sizeof(HV_X64_HYPERCALL_INPUT) + 16)
		return STATUS_NDIS_INVALID_LENGTH;
	
	NTSTATUS status = Hypercall::hypercall(
		*(PHV_X64_HYPERCALL_INPUT)Irp->AssociatedIrp.SystemBuffer,
		(PUINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(HV_X64_HYPERCALL_INPUT),
		pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength - sizeof(HV_X64_HYPERCALL_INPUT), 
		(PUINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(HV_X64_HYPERCALL_OUTPUT),
		pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength - sizeof(HV_X64_HYPERCALL_OUTPUT), 
		(PHV_X64_HYPERCALL_OUTPUT)Irp->AssociatedIrp.SystemBuffer
	);

	if (status == STATUS_SUCCESS)
		*pdwDataWritten = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	return status;
}

NTSTATUS DevIoCtrlHandler::hypercallHooking(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HYPERCALLS_HOOK:
		return Hypercall::hook();
	case IOCTL_HYPERCALLS_UNHOOK:
		return Hypercall::unhook();
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}	
}


NTSTATUS DevIoCtrlHandler::hypercallLogging(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HYPERCALLS_START_RECORD:
	{
		if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < 10 || pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength > 500)
			return STATUS_NDIS_INVALID_LENGTH;
		UNICODE_STRING uniName;
		ANSI_STRING AS;
		char name[512];
		memcpy(name, (char*)Irp->AssociatedIrp.SystemBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength);
		name[pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength] = 0x00;
		RtlInitAnsiString(&AS, name);
		RtlAnsiStringToUnicodeString(&uniName, &AS, TRUE);
		return Hypercall::logToFile(&uniName);
		break;
	}
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	return STATUS_SUCCESS;
}


NTSTATUS DevIoCtrlHandler::hypercallSetGeneralConf(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < 1)
		return STATUS_NDIS_INVALID_LENGTH;

	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HYPERCALLS_GENERAL_DISGARD_SLOW:
	case IOCTL_HYPERCALLS_GENERAL_DISGARD_FAST:
	case IOCTL_HYPERCALLS_GENERAL_DBG_MSG:
		HV_HOOKING_CONF conf;
		Hypercall::getConf(&conf);
		if (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode == IOCTL_HYPERCALLS_GENERAL_DISGARD_SLOW)
			conf.hookingDiscardAllSlow = *((UINT8*)Irp->AssociatedIrp.SystemBuffer);
		else if (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode == IOCTL_HYPERCALLS_GENERAL_DISGARD_FAST)
			conf.hookingDiscardAllFast = *((UINT8*)Irp->AssociatedIrp.SystemBuffer);
		else if (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode == IOCTL_HYPERCALLS_GENERAL_DBG_MSG)
			conf.hookingDbgPrintAll = *((UINT8*)Irp->AssociatedIrp.SystemBuffer);
		Hypercall::setConf(&conf);
		break;
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DevIoCtrlHandler::hypercallSetSingleConf(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < 8)
		return STATUS_NDIS_INVALID_LENGTH;

	UINT32 start = *(((UINT32*)Irp->AssociatedIrp.SystemBuffer));
	UINT32 end = HYPERCALL_LAST_NR, secondValue = *(((UINT32*)Irp->AssociatedIrp.SystemBuffer) + 1);

	if (start > HYPERCALL_LAST_NR)
		return STATUS_INVALID_DEVICE_REQUEST;
	if (!start)
		start = 1;
	else
		end = start;

	HV_HOOKING_CONF conf;
	Hypercall::getConf(&conf);
	for (UINT32 callNr = start; callNr <= end; callNr++)
	{
		switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_HYPERCALLS_SINGLE_CLEAR:
			conf.hcallConfs[callNr].dbgPrint = 0;
			conf.hcallConfs[callNr].breakpoint = 0;
			conf.hcallConfs[callNr].log = 0;
			conf.hcallConfs[callNr].fuzz = 0;
			break;
		case IOCTL_HYPERCALLS_SINGLE_DBG_MSG:
			conf.hcallConfs[callNr].dbgPrint = (secondValue ? 1 : 0);
			break;
		case IOCTL_HYPERCALLS_SINGLE_BREAKPOINT:
			conf.hcallConfs[callNr].breakpoint = (secondValue ? 1 : 0);
			break;
		case IOCTL_HYPERCALLS_SINGLE_LOG:
			conf.hcallConfs[callNr].log = secondValue;
			break;
		case IOCTL_HYPERCALLS_SINGLE_FUZZ:
			conf.hcallConfs[callNr].fuzz = secondValue;
			break;
		default:
			return STATUS_INVALID_DEVICE_REQUEST;
		}
	}
	Hypercall::setConf(&conf);
	return STATUS_SUCCESS;
}

NTSTATUS DevIoCtrlHandler::hypercallGetData(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HYPERCALLS_GET_STATS:
		if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HYPERCALL_STATUSES))
			return STATUS_NDIS_INVALID_LENGTH;
		Hypercall::getStats((PHYPERCALL_STATUSES)Irp->AssociatedIrp.SystemBuffer);
		*pdwDataWritten = sizeof(HYPERCALL_STATUSES);
		break;
	case IOCTL_HYPERCALLS_GET_CONF:
		if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HV_HOOKING_CONF))
			return STATUS_NDIS_INVALID_LENGTH;
		Hypercall::getConf((PHV_HOOKING_CONF)Irp->AssociatedIrp.SystemBuffer);
		*pdwDataWritten = sizeof(HV_HOOKING_CONF);
		break;
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DevIoCtrlHandler::hypercallFuzz(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(HV_X64_HYPERCALL_INPUT))
		return STATUS_NDIS_INVALID_LENGTH;
	if (((PHV_X64_HYPERCALL_INPUT)Irp->AssociatedIrp.SystemBuffer)->IsFast && pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != sizeof(HV_X64_HYPERCALL_INPUT) + 16)
		return STATUS_NDIS_INVALID_LENGTH;

	NTSTATUS status = Hypercall::fuzzByAdd(
		*(PHV_X64_HYPERCALL_INPUT)Irp->AssociatedIrp.SystemBuffer,
		(PUINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(HV_X64_HYPERCALL_INPUT),
		pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength - sizeof(HV_X64_HYPERCALL_INPUT)
	);

	if (status == STATUS_SUCCESS)
	{
		NTSTATUS status = Hypercall::fuzzBySpecialValues(
			*(PHV_X64_HYPERCALL_INPUT)Irp->AssociatedIrp.SystemBuffer,
			(PUINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(HV_X64_HYPERCALL_INPUT),
			pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength - sizeof(HV_X64_HYPERCALL_INPUT)
		);
	}

	*pdwDataWritten = 0;
	return status;
}

NTSTATUS DevIoCtrlHandler::msrRead(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	NTSTATUS status = STATUS_SUCCESS;
	UINT32* buffer = (UINT32*)Irp->AssociatedIrp.SystemBuffer;

	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != 4 || pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength != 8)
		return STATUS_NDIS_INVALID_LENGTH;

	status = MSR::read(buffer[0], (UINT64*)buffer);
	if (status == STATUS_SUCCESS)
		* pdwDataWritten = 8;
	return status;
}

NTSTATUS DevIoCtrlHandler::msrWrite(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	UINT32* buffer = (UINT32*)Irp->AssociatedIrp.SystemBuffer;
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != 12)
		return STATUS_NDIS_INVALID_LENGTH;
	return MSR::write(buffer[0], *(PUINT64) & (buffer[1]));
}

NTSTATUS DevIoCtrlHandler::channelHooking(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_CHANNELS_HOOK:
	{
		if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(GUID))
			return STATUS_NDIS_INVALID_LENGTH;

		PGUID guid = (PGUID)Irp->AssociatedIrp.SystemBuffer;
		if (!VMbusChannels::hookChannel(*guid))
			return STATUS_INVALID_MEMBER;
		break;
	}
	case IOCTL_CHANNELS_UNHOOK:
		VMbusChannels::unhookChannel();
		break;
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DevIoCtrlHandler::channelGetData(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_CHANNELS_LIST:
	{
		if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VMBUS_CHANNEL) * VMbusChannels::getChannelsCount())
			return STATUS_NDIS_INVALID_LENGTH;

		UINT32 count = 0;
		PVMBUS_CHANNEL channels = VMbusChannels::getAllChannels(&count);
		if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VMBUS_CHANNEL) * count)
		{
			ExFreePool(channels);
			return STATUS_NDIS_INVALID_LENGTH;
		}

		if (count && channels)
			memcpy(Irp->AssociatedIrp.SystemBuffer, channels, sizeof(VMBUS_CHANNEL) * count);
		*pdwDataWritten = sizeof(VMBUS_CHANNEL) * count;
		ExFreePool(channels);
		break;
	}
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DevIoCtrlHandler::channelLogging(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_CHANNELS_START_RECORD:
	{
		if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < 4 || pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength > 500)
			return STATUS_NDIS_INVALID_LENGTH;

		UNICODE_STRING     uniName;
		ANSI_STRING AS;
		char name[512];
		memcpy(name, (char*)Irp->AssociatedIrp.SystemBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength);
		name[pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength] = 0x00;
		RtlInitAnsiString(&AS, name);
		RtlAnsiStringToUnicodeString(&uniName, &AS, TRUE);
		return VMbusChannels::logToFile(&uniName);
	}
	case IOCTL_CHANNELS_STOP_RECORD:
		return VMbusChannels::stopLog();
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DevIoCtrlHandler::channelSend(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMBUS_CHANNEL_PACKET_SEND))
		return STATUS_NDIS_INVALID_LENGTH;
	PVMBUS_CHANNEL_PACKET_SEND packet = (PVMBUS_CHANNEL_PACKET_SEND)Irp->AssociatedIrp.SystemBuffer;
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMBUS_CHANNEL_PACKET_SEND) + packet->sizeOfData + packet->sizeOfMDL)
		return STATUS_NDIS_INVALID_LENGTH;

	return VMbusChannels::sendPacket(
		packet->id,
		(PINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(VMBUS_CHANNEL_PACKET_SEND),
		packet->sizeOfData,
		(PINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(VMBUS_CHANNEL_PACKET_SEND) + packet->sizeOfData,
		packet->sizeOfMDL);
}

NTSTATUS DevIoCtrlHandler::channelFuzz(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMBUS_CHANNEL_PACKET_FUZZ))
		return STATUS_NDIS_INVALID_LENGTH;
	PVMBUS_CHANNEL_PACKET_FUZZ packet = (PVMBUS_CHANNEL_PACKET_FUZZ)Irp->AssociatedIrp.SystemBuffer;
	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMBUS_CHANNEL_PACKET_FUZZ) + packet->sizeOfData + packet->sizeOfMDL)
		return STATUS_NDIS_INVALID_LENGTH;

	return VMbusChannels::fuzzPacket(
		packet->id,
		(PINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(VMBUS_CHANNEL_PACKET_FUZZ),
		packet->sizeOfData,
		(PINT8)Irp->AssociatedIrp.SystemBuffer + sizeof(VMBUS_CHANNEL_PACKET_FUZZ) + packet->sizeOfData,
		packet->sizeOfMDL,
		&(packet->conf));
}

NTSTATUS DevIoCtrlHandler::pipeHooking(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_PIPE_HOOK:
	{
		if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < sizeof(GUID))
			return STATUS_NDIS_INVALID_LENGTH;

		PGUID guid = (PGUID)Irp->AssociatedIrp.SystemBuffer;
		return VMbusPipe::hook(guid);
	}
	case IOCTL_PIPE_UNHOOK:
		return VMbusPipe::unhook();
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
}

NTSTATUS DevIoCtrlHandler::pipeLogging(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_PIPE_START_RECORD:
	{
		if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength < 4 || pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength > 500)
			return STATUS_NDIS_INVALID_LENGTH;

		UNICODE_STRING     uniName;
		ANSI_STRING AS;
		char name[512];
		memcpy(name, (char*)Irp->AssociatedIrp.SystemBuffer, pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength);
		name[pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength] = 0x00;
		RtlInitAnsiString(&AS, name);
		RtlAnsiStringToUnicodeString(&uniName, &AS, TRUE);
		return VMbusPipe::logToFile(&uniName);
	}
	case IOCTL_PIPE_STOP_RECORD:
		return VMbusPipe::stopLog();
	default:
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DevIoCtrlHandler::pmioRead(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;

	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != 2)
		return STATUS_NDIS_INVALID_LENGTH;		
	if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength != 1 && pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength != 2 && pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength != 4)
		return STATUS_NDIS_INVALID_LENGTH;

	status = PMIO::read(*(PUINT16)buffer, (PUINT64)buffer, (UINT8)pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength);
	if (status == STATUS_SUCCESS)
		* pdwDataWritten = 8;
	return status;
}

NTSTATUS DevIoCtrlHandler::pmioWrite(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten)
{
	PUINT8 buffer = (PUINT8)Irp->AssociatedIrp.SystemBuffer;

	if (pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != 3 && pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != 4 && pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength != 6)
		return STATUS_NDIS_INVALID_LENGTH;
	return PMIO::write(*(PUINT16)buffer, *(PUINT64)(buffer+2), (UINT8)pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength - 2);
}