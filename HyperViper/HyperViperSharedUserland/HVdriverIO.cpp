#include "HVdriverIO.h"
#include <stdio.h>

bool HVdriverIO::init()
{
	handle = CreateFile(L"\\\\.\\HyperViper", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	return (handle != INVALID_HANDLE_VALUE);
}

bool HVdriverIO::devIOctrl(DWORD code, PVOID inBuffer, DWORD inBufferSize, PVOID outBuffer, DWORD* outBufferSize)
{
	bool result = false;
	DWORD recv, outBufferSizeVal = 0;
	if (outBufferSize)
		outBufferSizeVal = *outBufferSize;

	if (DeviceIoControl(handle, code, inBuffer, inBufferSize, outBuffer, outBufferSizeVal, &recv, NULL))
	{
		result = true;
		if (outBufferSize)
			* outBufferSize = recv;
	}
	return result;
}

bool HVdriverIO::hypercallsCall(PHV_X64_HYPERCALL_INPUT callInfo, PVOID inBuffer, DWORD inBufferSize, PHV_X64_HYPERCALL_OUTPUT callResult, PVOID outBuffer, DWORD outBufferSize)
{
	bool result = false;
	outBufferSize += sizeof(HV_X64_HYPERCALL_OUTPUT);
	BYTE* bufIn = new BYTE[inBufferSize + sizeof(HV_X64_HYPERCALL_INPUT)];
	BYTE* bufOut = new BYTE[outBufferSize];

	memcpy(bufIn, callInfo, sizeof(HV_X64_HYPERCALL_INPUT));
	memcpy(bufIn + sizeof(HV_X64_HYPERCALL_INPUT), inBuffer, inBufferSize);

	if (devIOctrl(IOCTL_HYPERCALLS_CALL, bufIn, inBufferSize + sizeof(HV_X64_HYPERCALL_INPUT), bufOut, &outBufferSize))
	{
		result = true;
		memcpy(callResult, bufOut, sizeof(HV_X64_HYPERCALL_OUTPUT));
		memcpy(outBuffer, bufOut + sizeof(HV_X64_HYPERCALL_OUTPUT), outBufferSize - sizeof(HV_X64_HYPERCALL_OUTPUT));
	}
	delete bufIn;
	delete bufOut;
	return result;
}

bool HVdriverIO::hypercallsHook(void)
{
	return devIOctrl(IOCTL_HYPERCALLS_HOOK, NULL, 0, NULL, NULL);
}

bool HVdriverIO::hypercallsUnhook(void)
{
	return devIOctrl(IOCTL_HYPERCALLS_UNHOOK, NULL, 0, NULL, NULL);
}

bool HVdriverIO::hypercallsGeneralDiscardSlow(BYTE value)
{
	return devIOctrl(IOCTL_HYPERCALLS_GENERAL_DISGARD_SLOW, &value, 1, NULL, NULL);
}

bool HVdriverIO::hypercallsGeneralDiscardFast(BYTE value)
{
	return devIOctrl(IOCTL_HYPERCALLS_GENERAL_DISGARD_FAST, &value, 1, NULL, NULL);
}

bool HVdriverIO::hypercallsGeneralDbgMsg(BYTE value)
{
	return devIOctrl(IOCTL_HYPERCALLS_GENERAL_DBG_MSG, &value, 1, NULL, NULL);
}

bool HVdriverIO::hypercallsSingleDbgMsg(DWORD callNr, DWORD value)
{
	DWORD buffer[2];
	buffer[0] = callNr;
	buffer[1] = value;
	return devIOctrl(IOCTL_HYPERCALLS_SINGLE_DBG_MSG, buffer, 8, NULL, NULL);
}

bool HVdriverIO::hypercallsSingleBreak(DWORD callNr, DWORD value)
{
	DWORD buffer[2];
	buffer[0] = callNr;
	buffer[1] = value;
	return devIOctrl(IOCTL_HYPERCALLS_SINGLE_BREAKPOINT, buffer, 8, NULL, NULL);
}

bool HVdriverIO::hypercallsSingleLog(DWORD callNr, DWORD count)
{
	DWORD buffer[2];
	buffer[0] = callNr;
	buffer[1] = count;
	return devIOctrl(IOCTL_HYPERCALLS_SINGLE_LOG, buffer, 8, NULL, NULL);
}

bool HVdriverIO::hypercallsSingleFuzz(DWORD callNr, DWORD count)
{
	DWORD buffer[2];
	buffer[0] = callNr;
	buffer[1] = count;
	return devIOctrl(IOCTL_HYPERCALLS_SINGLE_FUZZ, buffer, 8, NULL, NULL);
}

bool HVdriverIO::hypercallsStartRecord(char* filename)
{
	char* buffer = new char[strlen(filename) + 13];
	memcpy(buffer, "\\DosDevices\\", 12);
	memcpy(buffer + 12, filename, strlen(filename) + 1);
	bool result = devIOctrl(IOCTL_HYPERCALLS_START_RECORD, buffer, (DWORD)strlen(buffer), NULL, NULL);
	delete buffer;
	return result;
}

bool HVdriverIO::hypercallsStopRecord()
{
	return devIOctrl(IOCTL_HYPERCALLS_START_RECORD, NULL, 0, NULL, NULL);
}


bool HVdriverIO::hypercallsGetStats(HYPERCALL_STATUSES output)
{
	DWORD len = sizeof(HYPERCALL_STATUSES);
	return devIOctrl(IOCTL_HYPERCALLS_GET_STATS, NULL, 0, output, &len);
}

bool HVdriverIO::hypercallsGetConf(PHV_HOOKING_CONF output)
{
	DWORD len = sizeof(HV_HOOKING_CONF);
	return devIOctrl(IOCTL_HYPERCALLS_GET_CONF, NULL, 0, output, &len);
}

bool HVdriverIO::msrWrite(DWORD32 code, DWORD32 values[2])
{
	DWORD inputs[3];
	inputs[0] = code;
	inputs[1] = values[0];
	inputs[2] = values[1];
	return devIOctrl(IOCTL_MSR_WRITE, inputs, 12, NULL, NULL);
}

bool HVdriverIO::msrRead(DWORD32 code, DWORD32 values[2])
{
	DWORD outSize = 8;
	return devIOctrl(IOCTL_MSR_READ, &code, 4, values, &outSize);
}

bool HVdriverIO::channelsSend(GUID guid, PVOID data, DWORD length, PVOID mdlData, DWORD mdlLength)
{
	char* buffer = new char[sizeof(VMBUS_CHANNEL_PACKET_SEND) + length + mdlLength];
	PVMBUS_CHANNEL_PACKET_SEND packet = (PVMBUS_CHANNEL_PACKET_SEND)buffer;
	memcpy(&packet->id, &guid, sizeof(GUID));
	packet->sizeOfData = length;
	packet->sizeOfMDL = mdlLength;
	memcpy(buffer + sizeof(VMBUS_CHANNEL_PACKET_SEND), data, length);
	memcpy(buffer + sizeof(VMBUS_CHANNEL_PACKET_SEND) + length, mdlData, mdlLength);
	bool result = devIOctrl(IOCTL_CHANNELS_SEND, buffer, sizeof(VMBUS_CHANNEL_PACKET_SEND) + length + mdlLength, NULL, NULL);
	delete buffer;
	return result;
}

bool HVdriverIO::channelsList(PVMBUS_CHANNEL output, PDWORD size)
{
	return devIOctrl(IOCTL_CHANNELS_LIST, NULL, 0, output, size);
}

bool HVdriverIO::channelsHook(GUID guid)
{
	return devIOctrl(IOCTL_CHANNELS_HOOK, (PVOID)&guid, sizeof(GUID), NULL, 0);
}

bool HVdriverIO::channelsUnhook()
{
	return devIOctrl(IOCTL_CHANNELS_UNHOOK, NULL, 0, NULL, 0);
}

bool HVdriverIO::channelsStartRecord(char* filename)
{
	char* buffer = new char[strlen(filename) + 13];
	memcpy(buffer, "\\DosDevices\\", 12);
	memcpy(buffer + 12, filename, strlen(filename) + 1);
	bool result = devIOctrl(IOCTL_CHANNELS_START_RECORD, buffer, (DWORD)strlen(buffer), NULL, NULL);
	delete buffer;
	return result;
}

bool HVdriverIO::channelsStopRecord()
{
	return devIOctrl(IOCTL_CHANNELS_STOP_RECORD, NULL, 0, NULL, 0);
}

bool HVdriverIO::channelsFuzz(GUID guid, PVOID data, DWORD length, PVOID mdlData, DWORD mdlLength, PVMBUS_CHANNEL_PACKET_FUZZ_CONF conf)
{
	char* buffer = new char[sizeof(VMBUS_CHANNEL_PACKET_FUZZ) + length + mdlLength];
	PVMBUS_CHANNEL_PACKET_FUZZ packet = (PVMBUS_CHANNEL_PACKET_FUZZ)buffer;
	memcpy(&packet->id, &guid, sizeof(GUID));
	memcpy(&packet->conf, conf, sizeof(VMBUS_CHANNEL_PACKET_FUZZ_CONF));
	packet->sizeOfData = length;
	packet->sizeOfMDL = mdlLength;
	memcpy(buffer + sizeof(VMBUS_CHANNEL_PACKET_FUZZ), data, length);
	memcpy(buffer + sizeof(VMBUS_CHANNEL_PACKET_FUZZ) + length, mdlData, mdlLength);
	bool result = devIOctrl(IOCTL_CHANNELS_FUZZ_SINGLE, buffer, sizeof(VMBUS_CHANNEL_PACKET_FUZZ) + length + mdlLength, NULL, NULL);
	delete buffer;
	return result;
}

bool HVdriverIO::pipeHook(GUID guid)
{
	return devIOctrl(IOCTL_PIPE_HOOK, (PVOID)& guid, sizeof(GUID), NULL, 0);
}

bool HVdriverIO::pipeUnhook()
{
	return devIOctrl(IOCTL_PIPE_UNHOOK, NULL, 0, NULL, 0);
}

bool HVdriverIO::pipeStartRecord(char* filename)
{
	char* buffer = new char[strlen(filename) + 13];
	memcpy(buffer, "\\DosDevices\\", 12);
	memcpy(buffer + 12, filename, strlen(filename) + 1);
	bool result = devIOctrl(IOCTL_PIPE_START_RECORD, buffer, (DWORD)strlen(buffer), NULL, NULL);
	delete buffer;
	return result;
}

bool HVdriverIO::pipeStopRecord()
{
	return devIOctrl(IOCTL_PIPE_STOP_RECORD, NULL, 0, NULL, 0);
}

bool HVdriverIO::pmioWrite(WORD port, DWORD32 value, BYTE size)
{
	BYTE input[6];
	*(PWORD)input = port;
	switch (size)
	{
	case 1:
		*(PBYTE)(input + 2) = (BYTE)value;
		return devIOctrl(IOCTL_PMIO_WRITE, input, 3, NULL, NULL);
	case 2:
		*(PWORD)(input + 2) = (WORD)value;
		return devIOctrl(IOCTL_PMIO_WRITE, input, 4, NULL, NULL);
	case 4:
		*(PDWORD32)(input + 2) = (DWORD32)value;
		return devIOctrl(IOCTL_PMIO_WRITE, input, 6, NULL, NULL);
	default:
		return STATUS_INVALID_PARAMETER;
	}
}

bool HVdriverIO::pmioRead(WORD port, PDWORD32 value, BYTE size)
{
	DWORD output = size;
	return devIOctrl(IOCTL_PMIO_READ, &port, 2, value, &output);
}