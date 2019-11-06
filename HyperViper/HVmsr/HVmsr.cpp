#include <windows.h>
#include <stdio.h>
#include "HVdef.h"
#include "HVdriverIO.h"
#include "Convertions.h"

#define ERROR_EXIT(e) {printf("[ERROR][0x%X] %s\n", GetLastError(), e); exit(0);}

int main(int argc, char* argv[])
{
	if (argc < 2)
		ERROR_EXIT("Missing action operation");

	HVdriverIO driver;
	if (!driver.init())
		ERROR_EXIT("Could not open handle to driver");

	if (!strcmp(argv[1], "readMSR"))
	{
		if (argc < 3)
			ERROR_EXIT("Missing processor nr");
		if (argc < 4)
			ERROR_EXIT("Missing read nr");

		DWORD cpu = atoi(argv[2]);
		DWORD_PTR proc, sys;
		GetProcessAffinityMask(GetCurrentProcess(), &proc, &sys);
		if (!((1 << cpu) & sys))
			ERROR_EXIT("Processor with such number does not exist");
		SetProcessAffinityMask(GetCurrentProcess(), (1 << cpu));

		DWORD outSize;
		DWORD32 input;
		DWORD32 outputs[2];

		input = getVal(argv[3]);

		outSize = 8;
		if (driver.msrRead(input, outputs))
		{
			printf("%08X:%08X", outputs[0], outputs[1]);
		}
		else
		{
			if (GetLastError() == STATUS_ILLEGAL_INSTRUCTION)
				ERROR_EXIT("Request(DeviceIoControl) failed because of illegal instruction exception");
			ERROR_EXIT("Request(DeviceIoControl) failed");
		}
	}
	else if (!strcmp(argv[1], "writeMSR"))
	{
		if (argc < 3)
			ERROR_EXIT("Missing processor nr");
		if (argc < 4)
			ERROR_EXIT("Missing read nr");
		if (argc < 5)
			ERROR_EXIT("Missing new value (high)");
		if (argc < 6)
			ERROR_EXIT("Missing new value (low)");

		DWORD cpu = atoi(argv[1]);
		DWORD_PTR proc, sys;
		GetProcessAffinityMask(GetCurrentProcess(), &proc, &sys);
		if (!((1 << cpu) & sys))
			ERROR_EXIT("Processor with such number does not exist");
		SetProcessAffinityMask(GetCurrentProcess(), (1 << cpu));

		DWORD32 input[2], code;

		code = getVal(argv[3]);
		for (int x = 0; x < 2; x++)
			input[x] = getVal(argv[x + 4]);

		if (driver.msrWrite(code, input))
		{
			printf("OK");
		}
		else
		{
			if (GetLastError() == STATUS_ILLEGAL_INSTRUCTION)
				ERROR_EXIT("Request(DeviceIoControl) failed because of illegal instruction exception");
			ERROR_EXIT("Request(DeviceIoControl) failed");
		}
	}
	else if (!strcmp(argv[1], "readPMIO"))
	{
		if (argc < 3)
			ERROR_EXIT("Missing port nr");
		if (argc < 4)
			ERROR_EXIT("Missing size");
		DWORD32 size, port, result = 0;
		port = getVal(argv[2]);
		size = getVal(argv[3]);

		if (driver.pmioRead(port, &result, size))
		{
			printf("%08X", result);
		}
		else
		{
			if (GetLastError() == STATUS_ILLEGAL_INSTRUCTION)
				ERROR_EXIT("Request(DeviceIoControl) failed because of illegal instruction exception");
			ERROR_EXIT("Request(DeviceIoControl) failed");
		}
	}
	else if (!strcmp(argv[1], "writePMIO"))
	{
		if (argc < 3)
			ERROR_EXIT("Missing port nr");
		if (argc < 4)
			ERROR_EXIT("Missing value");
		if (argc < 5)
			ERROR_EXIT("Missing size");
		DWORD32 size, port, value = 0;
		port = getVal(argv[2]);
		value = getVal(argv[3]);
		size = getVal(argv[4]);

		if (!driver.pmioWrite(port, value, size))
		{
			if (GetLastError() == STATUS_ILLEGAL_INSTRUCTION)
				ERROR_EXIT("Request(DeviceIoControl) failed because of illegal instruction exception");
			ERROR_EXIT("Request(DeviceIoControl) failed");
		}
	}
	else
	{
		ERROR_EXIT("Unknown command");
	}
}

