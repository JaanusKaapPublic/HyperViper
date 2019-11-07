#include <windows.h>
#include <stdio.h>
#include <map>
#include "HVdef.h"
#include "HVUdefs.h"
#include "HVdriverIO.h"
#include "Convertions.h"

void help(bool doErrorMsg)
{
	if (doErrorMsg)
		printf("[ERROR] Unknown or missing command type\n\n");

	printf("Syntax: HVhypercalls.exe {command} {command arguments...}\n");
	printf("  Commands & arguments:\n");
	printf("    fast {code} {count} {start index} {param1} {param2}\n");
	printf("    slow {code} {count} {start index} {input buffer file} {output buffer file} {output buffer size}\n");
	printf("    fuzz {file containing recorded hypercalls}\n");
	printf("    hook\n");
	printf("    unhook\n");
	printf("    hook-slow {0 or 1}\n");
	printf("    hook-fast {0 or 1}\n");
	printf("    hook-dbg {0 or 1}\n");
	printf("    hook-log {filename where to log}\n");
	printf("    hook-hc-dbg {code} {count}\n");
	printf("    hook-hc-break {code} {count}\n");
	printf("    hook-hc-log {code} {count}\n");
	printf("    hook-hc-fuzz {code} {count}\n");
	printf("    stats-hc\n");
	printf("    conf\n");

	exit(0);
}

HV_X64_HYPERCALL_OUTPUT fastCall(HVdriverIO driver, UINT32 code, UINT32 count, UINT32 start, UINT64 param1, UINT64 param2)
{
	HV_X64_HYPERCALL_INPUT call;
	memset(&call, 0x0, sizeof(HV_X64_HYPERCALL_INPUT));
	call.CallCode = code;
	call.CountOfElements = count;
	call.IsFast = 1;
	call.RepStartIndex = start;

	UINT64 data[2];
	data[0] = param1;
	data[0] = param2;

	HV_X64_HYPERCALL_OUTPUT result;
	if (!driver.hypercallsCall(&call, data, 16, &result, 0, NULL))
	{
		if (GetLastError() == STATUS_ILLEGAL_INSTRUCTION)
			ERROR_EXIT("Request was made and was considered illegal by the HyperV (crashes the system if not caught)\n");
		ERROR_EXIT("DeviceIoControl failed");
	}

	return result;
}

HV_X64_HYPERCALL_OUTPUT slowCall(HVdriverIO driver, UINT32 code, UINT32 count, UINT32 start, PVOID inBuffer, UINT32 inBufferLen, PVOID outBuffer, UINT32 outBufferLen)
{
	HV_X64_HYPERCALL_INPUT call;
	memset(&call, 0x0, sizeof(HV_X64_HYPERCALL_INPUT));
	call.CallCode = code;
	call.CountOfElements = count;
	call.IsFast = 0;
	call.RepStartIndex = start;
	
	HV_X64_HYPERCALL_OUTPUT result;
	if (!driver.hypercallsCall(&call, inBuffer, inBufferLen, &result, outBuffer, outBufferLen))
	{
		if (GetLastError() == STATUS_ILLEGAL_INSTRUCTION)
			ERROR_EXIT("Request was made and was considered illegal by the HyperV (crashes the system if not caught)\n");
		ERROR_EXIT("DeviceIoControl failed");
	}

	return result;
}

DWORD unpack(char* file, char* dir)
{
	FILE *fin = NULL;
	char magic[4], filenameTmp[512];
	std::map<DWORD, DWORD> counter;
	DWORD count = 0;

	while (dir[strlen(dir) - 1] == '\\' || dir[strlen(dir) - 1] == '/')
		dir[strlen(dir) - 1] = 0x00;

	fopen_s(&fin, file, "rb");
	if (!fin)
		ERROR_EXIT("Could not open file '%s'", file);

	fread(magic, 1, sizeof(magic), fin);
	if (memcmp(magic, "HVCL", 4))
		ERROR_EXIT("Invalid file '%s' - no magic value", file);


	while (!feof(fin))
	{
		FILE* fout = NULL, * foutInfo = NULL, * foutData = NULL;
		HV_X64_HYPERCALL_INPUT inputValue;
		DWORD size;
		BYTE* content;

		fread(&inputValue, 1, sizeof(HV_X64_HYPERCALL_INPUT), fin);
		if (counter.count(0x1000 * inputValue.IsFast + inputValue.CallCode) == 0)
			counter[0x1000 * inputValue.IsFast + inputValue.CallCode] = 0;

		sprintf_s(filenameTmp, 500, "%s\\hcall_%02X_%c_%04X.txt", dir, inputValue.CallCode, (inputValue.IsFast ? 'f' : 's'), counter[0x1000 * inputValue.IsFast + inputValue.CallCode]);
		fopen_s(&foutInfo, filenameTmp, "wb");
		if (!foutInfo)
			ERROR_EXIT("Could not create file '%s'", filenameTmp);
		sprintf_s(filenameTmp, 500, "%s\\hcall_%02X_%c_%04X.hvcl", dir, inputValue.CallCode, (inputValue.IsFast ? 'f' : 's'), counter[0x1000 * inputValue.IsFast + inputValue.CallCode]);
		fopen_s(&fout, filenameTmp, "wb");
		if (!fout)
			ERROR_EXIT("Could not create file '%s'", filenameTmp);
		fwrite("HVCL", 1, 4, fout);
		fwrite(&inputValue, 1, sizeof(HV_X64_HYPERCALL_INPUT), fout);
		counter[0x1000 * inputValue.IsFast + inputValue.CallCode] += 1;

		fprintf(foutInfo, "Code: 0x%X\n", inputValue.CallCode);
		fprintf(foutInfo, "Fast: 0x%X\n", inputValue.IsFast);
		fprintf(foutInfo, "Count: 0x%X\n", inputValue.CountOfElements);
		fprintf(foutInfo, "Start: 0x%X\n", inputValue.RepStartIndex);
		if (!inputValue.IsFast)
		{
			sprintf_s(filenameTmp, 500, "%s\\hcall_%02X_%c_%04X.bin", dir, inputValue.CallCode, (inputValue.IsFast ? 'f' : 's'), counter[0x1000 * inputValue.IsFast + inputValue.CallCode]);
			fopen_s(&foutData, filenameTmp, "wb");
			if (!foutData)
				ERROR_EXIT("Could not create file '%s'", filenameTmp);

			fread(&size, 1, sizeof(size), fin);
			content = new BYTE[size];
			if (!content)
				ERROR_EXIT("Could not allocate 0x%X byte buffer", size);
			fread(content, 1, size, fin);
			fwrite(&size, 1, sizeof(size), fout);
			fwrite(content, 1, size, fout);
			fwrite(content, 1, size, foutData);
			delete content;
			fclose(foutData);
		}
		else
		{
			DWORD64 param1, param2;
			fread(&param1, 1, sizeof(DWORD64), fin);
			fread(&param2, 1, sizeof(DWORD64), fin);
			fwrite(&param1, 1, sizeof(param1), fout);
			fwrite(&param2, 1, sizeof(param2), fout);
			fprintf(foutInfo, "Param1: 0x%llX\n",param1);
			fprintf(foutInfo, "Param2: 0x%llX\n",param2);
		}
		count++;
		fclose(fout);
		fclose(foutInfo);
	}
	fclose(fin);

	return count;
}



DWORD fuzz(HVdriverIO driver, char* file)
{
	FILE* fin;
	char magic[4];
	DWORD count = 0;

	fopen_s(&fin, file, "rb");
	if (!fin)
		ERROR_EXIT("Could not open file '%s'", file);

	fread(magic, 1, sizeof(magic), fin);
	if (memcmp(magic, "HVCL", 4))
		ERROR_EXIT("Invalid file '%s' - no magic value", file);

	while (!feof(fin))
	{
		HV_X64_HYPERCALL_INPUT inputValue;
		BYTE* content;
		DWORD size;

		if (fread(&inputValue, 1, sizeof(HV_X64_HYPERCALL_INPUT), fin) != sizeof(HV_X64_HYPERCALL_INPUT))
			break;

		if (!inputValue.IsFast)
		{
			fread(&size, 1, sizeof(size), fin);
			content = new BYTE[sizeof(HV_X64_HYPERCALL_INPUT) + size];
			if (!content)
				ERROR_EXIT("Could not allocate 0x%X byte buffer", sizeof(HV_X64_HYPERCALL_INPUT) + size);
			memcpy(content, &inputValue, sizeof(HV_X64_HYPERCALL_INPUT));
			fread(content + sizeof(HV_X64_HYPERCALL_INPUT), 1, size, fin);
			size += sizeof(HV_X64_HYPERCALL_INPUT);
		}
		else
		{
			content = new BYTE[sizeof(HV_X64_HYPERCALL_INPUT) + sizeof(DWORD64) + sizeof(DWORD64)];
			if (!content)
				ERROR_EXIT("Could not allocate 0x%X byte buffer", sizeof(HV_X64_HYPERCALL_INPUT) + sizeof(DWORD64) + sizeof(DWORD64));
			memcpy(content, &inputValue, sizeof(HV_X64_HYPERCALL_INPUT));
			fread(content + sizeof(HV_X64_HYPERCALL_INPUT), 1, sizeof(DWORD64), fin);
			fread(content + sizeof(HV_X64_HYPERCALL_INPUT) + sizeof(DWORD64), 1, sizeof(DWORD64), fin);
			size = sizeof(HV_X64_HYPERCALL_INPUT) + sizeof(DWORD64) + sizeof(DWORD64);
		}

		printf("Fuzzing hypercall 0x%02X (%s) - input size 0x%X bytes\n", inputValue.CallCode, (inputValue.IsFast ? "FAST" : "SLOW"), size - sizeof(HV_X64_HYPERCALL_INPUT));
		if (!driver.devIOctrl(IOCTL_HYPERCALLS_FUZZ_ADDITION, content, size, NULL, NULL))
			printf("  FAILED: 0x%X\n", GetLastError());
		delete content;
		count++;
	}
	fclose(fin);

	return count;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
		help(true);

	if (!strcmp(argv[1], "unpack"))
	{
		if (argc < 3)
			ERROR_EXIT("No file location specified");
		if (argc < 4)
			ERROR_EXIT("No output directory specified");
		UINT32 count = unpack(argv[2], argv[3]);
		printf("Unpacked %d hypercalls\n", count);
		return 0;
	}
	else if (!strcmp(argv[1], "help"))
	{
		help(false);
	}

	HVdriverIO driver;
	if (!driver.init())
		ERROR_EXIT("Could not open driver\n");

	if (!strcmp(argv[1], "fast"))
	{
		if (argc < 3)
			ERROR_EXIT("No hypercall code specified");
		if (argc < 4)
			ERROR_EXIT("No hypercall count specified");
		if (argc < 5)
			ERROR_EXIT("No hypercall start specified");
		if (argc < 6)
			ERROR_EXIT("No hypercall rcx value specified");
		if (argc < 7)
			ERROR_EXIT("No hypercall rdx value specified");

		UINT32 code = getVal(argv[2]);
		UINT32 count = getVal(argv[3]);
		UINT32 start = getVal(argv[4]);
		UINT64 param1 = getVal64(argv[5]);
		UINT64 param2 = getVal64(argv[6]);

		HV_X64_HYPERCALL_OUTPUT result = fastCall(driver, code, count, start, param1, param2);
		printf("[INFO] Request successful:\n");
		printf("          CallStatus = 0x%X\n", result.CallStatus);
		printf("          ElementsProcessed = 0x%X\n", result.ElementsProcessed);
	}
	else if (!strcmp(argv[1], "slow"))
	{
		if (argc < 3)
			ERROR_EXIT("No hypercall code specified");
		if (argc < 4)
			ERROR_EXIT("No hypercall count specified");
		if (argc < 5)
			ERROR_EXIT("No hypercall start specified");
		if (argc < 6)
			ERROR_EXIT("No input file specified");
		if (argc < 7)
			ERROR_EXIT("No output file specified");
		if (argc < 8)
			ERROR_EXIT("No output size specified");

		UINT32 code = getVal(argv[2]);
		UINT32 count = getVal(argv[3]);
		UINT32 start = getVal(argv[4]);
		char* inFileName = argv[5];
		char* outFileName = argv[6];
		UINT32 outSize = getVal(argv[7]);
		BYTE* outBuf = new BYTE[outSize];
			
		FILE* f = NULL;
		fopen_s(&f, inFileName, "rb");
		if (!f)
			ERROR_EXIT("Could not open input file");
		fseek(f, 0, SEEK_END);
		UINT32 inSize = ftell(f);
		BYTE* inBuf = new BYTE[inSize];
		fseek(f, 0, SEEK_SET);
		fread(inBuf, 1, inSize, f);
		fclose(f);

		HV_X64_HYPERCALL_OUTPUT result = slowCall(driver, code, count, start, inBuf, inSize, outBuf, outSize);
		printf("[INFO] Request successful:\n");
		printf("          CallStatus = 0x%X\n", result.CallStatus);
		printf("          ElementsProcessed = 0x%X\n", result.ElementsProcessed);

		f = NULL;
		fopen_s(&f, outFileName, "wb");
		if (!f)
			ERROR_EXIT("Could not open output file");
		fwrite(outBuf, 1, outSize, f);
		fclose(f);
	}
	else if (!strcmp(argv[1], "fuzz"))
	{
		if (argc < 3)
			ERROR_EXIT("No file location specified");
		UINT32 count = fuzz(driver, argv[2]);
		printf("Fuzzed through %d hypercalls\n", count);
	}
	else if (!strcmp(argv[1], "hook"))
	{
		if (!driver.hypercallsHook())
			ERROR_EXIT("Hooking failed");
	}
	else if (!strcmp(argv[1], "unhook"))
	{
		if (!driver.hypercallsUnhook())
			ERROR_EXIT("Unhooking failed");
	}
	else if (!strcmp(argv[1], "hook-slow"))
	{
		if (argc < 3)
			ERROR_EXIT("No value specified");
		if (!driver.hypercallsGeneralDiscardSlow(getVal(argv[2]) ? 1 : 0))
			ERROR_EXIT("Flipping 'Discard slow' flag failed");
	}
	else if (!strcmp(argv[1], "hook-fast"))
	{
		if (argc < 3)
			ERROR_EXIT("No value specified");
		if (!driver.hypercallsGeneralDiscardFast(getVal(argv[2]) ? 1 : 0))
			ERROR_EXIT("Flipping 'Discard fast' flag failed");
	}
	else if (!strcmp(argv[1], "hook-dbg"))
	{
		if (argc < 3)
			ERROR_EXIT("No value specified");
		if (!driver.hypercallsGeneralDbgMsg(getVal(argv[2]) ? 1 : 0))
			ERROR_EXIT("Flipping 'Show debug messages' flag failed");
	}
	else if (!strcmp(argv[1], "hook-log"))
	{
		if (argc < 3)
			ERROR_EXIT("No file location specified");
		if (!driver.hypercallsStartRecord(argv[2]))
			ERROR_EXIT("Enabling logging failed");
	}

	else if (!strcmp(argv[1], "hook-hc-dbg"))
	{
		if (argc < 3)
			ERROR_EXIT("No hypercall specified");
		if (argc < 4)
			ERROR_EXIT("No value specified");
		if (!driver.hypercallsSingleDbgMsg(getVal(argv[2]), getVal(argv[3])))
			ERROR_EXIT("Flipping 'Show debug messages' flag failed for hypercall 0x%X", getVal(argv[2]));
	}
	else if (!strcmp(argv[1], "hook-hc-break"))
	{
		if (argc < 3)
			ERROR_EXIT("No hypercall specified");
		if (argc < 4)
			ERROR_EXIT("No value specified");
		if (!driver.hypercallsSingleBreak(getVal(argv[2]), getVal(argv[3])))
			ERROR_EXIT("Flipping 'Break (software breakpoint)' flag failed for hypercall 0x%X", getVal(argv[2]));
	}
	else if (!strcmp(argv[1], "hook-hc-log"))
	{
		if (argc < 3)
			ERROR_EXIT("No hypercall specified");
		if (argc < 4)
			ERROR_EXIT("No value specified");
		if (!driver.hypercallsSingleLog(getVal(argv[2]), getVal(argv[3])))
			ERROR_EXIT("Setting 'Number of log entries to write' flag failed for hypercall 0x%X", getVal(argv[2]));
	}
	else if (!strcmp(argv[1], "hook-hc-fuzz"))
	{
		if (argc < 3)
			ERROR_EXIT("No hypercall specified");
		if (argc < 4)
			ERROR_EXIT("No fuzz count specified");
		if (!driver.hypercallsSingleFuzz(getVal(argv[2]), getVal(argv[3])))
			ERROR_EXIT("Setting 'Number of fuzzing tries' flag failed for hypercall 0x%X", getVal(argv[2]));
	}
	else if (!strcmp(argv[1], "stats-hc"))
	{
		HYPERCALL_STATUSES stats;
		if (!driver.hypercallsGetStats(stats))
			ERROR_EXIT("Hypercall statistics could not be recieved");
		for (DWORD x = 1; x <= HYPERCALL_LAST_NR; x++)
			printf("Hypercall 0x%02X: %c%c  count=0x%08X   last-CountOfElements: 0x%03X   last-PID: 0x%04X\n",
				x,
				stats[x].fast ? 'F' : ' ',
				stats[x].slow ? 'S' : ' ',
				stats[x].count,
				stats[x].lastElementCount,
				stats[x].lastProcessID);
	}
	else if (!strcmp(argv[1], "conf"))
	{
		HV_HOOKING_CONF conf;
		if (!driver.hypercallsGetConf(&conf))
			ERROR_EXIT("HyperV configuration could not be recieved");
		printf("Hooking activated = 0x%X\n", conf.hookingActivated);
		printf("Discard Slow = 0x%X\n", conf.hookingDiscardAllSlow);
		printf("Discard Fast = 0x%X\n", conf.hookingDiscardAllFast);
		printf("Debug messages = 0x%X\n", conf.hookingDbgPrintAll);
		printf("Logging active = 0x%X\n", conf.hookingLogActive);
		printf("Log all = 0x%X\n", conf.hookingLogAll);

		for (DWORD x = 1; x <= HYPERCALL_LAST_NR; x++)
			printf("Hypercall 0x%02X:   breakpoint: 0x%X    debugMsg: 0x%X    fuzzing: 0x%04X    logging: 0x%04X\n",
				x,
				conf.hcallConfs[x].breakpoint,
				conf.hcallConfs[x].dbgPrint,
				conf.hcallConfs[x].fuzz,
				conf.hcallConfs[x].log);
	}
	else
	{
		help(true);
	}
	
}

