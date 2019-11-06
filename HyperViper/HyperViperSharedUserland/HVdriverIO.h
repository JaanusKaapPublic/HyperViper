#pragma once
#include<Windows.h>
#include"HVstructures.h"
#include"HVdef.h"

class HVdriverIO
{
private:
	HANDLE handle;

public:
	bool init();
	bool devIOctrl(DWORD code, PVOID inBuffer, DWORD inBufferSize, PVOID outBuffer, DWORD* outBufferSize);

	//Hypercalls
	bool hypercallsCall(PHV_X64_HYPERCALL_INPUT callInfo, PVOID inBuffer, DWORD inBufferSize, PHV_X64_HYPERCALL_OUTPUT callResult, PVOID outBuffer, DWORD outBufferSize);
	bool hypercallsHook(void);
	bool hypercallsUnhook(void);
	bool hypercallsGeneralDiscardSlow(BYTE value);
	bool hypercallsGeneralDiscardFast(BYTE value);
	bool hypercallsGeneralDbgMsg(BYTE value);
	bool hypercallsSingleDbgMsg(DWORD callNr, DWORD value);
	bool hypercallsSingleBreak(DWORD callNr, DWORD value);
	bool hypercallsSingleLog(DWORD callNr, DWORD count);
	bool hypercallsSingleFuzz(DWORD callNr, DWORD count);
	bool hypercallsStartRecord(char* fname);
	bool hypercallsStopRecord();
	bool hypercallsGetStats(HYPERCALL_STATUSES output);
	bool hypercallsGetConf(PHV_HOOKING_CONF output);
	
	//MSR
	bool msrWrite(DWORD32 code, DWORD32 values[2]);
	bool msrRead(DWORD32 code, DWORD32 values[2]);

	//Channel
	bool channelsSend(GUID guid, PVOID data, DWORD length, PVOID mdlData, DWORD mdlLength);
	bool channelsList(PVMBUS_CHANNEL output, PDWORD size);
	bool channelsHook(GUID guid);
	bool channelsUnhook();
	bool channelsStartRecord(char*);
	bool channelsStopRecord();
	bool channelsFuzz(GUID guid, PVOID data, DWORD length, PVOID mdlData, DWORD mdlLength, PVMBUS_CHANNEL_PACKET_FUZZ_CONF conf);

	//Pipe
	bool pipeHook(GUID guid);
	bool pipeUnhook();
	bool pipeStartRecord(char*);
	bool pipeStopRecord();

	//PMIO
	bool pmioWrite(WORD port, DWORD32 result, BYTE size);
	bool pmioRead(WORD port, PDWORD32 value, BYTE size);
};
