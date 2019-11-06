#include "pch.h"
#include "HVdriverIO.h"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)


HVdriverIO driver;

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

EXTERN_DLL_EXPORT bool init(void)
{
	return driver.init();
}

//Hypercalls
EXTERN_DLL_EXPORT bool hypercallsCall(PHV_X64_HYPERCALL_INPUT callInfo, PVOID inBuffer, DWORD inBufferSize, PHV_X64_HYPERCALL_OUTPUT callResult, PVOID outBuffer, DWORD outBufferSize)
{
	return driver.hypercallsCall(callInfo, inBuffer, inBufferSize, callResult, outBuffer, outBufferSize);
}

EXTERN_DLL_EXPORT bool hypercallsHook(void)
{
	return driver.hypercallsHook();
}

EXTERN_DLL_EXPORT bool hypercallsUnhook(void)
{
	return driver.hypercallsUnhook();
}

EXTERN_DLL_EXPORT bool hypercallsGeneralDiscardSlow(BYTE value)
{
	return driver.hypercallsGeneralDiscardSlow(value);
}

EXTERN_DLL_EXPORT bool hypercallsGeneralDiscardFast(BYTE value)
{
	return driver.hypercallsGeneralDiscardFast(value);
}

EXTERN_DLL_EXPORT bool hypercallsGeneralDbgMsg(BYTE value)
{
	return driver.hypercallsGeneralDbgMsg(value);
}

EXTERN_DLL_EXPORT bool hypercallsSingleDbgMsg(DWORD callNr, DWORD value)
{
	return driver.hypercallsSingleDbgMsg(callNr, value);
}

EXTERN_DLL_EXPORT bool hypercallsSingleBreak(DWORD callNr, DWORD value)
{
	return driver.hypercallsSingleBreak(callNr, value);
}

EXTERN_DLL_EXPORT bool hypercallsSingleLog(DWORD callNr, DWORD count)
{
	return driver.hypercallsSingleLog(callNr, count);
}

EXTERN_DLL_EXPORT bool hypercallsSingleFuzz(DWORD callNr, DWORD count)
{
	return driver.hypercallsSingleFuzz(callNr, count);
}

EXTERN_DLL_EXPORT bool hypercallsStartRecord(char* fname)
{
	return driver.hypercallsStartRecord(fname);
}

EXTERN_DLL_EXPORT bool hypercallsStopRecord()
{
	return driver.hypercallsStopRecord();
}

EXTERN_DLL_EXPORT bool hypercallsGetStats(HYPERCALL_STATUSES output)
{
	return driver.hypercallsGetStats(output);
}

EXTERN_DLL_EXPORT bool hypercallsGetConf(PHV_HOOKING_CONF output)
{
	return driver.hypercallsGetConf(output);
}

//MSR
EXTERN_DLL_EXPORT bool msrWrite(DWORD32 code, DWORD32 values[2])
{
	return driver.msrWrite(code, values);
}

EXTERN_DLL_EXPORT bool msrRead(DWORD32 code, DWORD32 values[2])
{
	return driver.msrRead(code, values);
}

//Channel
EXTERN_DLL_EXPORT bool channelsSend(GUID guid, PVOID data, DWORD length, PVOID mdlData, DWORD mdlLength)
{
	return driver.channelsSend(guid, data, length, mdlData, mdlLength);
}

EXTERN_DLL_EXPORT bool channelsList(PVMBUS_CHANNEL output, PDWORD size)
{
	return driver.channelsList(output, size);
}

EXTERN_DLL_EXPORT bool channelsHook(GUID guid)
{
	return driver.channelsHook(guid);
}

EXTERN_DLL_EXPORT bool channelsUnhook()
{
	return driver.channelsUnhook();
}

EXTERN_DLL_EXPORT bool channelsStartRecord(char* data)
{
	return driver.channelsStartRecord(data);
}

EXTERN_DLL_EXPORT bool channelsStopRecord()
{
	return driver.channelsStopRecord();
}

//Pipe
EXTERN_DLL_EXPORT bool pipeHook(GUID guid)
{
	return driver.pipeHook(guid);
}

EXTERN_DLL_EXPORT bool pipeUnhook()
{
	return driver.pipeUnhook();
}

EXTERN_DLL_EXPORT bool pipeStartRecord(char* data)
{
	return driver.pipeStartRecord(data);
}

EXTERN_DLL_EXPORT bool pipeStopRecord()
{
	return driver.pipeStopRecord();
}
