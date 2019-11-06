#pragma once
#include<ntddk.h>
#include"HVstructures.h"
#include"HVdef.h"

typedef struct _HV_WORKER_LOG_DATA
{
	PWORK_QUEUE_ITEM WorkItem;
	PVOID bufferIn;
	UINT64 param1;
	UINT64 param2;
	_HV_X64_HYPERCALL_INPUT input;
} HV_WORKER_LOG_DATA, * PHV_WORKER_LOG_DATA;

typedef HV_X64_HYPERCALL_OUTPUT (NTAPI *HypercallInvoker)(HV_X64_HYPERCALL_INPUT InputValue, ULONGLONG InputPa, ULONGLONG OutputPa);

extern "C" NTSYSAPI HV_X64_HYPERCALL_OUTPUT NTAPI HvlInvokeHypercall(HV_X64_HYPERCALL_INPUT InputValue, ULONGLONG InputPa, ULONGLONG OutputPa);
extern "C" void inline hypercallHook(void);
extern "C" UINT64 originalHypercallLocation;
extern "C" UINT64 originalHypercallPre;

class Hypercall
{
private:
	static HV_HOOKING_CONF conf;
	static HYPERCALL_STATUSES hypercallStats;
	static HANDLE logHandle;
	static FAST_MUTEX logHandleLock;

	static NTSTATUS generateMDL(ULONG size, PULONGLONG pa, PMDL* mdl, PVOID* ptr);
	static NTSTATUS generateMDLs(PVOID inBuffer, ULONG inBufferSize, ULONG outBufferSize, PULONGLONG inPA, PMDL* inMdl, PULONGLONG outPA, PMDL* outMdl);

	static void preHypercall(HV_X64_HYPERCALL_INPUT InputValue, ULONGLONG InputPa, ULONGLONG OutputP);
	static void	LogRoutine(PVOID Parameter);
public:
	static void init(void);
	static void close(void);
	static void getConf(PHV_HOOKING_CONF conf);
	static void setConf(PHV_HOOKING_CONF conf);
	static void getStats(PHYPERCALL_STATUSES conf);
	static NTSTATUS hypercall(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen, void* bufferOut, UINT32 bufferOutLen, PHV_X64_HYPERCALL_OUTPUT hvOutput);
	static NTSTATUS hook();
	static NTSTATUS unhook();
	static NTSTATUS logToFile(PUNICODE_STRING filename);
	static NTSTATUS fuzzByAdd(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen);
	static NTSTATUS fuzzBySpecialValues(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen);
};