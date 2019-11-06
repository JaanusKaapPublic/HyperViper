#pragma once
#include "VMbusChannels.h"

#define VMBUSR_PIPE_TRY_READ "\xE8\x16\x00\x00\x00\x48\x8B\x5C\x24\x40\x48\x8B\x74\x24\x48\x48\x83\xC4\x30\x5F\xC3"

typedef struct _HV_WORKER_LOG_PIPE_DATA
{
	PWORK_QUEUE_ITEM WorkItem;
	PVOID mainBuffer;
	UINT32 mainBufferSize;
} HV_WORKER_LOG_PIPE_DATA, * PHV_WORKER_LOG_PIPE_DATA;

extern "C" void inline pipeTryReadHook(void);
extern "C" UINT64 pipeTryReadHookLogFunc;

class VMbusPipe
{
private:
	static PVOID pipeTryRead;
	static UINT8 pipeTryReadOldCode[0x20];
	static UINT32 pipeTryReadOldCodeLen;
	static HANDLE logHandle;
	static FAST_MUTEX logHandleLock;
	static GUID activeLogGuid;

	static void log(PIRP irp, PVOID data);
	static void	LogRoutine(PVOID Parameter);
public:
	static void init(void);
	static void close(void);
	static bool hook(PGUID);
	static bool unhook(void);
	static NTSTATUS logToFile(PUNICODE_STRING filename);
	static NTSTATUS VMbusPipe::stopLog(void);
};