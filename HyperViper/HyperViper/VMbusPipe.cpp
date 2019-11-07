#include "CodeStolenFromOthers.h"
#include "VMbusPipe.h"
#include "MemoryUtils.h"
#include "VMbusChannels.h"

PVOID VMbusPipe::pipeTryRead = NULL;
UINT8 VMbusPipe::pipeTryReadOldCode[0x20];
UINT32 VMbusPipe::pipeTryReadOldCodeLen = 0;
HANDLE VMbusPipe::logHandle;
FAST_MUTEX VMbusPipe::logHandleLock;
GUID VMbusPipe::activeLogGuid;

void VMbusPipe::init(void)
{
	PUINT8 base, ptr;

	base = (PUINT8)KernelGetModuleBase("vmbusr.sys");
	if (base)
	{
		ptr = base + 0x1000;
		while (ptr - base < 0x4000)
		{
			if (!memcmp(ptr, VMBUSR_PIPE_TRY_READ, sizeof(VMBUSR_PIPE_TRY_READ)-1))
			{
				pipeTryRead = ptr + 0x5;
				break;
			}
			ptr++;
		}
	}

	pipeTryReadHookLogFunc = (UINT64)log;
	ExInitializeFastMutex(&logHandleLock);
}


void VMbusPipe::close(void)
{
	unhook();
	stopLog();
}


bool VMbusPipe::hook(PGUID guid)
{
	if (!pipeTryRead)
	{
		DbgPrint("[VMbusPipe::hook] Could not find 'PipeTryRead'\n");
		return false;
	}
	if (pipeTryReadOldCodeLen)
	{
		DbgPrint("[VMbusPipe::hook] Hook is already set\n");
		return false;
	}

	PVMBUS_CHANNEL_INTERNAL channel = VMbusChannels::getChannel(*guid);
	if (!channel)
	{
		DbgPrint("[VMbusPipe::hook] No such channel\n");
		return false;
	}
	activeLogGuid = channel->id;

	pipeTryReadOldCodeLen = 0x20;
	if (!MemoryUtils::injectHook(pipeTryRead, &pipeTryReadHook, pipeTryReadOldCode, &pipeTryReadOldCodeLen))
	{
		DbgPrint("[VMbusPipe::hook] Could not inject hook\n");
		pipeTryReadOldCodeLen = 0;
		return false;
	}

	return true;
}

bool VMbusPipe::unhook(void)
{
	if (!pipeTryReadOldCodeLen)
		return true;
	if (MemoryUtils::writeNotReadableMemory(pipeTryRead, pipeTryReadOldCode, pipeTryReadOldCodeLen))
	{
		pipeTryReadOldCodeLen = 0;
		return true;
	}
	return false;
}

void VMbusPipe::log(PIRP irp, PVOID data)
{
	if (!irp->IoStatus.Information)
		return;
	PVMBUS_CHANNEL_INTERNAL channel = *(PVMBUS_CHANNEL_INTERNAL*)((PCHAR)data + 0x100);

	if (logHandle && !memcmp(&(channel->id), &activeLogGuid, sizeof(GUID)))
	{
		PHV_WORKER_LOG_PIPE_DATA data = (PHV_WORKER_LOG_PIPE_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(HV_WORKER_LOG_PIPE_DATA), 0x76687668);
		data->WorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(WORK_QUEUE_ITEM), 0x76687668);
		data->mainBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, irp->IoStatus.Information, 0x76687668);
		data->mainBufferSize = (UINT32)irp->IoStatus.Information;
		PVOID ptr = MmGetSystemAddressForMdlSafe(irp->MdlAddress, MdlMappingNoExecute);
		memcpy(data->mainBuffer, ptr, data->mainBufferSize);
		ExInitializeWorkItem(data->WorkItem, LogRoutine, data);
		ExQueueWorkItem(data->WorkItem, DelayedWorkQueue);
	}
}

NTSTATUS VMbusPipe::logToFile(PUNICODE_STRING filename)
{
	if (logHandle)
		return STATUS_INVALID_DEVICE_REQUEST;

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	IO_STATUS_BLOCK    ioStatusBlock;
	NTSTATUS ntstatus = ZwCreateFile(&logHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(ntstatus))
	{
		logHandle = NULL;
		return ntstatus;
	}
	ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, "HVPR", 4, NULL, NULL); //HyperViper Pipe recording
	return STATUS_SUCCESS;
}

NTSTATUS VMbusPipe::stopLog(void)
{	
	ExAcquireFastMutex(&logHandleLock);
	if (logHandle)
	{
		ZwClose(logHandle);
		logHandle = NULL;
	}
	ExReleaseFastMutex(&logHandleLock);
	return STATUS_SUCCESS;
}

void VMbusPipe::LogRoutine(PVOID Parameter)
{
	PHV_WORKER_LOG_PIPE_DATA data = (PHV_WORKER_LOG_PIPE_DATA)Parameter;

	ExAcquireFastMutex(&logHandleLock);
	if (logHandle)
	{
		IO_STATUS_BLOCK    ioStatusBlock;
		ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &(data->mainBufferSize), sizeof(UINT32), NULL, NULL);
		ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, data->mainBuffer, data->mainBufferSize, NULL, NULL);
	}
	ExReleaseFastMutex(&logHandleLock);

	ExFreePool(data->WorkItem);
	ExFreePool(data->mainBuffer);
	ExFreePool(data);
}