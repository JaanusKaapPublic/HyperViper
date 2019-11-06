#include<ntddk.h>
#include"Hypercall.h"

HV_HOOKING_CONF Hypercall::conf;
HYPERCALL_STATUSES Hypercall::hypercallStats;
HANDLE Hypercall::logHandle;
FAST_MUTEX Hypercall::logHandleLock;

void Hypercall::init(void)
{
	memset(&conf, 0x00, sizeof(HV_HOOKING_CONF));
	memset(hypercallStats, 0x00, sizeof(HYPERCALL_STATUSES));
	conf.logSize = 0x1000;
	conf.hookingDiscardAllSlow = 1;
	conf.hookingDiscardAllFast = 1;

	ExInitializeFastMutex(&logHandleLock);
}

void Hypercall::close(void)
{
	unhook();
}

NTSTATUS Hypercall::generateMDL(ULONG size, PULONGLONG pa, PMDL* mdl, PVOID* ptr)
{
	PHYSICAL_ADDRESS low, high;
	NTSTATUS status = STATUS_SUCCESS;

	low.QuadPart = 0;
	high.QuadPart = ~0ULL;
	*mdl = NULL;

	*mdl = MmAllocatePartitionNodePagesForMdlEx(low, high, low, ROUND_TO_PAGES(size), MmCached, KeGetCurrentNodeNumber(), MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS | MM_ALLOCATE_FULLY_REQUIRED | MM_DONT_ZERO_ALLOCATION, NULL);
	if (!(*mdl))
		status = STATUS_INSUFFICIENT_RESOURCES;

	if (status == STATUS_SUCCESS && ptr)
	{
		*ptr = MmGetSystemAddressForMdlSafe(*mdl, MdlMappingNoExecute);
		if(!(*ptr))
			status = STATUS_INSUFFICIENT_RESOURCES;
	}

	if (status == STATUS_SUCCESS)
		*pa = *MmGetMdlPfnArray(*mdl) << PAGE_SHIFT;

	if (status != STATUS_SUCCESS)
	{
		MmFreePagesFromMdlEx(*mdl, 0);
		ExFreePool(*mdl);
	}
	return status;
}

NTSTATUS Hypercall::generateMDLs(PVOID inBuffer, ULONG inBufferSize, ULONG outBufferSize, _Out_ PULONGLONG inPA, _Out_ PMDL* inMdl, _Out_ PULONGLONG outPA, _Out_ PMDL* outMdl)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID inPtr, outPtr;

	*inPA = NULL;
	*inMdl = NULL;
	*outPA = NULL;
	*outMdl = NULL;

	if (inBufferSize)
	{
		status = generateMDL(inBufferSize, inPA, inMdl, &inPtr);
		if (status != STATUS_SUCCESS)
		{
			return status;
		}
		RtlCopyMemory(inPtr, inBuffer, inBufferSize);
	}
	if (outBufferSize)
	{
		status = generateMDL(outBufferSize, outPA, outMdl, &outPtr);
		if (status != STATUS_SUCCESS)
		{
			if (*inMdl)
			{
				MmFreePagesFromMdlEx(*inMdl, 0);
				ExFreePool(*inMdl);
			}
			*inMdl = NULL;
			return status;
		}
	}
	return status;
}

void Hypercall::preHypercall(HV_X64_HYPERCALL_INPUT InputValue, ULONGLONG InputPa, ULONGLONG OutputPa)
{
	if (InputValue.CallCode > HYPERCALL_LAST_NR)
		return;
	hypercallStats[InputValue.CallCode].count++;
	hypercallStats[InputValue.CallCode].lastElementCount = InputValue.CountOfElements;
	hypercallStats[InputValue.CallCode].lastProcessID = PsGetProcessId(PsGetCurrentProcess());
	if (InputValue.IsFast)
		hypercallStats[InputValue.CallCode].fast = 1;
	if (!InputValue.IsFast)
		hypercallStats[InputValue.CallCode].slow = 1;


	if (InputValue.IsFast && conf.hookingDiscardAllFast && !conf.hcallConfs[InputValue.CallCode].breakpoint && !conf.hcallConfs[InputValue.CallCode].dbgPrint && !conf.hcallConfs[InputValue.CallCode].fuzz && !conf.hcallConfs[InputValue.CallCode].log)
		return;
	if (!InputValue.IsFast && conf.hookingDiscardAllSlow && !conf.hcallConfs[InputValue.CallCode].breakpoint && !conf.hcallConfs[InputValue.CallCode].dbgPrint && !conf.hcallConfs[InputValue.CallCode].fuzz && !conf.hcallConfs[InputValue.CallCode].log)
		return;

	if (conf.hookingDbgPrintAll || conf.hcallConfs[InputValue.CallCode].dbgPrint)
	{
		if (InputValue.IsFast)
			DbgPrint("Hypercall(FAST):\n    code: 0x%X\n    count of elements: 0x%X\n    start idex: 0x%X    Input: 0x%llX:0x%llX\n", InputValue.CallCode, InputValue.CountOfElements, InputValue.RepStartIndex, InputPa, OutputPa);
		else
			DbgPrint("Hypercall(SLOW):\n    code: 0x%X\n    count of elements: 0x%X\n    start idex: 0x%X\n", InputValue.CallCode, InputValue.CountOfElements, InputValue.RepStartIndex);
	}

	if (conf.hcallConfs[InputValue.CallCode].breakpoint)
		__debugbreak();

	if (conf.hookingLogActive)
	{		
		if(conf.hcallConfs[InputValue.CallCode].log || conf.hookingLogAll)
		{			
			PHV_WORKER_LOG_DATA data = (PHV_WORKER_LOG_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(HV_WORKER_LOG_DATA), 0x76687668);
			data->WorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(WORK_QUEUE_ITEM), 0x76687668);
			if (InputPa == NULL)
				data->bufferIn = NULL;
			else
				data->bufferIn = ExAllocatePoolWithTag(NonPagedPoolNx, conf.logSize, 0x76687668);
			if (InputValue.IsFast)
			{
				data->param1 = InputPa;
				data->param2 = OutputPa;
			}
			data->input = InputValue;

			if (data->bufferIn)
			{
				SIZE_T size;
				_MM_COPY_ADDRESS addr;
				addr.PhysicalAddress.QuadPart = InputPa;
				MmCopyMemory(data->bufferIn, addr, conf.logSize, MM_COPY_MEMORY_PHYSICAL, &size);
			}
			ExInitializeWorkItem(data->WorkItem, LogRoutine, data);
			ExQueueWorkItem(data->WorkItem, DelayedWorkQueue);
		}
	}

	if (conf.hcallConfs[InputValue.CallCode].fuzz)
	{
		conf.hcallConfs[InputValue.CallCode].fuzz--;

		if (InputValue.IsFast)
			return;

		ULONGLONG inPA;
		PMDL inMdl = NULL;
		UINT8* inVM = NULL;
		SIZE_T size;
		
		if (generateMDL(conf.logSize, &inPA, &inMdl, (PVOID*)&inVM) != STATUS_SUCCESS)
			return;

		_MM_COPY_ADDRESS addr;
		addr.PhysicalAddress.QuadPart = InputPa;
		MmCopyMemory(inVM, addr, conf.logSize, MM_COPY_MEMORY_PHYSICAL, &size);

		DbgPrint("Fuzzing hypercall 0x%X during making\n", InputValue.CallCode);
		for (int x = 0; x < 0x1000; x++)
		{
			for (int y = 0; y < 0x100; y++)
			{
				inVM[x]++;
				__try
				{
					HvlInvokeHypercall(InputValue, inPA, OutputPa);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
				}
			}
		}

		if (inMdl)
		{
			MmFreePagesFromMdlEx(inMdl, 0);
			ExFreePool(inMdl);
		}
	}
}

void Hypercall::LogRoutine(PVOID Parameter)
{
	PHV_WORKER_LOG_DATA data = (PHV_WORKER_LOG_DATA)Parameter;

	ExAcquireFastMutex(&logHandleLock);	
	if (logHandle && (conf.hcallConfs[data->input.CallCode].log || conf.hookingLogAll))
	{
		if (conf.hcallConfs[data->input.CallCode].log)
			conf.hcallConfs[data->input.CallCode].log--;

		DbgPrint("Logging hypercall info for hypercall 0x%X\n", data->input.CallCode);
		IO_STATUS_BLOCK    ioStatusBlock;
		ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &(data->input), sizeof(_HV_X64_HYPERCALL_INPUT), NULL, NULL);
		if (data->input.IsFast)
		{
			ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &data->param1, sizeof(UINT64), NULL, NULL);
			ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &data->param2, sizeof(UINT64), NULL, NULL);
		}
		else
		{
			if (data->bufferIn)
			{
				ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &conf.logSize, sizeof(UINT32), NULL, NULL);
				ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, data->bufferIn, conf.logSize, NULL, NULL);
			}
			else
			{
				ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, "\x00\x00\x00\x00", sizeof(UINT32), NULL, NULL);
			}
		}
	}
	ExReleaseFastMutex(&logHandleLock);

	ExFreePool(data->WorkItem);
	if (data->bufferIn)
		ExFreePool(data->bufferIn);
	ExFreePool(data);
}


NTSTATUS Hypercall::hypercall(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen, void* bufferOut, UINT32 bufferOutLen, PHV_X64_HYPERCALL_OUTPUT hvOutput)
{
	__debugbreak();
	NTSTATUS status = STATUS_SUCCESS;
	ULONGLONG inPA, outPA;
	PMDL inMdl = NULL, outMdl = NULL;

	if (hvInput.IsFast && bufferInLen != 16)
		return STATUS_NDIS_INVALID_LENGTH;

	if (hvInput.IsFast)
	{
		inPA = ((ULONGLONG*)bufferIn)[0];
		outPA = ((ULONGLONG*)bufferIn)[1];
	}
	else
	{
		status = generateMDLs(bufferIn, bufferInLen, bufferOutLen, &inPA, &inMdl, &outPA, &outMdl);
	}


	if (status == STATUS_SUCCESS)
	{
		__try
		{
			DbgPrint("Making hypercall: code=0x%X   fast=0x%X   count=0x%X   index=0x%X  input_len = 0x%X\n", hvInput.CallCode, hvInput.IsFast, hvInput.CountOfElements, hvInput.RepStartIndex, bufferInLen);
			*hvOutput = HvlInvokeHypercall(hvInput, inPA, outPA);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_ILLEGAL_INSTRUCTION;
		}
	}

	if (status == STATUS_SUCCESS && !hvInput.IsFast)
	{
		if (hvOutput->CallStatus == 0x0)
		{
			void* ptr = MmGetSystemAddressForMdlSafe(outMdl, NormalPagePriority);
			if (ptr)
			{
				RtlCopyMemory(bufferOut, ptr, bufferOutLen);
			}
			else
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}
	}
	if (inMdl)
	{
		MmFreePagesFromMdlEx(inMdl, 0);
		ExFreePool(inMdl);
	}
	if (outMdl)
	{
		MmFreePagesFromMdlEx(outMdl, 0);
		ExFreePool(outMdl);
	}
	return status;
}

NTSTATUS Hypercall::hook()
{
	if (originalHypercallLocation)
		return STATUS_INVALID_DEVICE_REQUEST;

	UINT8* ptr = (UINT8*)& HvlInvokeHypercall;
	ptr += 7;
	UINT32 offset = *((UINT32*)ptr);
	ptr += offset + 4;
	originalHypercallLocation = *(UINT64*)ptr;
	*((UINT64*)ptr) = ((UINT64)& hypercallHook);
	originalHypercallPre = (UINT64)& preHypercall;
	return STATUS_SUCCESS;
}

NTSTATUS Hypercall::unhook()
{

	if (!originalHypercallLocation)
		return STATUS_INVALID_DEVICE_REQUEST;

	UINT8* ptr = (UINT8*)& HvlInvokeHypercall;
	ptr += 7;
	UINT32 offset = *((UINT32*)ptr);
	ptr += offset + 4;
	*((UINT64*)ptr) = originalHypercallLocation;
	originalHypercallLocation = NULL;
	originalHypercallPre = NULL;
	conf.hookingActivated = 0;

	if (logHandle)
	{
		ExAcquireFastMutex(&logHandleLock);
		ZwClose(logHandle);
		logHandle = NULL;
		ExReleaseFastMutex(&logHandleLock);
	}
	return STATUS_SUCCESS;
}


NTSTATUS Hypercall::logToFile(PUNICODE_STRING filename)
{
	if (logHandle)
		return STATUS_INVALID_DEVICE_REQUEST;
	OBJECT_ATTRIBUTES  objAttr;
	InitializeObjectAttributes(&objAttr, filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	IO_STATUS_BLOCK    ioStatusBlock;
	NTSTATUS ntstatus = ZwCreateFile(&logHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(ntstatus))
	{
		logHandle = NULL;
		return ntstatus;
	}
	ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, "HVCL", 4, NULL, NULL); //HyperViper Call Log/List
	conf.hookingLogActive = 1;
	return STATUS_SUCCESS;
}

void Hypercall::getConf(PHV_HOOKING_CONF confOut)
{
	memcpy(confOut, &conf, sizeof(HV_HOOKING_CONF));
}

void Hypercall::setConf(PHV_HOOKING_CONF confIn)
{
	memcpy(&conf, confIn, sizeof(HV_HOOKING_CONF));
}

void Hypercall::getStats(PHYPERCALL_STATUSES conf)
{
	memcpy(conf, hypercallStats, sizeof(HYPERCALL_STATUSES));
}

NTSTATUS Hypercall::fuzzByAdd(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONGLONG inPA, outPA;
	PMDL inMdl = NULL, outMdl = NULL;

	if (hvInput.IsFast && bufferInLen != 16)
		return STATUS_NDIS_INVALID_LENGTH;

	if (hvInput.IsFast)
	{
		inPA = ((ULONGLONG*)bufferIn)[0];
		outPA = ((ULONGLONG*)bufferIn)[1];
	}
	else
	{
		status = generateMDLs(bufferIn, bufferInLen, 0x1000, &inPA, &inMdl, &outPA, &outMdl);
	}


	if (status == STATUS_SUCCESS)
	{
		DbgPrint("Fuzzing(ADDING) hypercall 0x%02X (%s)\n", hvInput.CallCode, (hvInput.IsFast ? "FAST" : "SLOW"));
		INT8* ptr = NULL;
		if (inMdl)
			ptr = (INT8*)MmGetSystemAddressForMdlSafe(inMdl, MdlMappingNoExecute);
		for (UINT64 x = 0; x < bufferInLen; x++)
		{
			ULONGLONG add = (UINT64)0x1 << ((x % 8) * 0x8);
			for (int y = 0; y < 0x100; y++)
			{
				__try
				{
					HvlInvokeHypercall(hvInput, inPA, outPA);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
				}
				if (hvInput.IsFast)
				{
					if (x < 8)
						inPA += add;
					else
						outPA += add;
				}
				else
				{
					ptr[x]++;
				}
			}
		}
	}

	if (!hvInput.IsFast)
	{
		if (inMdl)
		{
			MmFreePagesFromMdlEx(inMdl, 0);
			ExFreePool(inMdl);
		}
		if (outMdl)
		{
			MmFreePagesFromMdlEx(outMdl, 0);
			ExFreePool(outMdl);
		}
	}
	return status;
}

NTSTATUS Hypercall::fuzzBySpecialValues(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen)
{
	if (hvInput.IsFast)
		return STATUS_SUCCESS;
	UINT16 special16[] = { 0x00000000, 0xFFFF, 0x7F00, 0x7FFF, 0x8000, 0xFF00, 0xFFFE, 0x0001 };
	UINT32 special32[] = { 0x00000000, 0xFFFFFFFF, 0x7F000000, 0x7FFFFFFF, 0x80000000, 0xFF000000, 0xFFFFFFFE, 0x00000001 };
	UINT64 special64[] = { 0x0000000000000000, 0xFFFFFFFFFFFFFFFF, 0x7F00000000000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFF00000000000000, 0xFFFFFFFFFFFFFFFE, 0x0000000000000001 };

	NTSTATUS status = STATUS_SUCCESS;
	ULONGLONG inPA, outPA;
	PMDL inMdl = NULL, outMdl = NULL;

	if (hvInput.IsFast && bufferInLen != 16)
		return STATUS_NDIS_INVALID_LENGTH;

	if (hvInput.IsFast)
	{
		inPA = ((ULONGLONG*)bufferIn)[0];
		outPA = ((ULONGLONG*)bufferIn)[1];
	}
	else
	{
		status = generateMDLs(bufferIn, bufferInLen, 0x1000, &inPA, &inMdl, &outPA, &outMdl);
	}


	if (status == STATUS_SUCCESS)
	{
		DbgPrint("Fuzzing(SPECIAL VALUES) hypercall 0x%02X (%s)\n", hvInput.CallCode, (hvInput.IsFast ? "FAST" : "SLOW"));
		INT8* ptr = NULL;
		if (inMdl)
			ptr = (INT8*)MmGetSystemAddressForMdlSafe(inMdl, MdlMappingNoExecute);

		for (UINT64 x = 0; x < bufferInLen - 1; x++)
		{
			UINT16 original = *(PUINT16)(ptr + x);
			for (int y = 0; y < 8; y++)
			{
				*(PUINT16)(ptr + x) = special16[y];
				__try
				{
					HvlInvokeHypercall(hvInput, inPA, outPA);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
				}

			}
			*(PUINT16)(ptr + x) = original;
		}

		for (UINT64 x = 0; x < bufferInLen - 3; x++)
		{
			UINT32 original = *(PUINT32)(ptr + x);
			for (int y = 0; y < 8; y++)
			{
				*(PUINT32)(ptr + x) = special32[y];
				__try
				{
					HvlInvokeHypercall(hvInput, inPA, outPA);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
				}

			}
			*(PUINT32)(ptr + x) = original;
		}

		for (UINT64 x = 0; x < bufferInLen - 7; x++)
		{
			UINT64 original = *(PUINT64)(ptr + x);
			for (int y = 0; y < 8; y++)
			{
				*(PUINT64)(ptr + x) = special64[y];
				__try
				{
					HvlInvokeHypercall(hvInput, inPA, outPA);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
				}

			}
			*(PUINT64)(ptr + x) = original;
		}
	}

	if (!hvInput.IsFast)
	{
		if (inMdl)
		{
			MmFreePagesFromMdlEx(inMdl, 0);
			ExFreePool(inMdl);
		}
		if (outMdl)
		{
			MmFreePagesFromMdlEx(outMdl, 0);
			ExFreePool(outMdl);
		}
	}
	return status;
}