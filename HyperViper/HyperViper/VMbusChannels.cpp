#include "VMbusChannels.h"
#include "HVstructures.h"

PVOID VMbusChannels::kmclChannelListLocation = NULL;
PFN_VMB_PACKET_GET_EXTERNAL_DATA VMbusChannels::VmbChannelPacketGetExternalData = NULL;
PFN_VMB_CHANNEL_PROCESS_PACKET VMbusChannels::hookedCorrectPacketHandler = NULL;
PFN_VMB_PACKET_ALLOCATE VMbusChannels::VmbPacketAllocate = NULL;
PFN_VMB_PACKET_SEND VMbusChannels::VmbPacketSend = NULL;
GUID VMbusChannels::hookedChannelGUID;
HANDLE VMbusChannels::logHandle;
FAST_MUTEX VMbusChannels::logHandleLock;
bool VMbusChannels::sentPacketHandled = true;
UINT32 VMbusChannels::lastPacketsStored[16];
UINT32 VMbusChannels::lastPacketsStoredCount = 0;


void VMbusChannels::init(void)
{
	//Find KmclChannelList
	PUINT8 ptr, driver;
	driver = (PUINT8)KernelGetModuleBase("vmbkmclr.sys");
	if(!driver)
		driver = (PUINT8)KernelGetModuleBase("vmbkmcl.sys");
	if(driver)
	{
		LONG WPP_MAIN_CB_OFFSET = 0x130E0; //  vmbkmcl.sys build 10.0.19044.1526, offset 0x130E0 ==> vmbkmcl!WPP_MAIN_CB 
		if (driver)
		{
		    //kmclChannelListLocation = poi(vmbkmcl+0x130e0+WPP_MAIN_CB_OFFSET)+0x20 (within windbg)
		    kmclChannelListLocation = (PVOID)((UINT64)driver + WPP_MAIN_CB_OFFSET);   // vmbkmcl!WPP_MAIN_CB
		    kmclChannelListLocation = (PVOID)((UINT64)kmclChannelListLocation + 0xA0);          // vmbkmcl!WPP_MAIN_CB.DeviceQueue
		    kmclChannelListLocation = (PVOID)(*(PUINT64)kmclChannelListLocation + 0x20);        // vmbkmcl!WPP_MAIN_CB.DeviceQueue.kmclChannelListLocation
		}
		VmbChannelPacketGetExternalData = (PFN_VMB_PACKET_GET_EXTERNAL_DATA)KernelGetProcAddress(driver, "VmbChannelPacketGetExternalData");
		VmbPacketAllocate = (PFN_VMB_PACKET_ALLOCATE)KernelGetProcAddress(driver, "VmbPacketAllocate");
		VmbPacketSend = (PFN_VMB_PACKET_SEND)KernelGetProcAddress(driver, "VmbPacketSend");
	}

	ExInitializeFastMutex(&logHandleLock);
}

void VMbusChannels::close(void)
{
	unhookChannel();
}


PVMBUS_CHANNEL_INTERNAL VMbusChannels::getChannelList()
{
	if (!kmclChannelListLocation)
		return NULL;
	PVMBUS_CHANNEL_INTERNAL result = *((PVMBUS_CHANNEL_INTERNAL*)kmclChannelListLocation);
	if (!result || result == kmclChannelListLocation)
		return NULL;
	result = (PVMBUS_CHANNEL_INTERNAL)((UINT64)result - 0x760);
	return result;
}

UINT32 VMbusChannels::getChannelsCount()
{
	PVMBUS_CHANNEL_INTERNAL channel;
	UINT32 count = 0;

	channel = getChannelList();
	if (!channel)
		return 0;
	while (true)
	{
		if (channel->ptrToMyself != channel)
			return 0;
		count++;
		channel = channel->next;
		if (!channel || channel == kmclChannelListLocation)
			break;
		channel = (PVMBUS_CHANNEL_INTERNAL)((UINT64)channel - 0x760);
	}
	return count;
}

PVMBUS_CHANNEL_INTERNAL VMbusChannels::getChannel(GUID guid)
{
	PVMBUS_CHANNEL_INTERNAL channel;
	channel = getChannelList();
	if (!channel)
		return NULL;
	while (true)
	{
		if (channel->ptrToMyself != channel)
			return NULL;

		if (!memcmp(&(channel->id), &guid, sizeof(GUID)))
			return channel;

		channel = channel->next;
		if (!channel || channel == kmclChannelListLocation)
			break;
		channel = (PVMBUS_CHANNEL_INTERNAL)((UINT64)channel - 0x760);
	}
	return NULL;
}

PVMBUS_CHANNEL VMbusChannels::getAllChannels(PUINT32 count)
{
	PVMBUS_CHANNEL_INTERNAL channel;
	PVMBUS_CHANNEL result = NULL;

	*count = getChannelsCount();
	if (!count)
		return NULL;

	result = (VMBUS_CHANNEL*)ExAllocatePoolWithTag(NonPagedPoolNx, (*count) * sizeof(VMBUS_CHANNEL), 0x76687668);
	if (!result)
		return NULL;
	memset(result, 0x00, (*count) * sizeof(VMBUS_CHANNEL));
	
	channel = getChannelList();
	if (!channel)
	{
		ExFreePool(result);
		return NULL;
	}
	for (UINT32 x=0; x < *count; x++)
	{
		if (channel->ptrToMyself != channel)
		{
			ExFreePool(result);
			return NULL;
		}

		result[x].clientContextSize = channel->clientContextSize;
		result[x].isPipe = channel->isPipe;
		result[x].maxExternalDataSize = channel->maxExternalDataSize;
		result[x].maxNrOfMDLs = channel->maxNrOfMDLs;
		result[x].maxNrOfPackets = channel->maxNrOfPackets;
		result[x].maxPacketSize = channel->maxPacketSize;
		result[x].nrOfPagesToAllocateInIncomingRingBuffer = channel->nrOfPagesToAllocateInIncomingRingBuffer;
		result[x].nrOfPagesToAllocateInOutgoingRingBuffer = channel->nrOfPagesToAllocateInOutgoingRingBuffer;
		result[x].vmBusHandle = channel->vmBusHandle;
		result[x].vmID = channel->vmID;
		result[x].vtlLevel = channel->vtlLevel;
		memcpy(&(result[x].id),  &(channel->id), sizeof(GUID));
		if (channel->name.Length && channel->name.Buffer)
			memcpy(result[x].name, channel->name.Buffer, min(channel->name.Length, 63));

		channel = channel->next;
		if (!channel || channel == kmclChannelListLocation)
			break;
		channel = (PVMBUS_CHANNEL_INTERNAL)((UINT64)channel - 0x760);
	}
	return result;
}

bool VMbusChannels::overwriteChannelProcessPacket(GUID guid, PVOID newPtr, PVOID* oldPtr)
{
	PVMBUS_CHANNEL_INTERNAL channel;
	channel = getChannelList();
	if (!channel)
		return false;
	while (true)
	{
		if (channel->ptrToMyself != channel)
			return false;
		
		if (!memcmp(&(channel->id), &guid, sizeof(GUID)))
		{
			if(oldPtr)
				*oldPtr = channel->callbackProcessPacket;
			channel->callbackProcessPacket = newPtr;
			return true;
		}

		channel = channel->next;
		if (!channel || channel == kmclChannelListLocation)
			break;
		channel = (PVMBUS_CHANNEL_INTERNAL)((UINT64)channel - 0x760);
	}
	return false;
}

bool VMbusChannels::hookChannel(GUID guid)
{
	if (!hookedCorrectPacketHandler && overwriteChannelProcessPacket(guid, (PVOID)& processPacketHookFunc, (PVOID*)& hookedCorrectPacketHandler))
	{
		memcpy(&hookedChannelGUID, &guid, sizeof(GUID));
		return true;
	}
	return false;
}

bool VMbusChannels::unhookChannel()
{
	if (hookedCorrectPacketHandler)
		overwriteChannelProcessPacket(hookedChannelGUID, hookedCorrectPacketHandler, NULL);
	hookedCorrectPacketHandler = NULL;

	if (logHandle)
	{
		ExAcquireFastMutex(&logHandleLock);
		ZwClose(logHandle);
		logHandle = NULL;
		ExReleaseFastMutex(&logHandleLock);
	}
	return true;
}

VOID VMbusChannels::processPacketHookFunc(PVMBUS_CHANNEL_INTERNAL Channel, PVOID Packet, PVOID Buffer, UINT32 BufferLength, UINT32 Flags)
{
	if (logHandle)
	{
		PHV_WORKER_LOG_CHANNEL_DATA data = (PHV_WORKER_LOG_CHANNEL_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(HV_WORKER_LOG_CHANNEL_DATA), 0x76687668);
		data->WorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(WORK_QUEUE_ITEM), 0x76687668);
		memcpy(&(data->guid), &(Channel->id), sizeof(GUID));
		data->mainBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, BufferLength, 0x76687668);
		data->mainBufferSize = BufferLength;
		memcpy(data->mainBuffer, Buffer, BufferLength);
		data->mdlBuffer = NULL;
		data->mdlBufferSize = 0;
		if (Flags && VmbChannelPacketGetExternalData)
		{
			PMDL mdl;
			VmbChannelPacketGetExternalData(Packet, 0, &mdl);
			data->mdlBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, mdl->ByteCount, 0x76687668);
			data->mdlBufferSize = mdl->ByteCount;
			PVOID ptr = MmGetSystemAddressForMdlSafe(mdl, MdlMappingNoExecute);
			memcpy(data->mdlBuffer, ptr, mdl->ByteCount);
		}

		ExInitializeWorkItem(data->WorkItem, LogRoutine, data);
		ExQueueWorkItem(data->WorkItem, DelayedWorkQueue);
	}
	
	hookedCorrectPacketHandler(Channel, Packet, Buffer, BufferLength, Flags);	
}

void VMbusChannels::LogRoutine(PVOID Parameter)
{
	PHV_WORKER_LOG_CHANNEL_DATA data = (PHV_WORKER_LOG_CHANNEL_DATA)Parameter;
	UINT32 crc = 0;
	bool isUnique = true;

	for (UINT32 x = 0; x < data->mainBufferSize; x++)
		crc = (crc >> 8) ^ Utils::Crc32Lookup[(crc & 0xFF) ^ ((PUINT8)(data->mainBuffer))[x]];
	for (UINT32 x = 0; x < data->mdlBufferSize; x++)
		crc = (crc >> 8) ^ Utils::Crc32Lookup[(crc & 0xFF) ^ ((PUINT8)(data->mdlBuffer))[x]];


	ExAcquireFastMutex(&logHandleLock);

	for (UINT32 x = 0; x < min(lastPacketsStoredCount, 16); x++)
	{
		if (crc == lastPacketsStored[x])
		{
			isUnique = false;
			break;
		}
	}

	if (isUnique)
	{
		lastPacketsStored[lastPacketsStoredCount++ % 16] = crc;

		if (logHandle)
		{
			IO_STATUS_BLOCK    ioStatusBlock;
			ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &(data->guid), sizeof(GUID), NULL, NULL);
			ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &(data->mainBufferSize), sizeof(UINT32), NULL, NULL);
			ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, data->mainBuffer, data->mainBufferSize, NULL, NULL);
			ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, &(data->mdlBufferSize), sizeof(UINT32), NULL, NULL);
			if (data->mdlBufferSize)
				ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, data->mdlBuffer, data->mdlBufferSize, NULL, NULL);
		}
	}

	ExReleaseFastMutex(&logHandleLock);
	ExFreePool(data->WorkItem);
	ExFreePool(data->mainBuffer);
	if (data->mdlBufferSize)
		ExFreePool(data->mdlBuffer);
	ExFreePool(data);
}

NTSTATUS VMbusChannels::logToFile(PUNICODE_STRING filename)
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
	ZwWriteFile(logHandle, NULL, NULL, NULL, &ioStatusBlock, "HVCH", 4, NULL, NULL); //HyperViper CHannel recording
	return STATUS_SUCCESS;
}

NTSTATUS VMbusChannels::stopLog(void)
{
	ExAcquireFastMutex(&logHandleLock);
	ZwClose(logHandle);
	logHandle = NULL;
	lastPacketsStoredCount = 0;
	ExReleaseFastMutex(&logHandleLock);
	return STATUS_SUCCESS;
}

NTSTATUS VMbusChannels::sendPacket(GUID guid, PVOID buffer, UINT32 bufferLen, PVOID bufferMdl, UINT32 bufferMdlLen)
{
	PVMBUS_CHANNEL_INTERNAL channel = getChannel(guid);
	if (!channel)
		return STATUS_INVALID_MEMBER;

	PMDL mdl = NULL;
	if (bufferMdlLen > 0)
	{
		mdl = IoAllocateMdl(
			bufferMdl,
			bufferMdlLen,
			FALSE,
			FALSE,
			NULL
		);
		MmBuildMdlForNonPagedPool(mdl);
	}

	VMBPACKETCOMPLETION vmbPacket = VmbPacketAllocate((VMBCHANNEL)channel);
	((PUINT64)vmbPacket)[8] = (UINT64)& setPacketHandled;
	sentPacketHandled = false;
	NTSTATUS status = VmbPacketSend(vmbPacket, buffer, bufferLen, mdl, 0x1);
	
	if (status == STATUS_SUCCESS)
	{
		while (!sentPacketHandled)
		{
			INT64 interval = 10 * -10000i64;
			KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)& interval);
		}
	}

	return status;
}

NTSTATUS VMbusChannels::fuzzPacket(GUID guid, PVOID buffer, UINT32 bufferLen, PVOID bufferMdl, UINT32 bufferMdlLen, PVMBUS_CHANNEL_PACKET_FUZZ_CONF conf)
{
	PVMBUS_CHANNEL_INTERNAL channel = getChannel(guid);
	if (!channel)
		return STATUS_INVALID_MEMBER;

	PMDL mdl = NULL;
	if (bufferMdlLen > 0)
	{
		mdl = IoAllocateMdl(
			bufferMdl,
			bufferMdlLen,
			FALSE,
			FALSE,
			NULL
		);
		MmBuildMdlForNonPagedPool(mdl);
	}


	DbgPrint("[fuzzPacket] Fuzzing conf:\n");
	DbgPrint("  Main buffer: 0x%X bytes\n", bufferLen);
	DbgPrint("  MDL buffer: 0x%X bytes\n", bufferMdlLen);
	DbgPrint("  fuzzIncrementMain: 0x%X\n", conf->fuzzIncrementMain);
	DbgPrint("  fuzzIncrementMdl: 0x%X\n", conf->fuzzIncrementMdl);
	DbgPrint("  fuzzRandomMain: 0x%X\n", conf->fuzzRandomMain);
	DbgPrint("  fuzzRandomMdl: 0x%X\n", conf->fuzzRandomMdl);

	if(conf->fuzzIncrementMain || (conf->fuzzIncrementMdl && mdl))
		fuzzPacketIncremental(channel, buffer, bufferLen, mdl, conf->fuzzIncrementMain, conf->fuzzIncrementMdl);
	if(conf->fuzzRandomMain || conf->fuzzRandomMdl)
	fuzzPacketRandom(channel, buffer, bufferLen, mdl, conf->fuzzRandomMain, conf->fuzzRandomMdl);
	
	if (mdl)
		IoFreeMdl(mdl);
	return STATUS_SUCCESS;
}

VOID VMbusChannels::setPacketHandled(PVOID packet, NTSTATUS status, PVOID buffer, UINT32 bufferLen)
{
	sentPacketHandled = true;
}

NTSTATUS VMbusChannels::fuzzPacketIncremental(PVMBUS_CHANNEL_INTERNAL channel, PVOID buffer, UINT32 bufferLen, PMDL mdl, UINT8 fuzzMain, UINT8 fuzzMdl)
{
	if (fuzzMain)
	{
		for (UINT32 x = 0; x < bufferLen && fuzzMain; x++)
		{
			DbgPrint("[fuzzPacketIncremental] Incrementing main buffer at position 0x%X\n", x);
			for (int y = 0; y < 0x100; y++)
			{
				((PINT8)buffer)[x]++;
				if (y == 0xFF)
					break;
				VMBPACKETCOMPLETION vmbPacket = VmbPacketAllocate((VMBCHANNEL)channel);
				((PUINT64)vmbPacket)[8] = (UINT64)&setPacketHandled;
				sentPacketHandled = false;
				NTSTATUS status = VmbPacketSend(vmbPacket, buffer, bufferLen, mdl, 0x1);
				if (status)
				{
					DbgPrint("[FAILURE] status=0x%X   x=0x%X   y=0x%X\n", status, x, y);
					return STATUS_SUCCESS;
				}
				while (!sentPacketHandled)
				{
					INT64 interval = 10 * -10000i64;
					KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&interval);
				}
			}
		}
	}
	if (mdl && fuzzMdl)
	{
		PUINT8 ptr = (PUINT8)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
		for (UINT32 x = 0; x < min(mdl->ByteCount, 0x100); x++)
		{
			DbgPrint("[fuzzPacketIncremental] Incrementing MDL at position 0x%X\n", x);
			for (int y = 0; y < 0x100; y++)
			{
				ptr[x]++;
				if (y == 0xFF)
					break;

				VMBPACKETCOMPLETION vmbPacket = VmbPacketAllocate((VMBCHANNEL)channel);
				((PUINT64)vmbPacket)[8] = (UINT64)& setPacketHandled;
				sentPacketHandled = false;
				NTSTATUS status = VmbPacketSend(vmbPacket, buffer, bufferLen, mdl, 0x1);
				if (status)
				{
					DbgPrint("[FAILURE] status=0x%X   x=0x%X   y=0x%X\n", status, x, y);
					return STATUS_SUCCESS;
				}
				while (!sentPacketHandled)
				{
					INT64 interval = 10 * -10000i64;
					KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)& interval);
				}
			}
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS VMbusChannels::fuzzPacketRandom(PVMBUS_CHANNEL_INTERNAL channel, PVOID buffer, UINT32 bufferLen, PMDL mdl, UINT64 countMain, UINT64 countMdl)
{
	UINT64 changes[8][2];

	while (countMain--)
	{
		if (countMain % 100 == 0)
			DbgPrint("[fuzzPacketRandom] Fuzzing main buffer, %d tries left, current seed 0x%llX\n", countMain, Utils::getCurrentSeed());
		UINT64 changeCount = (Utils::rand() % 8) + 1;
		for (UINT64 x = 0; x < changeCount; x++)
		{
			changes[x][0] = Utils::rand() % bufferLen;
			changes[x][1] = ((PUINT8)buffer)[changes[x][0]];
			((PUINT8)buffer)[changes[x][0]] = (UINT8)(Utils::rand() % 0x100);
		}

		VMBPACKETCOMPLETION vmbPacket = VmbPacketAllocate((VMBCHANNEL)channel);
		((PUINT64)vmbPacket)[8] = (UINT64)&setPacketHandled;
		sentPacketHandled = false;
		NTSTATUS status = VmbPacketSend(vmbPacket, buffer, bufferLen, mdl, 0x1);
		if (status)
		{
			DbgPrint("[FAILURE] status=0x%X\n", status);
			return STATUS_SUCCESS;
		}
		while (!sentPacketHandled)
		{
			INT64 interval = 10 * -10000i64;
			KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&interval);
		}

		for (UINT64 x = changeCount - 1; x > 0; x--)
			((PUINT8)buffer)[changes[x][0]] = (UINT8)changes[x][1];
		((PUINT8)buffer)[changes[0][0]] = (UINT8)changes[0][1];
	}
		
	while (mdl && countMdl--)
	{
		PUINT8 ptr = (PUINT8)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
		if (countMdl % 100 == 0)
			DbgPrint("[fuzzPacketRandom] Fuzzing MDL, %d tries left, current seed 0x%llX\n", countMdl, Utils::getCurrentSeed());
		UINT64 changeCount = (Utils::rand() % 8) + 1;
		for (UINT64 x = 0; x < changeCount; x++)
		{
			changes[x][0] = Utils::rand() % bufferLen;
			changes[x][1] = ptr[changes[x][0]];
			ptr[changes[x][0]] = (UINT8)(Utils::rand() % 0x100);
		}

		VMBPACKETCOMPLETION vmbPacket = VmbPacketAllocate((VMBCHANNEL)channel);
		((PUINT64)vmbPacket)[8] = (UINT64)&setPacketHandled;
		sentPacketHandled = false;
		NTSTATUS status = VmbPacketSend(vmbPacket, buffer, bufferLen, mdl, 0x1);
		if (status)
		{
			DbgPrint("[FAILURE] status=0x%X\n", status);
			return STATUS_SUCCESS;
		}
		while (!sentPacketHandled)
		{
			INT64 interval = 10 * -10000i64;
			KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&interval);
		}

		for (UINT64 x = changeCount - 1; x > 0; x--)
			ptr[changes[x][0]] = (UINT8)changes[x][1];
		ptr[changes[0][0]] = (UINT8)changes[0][1];
	}
	return STATUS_SUCCESS;
}
