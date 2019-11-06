#pragma once
#include "CodeStolenFromOthers.h"
#include "HVstructures.h"
#include "Utils.h"

typedef struct _VMBUS_CHANNEL_INTERNAL
{
	_VMBUS_CHANNEL_INTERNAL* ptrToMyself;
	UINT8 filler1[0x604 - 0x8];
	UINT32 maxNrOfPackets;  //0x604
	UINT32 maxPacketSize;  //0x608
	UINT32 maxExternalDataSize;  //0x60C
	UINT32 maxNrOfMDLs;  //0x610
	UINT32 clientContextSize;  //0x614
	UINT8 filler2[0x638 - 0x614];
	UINT8 isPipe;  //0x63C
	UINT8 filler3[0x64C - 0x63D];
	UINT16 vmID;  //0x64C
	UINT8 filler4[0x6D8 - 0x64E];
	UINT64 vmBusHandle;  //0x6D8
	UINT32 nrOfPagesToAllocateInIncomingRingBuffer;  //0x6E0
	UINT32 nrOfPagesToAllocateInOutgoingRingBuffer;  //0x6E4
	UINT8 filler5[0x6FA - 0x6E8];
	UINT8 vtlLevel;  //0x6FA
	UINT8 filler6[0x700 - 0x6FB];
	PVOID callbackProcessPacket; //0x700
	PVOID callbackProcessingComplete; //0x708
	UINT8 filler7[0x738 - 0x710];
	PVOID callbackChannelOpened; //0x738
	PVOID callbackChannelClosed; //0x740
	PVOID callbackChannelSuspended; //0x748
	PVOID callbackChannelStarted; //0x750
	UINT8 filler8[0x760 - 0x758];
	_VMBUS_CHANNEL_INTERNAL* next; //0x760
	UINT8 filler9[0x788 - 0x768];
	UNICODE_STRING name; //0x788	
	UINT8 fillerA[0x7F8 - 0x788	- sizeof(UNICODE_STRING)];
	PVOID ptr; //0x7F8
	UINT8 fillerB[0x940 - 0x800];
	PVOID targetDeviceObject; //0x940
	UINT8 fillerC[0x960 - 0x948];
	GUID id; //0x960
	UINT8 fillerD[0xB00 - 0x970];
	PVOID parentDeviceObject; //0xB00
} VMBUS_CHANNEL_INTERNAL, * PVMBUS_CHANNEL_INTERNAL;

typedef struct _HV_WORKER_LOG_CHANNEL_DATA
{
	PWORK_QUEUE_ITEM WorkItem;
	GUID guid;
	PVOID mainBuffer;
	UINT32 mainBufferSize;
	PVOID mdlBuffer;
	UINT32 mdlBufferSize;
} HV_WORKER_LOG_CHANNEL_DATA, * PHV_WORKER_LOG_CHANNEL_DATA;

typedef PVOID VMBCHANNEL;
typedef PVOID VMBPACKETCOMPLETION;

typedef VOID EVT_VMB_CHANNEL_PROCESS_PACKET(VMBCHANNEL, VMBPACKETCOMPLETION, PVOID, UINT32, UINT32);
typedef EVT_VMB_CHANNEL_PROCESS_PACKET* PFN_VMB_CHANNEL_PROCESS_PACKET;

typedef VOID EVT_VMB_PACKET_GET_EXTERNAL_DATA(VMBPACKETCOMPLETION, UINT32, PMDL*);
typedef EVT_VMB_PACKET_GET_EXTERNAL_DATA* PFN_VMB_PACKET_GET_EXTERNAL_DATA;

typedef VMBPACKETCOMPLETION EVT_VMB_PACKET_ALLOCATE(VMBCHANNEL);
typedef EVT_VMB_PACKET_ALLOCATE* PFN_VMB_PACKET_ALLOCATE;

typedef NTSTATUS EVT_VMB_PACKET_SEND(VMBPACKETCOMPLETION, PVOID, UINT32, PMDL, UINT32);
typedef EVT_VMB_PACKET_SEND* PFN_VMB_PACKET_SEND;


class VMbusChannels
{
private:
	static PVOID kmclChannelListLocation;
	static PFN_VMB_PACKET_GET_EXTERNAL_DATA VmbChannelPacketGetExternalData;
	static PFN_VMB_PACKET_ALLOCATE VmbPacketAllocate;
	static PFN_VMB_PACKET_SEND VmbPacketSend;
	static bool sentPacketHandled;
	static UINT32 lastPacketsStored[16];
	static UINT32 lastPacketsStoredCount;

	static PFN_VMB_CHANNEL_PROCESS_PACKET hookedCorrectPacketHandler;
	static GUID hookedChannelGUID;
	static HANDLE logHandle;
	static FAST_MUTEX logHandleLock;

	static PVMBUS_CHANNEL_INTERNAL getChannelList();
	static bool overwriteChannelProcessPacket(GUID guid, PVOID newPtr, PVOID* oldPtr);

	static VOID processPacketHookFunc(PVMBUS_CHANNEL_INTERNAL, PVOID, PVOID, UINT32, UINT32);
	static void	LogRoutine(PVOID Parameter);
	static VOID setPacketHandled(PVOID, NTSTATUS, PVOID, UINT32);
public:
	static void init(void);
	static void close(void);

	static PVMBUS_CHANNEL_INTERNAL getChannel(GUID guid);
	static UINT32 getChannelsCount();
	static PVMBUS_CHANNEL getAllChannels(PUINT32 count);

	static bool hookChannel(GUID guid);
	static bool unhookChannel();
	
	static NTSTATUS logToFile(PUNICODE_STRING filename);
	static NTSTATUS stopLog(void);

	static NTSTATUS sendPacket(GUID, PVOID, UINT32, PVOID, UINT32);
	static NTSTATUS fuzzPacket(GUID, PVOID, UINT32, PVOID, UINT32, PVMBUS_CHANNEL_PACKET_FUZZ_CONF);

	static NTSTATUS fuzzPacketIncremental(PVMBUS_CHANNEL_INTERNAL channel, PVOID buffer, UINT32 bufferLen, PMDL mdl, UINT8 fuzzMain, UINT8 fuzzMdl);
	static NTSTATUS fuzzPacketRandom(PVMBUS_CHANNEL_INTERNAL channel, PVOID buffer, UINT32 bufferLen, PMDL mdl, UINT64 countMain, UINT64 countMdl);
};
