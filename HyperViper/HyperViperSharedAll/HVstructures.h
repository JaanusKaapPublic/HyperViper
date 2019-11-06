#pragma once
#include "HVdef.h"

typedef unsigned short HV_STATUS;

typedef union _HV_X64_HYPERCALL_INPUT
{
	struct
	{
		UINT32 CallCode : 16;
		UINT32 IsFast : 1;
		UINT32 dontCare1 : 15;
		UINT32 CountOfElements : 12;
		UINT32 dontCare2 : 4;
		UINT32 RepStartIndex : 12;
		UINT32 dontCare3 : 4;
	};
	UINT64 AsUINT64;
} HV_X64_HYPERCALL_INPUT, * PHV_X64_HYPERCALL_INPUT;

typedef union _HV_X64_HYPERCALL_OUTPUT
{
	struct
	{
		HV_STATUS CallStatus;
		UINT16 dontCare1;
		UINT32 ElementsProcessed : 12;
		UINT32 dontCare2 : 20;
	};
	UINT64 AsUINT64;
} HV_X64_HYPERCALL_OUTPUT, * PHV_X64_HYPERCALL_OUTPUT;

typedef struct _HV_HOOKING_HCALL_CONF
{
	UINT8 breakpoint;
	UINT8 dbgPrint;
	UINT32 log;
	UINT32 fuzz;
}HV_HOOKING_HCALL_CONF, * PHV_HOOKING_HCALL_CONF;

typedef struct _HV_HOOKING_HCALL_STATS
{
	UINT32 count;
	UINT16 lastElementCount;
	HANDLE lastProcessID;
	UINT8 fast:1;
	UINT8 slow:1;
}HV_HOOKING_HCALL_STATS, * PHV_HOOKING_HCALL_STATS;

typedef HV_HOOKING_HCALL_STATS HYPERCALL_STATUSES[HYPERCALL_LAST_NR + 1];
typedef HYPERCALL_STATUSES* PHYPERCALL_STATUSES;

typedef struct _HV_HOOKING_CONF
{
	UINT8 hookingActivated;
	UINT8 hookingDiscardAllSlow;
	UINT8 hookingDiscardAllFast;
	UINT8 hookingDbgPrintAll;
	UINT8 hookingLogActive;
	UINT8 hookingLogAll;
	UINT32 logSize;

	HV_HOOKING_HCALL_CONF hcallConfs[HYPERCALL_LAST_NR + 1];
} HV_HOOKING_CONF, * PHV_HOOKING_CONF;

typedef struct _VMBUS_CHANNEL
{
	GUID id;
	UINT32 maxNrOfPackets;
	UINT32 maxPacketSize;
	UINT32 maxExternalDataSize;
	UINT32 maxNrOfMDLs;
	UINT32 clientContextSize;
	UINT8 isPipe;
	UINT16 vmID;
	UINT64 vmBusHandle;
	UINT32 nrOfPagesToAllocateInIncomingRingBuffer;
	UINT32 nrOfPagesToAllocateInOutgoingRingBuffer;
	UINT8 vtlLevel;
	WCHAR name[64];
} VMBUS_CHANNEL, * PVMBUS_CHANNEL;

typedef struct _VMBUS_CHANNEL_PACKET_SEND
{
	GUID id;
	UINT32 sizeOfData;
	UINT32 sizeOfMDL;
} VMBUS_CHANNEL_PACKET_SEND, * PVMBUS_CHANNEL_PACKET_SEND;

typedef struct _VMBUS_CHANNEL_PACKET_FUZZ_CONF
{
	UINT8 fuzzIncrementMain;
	UINT8 fuzzIncrementMdl;
	UINT32 fuzzRandomMain;
	UINT32 fuzzRandomMdl;
} VMBUS_CHANNEL_PACKET_FUZZ_CONF, * PVMBUS_CHANNEL_PACKET_FUZZ_CONF;

typedef struct _VMBUS_CHANNEL_PACKET_FUZZ
{
	GUID id;
	UINT32 sizeOfData;
	UINT32 sizeOfMDL;
	VMBUS_CHANNEL_PACKET_FUZZ_CONF conf;
} VMBUS_CHANNEL_PACKET_FUZZ, * PVMBUS_CHANNEL_PACKET_FUZZ;