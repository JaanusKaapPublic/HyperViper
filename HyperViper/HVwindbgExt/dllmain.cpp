// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#define KDEXT_64BIT 
#include <Wdbgexts.h>
#include <Dbgeng.h>

#ifdef HVWINDBGEXT_EXPORTS
#define HVWINDBGEXT_API __declspec(dllexport)
#else
#define HVWINDBGEXT_API __declspec(dllimport)
#endif

#define FIND_MSR_HANLDER_MARKER "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x18\x55\x57\x41\x54\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x60\x8D\x82\x90\xFF\xFF\xBF"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
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

typedef enum Environment
{
	HYPERVISOR,
	KERNEL,
	VMWP,
	UNKNOWN
} Environment;


EXT_API_VERSION g_ExtApiVersion = {5, 5, EXT_API_VERSION_NUMBER64, 0};
WINDBG_EXTENSION_APIS ExtensionApis = { 0 };
Environment env;

CPPMOD __declspec(dllexport)  LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(void)
{ 
	return &g_ExtApiVersion; 
}

CPPMOD __declspec(dllexport)  VOID WDBGAPI WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{	
	ExtensionApis = *lpExtensionApis;
	if (GetExpression("hv"))
		env = HYPERVISOR;
	else if (GetExpression("nt"))
		env = KERNEL;
	else if (GetExpression("vmwp"))
		env = VMWP;
	else
		env = UNKNOWN;
}

CPPMOD __declspec(dllexport) VOID hyperviper(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	dprintf("HyperViper by Jaanus K‰‰p(@FoxHex0ne)\n");
	switch (env)
	{
	case HYPERVISOR:
		dprintf("Debugging hypervisor it seems\n\n");
		break;
	case KERNEL:
		dprintf("Debugging kernel it seems\n\n");
		break;
	case VMWP:
		dprintf("Debugging virtual machine working process it seems\n\n");
		break;
	case UNKNOWN:
		dprintf("Debugging.....something.....not sure what\n\n");
		break;
	}
}

ULONG_PTR showChannel(ULONG_PTR ptr)
{
	ULONG_PTR tmp = NULL, offset;
	UINT8 tmp8;
	UINT16 tmp16;
	UINT32 tmp32;
	GUID guid;
	WCHAR name[64];
	CHAR symbol[128];

	ReadMemory(ptr, &tmp, sizeof(tmp), NULL);
	if (tmp != ptr)
	{
		dprintf("Invalid channel @ 0x%I6X\n", ptr);
		return NULL;
	}

	dprintf("Channel @ 0x%I64x\n", ptr);

	ReadMemory(ptr+0x960, &guid, sizeof(guid), NULL);
	dprintf("  guid: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

	ReadMemory(ptr + 0x64C, &tmp16, sizeof(tmp16), NULL);
	dprintf("  vm-id: %i\n", tmp16);

	ReadMemory(ptr + 0x6FA, &tmp8, sizeof(tmp8), NULL);
	dprintf("  vtl: %i\n", tmp8);
	   
	ReadMemory(ptr + 0x788, &tmp16, sizeof(tmp16), NULL);
	if (tmp16 && tmp16 < sizeof(name))
	{
		ReadMemory(ptr + 0x788 + 8, &tmp, sizeof(tmp), NULL);
		ReadMemory(tmp, name, tmp16, NULL);
		name[tmp16/2] = 0x00;
		dprintf("  friendlyName: %S\n", name);
	}	

	ReadMemory(ptr + 0x63C, &tmp8, sizeof(tmp8), NULL);
	dprintf("  pipe: %s\n", (tmp8 ? "YES" : "NO"));
	if (tmp8)
	{
		ReadMemory(ptr + 0x7F8, &tmp, sizeof(tmp), NULL);
		dprintf("  pipe-obj: 0x%I64x\n", tmp);
	}
	{
		ReadMemory(ptr + 0x7F8, &tmp, sizeof(tmp), NULL);
		dprintf("  setPointer: 0x%I64x\n", tmp);
	}


	ReadMemory(ptr + 0x940, &tmp, sizeof(tmp), NULL);
	dprintf("  targetDeviceObject: 0xI64x\n", tmp);
	ReadMemory(ptr + 0x6E0, &tmp32, sizeof(tmp32), NULL);
	dprintf("  nrOfPagesToAllocateInIncomingRingBuffer: 0x%x\n", tmp32);
	ReadMemory(ptr + 0x6E4, &tmp32, sizeof(tmp32), NULL);
	dprintf("  nrOfPagesToAllocateInOutgoingRingBuffer: 0x%x\n", tmp32);

	ReadMemory(ptr + 0x700, &tmp, sizeof(tmp), NULL);
	if (tmp)
	{
		dprintf("  callbackProcessPacket: 0x%I64x", tmp);
		GetSymbol(tmp, symbol, &offset);
		dprintf("  %s+0x%x\n", symbol, offset);
	}
	ReadMemory(ptr + 0x708, &tmp, sizeof(tmp), NULL);
	if (tmp)
	{
		dprintf("  callbackProcessingComplete: 0x%I64x", tmp);
		GetSymbol(tmp, symbol, &offset);
		dprintf("  %s+0x%x\n", symbol, offset);
	}
	ReadMemory(ptr + 0x738, &tmp, sizeof(tmp), NULL);
	if (tmp)
	{
		dprintf("  callbackChannelOpened: 0x%I64x", tmp);
		GetSymbol(tmp, symbol, &offset);
		dprintf("  %s+0x%x\n", symbol, offset);
	}
	ReadMemory(ptr + 0x740, &tmp, sizeof(tmp), NULL);
	if (tmp)
	{
		dprintf("  callbackChannelClosed: 0x%I64x", tmp);
		GetSymbol(tmp, symbol, &offset);
		dprintf("  %s+0x%x\n", symbol, offset);
	}
	ReadMemory(ptr + 0x748, &tmp, sizeof(tmp), NULL);
	if (tmp)
	{
		dprintf("  callbackChannelSuspended: 0x%I64x", tmp);
		GetSymbol(tmp, symbol, &offset);
		dprintf("  %s+0x%x\n", symbol, offset);
	}
	ReadMemory(ptr + 0x750, &tmp, sizeof(tmp), NULL);
	if (tmp)
	{
		dprintf("  callbackChannelStarted: 0x%I64x", tmp);
		GetSymbol(tmp, symbol, &offset);
		dprintf("  %s+0x%x\n", symbol, offset);
	}
	   	 
	dprintf("\n");
	ReadMemory(ptr+0x760, &tmp, sizeof(tmp), NULL);
	return tmp;
}

CPPMOD __declspec(dllexport) VOID hv_channel(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	ULONG_PTR addr, base;

	addr = GetExpression(args);
	if (addr)
	{
		showChannel(addr);
		return;
	}
	
	base = GetExpression("vmbkmclr!KmclChannelList");
	if (!base)
		base = GetExpression("vmbkmcl!KmclChannelList");
	if (!base)
	{
		dprintf("Could not get expression 'vmbkmclr!KmclChannelList' or 'vmbkmcl!KmclChannelList' ('.reload' maybe....)\n");
		return;
	}

	if (!ReadMemory(base, &addr, sizeof(addr), NULL))
	{
		dprintf("Could not read pointer from address 0x%I64X\n", base);
		return;
	}
	if (!addr)
		return;
	addr -= 0x760;

	while (addr != base - 0x760)
	{
		addr = showChannel(addr);
		if (!addr)
			break;
		addr -= 0x760;
	}
}


CPPMOD __declspec(dllexport) VOID hv_hypercall(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	if (env != HYPERVISOR)
	{
		dprintf("This command should be executed when debugging hypervisor!\n");
		return;
	}

	ULONG_PTR addr, noCall, handler;
	UINT32 nr = 0;
	addr = GetExpression("hv");
	if (!addr)
	{
		dprintf("This is very weird - can't find base address of 'hv'\n");
		return;
	}

	addr += 0xC00000;
	ReadMemory(addr, &noCall, sizeof(noCall), NULL);
	while (true)
	{
		addr += 0x18;
		nr++;
		if (!ReadMemory(addr, &handler, sizeof(handler), NULL))
			break;
		if (!handler)
			break;
		dprintf("hypercall 0x%02x: %I64x", nr, handler);
		if (handler == noCall)
			dprintf("  [NO SUCH CALL ACTUALLY]\n");
		else
			dprintf("\n");
	}
}

CPPMOD __declspec(dllexport) VOID hv_msr(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	if (env != HYPERVISOR)
	{
		dprintf("This command should be executed when debugging hypervisor!\n");
		return;
	}

	ULONG_PTR addr, found = NULL, offset;
	CHAR symbol[128];
	BYTE tmp[sizeof(FIND_MSR_HANLDER_MARKER) - 1];
	addr = GetExpression("hv");
	if (!addr)
	{
		dprintf("This is very weird - can't find base address of 'hv'\n");
		return;
	}

	addr += 0x200000;
	while(true)
	{
		if (!ReadMemory(++addr, &tmp, sizeof(tmp), NULL))
		{
			dprintf("Could not find MSR handler. Probably the signature has changed - look for plugin update or if it's not there, inform author and hope he is sober enough\n");
			return;
		}
		if (!memcmp(tmp, FIND_MSR_HANLDER_MARKER, sizeof(FIND_MSR_HANLDER_MARKER) - 1))
			break;
	}
		
	GetSymbol(addr, symbol, &offset);
	dprintf("MSR handler function is at 0x%I64x   %s+0x%I64X", addr, symbol, offset);
}