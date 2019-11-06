#pragma once
#include<ntddk.h>

extern "C" UINT8 inline readPMIO1(UINT16 port);
extern "C" void inline writePMIO1(UINT16 port, UINT8 value);
extern "C" UINT16 inline readPMIO2(UINT16 port);
extern "C" void inline writePMIO2(UINT16 port, UINT16 value);
extern "C" UINT32 inline readPMIO4(UINT16 port);
extern "C" void inline writePMIO4(UINT16 port, UINT32 value);

class PMIO
{
public:
	static NTSTATUS read(UINT16, PUINT64, UINT8 size);
	static NTSTATUS write(UINT16, UINT64, UINT8 size);
};