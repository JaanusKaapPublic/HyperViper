#pragma once
#include<ntddk.h>

extern "C" void inline readMSR(UINT32 code, UINT64* output);
extern "C" void inline writeMSR(UINT32 Code, UINT32 high, UINT32 low);

class MSR
{
public:
	static NTSTATUS read(UINT32, PUINT64);
	static NTSTATUS write(UINT32, UINT64);
};