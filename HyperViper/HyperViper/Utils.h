#pragma once
#include<ntddk.h>

class Utils
{
private:
	static UINT64 seed;

public:
	static const UINT32 Crc32Lookup[256];
	static UINT64 getCurrentSeed();
	static void setCurrentSeed(UINT64);
	static UINT64 rand();
};