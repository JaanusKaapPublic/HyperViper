#pragma once
#include<ntddk.h>

class MemoryUtils
{
public:
	static bool writeNotReadableMemory(void* dst, void* src, UINT32 len);
	static bool injectHook(void* dst, void* hookRedirection, void* oldData, UINT32* oldDataLen);
};
