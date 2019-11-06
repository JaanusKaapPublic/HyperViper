#pragma once
#include <windows.h>

DWORD getVal(char*);
UINT64 getVal64(char* str);
GUID StringToGuid(char* str);
char* GuidToString(GUID guid);