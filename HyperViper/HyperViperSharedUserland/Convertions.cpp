#include "Convertions.h"
#include <stdio.h>
#include <stdlib.h>

DWORD getVal(char* str)
{
	if (!memcmp(str, "0x", 2))
		return strtol(str, NULL, 16);
	else
		return strtol(str, NULL, 10);
}

UINT64 getVal64(char* str)
{
	if (!memcmp(str, "0x", 2))
		return _strtoi64(str, NULL, 16);
	else
		return _strtoi64(str, NULL, 10);
}

GUID StringToGuid(char* str)
{
	GUID guid;
	sscanf_s(str,
		"{%8x-%4hx-%4hx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx}",
		&guid.Data1, &guid.Data2, &guid.Data3,
		&guid.Data4[0], &guid.Data4[1], &guid.Data4[2], &guid.Data4[3],
		&guid.Data4[4], &guid.Data4[5], &guid.Data4[6], &guid.Data4[7]);

	return guid;
}

char* GuidToString(GUID guid)
{
	char guid_cstr[39];
	snprintf(guid_cstr, sizeof(guid_cstr),
		"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

	return guid_cstr;
}