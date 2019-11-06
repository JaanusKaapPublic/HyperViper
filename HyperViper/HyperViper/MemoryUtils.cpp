#include "MemoryUtils.h"

bool MemoryUtils::writeNotReadableMemory(void* dst, void* src, UINT32 len)
{
	PMDL mdl = NULL;
	__try
	{
		mdl = IoAllocateMdl((PVOID)dst, len, FALSE, FALSE, NULL);
		if (!mdl)
			return false;
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		PUINT8 buffer = (PUINT8)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
		if (!buffer)
		{
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return false;
		}
		memcpy(buffer, src, len);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if(mdl)
			IoFreeMdl(mdl);
		return false;
	}
}


bool MemoryUtils::injectHook(void* dst, void* hookRedirection, void* oldData, UINT32* oldDataLen)
{
	UINT8 bytes[0xC];

	if (*oldDataLen < 0xC)
		return false;

	//movabs rax, VALUE(hookRedirection)
	bytes[0] = 0x48;
	bytes[1] = 0xb8;
	*((PUINT64)(bytes + 2)) = (UINT64)hookRedirection;
	//jmp rax
	bytes[0xA] = 0xff;
	bytes[0xB] = 0xe0;

	memcpy(oldData, dst, 0xC);
	*oldDataLen = 0xC;

	return writeNotReadableMemory(dst, bytes, 0xC);
}