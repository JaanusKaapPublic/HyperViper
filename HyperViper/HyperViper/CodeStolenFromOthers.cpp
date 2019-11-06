//Stolen from https://github.com/sysprogs/VirtualKD/blob/master/kdpatch/moduleapi.h
//and https://github.com/feisuzhu/slaypubwin/blob/master/undoc.h
//and https://github.com/mirror/reactos/blob/master/reactos/drivers/storage/ide/uniata/ntddk_ex.h
#include "CodeStolenFromOthers.h"

PVOID KernelGetModuleBase(PCHAR  pModuleName)
{
	PVOID pModuleBase = NULL;
	PULONG pSystemInfoBuffer = NULL;

	__try
	{
		NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
		ULONG    SystemInfoBufferSize = 0;

		status = ZwQuerySystemInformation(SystemModuleInformation,
			&SystemInfoBufferSize,
			0,
			&SystemInfoBufferSize);

		if (!SystemInfoBufferSize)
			return NULL;

		pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

		if (!pSystemInfoBuffer)
			return NULL;

		memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);
		status = ZwQuerySystemInformation(SystemModuleInformation,
			pSystemInfoBuffer,
			SystemInfoBufferSize * 2,
			&SystemInfoBufferSize);

		if (NT_SUCCESS(status))
		{
			PSYSTEM_MODULE_ENTRY pSysModuleEntry =
				((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;
			ULONG i;
			UINT64 a = sizeof(SYSTEM_MODULE_ENTRY);

			for (i = 0; i < ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; i++)
			{
				if (!_stricmp((char*)pSysModuleEntry[i].FullPathName + pSysModuleEntry[i].OffsetToFileName, pModuleName))
				{
					pModuleBase = pSysModuleEntry[i].ImageBase;
					break;
				}
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		pModuleBase = NULL;
	}
	if (pSystemInfoBuffer) {
		ExFreePool(pSystemInfoBuffer);
	}

	return pModuleBase;
} // end KernelGetModuleBase()

//! Kernel-mode equivalent of GetProcAddress()
/*! This function returns the address of a function exported by a module loaded into kernel address space.
	\param ModuleBase Specifies the module base address (can be determined by calling KernelGetModuleBase()).
	\param pFunctionName Specifies the function name as an ANSI null-terminated string.
	\return The function returns the address of an exported function, or NULL if it was not found.
	\remarks The function body was downloaded from <a href="http://alter.org.ua/docs/nt_kernel/procaddr/">here</a>.
*/
PVOID KernelGetProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
	ASSERT(ModuleBase && pFunctionName);
	PVOID pFunctionAddress = NULL;

	ULONG size = 0;
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)
		RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

	ULONG_PTR addr = (ULONG_PTR)(PUCHAR)((UINT64)exports - (UINT64)ModuleBase);

	PULONG functions = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfFunctions);
	PSHORT ordinals = (PSHORT)((ULONG_PTR)ModuleBase + exports->AddressOfNameOrdinals);
	PULONG names = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfNames);
	ULONG  max_name = exports->NumberOfNames;
	ULONG  max_func = exports->NumberOfFunctions;

	ULONG i;

	for (i = 0; i < max_name; i++)
	{
		ULONG ord = ordinals[i];
		if (i >= max_name || ord >= max_func) {
			return NULL;
		}
		if (functions[ord] < addr || functions[ord] >= addr + size)
		{
			if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
			{
				pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
				break;
			}
		}
	}
	return pFunctionAddress;
} // end KernelGetProcAddress()