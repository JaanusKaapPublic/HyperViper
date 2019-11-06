#include<ntddk.h>
#include"MSR.h"

NTSTATUS MSR::read(UINT32 code, PUINT64 out)
{
	__try
	{
		readMSR(code, out);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ILLEGAL_INSTRUCTION;
	}
	return STATUS_SUCCESS;
	
}

NTSTATUS MSR::write(UINT32 code, UINT64 value)
{
	__try
	{
		writeMSR(code, ((PUINT32)&value)[0], ((PUINT32)&value)[1]);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ILLEGAL_INSTRUCTION;
	}
	return STATUS_SUCCESS;
}