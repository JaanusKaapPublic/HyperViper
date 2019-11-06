#include<ntddk.h>
#include"PMIO.h"

NTSTATUS PMIO::read(UINT16 port, PUINT64 out, UINT8 size)
{
	__try
	{
		switch (size)
		{
		case 1:
			*out = readPMIO1(port);
			break;
		case 2:
			*out = readPMIO2(port);
			break;
		case 4:
			*out = readPMIO4(port);
			break;
		default:
			return STATUS_INVALID_PARAMETER;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ILLEGAL_INSTRUCTION;
	}
	return STATUS_SUCCESS;

}

NTSTATUS PMIO::write(UINT16 port, UINT64 value, UINT8 size)
{
	__try
	{
		switch (size)
		{
		case 1:
			writePMIO1(port, (UINT8)value);
			break;
		case 2:
			writePMIO2(port, (UINT16)value);
			break;
		case 4:
			writePMIO4(port, (UINT32)value);
			break;
		default:
			return STATUS_INVALID_PARAMETER;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ILLEGAL_INSTRUCTION;
	}
	return STATUS_SUCCESS;
}