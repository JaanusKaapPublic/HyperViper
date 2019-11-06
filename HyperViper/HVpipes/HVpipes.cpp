#include <windows.h>
#include <stdio.h>
#include "HVdef.h"
#include "HVUdefs.h"
#include "HVdriverIO.h"
#include "Convertions.h"

DWORD unpack(char* file, char* dir)
{
	FILE* fin, * fout;
	char magic[4], filenameTmp[512];
	DWORD count = 0;
	fopen_s(&fin, file, "rb");

	if (!fin)
		ERROR_EXIT("Could not open file '%s'", file);

	fread(magic, 1, sizeof(magic), fin);
	if (memcmp(magic, "HVPR", 4))
		ERROR_EXIT("Invalid file '%s' - no magic value", file);


	while (!feof(fin))
	{
		DWORD size;
		BYTE* content = NULL;

		fread(&size, 1, sizeof(DWORD), fin);
		content = new BYTE[size];
		if (!content)
			ERROR_EXIT("Could not allocate 0x%X byte buffer", size);
		fread(content, 1, size, fin);

		sprintf_s(filenameTmp, 500, "%s\\hcall_%04X.bin", dir, count);
		fopen_s(&fout, filenameTmp, "wb");
		if (!fout)
			ERROR_EXIT("Could not create file '%s'", filenameTmp);
		fwrite(content, 1, size, fout);
		fclose(fout);
		delete content;
		count++;
	}
	fclose(fin);

	return count;
}


int main(int argc, char* argv[])
{
	if (argc < 2)
		ERROR_EXIT("[ERROR] No operation specified");

	if (!strcmp(argv[1], "unpack"))
	{
		if (argc < 3)
			ERROR_EXIT("No file location specified");
		if (argc < 4)
			ERROR_EXIT("No directory location specified");
		if (!unpack(argv[2], argv[3]))
			ERROR_EXIT("Unpacking failed");
		return 0;
	}

	HVdriverIO driver;
	if (!driver.init())
		ERROR_EXIT("[ERROR] Could not open driver");

	if (!strcmp(argv[1], "hook"))
	{
		if (argc < 3)
			ERROR_EXIT("No GUID specified");
		if (!driver.pipeHook(StringToGuid(argv[2])))
			ERROR_EXIT("Hooking pipe failed");
	}
	else if (!strcmp(argv[1], "unhook"))
	{
		if (!driver.pipeUnhook())
			ERROR_EXIT("Unhooking pipe failed");
	}
	else if (!strcmp(argv[1], "log"))
	{
		if (argc < 3)
			ERROR_EXIT("No file location specified");
		if (!driver.pipeStartRecord(argv[2]))
			ERROR_EXIT("Enabling pipe recording failed");
	}
	else if (!strcmp(argv[1], "unlog"))
	{
		if (!driver.pipeStopRecord())
			ERROR_EXIT("Stopping pipe recording failed");
	}
	else
	{
		printf("[ERROR] Unknown command\n");
	}
}

