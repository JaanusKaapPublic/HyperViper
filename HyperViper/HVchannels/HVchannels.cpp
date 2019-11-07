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
	if (memcmp(magic, "HVCH", 4))
		ERROR_EXIT("Invalid file '%s' - no magic value", file);


	while (!feof(fin))
	{
		DWORD size;
		BYTE* content = NULL;
		GUID guid;

		fread(&guid, 1, sizeof(GUID), fin);
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

		fread(&size, 1, sizeof(DWORD), fin);
		if (size)
		{
			content = new BYTE[size];
			if (!content)
				ERROR_EXIT("Could not allocate 0x%X byte buffer", size);
			fread(content, 1, size, fin);

			sprintf_s(filenameTmp, 500, "%s\\hcall_%04X_MDL.bin", dir, count);
			fopen_s(&fout, filenameTmp, "wb");
			if (!fout)
				ERROR_EXIT("Could not create file '%s'", filenameTmp);
			fwrite(content, 1, size, fout);
			fclose(fout);
			delete content;
		}

		count++;
	}
	fclose(fin);

	return count;
}



DWORD fuzz(HVdriverIO driver, char* file, bool showProgress, LPGUID guidDefault)
{
	FILE* fin;
	char magic[4];
	DWORD count = 0;
	fopen_s(&fin, file, "rb");

	if (!fin)
		ERROR_EXIT("Could not open file '%s'", file);

	fread(magic, 1, sizeof(magic), fin);
	if (memcmp(magic, "HVCH", 4))
		ERROR_EXIT("Invalid file '%s' - no magic value", file);


	while (!feof(fin))
	{
		PBYTE content = NULL, contentMdl = NULL;
		DWORD contentLen = NULL, contentMdlLen = NULL;
		GUID guid;

		fread(&guid, 1, sizeof(GUID), fin);
		if (guidDefault)
			guid = *guidDefault;
		fread(&contentLen, 1, sizeof(DWORD), fin);
		content = new BYTE[contentLen];
		if (!content)
			ERROR_EXIT("Could not allocate 0x%X byte buffer", contentLen);
		fread(content, 1, contentLen, fin);

		fread(&contentMdlLen, 1, sizeof(DWORD), fin);
		if (contentMdlLen)
		{
			contentMdl = new BYTE[contentMdlLen];
			if (!contentMdl)
				ERROR_EXIT("Could not allocate 0x%X byte buffer", contentMdlLen);
			fread(contentMdl, 1, contentMdlLen, fin);
		}


		if (showProgress)
		{
			printf("0x%X Fuzzing channel ", count);
			printf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
				guid.Data1, guid.Data2, guid.Data3,
				guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
				guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
			printf(" with 0x%X data block and 0x%X ext-data block\n", contentLen, contentMdlLen);
		}

		VMBUS_CHANNEL_PACKET_FUZZ_CONF conf;
		conf.fuzzIncrementMain = 1;
		conf.fuzzIncrementMdl = 1;
		conf.fuzzRandomMain = 10000;
		conf.fuzzRandomMdl = 10000;
		if (!driver.channelsFuzz(guid, content, contentLen, contentMdl, contentMdlLen, &conf))
			ERROR_EXIT("Sending packet to channel failed");
		count++;

		delete content;
		if (contentMdl)
			delete contentMdl;
	}
	fclose(fin);

	return count;
}


void send(HVdriverIO driver, GUID guid, char* file1, char* file2, bool fuzz)
{
	FILE* fin;
	char magic[4];
	char* buffer1 = NULL, * buffer2 = NULL;
	DWORD buffer1Len = 0, buffer2Len = 0;

	fopen_s(&fin, file1, "rb");
	if (!fin)
		ERROR_EXIT("Could not open file '%s'", file1);

	fseek(fin, 0, SEEK_END);
	buffer1Len = ftell(fin);
	buffer1 = new char[buffer1Len];
	fseek(fin, 0, SEEK_SET);
	fread(buffer1, 1, buffer1Len, fin);
	fclose(fin);

	if (file2)
	{
		fopen_s(&fin, file2, "rb");
		if (!fin)
			ERROR_EXIT("Could not open file '%s'", file1);

		fseek(fin, 0, SEEK_END);
		buffer2Len = ftell(fin);
		buffer2 = new char[buffer2Len];
		fseek(fin, 0, SEEK_SET);
		fread(buffer2, 1, buffer2Len, fin);
		fclose(fin);
	}

	if (fuzz)
	{
		VMBUS_CHANNEL_PACKET_FUZZ_CONF conf;
		conf.fuzzIncrementMain = 1;
		conf.fuzzIncrementMdl = 1;
		conf.fuzzRandomMain = 10000;
		conf.fuzzRandomMdl = 10000;

		if (!driver.channelsFuzz(guid, buffer1, buffer1Len, buffer2, buffer2Len, &conf))
			ERROR_EXIT("Sending packet to channel failed");
	}
	else
	{
		if (!driver.channelsSend(guid, buffer1, buffer1Len, buffer2, buffer2Len))
			ERROR_EXIT("Sending packet to channel failed");
	}
}


int main(int argc, char* argv[])
{
	if (argc < 2)
		ERROR_EXIT("No operation specified");

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
		ERROR_EXIT("Could not open driver");
	

	if (!strcmp(argv[1], "list"))
	{
		VMBUS_CHANNEL channels[128];
		DWORD size = sizeof(VMBUS_CHANNEL) * 128;

		if (!driver.channelsList(channels, &size))
			ERROR_EXIT("Requesting channels list failed");

		size = size / sizeof(VMBUS_CHANNEL);
		printf("There are 0x%X channels\n", size);
		for (int x = 0; x < size; x++)
		{
			printf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
				channels[x].id.Data1, channels[x].id.Data2, channels[x].id.Data3,
				channels[x].id.Data4[0], channels[x].id.Data4[1], channels[x].id.Data4[2], channels[x].id.Data4[3],
				channels[x].id.Data4[4], channels[x].id.Data4[5], channels[x].id.Data4[6], channels[x].id.Data4[7]);
			printf("\n  name = %S\n", channels[x].name);
			printf("  isPipe = 0x%X\n", channels[x].isPipe);
			printf("  vmID = 0x%X\n", channels[x].vmID);
			printf("  vtlLevel = 0x%X\n\n", channels[x].vtlLevel);
		}
	}
	else if (!strcmp(argv[1], "hook"))
	{
		if (argc < 3)
			ERROR_EXIT("No GUID specified");
		if (!driver.channelsHook(StringToGuid(argv[2])))
			ERROR_EXIT("Hooking channel failed");
	}
	else if (!strcmp(argv[1], "unhook"))
	{
		if (!driver.channelsUnhook())
			ERROR_EXIT("Unooking channel failed");
	}
	else if (!strcmp(argv[1], "log"))
	{
		if (argc < 3)
			ERROR_EXIT("No file location specified");
		if (!driver.channelsStartRecord(argv[2]))
			ERROR_EXIT("Enabling logging failed");
	}
	else if (!strcmp(argv[1], "unlog"))  //Bad naming I know :D
	{
		if (argc < 3)
			ERROR_EXIT("No file location specified");
		if (!driver.channelsStopRecord())
			ERROR_EXIT("Stopping logging failed");
	}
	else if (!strcmp(argv[1], "send"))
	{
		if (argc < 3)
			ERROR_EXIT("No GUID specified");
		if (argc < 4)
			ERROR_EXIT("No data");
		if (argc < 5)
			send(driver, StringToGuid(argv[2]), argv[3], NULL, false);
		else
			send(driver, StringToGuid(argv[2]), argv[3], argv[4], false);
	}
	else if (!strcmp(argv[1], "fuzz-custom"))
	{
		if (argc < 3)
			ERROR_EXIT("No GUID specified");
		if (argc < 4)
			ERROR_EXIT("No data");
		if (argc < 5)
			send(driver, StringToGuid(argv[2]), argv[3], NULL, true);
		else
			send(driver, StringToGuid(argv[2]), argv[3], argv[4], true);
	}
	else if (!strcmp(argv[1], "fuzz"))
	{
		if (argc < 3)
			ERROR_EXIT("No file specified");
		if (argc == 3)
			fuzz(driver, argv[2], true, NULL);
		else
		{
			GUID guid = StringToGuid(argv[3]);
			fuzz(driver, argv[2], true, &guid);
		}
	}
	else
	{
		printf("[ERROR] Unknown command\n");
	}
}

