#pragma once
#include <windows.h>
#include <map>
#include <string>

enum ConfValueType { boolType, intType, quadType, strType };

typedef struct _ConfValue
{
	const char* name;
	ConfValueType type;
	void* value;
	bool valueSet;
}ConfValue, * PConfValue;

class Conf
{
private:
	std::map<char, PConfValue> values;
	std::string lastError;

public:
	void addValue(char character, const char* name, ConfValueType type, void* defaultValue);
	void addValue(char character, const char* name, ConfValueType type);
	int parse(char* arg1, char* arg2);
	bool parseAll(char** args, int offset, int count);
	char getMissing(void);
	char* getError(void);

	bool isSet(char character);
	bool getBool(char character);
	int getInt(char character);
	char* getStr(char character);
	DWORD64 getQuad(char character);
};
