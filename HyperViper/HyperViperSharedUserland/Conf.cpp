#include "Conf.h"
#include "Convertions.h"

void Conf::addValue(char character, const char* name, ConfValueType type, void* defaultValue)
{
	PConfValue value = new ConfValue;
	value->name = name;
	value->type = type;
	value->value = defaultValue;
	value->valueSet = true;
	values[character] = value;
}

void Conf::addValue(char character, const char* name, ConfValueType type)
{
	PConfValue value = new ConfValue;
	value->name = name;
	value->type = type;
	value->value = NULL;
	value->valueSet = false;
	values[character] = value;
}

int Conf::parse(char* arg1, char* arg2)
{
	if (arg1[0] != '-')
	{
		lastError = "Argument \"" + std::string(arg1) + "\" could not be parsed";
		return 0;
	}

	if (!values.count(arg1[1]))
	{
		lastError = "Unknown argument: ";
		lastError += arg1[1];
		return 0;
	}

	if (values[arg1[1]]->type != boolType && arg2 == NULL)
	{
		lastError = "Argument needs value: ";
		lastError += arg1[1];
		return 0;
	}

	values[arg1[1]]->valueSet = true;
	switch (values[arg1[1]]->type)
	{
	case boolType:
		values[arg1[1]]->value = (void*)1;
		return 1;
	case intType:
		values[arg1[1]]->value = (void*)getVal(arg2);
		return 2;
	case quadType:
		values[arg1[1]]->value = (void*)getVal64(arg2);
		return 2;
	case strType:
		values[arg1[1]]->value = new char[strlen(arg2) + 1];
		memcpy(values[arg1[1]]->value, arg2, strlen(arg2) + 1);
		return 2;
	}

	lastError = "Eeeeeee...... No idea what happened....";
	return 0;
}

bool Conf::parseAll(char** args, int offset, int count)
{
	int step;
	for (int x = offset; x < count;)
	{
		if (x + 1 < count)
			step = parse(args[x], args[x + 1]);
		else
			step = parse(args[x], NULL);

		if (step == 0)
			return false;

		if (x + step > count)
		{
			lastError = "Last argument needs value also";
			return false;
		}

		x += step;
	}
	return true;
}

char Conf::getMissing(void)
{
	std::map<char, PConfValue>::iterator it;
	for (it = values.begin(); it != values.end(); it++)
	{
		if (!it->second->valueSet)
			return it->first;
	}
	return NULL;
}

char* Conf::getError(void)
{
	return (char*)lastError.c_str();
}

bool Conf::isSet(char character)
{
	return (values[character]->valueSet);
}

bool Conf::getBool(char character)
{
	return (bool)values[character]->value;
}

int Conf::getInt(char character)
{
	return (int)values[character]->value;
}

DWORD64 Conf::getQuad(char character)
{
	return (DWORD64)values[character]->value;
}

char* Conf::getStr(char character)
{
	return (char*)values[character]->value;
}