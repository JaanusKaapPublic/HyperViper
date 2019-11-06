#pragma once

#define ERROR_EXIT(e, ...) {printf("[ERROR][0x%X] ", GetLastError()); printf(e, __VA_ARGS__); exit(0);}
#define SHOW_WARNING(e, ...) {printf("[WARNING][0x%X] ", GetLastError()); printf(e, __VA_ARGS__);}