#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <fstream>

#define errorf(fmt, ...) fprintf(stderr, "\n[error at %s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define StrToWStr(s) (std::wstring(s, &s[strlen(s)]).c_str())

#include "comm.h"
#include "map.h"
#include "hijack.h"



#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <accctrl.h>
#include <aclapi.h>
#include <shlobj_core.h>
#include <tlhelp32.h>

#pragma comment(lib, "shlwapi.lib")

