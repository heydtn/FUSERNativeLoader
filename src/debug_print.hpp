#pragma once
#include <cstdio>

// Controls whether PrintString/console etc output is produced at all
#ifndef FNL_DEBUG
#define FNL_DEBUG 0
#endif

#if FNL_DEBUG
#define DBG_PRINT(...) printf(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif
