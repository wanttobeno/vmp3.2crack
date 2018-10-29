// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include <windows.h>

// TODO: reference additional headers your program requires here

#include <string>
#include <vector>
#include <map>

using namespace std;

#ifndef byte
typedef unsigned char byte;
#endif

#include "b64.h"
#include "sha-1.h"
#include "sshbn.h"
