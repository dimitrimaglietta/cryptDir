#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include "common.h"

#pragma comment(lib, "crypt32.lib")

#define BLOCK_LEN 128

//params: <input file> <output file> <is decrypt mode> <key>
//int wmain(int argc, wchar_t *argv[])
//{

bool crypt_block(wchar_t *filename, wchar_t *key_str, bool isDecrypt);
