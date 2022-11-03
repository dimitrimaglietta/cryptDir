#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")

#define BLOCK_LEN 128

bool crypt_block(wchar_t *filename, wchar_t *key_str, bool isDecrypt)
{
	size_t len = lstrlenW(key_str);

    #if _DEBUG
	  printf("[+] Key: %S\n", key_str);
	  printf("[+] Key len: %#x\n", len);
	  printf("[+] Input File: %S\n", filename);
    #endif

	//Apre il file di input
	HANDLE hInpFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInpFile == INVALID_HANDLE_VALUE) {
    #if _DEBUG
		printf("[-] Cannot open input file!\n");
    #endif
		return FALSE;
	}

    #if _DEBUG
	  if (isDecrypt) {
		  printf("[!] DECRYPTING\n");
	  }
	  else {
		  printf("[!] ENCRYPTING\n");
	  }
    #endif

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;
	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError(); 
    #if _DEBUG
		printf("[-] CryptAcquireContext failed: %x\n", dwStatus);
    #endif
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		dwStatus = GetLastError();
    #if _DEBUG
		printf("[-] CryptCreateHash failed: %x\n", dwStatus);
    #endif
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
		DWORD err = GetLastError();

    #if _DEBUG
		printf("[-] CryptHashData Failed : %#x\n", err);
    #endif
		return FALSE;
	}
    #if _DEBUG
	    printf("[+] CryptHashData Success\n");
    #endif

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
		dwStatus = GetLastError();

    #if _DEBUG
		printf("[-] CryptDeriveKey failed: %x\n", dwStatus);
    #endif
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
    #if _DEBUG
	    printf("[+] CryptDeriveKey Success\n");
    #endif

	const size_t chunk_size = BLOCK_LEN;
	BYTE chunk[chunk_size] = { 0 };
	DWORD out_len = 0;

	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;

	DWORD inputSize = GetFileSize(hInpFile, NULL);

	if (inputSize>(1024 * 1024 * 100)) {//MAX 100Mb
		return FALSE;
	}

	BYTE* final = new BYTE[inputSize + (inputSize*0.33)];
	//BYTE* final = (BYTE*)HeapAlloc(GetProcessHeap(), 0, inputSize+(inputSize*0.33));
	DWORD final_len = 0;

	while (bResult = ReadFile(hInpFile, chunk, chunk_size, &out_len, NULL)) {
		if (0 == out_len) {
			break;
		}
		readTotalSize += out_len;
		if (readTotalSize == inputSize) {
			isFinal = TRUE;
            #if _DEBUG
			    printf("[!] Final chunk set.\n");
            #endif
		}

		//Decripta
		if (isDecrypt) {
			if (!CryptDecrypt(hKey, NULL, isFinal, 0, chunk, &out_len)) {
				if (!isFinal) {
                    #if _DEBUG
					    printf("[-] CryptDecrypt failed\n");
                    #endif
					return FALSE;
				}
			}
		}

		//Cripta
		else {
			if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
				if (!isFinal) {
                    #if _DEBUG
					    printf("[-] CryptEncrypt failed\n");
                    #endif
					return FALSE;
				}
			}
		}

		//My pt1
		memcpy(final + final_len, chunk, out_len);
		final_len = final_len + out_len;

		memset(chunk, 0, chunk_size);
	}

	CloseHandle(hInpFile);  //Chiude il file di input

	//Apre il file di output
	HANDLE hOutFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE) {
        #if _DEBUG
		    printf("[-] Cannot open output file!\n");
        #endif
		return FALSE;
	}

	//My pt2
	DWORD written = 0;
	if (!WriteFile(hOutFile, final, final_len, &written, NULL)) {
        #if _DEBUG
		    printf("[-] Writing failed!\n");
        #endif
		return FALSE;
	}

	free(final);

	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);

	CloseHandle(hOutFile);

    #if _DEBUG
	    printf("[+] Finished. Processed %#x bytes.\n", readTotalSize);
    #endif

	return TRUE;
}