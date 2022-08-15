#include <Windows.h>
#include <stdio.h>
#include <iostream>

#include "Common.h"
#include "ipv4fuscation.h"
#include "ipv6fuscation.h"
#include "MacFuscation.h"


#define IPv4Fuscation 1000
#define MacFuscation  2000
#define IPv6Fuscation 3000



int printUsage(char * MeLocation) {
	printf("[!] Usage: %s <payload file path> [Option*]\n", MeLocation);
	printf("[i] Option Can Be : \n");
	printf("\t[1] \"MacFuscation\" || \"mac\" ::: Output The Shellcode As A Array Of Mac Addresses [FC-48-83-E4-F0-E8]\n");
	printf("\t[2] \"Ipv4Fuscation\" || \"ipv4\" ::: Output The Shellcode As A Array Of ipv4 Addresses [252.72.131.228]\n");
	printf("\t[3] \"Ipv6Fuscation\" || \"ipv6\" ::: Output The Shellcode As A Array Of ipv6 Addresses [FC48:83E4:F0E8:C000:0000:4151:4150:5251]\n");
	printf("[i] ");
	system("PAUSE");
	return -1;
}

void Logo() {

	// it probably wont be printed like that but ehh
	std::cout << R"(

   ▄█    █▄       ▄████████  ▄█        ▄█               ▄████████    ▄█    █▄       ▄████████  ▄█        ▄█       
  ███    ███     ███    ███ ███       ███              ███    ███   ███    ███     ███    ███ ███       ███       
  ███    ███     ███    █▀  ███       ███              ███    █▀    ███    ███     ███    █▀  ███       ███       
 ▄███▄▄▄▄███▄▄  ▄███▄▄▄     ███       ███              ███         ▄███▄▄▄▄███▄▄  ▄███▄▄▄     ███       ███       
▀▀███▀▀▀▀███▀  ▀▀███▀▀▀     ███       ███            ▀███████████ ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀     ███       ███       
  ███    ███     ███    █▄  ███       ███                     ███   ███    ███     ███    █▄  ███       ███       
  ███    ███     ███    ███ ███▌    ▄ ███▌    ▄         ▄█    ███   ███    ███     ███    ███ ███▌    ▄ ███▌    ▄ 
  ███    █▀      ██████████ █████▄▄██ █████▄▄██       ▄████████▀    ███    █▀      ██████████ █████▄▄██ █████▄▄██ 
                            ▀         ▀                                                       ▀         ▀         
	)" << "\t\t\t\t\t\t\t\t\t\t\t\tBY ORCA10K \n";
}


int main(int argc, char* argv[]) {
	int Type = 0;
	BOOL Success = FALSE;
	char OutputShellFileName[32];
	Logo();

	// args check:
	if (argc != 3) { 
		return printUsage(argv[0]);
	}

	// checking if we can read the payload
	if ((!ReadBinFile(argv[1])) || PayloadData.pShell == NULL || PayloadData.BytesNumber == NULL) {
		system("PAUSE");
		return -1;
	}
	printf("[i] Size Of Shellcode: %ld \n", (unsigned int) PayloadData.BytesNumber);

	// checking the format of the shellcode to output 

	if (strcmp(argv[2], "MacFuscation") == 0 || strcmp(argv[2], "macfuscation") == 0 || strcmp(argv[2], "mac") == 0 || strcmp(argv[2], "MAC") == 0){
		if (PayloadData.BytesNumber % 6 == 0) {
			printf("[i] The Shellcode is Already multiple of 6, No Need To Append Nops ... \n");
			PayloadData.pNewShell = malloc((SIZE_T)PayloadData.BytesNumber);
			memcpy(PayloadData.pNewShell, PayloadData.pShell, PayloadData.BytesNumber);
			PayloadData.FinalSize = PayloadData.BytesNumber;
		}
		else {
			printf("[i] The Shellcode is Not multiple of 6\n");
			AppendShellcode(6);
		}
		Type = MacFuscation;
	}
	
	else if (strcmp(argv[2], "Ipv4Fuscation") == 0 || strcmp(argv[2], "ipv4fuscation") == 0 || strcmp(argv[2], "ipv4") == 0 || strcmp(argv[2], "IPV4") == 0) {
		if (PayloadData.BytesNumber % 4 == 0) {
			printf("[i] The Shellcode is Already multiple of 4, No Need To Append Nops ... \n");
			PayloadData.pNewShell = malloc((SIZE_T)PayloadData.BytesNumber);
			memcpy(PayloadData.pNewShell, PayloadData.pShell, PayloadData.BytesNumber);
			PayloadData.FinalSize = PayloadData.BytesNumber;
		}
		else {
			printf("[i] The Shellcode is Not multiple of 4\n");
			AppendShellcode(4);
		}
		Type = IPv4Fuscation;
	}

	else if (strcmp(argv[2], "Ipv6Fuscation") == 0 || strcmp(argv[2], "ipv6fuscation") == 0 || strcmp(argv[2], "ipv6") == 0 || strcmp(argv[2], "IPV6") == 0) {
		if (PayloadData.BytesNumber % 16 == 0) {
			printf("[i] The Shellcode is Already multiple of 16, No Need To Append Nops ... \n");
			PayloadData.pNewShell = malloc((SIZE_T)PayloadData.BytesNumber);
			memcpy(PayloadData.pNewShell, PayloadData.pShell, PayloadData.BytesNumber);
			PayloadData.FinalSize = PayloadData.BytesNumber;
		}
		else {
			printf("[i] The Shellcode is Not multiple of 16\n");
			AppendShellcode(16);
		}
		Type = IPv6Fuscation;
	}
	
	else {
		printf("[!] Unkown Input : %s \n", argv[2]);
		return printUsage(argv[0]);
	}

	printf("[i] Final Shellcode Size : %ld\n", (unsigned int)PayloadData.FinalSize);
	unsigned char* FinallShell = (unsigned char*)malloc(PayloadData.FinalSize);
	memcpy(FinallShell, PayloadData.pNewShell, (SIZE_T)PayloadData.FinalSize);
	
	// writing the decoder functions and the shellcode 
	switch (Type){
		case IPv4Fuscation:
			strcpy(OutputShellFileName, "IPv4Fuscation.cpp");
			WriteShellCodeFile(OutputShellFileName, &Success);
			Generateipv4Output(PayloadData.FinalSize, FinallShell, &Success);
			break;
		case MacFuscation:
			strcpy(OutputShellFileName, "MacFuscation.cpp");
			WriteShellCodeFile(OutputShellFileName , &Success);
			GenerateMacOutput(PayloadData.FinalSize, FinallShell, &Success);
			break;
		case IPv6Fuscation:
			strcpy(OutputShellFileName, "IPv6Fuscation.cpp");
			WriteShellCodeFile(OutputShellFileName, &Success);
			Generateipv6Output(PayloadData.FinalSize, FinallShell, &Success);
			break;
		default:
			printf("[!] Unkown Error Occured %d \n", GetLastError());
			break;
	}
	
	if (Success){
		printf("[+] Wrote The Shellcode And The Decoder To : %s \n", OutputShellFileName);
	}
	else{
		printf("[!] Failed To Write The Shellcode; Returned Error : %d \n", GetLastError());
	}

	free(PayloadData.pNewShell);
	free(FinallShell);
	//printf("[#] Hit Enter To Exit ... \n");
	//getchar();
	return 0;
}
