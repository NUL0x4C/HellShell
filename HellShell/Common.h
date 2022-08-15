#pragma once

#include <Windows.h>
#include <stdio.h>


typedef struct MyStruct {
	SIZE_T BytesNumber; // number of bytes read from the file 
	PVOID pShell;       // pointer to the shellcode read (here it is not appended) 
	PVOID pNewShell;    // pointer to the shellcode (appended)
	SIZE_T FinalSize;   // the size of the new appended shellcode
	HANDLE hFile;		// handle to the file created  
};

struct MyStruct PayloadData = { 0 };

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//	Function Used To Read The Shellcode.bin File, Save the size of the shellcode and the Pointer To its Buffer in our struct.
BOOL ReadBinFile(char* FileInput) {
	HANDLE hFile;
	DWORD FileSize, lpNumberOfBytesRead;
	BOOL Succ;
	PVOID DllBytes;
	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: [%d]\n", GetLastError());
		return FALSE;
	}
	FileSize = GetFileSize(hFile, NULL);
	DllBytes = malloc((SIZE_T)FileSize);
	Succ = ReadFile(hFile, DllBytes, FileSize, &lpNumberOfBytesRead, NULL);
	if (!Succ) {
		printf("[!] ReadFile Failed With Error:\n", GetLastError());
		return FALSE;
	}
	PayloadData.BytesNumber = (SIZE_T)lpNumberOfBytesRead;
	PayloadData.pShell = DllBytes;
	CloseHandle(hFile);
	return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// used to round up 'numToRound' to be multiple of 'multiple'
// in ipv4 : multiple = 4
// in ipv6 : multiple = 16
// in Mac  : multiple = 6
int roundUp(int numToRound, int multiple) {
	if (multiple == 0) {
		return numToRound;
	}
	int remainder = numToRound % multiple;
	if (remainder == 0) {
		return numToRound;
	}
	return numToRound + multiple - remainder;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// used to appened the shellcode with nops ant the end, the nops are added of size 'n'
void AppendShellcode(int n) {
	unsigned char Nop[1] = { 0x90 };
	int MultipleByn, HowManyToAdd;
	PVOID NewPaddedShellcode;

	MultipleByn = roundUp(PayloadData.BytesNumber, n);
	printf("[+] Constructing the Shellcode To Be Multiple Of %d, Target Size: %d \n", n, MultipleByn);
	HowManyToAdd = MultipleByn - PayloadData.BytesNumber;
	NewPaddedShellcode = malloc((SIZE_T)PayloadData.BytesNumber + HowManyToAdd + 1);
	memcpy(NewPaddedShellcode, PayloadData.pShell, PayloadData.BytesNumber);
	int i = 0;
	while (i != HowManyToAdd) {
		memcpy(PVOID((ULONG_PTR)NewPaddedShellcode + PayloadData.BytesNumber + i), Nop, 1);
		i++;
	}
	printf("[+] Added : %d \n", i);
	PayloadData.FinalSize = PayloadData.BytesNumber + HowManyToAdd;
	PayloadData.pNewShell = NewPaddedShellcode;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// createfile of name 'FileName' to write the shellcode to
BOOL WriteShellCodeFile( char * FileName, PBOOL Success) {
	HANDLE hFile;
	hFile = CreateFileA(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: [%d]\n", GetLastError());
		*Success = FALSE;
		return FALSE;
	}
	PayloadData.hFile = hFile;
	*Success = TRUE;
	return TRUE;
}
