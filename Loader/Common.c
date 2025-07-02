#include <Windows.h>

#include "Common.h"
#include "Debug.h"

BOOL XmInitializeNetworkProtocols(OUT PNETWORK_CONFIG NetCfg) 
{
    if (NetCfg->bInitialized)
        return TRUE;

    if (!XmFetchSystemCall(TCP_CONNECT_HASH, &NetCfg->TcpConnect)) {
#ifdef DEBUG
        PRINT("[!] Network Protocol Binding Failed \"TCP_CONNECT\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!XmFetchSystemCall(HTTP_PROXY_HASH, &NetCfg->HttpProxy)) {
#ifdef DEBUG
        PRINT("[!] Network Protocol Binding Failed \"HTTP_PROXY\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!XmFetchSystemCall(TLS_HANDSHAKE_HASH, &NetCfg->TlsHandshake)) {
#ifdef DEBUG
        PRINT("[!] Network Protocol Binding Failed \"TLS_HANDSHAKE\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!XmFetchSystemCall(TCP_DISCONNECT_HASH, &NetCfg->TcpDisconnect)) {
#ifdef DEBUG
        PRINT("[!] Network Protocol Binding Failed \"TCP_DISCONNECT\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!XmFetchSystemCall(BUFFER_ALLOCATE_HASH, &NetCfg->BufferAllocate)) {
#ifdef DEBUG
        PRINT("[!] Network Protocol Binding Failed \"BUFFER_ALLOCATE\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!XmFetchSystemCall(KEEP_ALIVE_HASH, &NetCfg->KeepAlive)) {
#ifdef DEBUG
        PRINT("[!] Network Protocol Binding Failed \"KEEP_ALIVE\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINT("[SSL] TCP Connect [ Port: 0x%0.8X - Remote Endpoint: 0x%p ] \n", NetCfg->TcpConnect.dwConnectionId, NetCfg->TcpConnect.pHandlerAddress);
    PRINT("[SSL] HTTP Proxy [ Session: 0x%0.8X - Remote Endpoint: 0x%p ] \n", NetCfg->HttpProxy.dwConnectionId, NetCfg->HttpProxy.pHandlerAddress);
    PRINT("[SSL] TLS Handshake [ Protocol: 0x%0.8X - Remote Endpoint: 0x%p ] \n", NetCfg->TlsHandshake.dwConnectionId, NetCfg->TlsHandshake.pHandlerAddress);
    PRINT("[SSL] TCP Disconnect [ Socket: 0x%0.8X - Remote Endpoint: 0x%p ] \n", NetCfg->TcpDisconnect.dwConnectionId, NetCfg->TcpDisconnect.pHandlerAddress);
    PRINT("[SSL] Network Buffer [ Size: 0x%0.8X - Remote Endpoint: 0x%p ] \n", NetCfg->BufferAllocate.dwConnectionId, NetCfg->BufferAllocate.pHandlerAddress);
    PRINT("[SSL] Keep-Alive [ Timeout: 0x%0.8X - Remote Endpoint: 0x%p ] \n", NetCfg->KeepAlive.dwConnectionId, NetCfg->KeepAlive.pHandlerAddress);
#endif

    NetCfg->bInitialized = TRUE;

    return TRUE;
}

/*
*   Network hash calculation using DJB2 algorithm
*   From : https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp
*/
DWORD XmCalculateNetworkHash(IN LPCSTR String)
{
    ULONG Hash = 5381;
    INT c = 0;

    while (c = *String++)
        Hash = ((Hash << 5) + Hash) + c;

    return Hash;
}

/*
*   Session ID generator using XORshift algorithm
*/
unsigned int XmGenerateSessionId() 
{
    static unsigned int state = 123456789;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

// Protocol string concatenation
VOID XmConcatProtocolString(IN WCHAR* pDest, IN WCHAR* pSource) 
{
    while (*pDest != 0)
        pDest++;

    while (*pSource != 0) {
        *pDest = *pSource;
        pDest++;
        pSource++;
    }

    *pDest = 0;
}

// Network buffer copy operation
VOID XmCopyNetworkBuffer(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength) 
{
    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--)
        *D++ = *S++;
}

// Network buffer allocation with built-in error checking
PVOID XmAllocateNetworkBuffer(IN SIZE_T sBufferSize) 
{
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap) {
#ifdef DEBUG
        PRINT("[!] Network Memory Pool Initialization Failed - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return NULL;
    }

    PVOID pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sBufferSize);
    if (!pBuffer) {
#ifdef DEBUG
        PRINT("[!] Network Buffer Allocation Failed - Size: %d - %s.%d \n", (int)sBufferSize, GET_FILENAME(__FILE__), __LINE__);
#endif
        return NULL;
    }

#ifdef DEBUG
    PRINT("[+] Network Buffer Allocated - Address: 0x%p Size: %d \n", pBuffer, (int)sBufferSize);
#endif

    return pBuffer;
}

// Buffer secure wipe operation
extern void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
    unsigned char* p = (unsigned char*)pTarget;
    while (cbTarget-- > 0) {
        *p++ = (unsigned char)value;
    }
    return pTarget;
}

// Network path component search
extern void* __cdecl strrchr(const char*, int);

#pragma intrinsic(strrchr)
#pragma function(strrchr)
char* strrchr(const char* str, int c) {
    char* last_occurrence = NULL;  
    while (*str) {
        if (*str == c) {
            last_occurrence = (char*)str;  
        }
        str++;
    }

    return last_occurrence;
}

// Implement memcpy
extern void* __cdecl memcpy(void*, const void*, size_t);

#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* dest, const void* src, size_t count) {
    char* char_dest = (char*)dest;
    const char* char_src = (const char*)src;
    while (count--) {
        *char_dest++ = *char_src++;
    }
    return dest;
}