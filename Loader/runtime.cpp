#include <Windows.h>

// Runtime check support
extern "C" {
    void _RTC_InitBase(void) {}
    void _RTC_Shutdown(void) {}
    void _RTC_CheckStackVars(void) {}
}

// String length functions
// Note: These are marked extern "C" to ensure C linkage
extern "C" {
    size_t strlen(const char* str) {
        const char* s = str;
        while (*s) s++;
        return s - str;
    }

    size_t wcslen(const wchar_t* str) {
        const wchar_t* s = str;
        while (*s) s++;
        return s - str;
    }
}