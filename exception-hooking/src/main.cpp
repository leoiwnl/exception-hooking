#include "includes.h"

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = nullptr;
BYTE OriginalByte = 0;

int WINAPI MessageBoxAHk(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) 
{
    printf("Hook triggered\n");

    DWORD oldProtect; // write the original byte so the original function still works
    VirtualProtect((LPVOID)OriginalMessageBoxA, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)OriginalMessageBoxA = OriginalByte;
    VirtualProtect((LPVOID)OriginalMessageBoxA, 1, oldProtect, &oldProtect);

    int result = OriginalMessageBoxA(hWnd, "Hooked MessageBox", "Hooked", uType); // store returned value of function

    // patch the function again so it the exception is created again
    VirtualProtect((LPVOID)OriginalMessageBoxA, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)OriginalMessageBoxA = 0xCC;
    VirtualProtect((LPVOID)OriginalMessageBoxA, 1, oldProtect, &oldProtect);

    return result;
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* Exception)
{
    auto code = Exception->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT)
    {
        void* address = Exception->ExceptionRecord->ExceptionAddress;
        printf("Exception at: %p\n", Exception->ExceptionRecord->ExceptionAddress);
        if (address == (void*)OriginalMessageBoxA)
        {
            printf("Caught our exception. Redirecting...\n");

            Exception->ContextRecord->Rip = (DWORD64)MessageBoxAHk;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) return 1;

    AddVectoredExceptionHandler(1, ExceptionHandler);

    OriginalMessageBoxA = (MessageBoxA_t)GetProcAddress(hUser32, "MessageBoxA");

    DWORD vprotect;
    VirtualProtect((LPVOID)OriginalMessageBoxA, 1, PAGE_EXECUTE_READWRITE, &vprotect);
    OriginalByte = *(BYTE*)OriginalMessageBoxA;
    *(BYTE*)OriginalMessageBoxA = 0xCC; // patch first byte with int 3 which causes crash
    VirtualProtect((LPVOID)OriginalMessageBoxA, 1, vprotect, &vprotect);

    printf("Hooked MessageBoxA\n");
    printf("Testing Hook...\n");

    MessageBoxA(NULL, "Test Hook", "Test", MB_OK);
    MessageBoxA(NULL, "Test Hook", "Test", MB_OK);

    std::cin.get();
    return 0;
}