/* wowJit - Call 32bit NtDLL API directly from WoW64 Layer
 * author: aaaddress1@chroot.org
 *
 * inspired by ReWolf's blog: Mixing x86 with x64 code
 * > http://blog.rewolf.pl/blog/?p=102
 */ 
#include <iostream>
#include <Windows.h>
using namespace std;
#pragma warning(disable:4996)
#define errorExit(msg) { OutputDebugStringA(msg), exit(-1); }
template <typename... Args> NTSTATUS NtAPI(const char* szNtApiToCall, Args... a) {
    uint8_t stub_template[] = {
        /* +00 - mov eax, 00000000 */ 0xB8, 0x00, 0x00, 0x00, 0x00,
        /* +05 - call fs: [0xC0]   */ 0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,
        /* +0C - ret 0xFFFF        */ 0xC2, 0xFF, 0xFF
    };
    PCHAR apiAddr = (PCHAR)GetProcAddress(LoadLibraryA("ntdll"), szNtApiToCall);
    if (*apiAddr - '\xB8') errorExit("this NtAPI not supported.");

    PCHAR jit_stub = (PCHAR)VirtualAlloc(0, sizeof(stub_template), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(jit_stub, stub_template, sizeof(stub_template));
    *(uint32_t *)&jit_stub[0x01] = *(uint32_t *)&apiAddr[1];
    *(uint16_t *)&jit_stub[0x0d] = sizeof...(a) * sizeof(uint32_t);
    auto ret = ((NTSTATUS(__fastcall*)(...))jit_stub)(forward<Args>(a)...);
    VirtualFree(jit_stub, sizeof(stub_template), MEM_FREE);
    return ret;
}

int main() {
    DWORD PID;
    if (!GetWindowThreadProcessId(FindWindowA("notepad", NULL), &PID))
        errorExit("notepad not exist?");
   
    if (HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID)) {
        NtAPI("ZwTerminateProcess", hProcess, 1);
        errorExit("done.");
    }
    else errorExit("fetch hProcess fail.");
}