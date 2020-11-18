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

size_t getBytecodeOfNtAPI(const char* ntAPItoLookup) {
    static BYTE* dumpImage = 0;
    if (dumpImage == nullptr) {
        // read whole PE static binary.
        FILE* fileptr; BYTE* buffer; LONGLONG filelen;
        fileptr = fopen("C:/Windows/SysWoW64/ntdll.dll", "rb");
        fseek(fileptr, 0, SEEK_END); 
        filelen = ftell(fileptr);
        rewind(fileptr);
        buffer = (BYTE*)malloc((filelen + 1) * sizeof(char));
        fread(buffer, filelen, 1, fileptr);

        // dump static PE binary into image.
        PIMAGE_NT_HEADERS ntHdr = (IMAGE_NT_HEADERS*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
        dumpImage = (BYTE*)malloc(ntHdr->OptionalHeader.SizeOfImage);
        memcpy(dumpImage, buffer, ntHdr->OptionalHeader.SizeOfHeaders);
        for (size_t i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
            auto curr = PIMAGE_SECTION_HEADER(size_t(ntHdr) + sizeof(IMAGE_NT_HEADERS))[i];
            memcpy(dumpImage + curr.VirtualAddress, buffer + curr.PointerToRawData, curr.SizeOfRawData);
        }
        free(buffer);
        fclose(fileptr);
    }
    // EAT parse.
    PIMAGE_NT_HEADERS ntHdr = (IMAGE_NT_HEADERS*)(dumpImage + ((IMAGE_DOS_HEADER*)dumpImage)->e_lfanew);
    auto a = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)dumpImage + a.VirtualAddress);
    uint32_t* addrOfNames = (uint32_t*)((size_t)dumpImage + ied->AddressOfNames);
    uint16_t* addrOfNameOrds = (uint16_t*)((size_t)dumpImage + ied->AddressOfNameOrdinals);
    uint32_t* AddrOfFuncAddrs = (uint32_t*)((size_t)dumpImage + ied->AddressOfFunctions);
    if (ied->NumberOfNames == 0) return (size_t)0;
    for (DWORD i = 0; i < ied->NumberOfNames; i++)
        if (!stricmp((char*)((size_t)dumpImage + addrOfNames[i]), ntAPItoLookup))
            return ((size_t)dumpImage + AddrOfFuncAddrs[addrOfNameOrds[i]]);
    return 0;
}

template <typename... Args> NTSTATUS NtAPI(const char* szNtApiToCall, Args... a) {
    uint8_t stub_template[] = {
        /* +00 - mov eax, 00000000 */ 0xB8, 0x00, 0x00, 0x00, 0x00,
        /* +05 - call fs: [0xC0]   */ 0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,
        /* +0C - ret               */ 0xC3
    };
    PCHAR apiAddr = PCHAR(getBytecodeOfNtAPI(szNtApiToCall));
    if (*apiAddr - '\xB8') errorExit("this NtAPI not supported.");
    PCHAR jit_stub = (PCHAR)VirtualAlloc(0, sizeof(stub_template), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(jit_stub, stub_template, sizeof(stub_template));
    *(uint32_t *)&jit_stub[0x01] = *(uint32_t *)&apiAddr[1];
    auto ret = ((NTSTATUS(__cdecl*)(...))jit_stub)(forward<Args>(a)...);
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
