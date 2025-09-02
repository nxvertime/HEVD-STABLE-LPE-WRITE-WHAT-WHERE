#include "patternScanner.h"





////////////////// UTILS //////////////////////
void bye() {
    cout << "bye <3\n";
    system("pause");
    exit(-1);
}

ULONG_PTR GetNtoskrnlBase() {
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        return (ULONG_PTR)drivers[0];
    }
    return 0;
}


vector<BYTE> LoadFile(const wstring& path) {
    ifstream file(path, ios::binary);
    return vector<BYTE>((istreambuf_iterator<char>(file)), {});

}

PIMAGE_SECTION_HEADER GetSection(BYTE* base, const char* name) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec =
        (PIMAGE_SECTION_HEADER)((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (strncmp((char*)sec->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            return sec;
        }
    }
    return nullptr;
}

ULONG_PTR RvaToOffset(DWORD rva, PIMAGE_NT_HEADERS64 nt, BYTE* base) {
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize) {
            return rva - sec->VirtualAddress + sec->PointerToRawData;
        }
    }
    return 0;
}
PIMAGE_SECTION_HEADER GetSectionForRVA(PIMAGE_NT_HEADERS64 nt, DWORD rva) {
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize) {
            return sec;
        }
    }
    return nullptr;
}
BYTE* GetExportPtrAndSize(BYTE* imageBase, const char* exportName, SIZE_T* sectionSize) {
    auto dos = (PIMAGE_DOS_HEADER)imageBase;
    auto nt = (PIMAGE_NT_HEADERS64)(imageBase + dos->e_lfanew);

    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return nullptr;

    DWORD expOff = RvaToOffset(expRVA, nt, imageBase);
    auto expDir = (PIMAGE_EXPORT_DIRECTORY)(imageBase + expOff);

    auto names = (DWORD*)(imageBase + RvaToOffset(expDir->AddressOfNames, nt, imageBase));
    auto ords = (WORD*)(imageBase + RvaToOffset(expDir->AddressOfNameOrdinals, nt, imageBase));
    auto funcs = (DWORD*)(imageBase + RvaToOffset(expDir->AddressOfFunctions, nt, imageBase));

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* name = (char*)(imageBase + RvaToOffset(names[i], nt, imageBase));

        if (_stricmp(name, exportName) == 0) {
            WORD ord = ords[i];
            DWORD funcRVA = funcs[ord];
            DWORD funcOff = RvaToOffset(funcRVA, nt, imageBase);

    
            auto sec = GetSectionForRVA(nt, funcRVA);
            if (!sec) return nullptr;

            *sectionSize = sec->SizeOfRawData;     
            return imageBase + funcOff;             
        }
    }
    return nullptr;
}


BYTE* GetExportFromFile(BYTE* imageBase, const char* exportName) {
    auto dos = (PIMAGE_DOS_HEADER)imageBase;
    auto nt = (PIMAGE_NT_HEADERS64)(imageBase + dos->e_lfanew);

    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return nullptr;

    DWORD expOff = RvaToOffset(expRVA, nt, imageBase);
    auto expDir = (PIMAGE_EXPORT_DIRECTORY)(imageBase + expOff);

    auto names = (DWORD*)(imageBase + RvaToOffset(expDir->AddressOfNames, nt, imageBase));
    auto ords = (WORD*)(imageBase + RvaToOffset(expDir->AddressOfNameOrdinals, nt, imageBase));
    auto funcs = (DWORD*)(imageBase + RvaToOffset(expDir->AddressOfFunctions, nt, imageBase));

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* name = (char*)(imageBase + RvaToOffset(names[i], nt, imageBase));
        if (_stricmp(name, exportName) == 0) {
            WORD ord = ords[i];
            DWORD funcRVA = funcs[ord];
            DWORD funcOff = RvaToOffset(funcRVA, nt, imageBase);
            return imageBase + funcOff;  
        }
    }
    return nullptr;
}

ULONG_PTR GetKernelExport(const char* exportName) {
    ULONG_PTR kernelBase = GetNtoskrnlBase();
    if (!kernelBase) return 0;

    auto data = LoadFile(L"C:\\Windows\\System32\\ntoskrnl.exe");
    if (data.empty()) return 0;

    auto dos = (PIMAGE_DOS_HEADER)data.data();
    auto nt = (PIMAGE_NT_HEADERS64)(data.data() + dos->e_lfanew);

    auto expDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto expDirOff = RvaToOffset(expDirRVA, nt, data.data());
    auto expDir = (PIMAGE_EXPORT_DIRECTORY)(data.data() + expDirOff);

    auto names = (DWORD*)(data.data() + RvaToOffset(expDir->AddressOfNames, nt, data.data()));
    auto ords = (WORD*)(data.data() + RvaToOffset(expDir->AddressOfNameOrdinals, nt, data.data()));
    auto funcs = (DWORD*)(data.data() + RvaToOffset(expDir->AddressOfFunctions, nt, data.data()));

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* name = (char*)(data.data() + RvaToOffset(names[i], nt, data.data()));
        if (_stricmp(name, exportName) == 0) {
            WORD ord = ords[i];
            DWORD funcRVA = funcs[ord];
            return kernelBase + funcRVA;
        }
    }
    return 0;
}
//////////////////////////////////////////////////////////////////////




ULONG_PTR PatternScanner::FindPatternWithMask(BYTE* base, SIZE_T size, const char* pattern, const char* mask) {
    SIZE_T patternLen = strlen(mask);

    for (SIZE_T i = 0; i <= size - patternLen; i++) {
        bool found = true;
        for (SIZE_T j = 0; j < patternLen; j++) {
            if (mask[j] == 'x' && base[i + j] != (BYTE)pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return (ULONG_PTR)(base + i);
        }
    }
    return 0;
}

DWORD PatternScanner::ExtractOffset(BYTE* match, int offset) {


    return *(DWORD*)(match + offset); // 3 = number of opcodes <3
}

// usage (ntoskrnl example):
// you need .text raw section of ntoskrnl
// const char* patternToken = "\x48\x8D\xB1\x00\x00\x00\x00";
// const char* maskToken = "xxx????";
// DWORD uniquePidOffset =  PatternScanner::FindOffset(data.data(), data.size(), pattern, mask);
DWORD PatternScanner::FindOffset(BYTE* base, SIZE_T size, const char* pattern, const char* mask, int offset) {
    ULONG_PTR match = FindPatternWithMask(base, size, pattern, mask);
    if (!match) return 0;
    return ExtractOffset((BYTE*)match);
}

/*
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠤⢒⣖⣒⠒⠒⠤⠄⣀⣀⣠⡤⠒⠒⠒⠒⠒⠦⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠞⠁⡤⠚⣉⡠⠼⠗⠀⠀⠀⠀⠀⣼⣷⡄⠰⣏⠉⠉⠑⠲⢌⡑⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡠⠊⠀⠀⠘⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠈⠉⠉⠉⠐⠺⢦⡙⢦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀0xc0ffeebabe <3⠀⠀⠀⠀⠉⠀⠑⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠋⠀⠀⠀⠀⢀⣠⠤⠒⠒⢲⠒⠒⠤⠤⠤⠤⡤⠤⠤⠤⠖⠒⣶⠒⠒⠢⢄⡀⠀⠀⠀⠀⠈⢦⠀⠀⠀⠀
⠀⠀⣠⠞⠁⠀⠀⢀⡤⠒⣟⠀⠀⠀⠀⢺⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⢹⠓⠤⡀⠀⠀⠀⠑⢄⡀⠀
⣴⡎⠁⢀⣀⡤⠒⠉⠉⠉⢹⠀⠀⠀⢠⠟⠦⠤⠀⣀⠠⠴⠧⠤⣀⡀⠤⠤⠚⡆⠀⠀⠀⡸⠉⠉⠉⠓⠤⣄⣀⠀⠉⢢
⠙⠻⣄⠀⠉⠉⠒⠤⢄⣀⠀⢇⠀⠀⢻⠀⠀⠀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⢰⠀⠀⣰⠃⢀⣀⠤⠒⠊⠉⠀⢀⡴⠋
⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠈⢙⣧⡀⠘⣍⠿⠇⠀⠀⢠⡖⠒⠒⠢⣤⠈⠯⣍⡇⠀⣰⣟⠉⠁⠀⠀⠀⠀⢀⠔⠁⠀⠀
⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠠⠔⠓⠦⠃⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠈⠧⠞⠳⠄⠀⠀⠀⠀⢀⠔⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠑⠦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠚⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠒⠤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠖⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠚⢯⠁⢰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⢷⡶⢶⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆⣉⣉⡜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀*/
