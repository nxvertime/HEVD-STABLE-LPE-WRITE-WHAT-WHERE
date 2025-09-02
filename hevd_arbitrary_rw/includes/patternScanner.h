#pragma once
#include <vector>
#include <Windows.h>
#include <string>
#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#pragma comment(lib, "Psapi.lib")

#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader) \
    ((PIMAGE_SECTION_HEADER)((ULONG_PTR)&((PIMAGE_NT_HEADERS)(ntheader))->OptionalHeader + \
    ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))
#endif
using namespace std;

void bye();
ULONG_PTR GetNtoskrnlBase();
vector<BYTE> LoadFile(const wstring& path);
ULONG_PTR GetKernelExport(const char* exportName);
BYTE* GetExportFromFile(BYTE* imageBase, const char* exportName);
BYTE* GetExportPtrAndSize(BYTE* imageBase, const char* exportName, SIZE_T* sectionSize);
PIMAGE_SECTION_HEADER GetSection(BYTE* base, const char* name);

namespace PatternScanner {
	ULONG_PTR FindPatternWithMask(BYTE* base, SIZE_T size, const char* pattern, const char* mask);
	DWORD ExtractOffset(BYTE* match, int offset = 3);
	DWORD FindOffset(BYTE* base, SIZE_T size, const char* pattern, const char* mask, int offset = 3);
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

