#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

// Manually defining NtQueryInformationProcess
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    IN	HANDLE              ProcessHandle,
    IN	PROCESSINFOCLASS    ProcessInformationClass,
    OUT	PVOID               ProcessInformation,
    IN	ULONG               ProcessInformationLength,
    OUT PULONG              ReturnLength OPTIONAL
);
_NtQueryInformationProcess NtQueryInfoProcess;

int main() {
    HANDLE                      hProcess;
    DWORD                       processId = 1234;
    BYTE                        beingDebugged;
    PROCESS_BASIC_INFORMATION   pbi;

    // Dynamically resolving NtQueryInformationProcess
    NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
    if (NtQueryInfoProcess == NULL) {
        printf("Failed to resolve NtQueryInformationProcess\n");
        return 0;
    }

    // Get handle to process using pid
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        printf("OpenProcess failed for pid: %i\n", processId);
        return 0;
    }

    // Get ProcessBasicInformation using the process handle in NtQueryInfoProcess
    NTSTATUS status = NtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
    if (!NT_SUCCESS(status)) {
        printf("NTSTATUS had a failure code when trying NtQueryInfoProcess for pid: %i\n", processId);
        return 0;
    }

    // Offset from PEB->BeingDebugged is +0x02
    if (!ReadProcessMemory(hProcess, (PVOID)((uint64_t)pbi.PebBaseAddress + 0x02), &beingDebugged, sizeof(beingDebugged), NULL)) {
        printf("ReadProcessMeory failed to read ProcessParameters offset for pid %i, Error:%i\n", processId, GetLastError());
        return 0;
    }

    printf("Value in beingDebugged PEB flag is: %i\n", beingDebugged);

    return 1;
}