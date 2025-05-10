#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#include <memory>

#pragma comment(lib, "ntdll")

#define NT_SUCCESS(status) (status >= 0)

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

enum PROCESSINFOCLASS {
    ProcessHandleInformation = 51
};

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;





int main() {
    DWORD pid = 11111;
    if (pid == 0) {
        printf("Failed to locate media player\n");
        return 1;
    }
    printf("Located media player: PID=%u\n", pid);

    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
    FALSE, pid);
    if (!hProcess) {
        printf("Failed to open WMP process handle (error=%u)\n",
            ::GetLastError());
        return 1;
}

    return 0;
}
