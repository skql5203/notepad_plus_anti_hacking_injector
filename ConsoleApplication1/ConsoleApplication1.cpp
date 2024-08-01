#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>

void InjectDLL(DWORD pid, LPCSTR dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (NULL == hProcess) {
        return;
    }
    LPVOID lpAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (lpAddr) {
        WriteProcessMemory(hProcess, lpAddr, dllPath, strlen(dllPath) + 1, NULL);
    }
    else {
        return;
    }
    LPTHREAD_START_ROUTINE pfnLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (pfnLoadLibraryA) {
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnLoadLibraryA, lpAddr, 0, NULL);
        DWORD dwExitCode = NULL;
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            if (GetExitCodeThread(hThread, &dwExitCode))
                CloseHandle(hThread);
        }
    }
    VirtualFreeEx(hProcess, lpAddr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}
void WaitForEvent() {
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, L"Keettoo1234");
    if (!hEvent) {
        std::cerr << "Failed to create or open event." << std::endl;
        return;
    }

    while (true) {
        WaitForSingleObject(hEvent, INFINITE);

        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm;
        localtime_s(&now_tm, &now_c);

        std::cout << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << " hacking detected!!" << std::endl;
    }

    CloseHandle(hEvent);
}
char* GetDllPath() {
    char path[MAX_PATH];
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule != NULL) {
        GetModuleFileNameA(hModule, path, sizeof(path));
    }

    // .exe를 .dll로 변경
    char* pos = strrchr(path, '.');
    if (pos != NULL && strcmp(pos, ".exe") == 0) {
        strcpy(pos, ".dll");
    }

    // 결과를 동적 메모리에 복사
    char* dllPath = (char*)malloc(strlen(path) + 1);
    if (dllPath != NULL) {
        strcpy(dllPath, path);
    }
    return dllPath;
}
int main() {
    char* dllPath = GetDllPath();
    if (dllPath == NULL || GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("DLL not found.\n");
        free(dllPath);
        return 1;
    }
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitForEvent, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create event waiting thread." << std::endl;
        free(dllPath);
        return 1;
    }
    while (1) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            free(dllPath);

            return 1;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            free(dllPath);

            return 1;
        }

        do {

            if (pe.th32ProcessID != GetCurrentProcessId()) {
                InjectDLL(pe.th32ProcessID, dllPath);
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);
        Sleep(1000);

    }
    WaitForSingleObject(hThread, INFINITE);

    free(dllPath);

    return 0;
}