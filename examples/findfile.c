#include <Windows.h>
#include <stdio.h>
#include <winnt.h>
#include <winbase.h>
#include <winternl.h>
#include <libloaderapi.h>
#include <minwindef.h>
#include <minwinbase.h>
#include <fileapi.h>
// #include <shellapi.h>

typedef HANDLE (WINAPI *__FindFirstFileA) (
    _In_ LPCSTR lpFileName,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData
);

typedef BOOL (WINAPI *__FindNextFileA) (
    _In_ HANDLE hFindFile,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData
);

typedef BOOL (WINAPI *__FindClose) (
    _Inout_ HANDLE hFindFile
);

int main() {
    // 加载模块
    HMODULE hModule = LoadLibrary(TEXT("Kernel32.dll"));
    // 获取函数
    puts("Loading Functions");
    __FindFirstFileA find_first_file = (__FindFirstFileA)GetProcAddress(hModule, "FindFirstFileA");
    __FindNextFileA find_next_file = (__FindNextFileA)GetProcAddress(hModule, "FindNextFileA");
    __FindClose find_close = (__FindClose)GetProcAddress(hModule, "__FindClose");

    WIN32_FIND_DATAA FindFileData;
    char name[10] = ".\\*.*";
    // 它要求传进去的是个已经分配了空间的指针
    puts("Call FindFirstFileA");
    HANDLE hFindFile = find_first_file(name, &FindFileData);
    if(hFindFile == INVALID_HANDLE_VALUE) {
        puts("NO!!!!");
        return 0;
    }
    puts("Call FindNextFileA");
    LPWIN32_FIND_DATAA lpFindFileData = &FindFileData;
    do {
        printf("(%x): ", lpFindFileData->dwFileAttributes);
        puts(lpFindFileData->cFileName);
        // in winnt.h
        if(lpFindFileData->dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) puts("It's a file!");
        // puts(lpFindFileData->cAlternateFileName);
    } while(find_next_file(hFindFile, lpFindFileData));
    puts("Call FindClose");
    find_close(hFindFile);
    return 0;
}