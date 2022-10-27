#include <Windows.h> // 放在前面
#include <stdio.h>
#include <winnt.h>
#include <winbase.h>
#include <winternl.h>
#include <libloaderapi.h>
#include <minwindef.h>
#include <fileapi.h>
// #include <shellapi.h>

typedef HANDLE (WINAPI *__CreateFileA) (
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
);

typedef BOOL (WINAPI *__WriteFile) (
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);

int main() {
    // 加载模块
    HMODULE hModule = LoadLibrary(TEXT("Kernel32.dll"));
    // 获取函数
    __CreateFileA create_file = (__CreateFileA)GetProcAddress(hModule, "CreateFileA");
    __WriteFile write_file = (__WriteFile)GetProcAddress(hModule, "WriteFile");
    // 创建文件
    HANDLE hf = (create_file)(
        "myCreate.txt", /* File name with ascii*/ 
        GENERIC_READ | GENERIC_WRITE, /* File access */
        0, /* No share */
        NULL,
        CREATE_ALWAYS, /* Overwrite when file existed */
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );
    if(hf == INVALID_HANDLE_VALUE) return 0;
    // 写入 Hello World!
    char *buf = "Hello World!";
    BOOL e = write_file(hf, buf, 12, NULL, NULL);
    // 释放模块
    FreeLibrary(hModule);
    
    // 不加载也能用？
    HANDLE bf = CreateFileA(
        "myCreate1.txt", /* File name with ascii*/ 
        GENERIC_READ | GENERIC_WRITE, /* File access */
        0, /* No share */
        NULL,
        CREATE_ALWAYS, /* Overwrite when file existed */
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );
    WriteFile(bf, buf, 12, NULL, NULL);
    CHAR str[114];
    int n = GetFinalPathNameByHandleA(bf, str, 114, 0x8);   
    puts(str); 
    return 0;
}