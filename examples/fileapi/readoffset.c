#include <Windows.h> // 放在前面
#include <stdio.h>
#include <winnt.h>
#include <winbase.h>
#include <winternl.h>
#include <libloaderapi.h>
#include <minwindef.h>
#include <fileapi.h>
#include <handleapi.h>
// #include <shellapi.h>

typedef BOOL (WINAPI *__ReadFile) (
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);

typedef DWORD (WINAPI *__SetFilePointer) (
    _In_ HANDLE hFile,
    _In_ LONG lDistanceToMove,
    _Inout_opt_ PLONG lpDistanceToMoveHigh,
    _In_ DWORD dwMoveMethod
);

typedef BOOL (WINAPI *__CloseHandle) (
    _In_ _Post_ptr_invalid_ HANDLE hObject
);

int main() {
    HANDLE hf = CreateFileA(
        "readoffset.c", 
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    SetFilePointer(hf, 0x10, NULL, FILE_BEGIN);
    char buf[1 << 14];
    DWORD tmp;
    ReadFile(hf, buf, 0x10, &tmp, NULL);
    long x = SetFilePointer(hf, 0, NULL, FILE_CURRENT);
    puts(buf);
    printf("%x\n", x);
    CloseHandle(hf);
    printf("%d\n", (int)sizeof(IMAGE_OPTIONAL_HEADER32));
    return 0;
}