#include <Windows.h>
#include <winternl.h>
#include <minwindef.h>
#include <minwinbase.h>
#include <winnt.h>

#include <fileapi.h>
#include <handleapi.h>

// test for junior shellcode
// find a *.txt, copy it to another one

#define MAX_SIZE 128

void ShellCode() {
    // find an text file
    char textSrc[6] = {'*', '.', 't', 'x', 't', 0};
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(textSrc, &findData);
    if(hFind == INVALID_HANDLE_VALUE) goto __fail_find;
    // open target and close find
    HANDLE hf1 = CreateFileA(
        findData.cFileName, GENERIC_READ,
        0, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if(hf1 == NULL) goto __fail_src;
    // open target2
    char textDst[18] = {'2', '0', '2', '0', '3', '0', '2', '1', '8', '1', '0', '3', '2', '.', 't', 'x', 't', 0};
    HANDLE hf2 = CreateFileA(
        textDst, GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE,
        NULL
    );
    if(hf1 == NULL) goto __fail_dst;
    // get file size
    DWORD siz = GetFileSize(hf1, NULL);
    BYTE buf[MAX_SIZE];
    while(siz > 0) {
        DWORD csiz = siz > MAX_SIZE ? MAX_SIZE : siz;
        if(ReadFile(hf1, buf, csiz, NULL, NULL) == FALSE) goto __fail_copy; 
        if(WriteFile(hf2, buf, csiz, NULL, NULL) == FALSE) goto __fail_copy;
        siz -= csiz;
    }
__fail_copy:
    CloseHandle(hf2);
__fail_dst:
    CloseHandle(hf1);
__fail_src:
    FindClose(hFind);
__fail_find:
    return;
}

int main() {
    ShellCode();
    return 0;
}