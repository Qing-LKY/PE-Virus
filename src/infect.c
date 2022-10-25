#include <Windows.h>
#include <winnt.h>
#include <fileapi.h>

#include <stdio.h>
#include <malloc.h>
#include <string.h>

void ReadOffset(HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(!SetFilePointer(hFile, offset, NULL, mode)) {
        puts("Error when set file pointor!");
        exit(1);
    }
    if(!ReadFile(hFile, buf, size, NULL, NULL)) {
        puts("Error when read file!");
        exit(1);
    }
}

#define BUF_SIZE (1 << 20)

const char *TARGET = ".\\test.exe";
char shellCode[] = "Nothing here!";
char buf[BUF_SIZE];

HANDLE OpenTarget() {
    HANDLE hFile = CreateFileA(
        TARGET, 
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if(hFile == NULL) {
        puts("Open target failed.");
        exit(1);
    }
    puts("Open target success!");
    return hFile;
}

IMAGE_DOS_HEADER dosHeader;

void InfectTarget(HANDLE hFile) {
    // Parse DOS Header
    ReadOffset(
        hFile, offset, FILE_BEGIN, 
        (PVOID)&dosHeader, sizeof(IMAGE_DOS_HEADER)
    );
    PIMAGE_DOS_HEADER pDosHdr = &dosHeader;
    DWORD pe00;
    ReadOffset(
        hFile, pDosHdr->e_lfanew, FILE_BEGIN,
        (PVOID)&pe00, sizeof(DWORD)
    );
    if(pe00 != 0x00004550) {
        puts("Not a pe file!");
        exit(1);
    }
}

int main() {
    HANDLE hf = OpenTarget();
    InfectTarget(hf);
    return 0;
}