#include <Windows.h>
#include <winnt.h>
#include <fileapi.h>

#include <stdio.h>
#include <malloc.h>
#include <string.h>

char shellCode[] = "";

int main() {
    // Open Target
    const char *TARGET = ".\\test.exe";
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
        return 1;
    }
    puts("Open target success!");
    // Infect Target
    
    return 0;
}