#include <Windows.h>
#include <winternl.h>
#include <minwindef.h>

#pragma code_seg(".tiny")

/*
 cl -c tiny.c
 link -dll tiny.obj
*/
void ShellCode() {
    PBYTE peb;
    __asm {
        mov eax, fs:[30h]
        mov peb, eax
    }
    DWORD imageBase;
    imageBase = *(DWORD*)(peb + 0x8);
    __asm {
        mov eax, imageBase
        add eax, 0x11223344
        jmp eax
    }
}