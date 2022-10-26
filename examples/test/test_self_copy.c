#include <Windows.h>
#include <winternl.h>
#include <minwindef.h>
#include <minwinbase.h>
#include <winnt.h>

#include <stdio.h>
#include <string.h>

// test for a self copy

void ShellCode() {
__code_start:
    // do something
    int a, b, c;
    a = 1, b = 2;
    c = a + b;
    a = c - b;
    b = a * b * c;
    // copy self
    PVOID codeAdr;
    DWORD codeSize;
    __asm {
        mov eax, __code_start
        mov codeAdr, eax
        mov eax, __code_end
        sub eax, __code_start
        mov codeSize, eax
    }
    printf("%#p %d\n", codeAdr, codeSize);
    // system("PAUSE");
    // __asm {
    //     mov eax, codeAdr
    //     jmp eax
    // }
__code_end:
    __asm nop
}

int main() {
    ShellCode();
    return 0;
}