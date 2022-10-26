#pragma code_seg(".tiny")

void ShellCode() {
    __asm {
        mov eax, 0x11223344
        jmp eax
    }
}