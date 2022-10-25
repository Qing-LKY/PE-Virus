#include <Windows.h> // 放在前面
//#include <stdio.h>
#include <winnt.h>
//#include <winbase.h>
#include <libloaderapi.h>
#include <minwindef.h>
//#include <shellapi.h>

typedef int(WINAPI *ShellAboutProc)(HWND, LPCSTR, LPCSTR, HICON);

int main() {
    HMODULE hModule = LoadLibrary(TEXT("Shell32.dll"));
    ShellAboutProc shellAbout = (ShellAboutProc)GetProcAddress(hModule, "ShellAboutA");
    shellAbout(NULL, "hello", "world", NULL);
    FreeLibrary(hModule);
    return 0;
}