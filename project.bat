@echo off

set root=%cd%
set test=%cd%\test
set src=%cd%\src\shellcode
set tool=%cd%\src\tools

:help
echo "0: help"
echo "1: clear exe"
echo "2: build all (include 3, 4)"
echo "3: build tools"
echo "4: complie shellcode"
echo "5: test junior"
echo "6: test advance"
echo "9: quit"
echo "others: help"

:interact
cd %root%
set /p opt="Select to do: "
if %opt% equ 1 (
    goto clear_exe
) else if %opt% equ 2 (
    goto build_all
) else if %opt% equ 3 (
    goto build_tools
) else if %opt% equ 4 (
    goto complie_shell_code
) else if %opt% equ 5 (
    goto test_junior
) else if %opt% equ 6 (
    goto test_advance2
) else if %opt% equ 9 (
    goto quit
) else (
    goto help
)

:clear_exe
cd %root%
call clear.bat
goto interact

:build_all
cd %tool%
call build_tools.bat
cd %src%
cl /c /GS- /Ob1 junior.c
cl /c /GS- /Ob1 tiny.c
cl /c /GS- /Ob1 advance.c
cl /c /GS- /Ob1 advance2.c
goto interact

:build_tools
cd %tool%
call build_tools.bat
goto interact

:complie_shell_code
cd %src%
cl /c /GS- /Ob1 junior.c
cl /c /GS- /Ob1 tiny.c
cl /c /GS- /Ob1 advance.c
cl /c /GS- /Ob1 advance2.c
goto interact

:test_junior
if exist %test% rmdir /S /Q %test%
mkdir %test%
rem build shellcode.c
cd %src%
link /entry:ShellCode /subsystem:console junior.obj
%tool%\dump.exe /f:junior.exe /s:.junior /ob:junior.bin
%tool%\trans.exe junior.bin > %test%\shellcode.c
rem build infect.exe
cd %test%
copy %tool%\infect.c .\infect.c
cl /Ob1 /GS- infect.c
del infect.c
del infect.obj
del shellcode.c
rem set target files
copy %root%\blank.exe.bak %test%\hello.exe
echo "Test string!" > %test%\copy_me.txt
cd %test%
(echo hello.exe) | .\infect.exe
.\hello.exe
dumpbin hello.exe
goto interact

:test_advance2
if exist %test% rmdir /S /Q %test%
mkdir %test%
rem Advance2 can run itself
cd %src%
link /entry:ShellCode /subsystem:console advance2.obj
copy advance2.exe %test%\virus.exe
copy %root%\blank.exe.bak %test%\hello.exe
cd %test%
.\virus.exe
echo "Test string!" > %test%\copy_me.txt
.\hello.exe
dumpbin hello.exe
goto interact

:quit
echo "See you next time!"