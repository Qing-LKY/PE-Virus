@echo off
rmdir /S /Q test_dir
mkdir test_dir
echo "Advance v1: Just infecting\n"
echo "Build virus..."
cl /c /GS- /Ob1 test_advance.c
link /entry:ShellCode /subsystem:console test_advance.obj
copy test_advance.exe test_dir\virus.exe
echo "Build targets..."
copy blank.exe.bak test_dir\t1.exe
copy blank.exe.bak test_dir\t2.exe
cd test_dir
echo "Start infect..."
.\virus.exe
echo "Run infected..."
.\t1.exe
echo "Build new targets..."
cd ..
copy blank.exe.bak test_dir\t3.exe
cd test_dir
echo "Run infected..."
.\t1.exe
echo "Run new targets..."
.\t3.exe
cd ..
dumpbin /section:.ex /disasm test_dir\t1.exe > t1.c
dumpbin /section:.ex /disasm test_dir\t3.exe > t3.c
dumpbin /disasm test_dir\virus.exe > tv.c