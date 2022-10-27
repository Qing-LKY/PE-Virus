@echo off
rmdir /S /Q test_dir
mkdir test_dir
cl test_advance.c
copy test_advance.exe test_dir\virus.exe
copy blank.exe.bak test_dir\t1.exe
copy blank.exe.bak test_dir\t2.exe
copy blank.exe.bak test_dir\t3.exe
cd test_dir
.\virus.exe
cd ..