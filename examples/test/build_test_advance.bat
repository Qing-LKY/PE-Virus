@echo off
rmdir /S /Q test_dir
mkdir test_dir
echo "Build virus..."
cl /GS- test_advance.c
copy test_advance.exe test_dir\virus.exe
echo "Build targets..."
copy blank.exe.bak test_dir\t1.exe
copy blank.exe.bak test_dir\t2.exe
copy blank.exe.bak test_dir\t3.exe
cd test_dir
echo "Start infect..."
.\virus.exe
echo "Run infected..."
.\t1.exe
echo "Build new targets..."
cd ..
copy blank.exe.bak test_dir\t4.exe
copy blank.exe.bak test_dir\t5.exe
copy blank.exe.bak test_dir\t6.exe
cd test_dir
echo "Run infected..."
.\t3.exe
echo "Run new targets..."
.\t6.exe
cd ..