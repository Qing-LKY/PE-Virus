@echo off
echo Build Tools: dump.exe, trans.exe, format.exe
echo dump.exe: Read pe file, get section and output binary
cl dump.c
echo trans.exe: Read binary file and trans to C char array
cl trans.c
echo format.exe: Interactor. Read string and trans to C char array
cl format.c
echo Finish!