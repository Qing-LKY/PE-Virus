@ echo off
cd /d %~dp0
dir /s *.exe 0>nul 1>nul && del /s *.exe
dir /s *.obj 0>nul 1>nul && del /s *.obj
dir /s *.bin 0>nul 1>nul && del /s *.bin
echo "finish!"