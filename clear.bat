@ echo off
cd /d %~dp0
dir /s *.exe 0>nul 1>nul && del /s *.exe
dir /s *.obj 0>nul 1>nul && del /s *.obj
echo "finish!"