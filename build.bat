@echo off
cl /nologo /EHsc /O2 /MT /W3 /utf-8 /DUNICODE /D_UNICODE MabiChecker.cpp /link /SUBSYSTEM:WINDOWS /OUT:MabiChecker.exe
if errorlevel 1 (echo BUILD FAILED) else (echo BUILD OK)
del MabiChecker.obj MabiChecker.exe.manifest
pause