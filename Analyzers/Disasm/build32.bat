@echo off

set DDKPATH=X:\WINDDK\7600.16385.1
set Z0PATH=X:\Z0\FirstLook

set PATH=%DDKPATH%\bin\x86;%DDKPATH%\bin\x86\x86;%PATH%
set INCLUDE=%DDKPATH%\inc\api;%DDKPATH%\inc\crt;%Z0PATH%\Include
set LIB=%DDKPATH%\lib\wnet\i386;%DDKPATH%\lib\crt\i386;%Z0PATH%\lib\win32

cl /c /Zi /nologo /GS- opcodes.c
cl /c /Zi /nologo /GS- optypes.c
cl /c /Zi /nologo /GS- mnemonic.c
cl /c /Zi /nologo /GS- disasm.c
cl /c /Zi /nologo /GS- selfcheck.c
cl /c /Zi /nologo /GS- print.c
lib @win32.lib

cl /c /Zi /nologo /GS- constructor.c
cl /c /Zi /nologo /GS- generator.c
link @generator32.lnk

cl /c /Zi /nologo /GS- test.c
link @test32.lnk

del *.obj
