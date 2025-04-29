@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
if errorlevel 1 call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
if errorlevel 1 call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat"
if errorlevel 1 call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
if errorlevel 1 echo Visual Studio environment not found. Please install Visual Studio or Build Tools.

cl.exe /EHsc /std:c++17 /I"include" main.cpp file_utils.cpp registry_utils.cpp toast.cpp monitor.cpp /link /out:edr.exe 