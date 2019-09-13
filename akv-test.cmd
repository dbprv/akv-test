@echo off
pwsh.exe -ExecutionPolicy Bypass -Command "&'%~dp0akv-test.ps1'" -GitUrl 'https://github.com/dbprv/akv-test.git'
