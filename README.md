# Test task from Akvelon #
Author: Bakanov D.A., bakanovda@mail.ru, 2019-09-11

## Task ##

Manual:

Create a Git repo locally or any remote one (github for example)

Add there 1 C++ and 2 C# projects where one of C# projects references another one

Automation:

Get code from Git repo to a local folder

Modify project setting to enable debug symbols in release configuration of the projects

Build code in release configuration with any build engine/script (msbuild for example)

Calculate output files hashes for all binaries/assemblies and make hash/files manifest (xml or json for example)

Make a zip archive including all binaries/assemblies and generated manifest (use 7zip, Windows built in or any other)

Copy resulted zip to any release location

Copy resulted pdbs into a separate folder called Symbols in the same release location, saving original folder hierarchy

Script created and tested on the following environment:
- Windows 7 Pro x64 SP1
- PowerShell 6.2.0-preview.4
- Visual Studio 2017 Community Edition v15.9.13
- Git 2.17

## Usage ##
Run in CMD:

`akv-test.cmd`

Or in PowerShell:

`.\akv-test.ps1 -GitUrl "https://github.com/dbprv/akv-test.git"`
