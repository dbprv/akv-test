#Requires -Version 6

<#
.SYNOPSIS
Test task from Akvelon.
Author: Bakanov D.A., bakanovda@mail.ru
2019-09-11

.DESCRIPTION
Task:
Get code from Git repo to a local folder
Modify project setting to enable debug symbols in release configuration of the projects
Build code in release configuration with any build engine/script (msbuild for example)
Calculate output files hashes for all binaries/assemblies and make hash/files manifest (xml or json for example)
Make a zip archive including all binaries/assemblies and generated manifest (use 7zip, Windows built in or any other)
Copy resulted zip to any release location
Copy resulted pdbs into a separate folder called Symbols in the same release location, saving original folder hierarchy

.PARAMETER GitUrl
URL of Git repository.

.PARAMETER LocalFolder
Where to save code from Git.

.PARAMETER ReleaseLocation
Result folder.

.EXAMPLE
PS> .\akv-test.ps1 -GitUrl "https://github.com/dbprv/akv-test.git"

.LINK
https://github.com/dbprv/akv-test

#>

param (
  [string]$GitUrl = $(throw "Git URL is missing"),
  [string]$LocalFolder = (Join-Path $PSScriptRoot "LocalFolder"),
  [string]$ReleaseLocation = (Join-Path $PSScriptRoot "ReleaseLocation")
)

Set-PSDebug -Strict
$ErrorActionPreference = "Stop"

[string]$script_path, [string]$script_dir, [string]$script_name = Get-Item $MyInvocation.MyCommand.Path | % { @($_.FullName, $_.DirectoryName, $_.BaseName) }
$log = Join-Path $script_dir "$script_name.log"
try { Stop-Transcript >$null } catch { }
try { Start-Transcript -Path $log -Force -EA 0 } catch { }
$script_begin_time = Get-Date

### Variables:
$script:visual_studio_info = $null

### Functions:

function Test-Folder {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true,
               Position = 1)]
    [string]$Path,
    [switch]$Create,
    [switch]$Recreate,
    [switch]$Clear
  )
  
  try {
    if (Test-Path $Path -PathType "Container") {
      ### Folder exists
      if ($Clear) {
        dir $Path -Force | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction 'Continue'
      }
      if (! $Recreate) {
        return $true
      }
    }
    
    ### Folder not exists
    if (!$Create -and !$Recreate) {
      return $false
    }
    
    if ($Recreate) {
      try { Remove-Item -Path $Path -Recurse -Force -Confirm:$false -ErrorAction 'SilentlyContinue' >$null } catch { }
      if (Test-Path $Path -PathType "Container") {
        throw "Cannot delete folder 'Folder' to recreate"
      }
    }
    
    New-Item -Path $Path -ItemType Directory -ErrorAction 'SilentlyContinue' >$null
    if (Test-Path $Path -PathType "Container") {
      Write-Verbose "Folder '$Path' is created"
      return $true
    } else {
      throw "Cannot create folder '$Path'"
    }
    
    return $true
    
  } catch {
    if ($ErrorActionPreference -eq 'Stop') {
      throw
    } elseif ($ErrorActionPreference -ne 'SilentlyContinue') {
      Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
      Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
    }
    return $false
    
  } finally {
  }
}

function Add-FileHashProperty {
  param
    (
    [Parameter(Mandatory = $true,
               ValueFromPipeline = $true)]
    [System.IO.FileInfo]$File,
    [ValidateSet("MD5", IgnoreCase = $true)]
    [string]$HashType = "MD5",
    [string]$HashPropertyName = "Hash"
  )
  
  begin {
    $begin_time = [datetime]::Now
    Write-Host "`r`n*** Add Hash property to file..." -ForegroundColor 'White'
    $md5_csp = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
  }
  
  process {
    $hash_begin_time = [datetime]::Now
    $hash = $duration = $null
    if ($HashType -eq "MD5") {
      try {
        $hash = [string](([System.BitConverter]::ToString($md5_csp.ComputeHash([System.IO.File]::ReadAllBytes($File.FullName)))) -replace "-")
      } catch { }
    } else {
      throw "Unknown hash type '$HashType'"
    }
    $duration = [datetime]::Now - $hash_begin_time
    
    if ($hash) {
      $File `
      | Add-Member -MemberType NoteProperty -Name $HashPropertyName -Value $hash -Force -PassThru `
      | Add-Member -MemberType NoteProperty -Name "HashCalcDuration" -Value $duration -Force
    }
    
    $File
  }
  
  end {
    Write-Host ("Add-FileHashProperty end ({0:f3}s)" -f ((([datetime]::Now) - $begin_time).TotalSeconds))
  }
}


function Save-FormattedXml {
  param
    (
    [Parameter(Mandatory = $true)]
    [xml]$Xml,
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  $doc = [System.Xml.Linq.XDocument]::Parse($Xml.OuterXml)
  $new_xml = $null
  $new_xml = New-Object System.Xml.XmlDocument
  $new_xml.PreserveWhitespace = $true
  $xml.LoadXml($doc.ToString())
  $xml.Save($Path)
}

function Get-RegistryValue {
  [CmdletBinding()]
  param
    (
    [Parameter(Mandatory = $true)]
    [string]$KeyPath,
    [Parameter(Mandatory = $true)]
    [string]$ValueName,
    [string]$Computer = $env:COMPUTERNAME
  )
  
  try {
    
    $hive_name = $key_path = $null
    $hive_name, $key_path = $KeyPath -split "\\", 2
    
    $hive = $null
    if (@("HKLM", "HKLM:", "HKEY_LOCAL_MACHINE") -contains $hive_name) {
      $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    } elseif (@("HKCU", "HKCU:", "HKEY_CURRENT_USER") -contains $hive_name) {
      $hive = [Microsoft.Win32.RegistryHive]::CurrentUser
    } elseif (@("HKEY_USERS") -contains $hive_name) {
      $hive = [Microsoft.Win32.RegistryHive]::Users
    } else {
      throw "Unknown hive '$hive_name'"
    }
    
    $key = $null
    if ($Computer -eq $env:COMPUTERNAME) {
      if ($hive -eq [Microsoft.Win32.RegistryHive]::LocalMachine) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key_path)
      } elseif ($hive -eq [Microsoft.Win32.RegistryHive]::CurrentUser) {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($key_path)
      } elseif ($hive -eq [Microsoft.Win32.RegistryHive]::Users) {
        $key = [Microsoft.Win32.Registry]::Users.OpenSubKey($key_path)
      } else {
        throw "Unknown hive '$hive'"
      }
    } else {
      $remote_hive = $null
      $remote_hive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $Computer)
      if (! $remote_hive) {
        throw "Cannot open remote registry on '$Computer'"
      }
      $key = $remote_hive.OpenSubKey($key_path)
    }
    if (!$key) {
      throw "Registry key '$KeyPath' does not exist on '$Computer'"
    }
    
    if ($key.GetValueNames() -contains $ValueName) {
      $result = $null
      $result = $key.GetValue($ValueName)
      return @(, $result)
    } else {
      throw "Registry key '$KeyPath' on '$Computer' does not contain value '$ValueName'"
    }
    
  } catch {
    if ($ErrorActionPreference -eq 'Stop') {
      throw
    } elseif ($ErrorActionPreference -ne 'SilentlyContinue') {
      Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
      Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
    }
  }
}

function Clone-GitRepo {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$Url,
    [Parameter(Mandatory = $true)]
    [string]$Folder
  )
  Write-Host "`r`n*** Clone Git Repo:" -ForegroundColor 'White'
  try {
    Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
    
    $git_path = $null
    $git_path = Get-Command "git.exe" -CommandType 'Application' -ErrorAction 'Stop' | select -ExpandProperty Path
    
    Test-Folder -Path $LocalFolder -Create -Clear -ErrorAction 'Stop' >$null
    
    & $git_path @("clone", "--progress", "-v", $Url, $Folder)
    if ($LASTEXITCODE) {
      throw "Cannot clone Git repo '$Url' to '$Folder'"
    }
    
    Write-Host "Done!" -ForegroundColor 'Green'
        
  } catch {
    if ($ErrorActionPreference -eq 'Stop') {
      throw
    } elseif ($ErrorActionPreference -ne 'SilentlyContinue') {
      Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
      Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
    }
  }
}

function Compare-Conditions {
  [OutputType([bool])]
  param (
    [string]$Condition1,
    [string]$Condition2
  )  
  $left1 = $right1 = $left2 = $right2 = $null
  $left1, $right1 = $Condition1.Split("==") | % { $_.Trim() }
  $left2, $right2 = $Condition2.Split("==") | % { $_.Trim() }
  if (($left1 -eq $left2) -and ($right1 -eq $right2)) {
    return $true
  }
  return $false
}


function Enable-DebugSymbols {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true,
               ValueFromPipeline = $true)]
    [string]$ProjectPath,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Debug", "Release", IgnoreCase = $true)]
    [string]$Configuration = "Release"
  )
  
  begin {
    $begin_time = [datetime]::Now
    Write-Host "`r`n*** Enable Debug Symbols begin:" -ForegroundColor 'White'
    Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'    
    $cnt = 0
  }
  
  process {
    $cnt++    
    try {
      Write-Host "`r`nProcess project '$ProjectPath':"
            
      $xml = $null
      $xml = New-Object System.Xml.XmlDocument
      $xml.PreserveWhitespace = $true #to keep formatting
      $xml.LoadXml((gc $ProjectPath -ErrorAction 'Stop' | Out-String)) ### $xml.Load() don't work with UNC path!!!
      $xml_nsm = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
      $xml_nsm.AddNamespace("vs", "http://schemas.microsoft.com/developer/msbuild/2003")
      
      $ext = [System.IO.Path]::GetExtension($ProjectPath)
      
      $project_modified = $false
      $condition = ""
      $xpath = ""
      $namespace = $namespace_full = ""
      $node = $null
      $netcore_project = $false
      
      if ($ext -eq ".csproj") {        
        $condition = "'`$(Configuration)|`$(Platform)'=='$($Configuration)|AnyCPU'"        
        if (@("Microsoft.NET.Sdk", "Microsoft.NET.Sdk.Web") -contains $xml.DocumentElement.Sdk) {
          $netcore_project = $true
          $xpath = "/Project/PropertyGroup[@Condition]"
        } else {
          $xpath = "/vs:Project/vs:PropertyGroup[@Condition]"
          $namespace = "vs:"
          $namespace_full = "http://schemas.microsoft.com/developer/msbuild/2003"
        }
        
        foreach ($node in [System.Xml.XmlElement[]]$xml.SelectNodes($xpath, $xml_nsm)) {
          if ($node.Condition -and (Compare-Conditions $node.Condition $condition)) {
            ### Node found
            break
          }
        }
        
        if (!$node) {
          ### Create new node
          $node = [System.Xml.XmlElement]$xml.DocumentElement.AppendChild($xml.CreateElement("PropertyGroup", $namespace_full))
          $node.SetAttribute("Condition", $condition)
          $project_modified = $true
        }
        
        $props = @{
          DebugType = "full"
          DebugSymbols = "true"
        }
        
        foreach ($prop in $props.GetEnumerator()) {
          Write-Host "Set property $($prop.Key) = '$($prop.Value)': " -NoNewline
          $prop_node = $null
          $prop_node = $node.SelectSingleNode("$($namespace)$($prop.Key)", $xml_nsm)
          if (! $prop_node) {
            $prop_node = $node.AppendChild($xml.CreateElement($prop.Key, $namespace_full))
          }
          
          if ($prop_node.InnerText -ne $prop.Value) {
            $prop_node.InnerText = $prop.Value
            $project_modified = $true
            Write-Host "done" -ForegroundColor 'Magenta'
          } else {
            Write-Host "already set" -ForegroundColor 'Green'
          }
        }
        
      } elseif ($ext -eq ".vcxproj") {
        $condition1 = "'`$(Configuration)|`$(Platform)'=='$($Configuration)|Win32'"
        $condition2 = "'`$(Configuration)|`$(Platform)'=='$($Configuration)|x64'"
        $xpath = "/vs:Project/vs:ItemDefinitionGroup[@Condition]"
        $namespace = "vs:"
        $namespace_full = "http://schemas.microsoft.com/developer/msbuild/2003"
        
        foreach ($node in [System.Xml.XmlElement[]]$xml.SelectNodes($xpath, $xml_nsm)) {
          if ($node.Condition -and ((Compare-Conditions $node.Condition $condition1) -or (Compare-Conditions $node.Condition $condition2))) {
            ### Node found            
            $link_node = $null
            $link_node = $node.SelectSingleNode("vs:Link", $xml_nsm)
            if (! $link_node) {
              $link_node = [System.Xml.XmlElement]$node.AppendChild($xml.CreateElement("Link", $namespace_full))
            }
            $node = $link_node
            
            $props = @{
              GenerateDebugInformation = "true"
            }
            
            foreach ($prop in $props.GetEnumerator()) {
              Write-Host "Set property $($prop.Key) = '$($prop.Value)': " -NoNewline
              $prop_node = $null
              $prop_node = $node.SelectSingleNode("$($namespace)$($prop.Key)", $xml_nsm)
              if (! $prop_node) {
                $prop_node = $node.AppendChild($xml.CreateElement($prop.Key, $namespace_full))
              }
              
              if ($prop_node.InnerText -ne $prop.Value) {
                $prop_node.InnerText = $prop.Value
                $project_modified = $true
                Write-Host "done" -ForegroundColor 'Magenta'
              } else {
                Write-Host "already set" -ForegroundColor 'Green'
              }
            }
            
          }
        }
        
      } else {
        throw "Unknown project extension '$ext'"
      }
      
      if ($project_modified) {
        Write-Host "Update: " -ForegroundColor 'Magenta' -NoNewline
        Save-FormattedXml -Xml $xml -Path $ProjectPath
        Write-Host "OK" -ForegroundColor 'Green'
      } else {
        Write-Host "Project not changed"
      }
      
    } catch {
      if ($ErrorActionPreference -eq 'Stop') {
        throw
      } elseif ($ErrorActionPreference -ne 'SilentlyContinue') {
        Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
        Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
      }
    }
  }
  
  end {
    Write-Host ("Function end ({0:f3}s). Processed $cnt item(s)." -f ((([datetime]::Now) - $begin_time).TotalSeconds))
  }
}


function Get-VisualStudioInfo {
  [CmdletBinding()]
  param (
    [string]$Version = "2017",
    [switch]$x64 = $true
  )
  try {
    $versions_map = @{
      "2010" = "10.0"
      "2012" = "11.0"
      "2015" = "14.0"
      "2017" = "15.0"
    }
    if ($versions_map.ContainsKey($Version)) {
      $Version = $versions_map[$Version]
    }
    if (! $Version) {
      throw "Unknown version '$Version'"
    }
    $version_year = $null
    if (! $versions_map.ContainsValue($Version)) {
      return
    }
    $version_year = $versions_map.GetEnumerator() | ? { $_.Value -eq $Version } | select -First 1 | select -ExpandProperty Key
    if (! $version_year) {
      return
    }
    
    $result = [PSCustomObject]@{
      Name = ""
      Version = $Version
      VersionName = $version_year
      InstallationPath = ""
      MSBuildPath = ""
      BowerPath = ""
    }
    
    ### Check if Visual Studio installed
    $installation_path = Get-RegistryValue -KeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\SxS\VS7" -ValueName $Version -ErrorAction 'SilentlyContinue'
    if ($installation_path) {
      $result.Name = "Visual Studio $version_year"
      $result.InstallationPath = "$installation_path".TrimEnd('\')
      
    } else {
      ### Check if MSBuild Tools installed  
      foreach ($disk in @([System.IO.DriveInfo]::GetDrives() | ? { $_.DriveType -eq "Fixed" } | select -ExpandProperty Name | sort)) {
        $path = $null
        $path = Join-Path $disk "Program Files (x86)\Microsoft Visual Studio\$($version_year)\BuildTools"
        if (Test-Path $path -PathType "Container" -ErrorAction 'SilentlyContinue') {
          $result.Name = "Visual Studio $version_year Build Tools"
          $result.InstallationPath = $path
        }
      }
    }
    
    if (! $result.InstallationPath) {
      throw "Cannot find Visual Studio or Build Tools"
    }
    
    ### Resolve MSBuild path
    $x64path = if ($x64) { "amd64\" } else { "" }
    $msbuild_path = ""
    $msbuild_path = Join-Path $result.InstallationPath "MSBuild\$($result.Version)\Bin\$($x64path)MSBuild.exe"
    if (Test-Path $msbuild_path -PathType "Leaf") {
      $result.MSBuildPath = $msbuild_path
    }
    
    ### Find Bower
    $bower_paths = @((Join-Path $result.InstallationPath "Web\External\Bower.cmd"),
    (Join-Path ([System.Environment]::GetEnvironmentVariable("APPDATA")) "npm\bower.cmd"))
    if ([System.Environment]::UserName.EndsWith('$')) {
      $bower_paths += (Join-Path ([System.Environment]::GetEnvironmentVariable("APPDATA")) "npm\bower.cmd") -replace "\\System32\\", "\SysWOW64\"
    }
    foreach ($path in $bower_paths) {
      if (Test-Path $path -PathType 'Leaf') {
        $result.BowerPath = $path
        break
      }
    }
    
    return $result
    
  } catch {
    if ($ErrorActionPreference -eq 'Stop') {
      throw
    } elseif ($ErrorActionPreference -ne 'SilentlyContinue') {
      Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
      Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
    }
  }
}


function Get-MSBuildPath([string]$Version = "2017", [switch]$Silent) {
  if (! $script:visual_studio_info) {
    $script:visual_studio_info = Get-VisualStudioInfo -Version $Version -ErrorAction 'Stop'
  }
  if (! $script:visual_studio_info.MSBuildPath) {
    throw "MSBuild not found"
  }
  return $script:visual_studio_info.MSBuildPath
}

function Build-SolutionOrProject {
  [CmdletBinding()]
  param
    (
    [Parameter(Mandatory = $true,
               ValueFromPipeline = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Debug", "Release", IgnoreCase = $true)]
    [string]$Configuration = "Release"
  )
  
  begin {
    $begin_time = [datetime]::Now
    Write-Host "`r`n*** Build-Solution begin:" -ForegroundColor 'White'
    $cnt = 0
    $msbuild_path = Get-MSBuildPath
    Get-Command $msbuild_path -CommandType 'Application' -ErrorAction 'Stop' >$null
  }
  
  process {
    $cnt++
    try {
      Write-Host "`r`nBuild solution '$Path':" -ForegroundColor 'White'
      
      $params = @($Path, "/p:Configuration=`"$Configuration`"", "/maxcpucount", "/nodeReuse:false", "/restore", "/t:Clean;Rebuild")
      
      Write-Host "`r`nMSBuild command line:`r`n[$msbuild_path] [$params]" -ForegroundColor 'Cyan'
      & $msbuild_path $params
      $result = $?
      $exit_code = $LASTEXITCODE
      if (! $result) {
        throw "Error occurred while performing action '$Action'. Result: $result. Exit code: $exit_code"
      }
      
    } catch {
      if ($ErrorActionPreference -eq 'Stop') {
        throw
      } elseif ($ErrorActionPreference -ne 'SilentlyContinue') {
        Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
        Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
      }
    }
  }
  
  end {
    Write-Host ("Build-Solution end ({0:f3}s). Processed $cnt item(s)." -f ((([datetime]::Now) - $begin_time).TotalSeconds))
  }
}

function Get-ProjectBinaries {
  [CmdletBinding()]
  param
    (
    [Parameter(Mandatory = $true,
               ValueFromPipeline = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Debug", "Release", IgnoreCase = $true)]
    [string]$Configuration = "Release"
  )
  
  begin {
    $begin_time = [datetime]::Now
    Write-Host "`r`n*** Get-ProjectBinaries begin:" -ForegroundColor 'White'
    $cnt = 0
    $binaries_masks = @("*.dll", "*.exe")    
  }
  
  process {
    $cnt++
    try {
      Write-Host "`r`nGet binaries for project '$Path'" -ForegroundColor 'White'
      
      $project_folder = ""
      $project_folder = [System.IO.Path]::GetDirectoryName($Path)
      
      $binaries_folder = ""      
      $ext = [System.IO.Path]::GetExtension($Path)      
      if ($ext -eq ".csproj") {
        $binaries_folder = Join-Path $project_folder "bin" $Configuration
      } elseif ($ext -eq ".vcxproj") {
        $binaries_folder = Join-Path $project_folder $Configuration
      } else {
        throw "Unknown project extension '$ext'"
      }
      
      if (!(Test-Path $binaries_folder -PathType "Container")) {
        return
      }
      
      dir $binaries_folder -Include $binaries_masks -Recurse
      
    } catch {
      if ($ErrorActionPreference -eq 'Stop') {
        throw
      } elseif ($ErrorActionPreference -ne 'SilentlyContinue') {
        Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
        Write-Host ("Parameters:`r`n" + (New-Object "PSObject" -Property $PSBoundParameters | fl * | Out-String).Trim()) -ForegroundColor 'Cyan'
      }
    }
  }
  
  end {
    Write-Host ("Get-ProjectBinaries end ({0:f3}s). Processed $cnt item(s)." -f ((([datetime]::Now) - $begin_time).TotalSeconds))
  }
}


### Main:

try {
  
  Write-Host "`r`n*** TEST TASK ***" -ForegroundColor 'White'
  Write-Host "Script parameters:" -ForegroundColor 'Cyan'
  Write-Host "Git URL          : $GitUrl" -ForegroundColor 'Cyan'
  Write-Host "Local Folder     : $LocalFolder" -ForegroundColor 'Cyan'
  Write-Host "Release Location : $ReleaseLocation" -ForegroundColor 'Cyan'
 
  ### Get code from Git repo to a local folder
  Clone-GitRepo -Url $GitUrl -Folder $LocalFolder -ErrorAction 'Stop'
  
  ### Modify project setting to enable debug symbols in release configuration of the projects
  $projects = @(dir $LocalFolder -Include @("*.csproj", "*.vcxproj") -Recurse)
  $projects | Enable-DebugSymbols -Configuration 'Release'
  
  ### Build code in release configuration with any build engine/script (msbuild for example)
  dir $LocalFolder -Include "*.sln" -Recurse | Build-SolutionOrProject -Configuration 'Release'
  dir $LocalFolder -Include "*.vcxproj" -Recurse | Build-SolutionOrProject -Configuration 'Release'
  
  ### Calculate output files hashes for all binaries/assemblies and make hash/files manifest (xml or json for example)
  $pos = $LocalFolder.Length + 1
  $files = @($projects | Get-ProjectBinaries -Configuration 'Release' | Add-FileHashProperty `
  | % { Add-Member -InputObject $_ -PassThru -MemberType NoteProperty -Name "RelativePath" -Value $_.FullName.Substring($pos) } `
  | % { Add-Member -InputObject $_ -PassThru -MemberType NoteProperty -Name "RelativeDirectory" -Value ([System.IO.Path]::GetDirectoryName($_.RelativePath)) })
  
  Test-Folder -Path $ReleaseLocation -Create -Clear -ErrorAction 'Stop' >$null
  $manifest_path = Join-Path $ReleaseLocation "Manifest.json"
  # ??? Not specified in task - what file path save to manifest, so save relative path
  $files | % { [PSCustomObject]@{ Path = $_.RelativePath; Hash = $_.Hash } } | ConvertTo-Json | Out-File $manifest_path -Encoding "UTF8" -Force -Width 99999
  Write-Host "Manifest saved to '$manifest_path'" -ForegroundColor 'Green'
  
  ### Make a zip archive including all binaries/assemblies and generated manifest (use 7zip, Windows built in or any other)
  # ??? Not specified in task - save original folder hierarchy or not. So implement both cases
  
  $archive_path = Join-Path $ReleaseLocation "Release.zip"
  
  # Save original folder hierarchy
  $temp_folder = Join-Path $LocalFolder ".." "TempFolder" "Binaries"
  $files | % {
    $folder = Join-Path $temp_folder $_.RelativeDirectory
    if (! ([System.IO.Directory]::Exists($folder))) {
      [System.IO.Directory]::CreateDirectory($folder)
    }
    Copy-Item $_ -Destination $folder -Force >$null
  }
  "$temp_folder\*", $manifest_path | Compress-Archive -DestinationPath $archive_path -Force
  
  # Do not save original folder hierarchy
  #  $files, $manifest_path | Compress-Archive -DestinationPath $archive_path -Force
  
  ### Copy resulted zip to any release location
  # ??? Is it required? Archive already directly created in release folder in previous step
  $another_release_location = Join-Path $ReleaseLocation ".." "AnotherReleaseLocation"
  Test-Folder $another_release_location -Create -ErrorAction 'Stop' >$null
  $another_destination = Join-Path $another_release_location ([System.IO.Path]::GetFileName($archive_path))
  Copy-Item $archive_path -Destination $another_destination -Force
  
  ### Copy resulted pdbs into a separate folder called Symbols in the same release location, saving original folder hierarchy
  & robocopy.exe @($LocalFolder, (Join-Path $ReleaseLocation "Symbols"), "*.pdb", "/s", "/purge", "/xd", "obj")
  
  # Delete temp folder if required
  #try { Remove-Item -Path $temp_folder -Recurse -Force -Confirm:$false -ErrorAction 'SilentlyContinue' >$null } catch { }
  
  
} catch {
  Write-Host ($global:Error[0] | Out-String).Trim() -ForegroundColor 'Red'
} finally {
  Write-Host "Script duration:" ((Get-Date) - $script_begin_time).ToString()
  try { Stop-Transcript } catch { }
}
return
