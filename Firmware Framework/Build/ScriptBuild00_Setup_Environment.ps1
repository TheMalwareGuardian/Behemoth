# ====================================================================================
# ScriptBuild00_Setup_Environment.ps1
# Behemoth - Minimal Environment Setup
#
# Purpose:
#   Prepare the local toolchain required by the Behemoth GDT pipeline.
#
# Components handled automatically:
#   - Visual Studio Community + Desktop development with C++
#   - Ghidra
#   - EDK2 source tree
#   - Java JDK
#
# Pipeline:
#   Script00_Setup_Environment.ps1
#       -> ScriptBuild01_Analyze_EDK2.ps1
#       -> ScriptBuild02_Scan_Headers.ps1
#       -> ScriptBuild03_Build_GDT.ps1
#       -> ScriptBuild04_GUID_DB.ps1
#
# ====================================================================================



Clear-Host

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

if (Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue)
{
	$PSNativeCommandUseErrorActionPreference = $false
}



# ====================================================================================
# BANNER
# ====================================================================================

Write-Host ""
Write-Host "  ######  ####### ##   ## ####### ###    ###  ######  ######## ##   ## " -ForegroundColor DarkRed
Write-Host "  ##   ## ##      ##   ## ##      ####  #### ##    ##    ##    ##   ## " -ForegroundColor DarkRed
Write-Host "  ######  #####   ####### #####   ## #### ## ##    ##    ##    ####### " -ForegroundColor Red
Write-Host "  ##   ## ##      ##   ## ##      ##  ##  ## ##    ##    ##    ##   ## " -ForegroundColor DarkRed
Write-Host "  ######  ####### ##   ## ####### ##      ##  ######     ##    ##   ## " -ForegroundColor DarkRed
Write-Host ""
Write-Host "  Minimal Environment Setup" -ForegroundColor White
Write-Host "  github.com/TheMalwareGuardian/Behemoth" -ForegroundColor DarkGray
Write-Host ""



# ====================================================================================
# PATHS
# ====================================================================================

$Root   = $PSScriptRoot
$GDTDir = Join-Path $Root "GDT"

New-Item -ItemType Directory -Force -Path $GDTDir | Out-Null

$GhidraDir = Join-Path $GDTDir "Ghidra"
$EDK2Dir   = Join-Path $GDTDir "edk2"

$TempDir = Join-Path $GDTDir "Setup"

New-Item -ItemType Directory -Force -Path $TempDir | Out-Null



# ====================================================================================
# DOWNLOAD URLS
# ====================================================================================

# Visual Studio 2019 Community
$VisualStudioURL = "https://download.visualstudio.microsoft.com/download/pr/7c09e2e8-2b3e-4213-93ab-5646874f8a2b/0ac797413a56c6b2772f48a567a32cdddd3b739f5b2af649fcf90be4245762ff/vs_Community.exe"

$VisualStudioInstaller = Join-Path $TempDir "vs_Community.exe"

# Java JDK 24
$JavaURL = "https://download.oracle.com/java/24/archive/jdk-24.0.2_windows-x64_bin.exe"

$JavaInstaller = Join-Path $TempDir "jdk-24_windows-x64_bin.exe"

# Ghidra
$GhidraZipURL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1_build/ghidra_12.1_PUBLIC_20260513.zip"

$GhidraZip = Join-Path $GDTDir "ghidra_12.1_PUBLIC_20260513.zip"

# EDK2
$EDK2ZipURL = "https://github.com/tianocore/edk2/archive/refs/heads/master.zip"

$EDK2Zip = Join-Path $GDTDir "edk2-master.zip"



# ====================================================================================
# LOGGING
# ====================================================================================

function Write-Step
{
	param($n, $msg)

	Write-Host "[$n] $msg" -ForegroundColor Cyan
}

function Write-OK
{
	param($msg)

	Write-Host "  [+] $msg" -ForegroundColor Green
}

function Write-Info
{
	param($msg)

	Write-Host "  [-] $msg" -ForegroundColor Gray
}

function Write-Warn
{
	param($msg)

	Write-Host "  [!] $msg" -ForegroundColor Yellow
}

function Write-Fail
{
	param($msg)

	Write-Host "  [x] $msg" -ForegroundColor Red

	exit 1
}



# ====================================================================================
# HELPERS
# ====================================================================================

function Get-VisualStudioInstallation
{
	$VSWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

	if (-not (Test-Path $VSWhere))
	{
		return $null
	}

	$VSInstallPath = & $VSWhere `
		-latest `
		-products * `
		-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
		-property installationPath

	if (-not $VSInstallPath)
	{
		return $null
	}

	return $VSInstallPath
}

function Get-JavaInstallation
{
	$JavaRoots = @(

		"C:\Program Files\Java",

		"C:\Program Files\Eclipse Adoptium",

		"C:\Program Files\Microsoft",

		"C:\Program Files\Amazon Corretto"
	)

	foreach ($JavaRoot in $JavaRoots)
	{
		if (-not (Test-Path $JavaRoot))
		{
			continue
		}

		$JavacExe = Get-ChildItem `
			-Path $JavaRoot `
			-Recurse `
			-Filter "javac.exe" `
			-File `
			-ErrorAction SilentlyContinue |
			Where-Object {
				$_.FullName -match '\\bin\\javac\.exe$'
			} |
			Sort-Object FullName -Descending |
			Select-Object -First 1

		if ($JavacExe)
		{
			$JavaExe = Join-Path `
				$JavacExe.DirectoryName `
				"java.exe"

			if (Test-Path $JavaExe)
			{
				return [PSCustomObject]@{

					Java     = $JavaExe

					Javac    = $JavacExe.FullName

					JavaHome = Split-Path `
						$JavacExe.DirectoryName `
						-Parent

					Source   = "Installed JDK"
				}
			}
		}
	}

	$JavaCommand = Get-Command `
		java.exe `
		-ErrorAction SilentlyContinue


	$JavacCommand = Get-Command `
		javac.exe `
		-ErrorAction SilentlyContinue

	if ($JavaCommand -and $JavacCommand)
	{
		return [PSCustomObject]@{

			Java     = $JavaCommand.Source

			Javac    = $JavacCommand.Source

			JavaHome = $null

			Source   = "PATH"
		}
	}

	return $null
}



# ====================================================================================
# STEP 1 - VISUAL STUDIO
# ====================================================================================

Write-Step "1/5" "Checking Visual Studio..."

$VSInstallPath = Get-VisualStudioInstallation

if ($VSInstallPath)
{
	Write-OK "Visual Studio C++ build tools found"

	Write-Info $VSInstallPath
}
else
{
	Write-Warn "Visual Studio with C++ build tools not found"

	Write-Info "Downloading Visual Studio 2019 Community..."

	try
	{
		Invoke-WebRequest `
			-Uri $VisualStudioURL `
			-OutFile $VisualStudioInstaller
	}
	catch
	{
		Write-Fail "Failed to download Visual Studio 2019 Community: $($_.Exception.Message)"
	}

	if (-not (Test-Path $VisualStudioInstaller))
	{
		Write-Fail "Visual Studio installer was not downloaded"
	}

	Write-Info "Installing Visual Studio 2019 Community..."

	Write-Info "Workload: Desktop development with C++"

	try
	{
		$Process = Start-Process `
			-FilePath $VisualStudioInstaller `
			-Wait `
			-PassThru

		if ($Process.ExitCode -notin @(0, 3010))
		{
			Write-Fail "Visual Studio installer returned exit code $($Process.ExitCode)"
		}

		if ($Process.ExitCode -eq 3010)
		{
			Write-Warn "Visual Studio installation succeeded but Windows reports that a reboot is recommended"
		}
	}
	catch
	{
		Write-Fail "Visual Studio installation failed: $($_.Exception.Message)"
	}

	$VSInstallPath = Get-VisualStudioInstallation

	if (-not $VSInstallPath)
	{
		Write-Fail (
			"Visual Studio installation finished, but the C++ build tools " +
			"could not be detected"
		)
	}

	Write-OK "Visual Studio 2019 Community ready"

	Write-Info $VSInstallPath
}



# ====================================================================================
# STEP 2 - GHIDRA
# ====================================================================================

Write-Step "2/5" "Checking Ghidra..."

$AnalyzeHeadless = $null

if (Test-Path $GhidraDir)
{
	$AnalyzeHeadless = Get-ChildItem `
		-Path $GhidraDir `
		-Recurse `
		-Filter "analyzeHeadless.bat" `
		-ErrorAction SilentlyContinue |
		Select-Object -First 1
}

if (-not $AnalyzeHeadless)
{
	Write-Info "Ghidra not found"

	if (-not (Test-Path $GhidraZip))
	{
		Write-Info "Downloading Ghidra..."

		try
		{
			Invoke-WebRequest `
				-Uri $GhidraZipURL `
				-OutFile $GhidraZip
		}
		catch
		{
			Write-Fail "Failed to download Ghidra: $($_.Exception.Message)"
		}
	}

	Add-Type -AssemblyName System.IO.Compression.FileSystem

	try
	{
		[System.IO.Compression.ZipFile]::OpenRead(
			$GhidraZip
		).Dispose()
	}
	catch
	{
		Remove-Item `
			$GhidraZip `
			-Force `
			-ErrorAction SilentlyContinue

		Write-Fail "Downloaded Ghidra archive is corrupt. Re-run the script."
	}

	Write-Info "Extracting Ghidra..."

	New-Item `
		-ItemType Directory `
		-Force `
		-Path $GhidraDir |
		Out-Null

	Expand-Archive `
		-Path $GhidraZip `
		-DestinationPath $GhidraDir `
		-Force

	$InnerDir = Get-ChildItem `
		-Path $GhidraDir `
		-Directory |
		Select-Object -First 1

	if (
		$InnerDir -and
		$InnerDir.Name -like "ghidra_*"
	)
	{
		Get-ChildItem `
			-Path $InnerDir.FullName |
			Move-Item `
				-Destination $GhidraDir `
				-Force

		Remove-Item `
			-Path $InnerDir.FullName `
			-Recurse `
			-Force `
			-ErrorAction SilentlyContinue
	}

	Remove-Item `
		-Path $GhidraZip `
		-Force `
		-ErrorAction SilentlyContinue

	$AnalyzeHeadless = Get-ChildItem `
		-Path $GhidraDir `
		-Recurse `
		-Filter "analyzeHeadless.bat" `
		-ErrorAction SilentlyContinue |
		Select-Object -First 1
}

if (-not $AnalyzeHeadless)
{
	Write-Fail "analyzeHeadless.bat not found after Ghidra extraction"
}

Write-OK "Ghidra ready"

Write-Info $AnalyzeHeadless.FullName



# ====================================================================================
# STEP 3 - EDK2
# ====================================================================================

Write-Step "3/5" "Checking EDK2..."

$MdePkgIncludeDir = Join-Path $EDK2Dir "MdePkg\Include"

if (-not (Test-Path $MdePkgIncludeDir))
{
	Write-Info "EDK2 not found"

	if (-not (Test-Path $EDK2Zip))
	{
		Write-Info "Downloading EDK2..."

		try
		{
			Invoke-WebRequest `
				-Uri $EDK2ZipURL `
				-OutFile $EDK2Zip
		}
		catch
		{
			Write-Fail "Failed to download EDK2: $($_.Exception.Message)"
		}
	}

	Add-Type -AssemblyName System.IO.Compression.FileSystem

	try
	{
		[System.IO.Compression.ZipFile]::OpenRead(
			$EDK2Zip
		).Dispose()
	}
	catch
	{
		Remove-Item `
			$EDK2Zip `
			-Force `
			-ErrorAction SilentlyContinue

		Write-Fail "Downloaded EDK2 archive is corrupt. Re-run the script."
	}

	Write-Info "Extracting EDK2..."

	$TempEDK2 = Join-Path $GDTDir "edk2_tmp"

	Remove-Item `
		-Path $TempEDK2 `
		-Recurse `
		-Force `
		-ErrorAction SilentlyContinue

	New-Item `
		-ItemType Directory `
		-Force `
		-Path $TempEDK2 |
		Out-Null

	Expand-Archive `
		-Path $EDK2Zip `
		-DestinationPath $TempEDK2 `
		-Force

	$InnerEDK2 = Get-ChildItem `
		-Path $TempEDK2 `
		-Directory |
		Select-Object -First 1

	if (-not $InnerEDK2)
	{
		Write-Fail "Unable to locate extracted EDK2 directory"
	}

	if (Test-Path $EDK2Dir)
	{
		Remove-Item `
			-Path $EDK2Dir `
			-Recurse `
			-Force
	}

	Move-Item `
		-Path $InnerEDK2.FullName `
		-Destination $EDK2Dir `
		-Force

	Remove-Item `
		-Path $TempEDK2 `
		-Recurse `
		-Force `
		-ErrorAction SilentlyContinue

	Remove-Item `
		-Path $EDK2Zip `
		-Force `
		-ErrorAction SilentlyContinue
}

if (-not (Test-Path $MdePkgIncludeDir))
{
	Write-Fail "EDK2 MdePkg\Include not found after extraction"
}

$HeaderCount = (
	Get-ChildItem `
		-Path $EDK2Dir `
		-Recurse `
		-Filter "*.h" `
		-ErrorAction SilentlyContinue |
		Where-Object {
			$_.FullName -match "\\Include\\"
		}
).Count

Write-OK "EDK2 ready ($HeaderCount headers)"

Write-Info $EDK2Dir



# ====================================================================================
# STEP 4 - JAVA
# ====================================================================================

Write-Step "4/5" "Checking Java JDK..."

$JavaInstallation = Get-JavaInstallation

if ($JavaInstallation)
{
	Write-OK "Java JDK found"

	Write-Info $JavaInstallation.Java
}
else
{
	Write-Warn "Java JDK not found"

	Write-Info "Downloading Oracle JDK 24..."

	try
	{
		Invoke-WebRequest `
			-Uri $JavaURL `
			-OutFile $JavaInstaller
	}
	catch
	{
		Write-Fail "Failed to download Java JDK: $($_.Exception.Message)"
	}

	if (-not (Test-Path $JavaInstaller))
	{
		Write-Fail "Java JDK installer was not downloaded"
	}

	Write-Info "Installing Oracle JDK 24..."

	try
	{

		$Process = Start-Process `
			-FilePath $JavaInstaller `
			-ArgumentList "/s" `
			-Wait `
			-PassThru

		if ($Process.ExitCode -notin @(0, 3010))
		{
			Write-Fail "Java installer returned exit code $($Process.ExitCode)"
		}

		if ($Process.ExitCode -eq 3010)
		{
			Write-Warn "Java installation succeeded but Windows reports that a reboot is recommended"
		}
	}
	catch
	{
		Write-Fail "Java JDK installation failed: $($_.Exception.Message)"
	}

	$MachinePath = [Environment]::GetEnvironmentVariable(
		"Path",
		"Machine"
	)

	$UserPath = [Environment]::GetEnvironmentVariable(
		"Path",
		"User"
	)

	$env:Path = "$MachinePath;$UserPath"

	$MachineJavaHome = [Environment]::GetEnvironmentVariable(
		"JAVA_HOME",
		"Machine"
	)

	if ($MachineJavaHome)
	{
		$env:JAVA_HOME = $MachineJavaHome
	}

	$JavaInstallation = Get-JavaInstallation

	if (-not $JavaInstallation)
	{
		Write-Fail (
			"Java installation finished, but java.exe/javac.exe " +
			"could not be detected"
		)
	}

	Write-OK "Java JDK ready"

	Write-Info $JavaInstallation.Java
}



# ====================================================================================
# STEP 5 - FINAL VALIDATION
# ====================================================================================

Write-Step "5/5" "Validating environment..."

# ------------------------------------------------------------------------------------
# Visual Studio
# ------------------------------------------------------------------------------------

$VSInstallPath = Get-VisualStudioInstallation

if (-not $VSInstallPath)
{
	Write-Fail "Visual Studio C++ build tools validation failed"
}

Write-OK "Visual Studio C++ build tools"

# ------------------------------------------------------------------------------------
# Ghidra
# ------------------------------------------------------------------------------------

$AnalyzeHeadless = Get-ChildItem `
	-Path $GhidraDir `
	-Recurse `
	-Filter "analyzeHeadless.bat" `
	-ErrorAction SilentlyContinue |
	Select-Object -First 1

if (-not $AnalyzeHeadless)
{
	Write-Fail "Ghidra validation failed"
}

Write-OK "Ghidra"

# ------------------------------------------------------------------------------------
# EDK2
# ------------------------------------------------------------------------------------

if (-not (Test-Path $MdePkgIncludeDir))
{
	Write-Fail "EDK2 validation failed"
}

Write-OK "EDK2"

# ------------------------------------------------------------------------------------
# Java
# ------------------------------------------------------------------------------------

$JavaInstallation = Get-JavaInstallation

if (-not $JavaInstallation)
{
	Write-Fail "Java JDK validation failed"
}

Write-OK "Java JDK"

Write-Info $JavaInstallation.Java

Write-Info $JavaInstallation.Javac

# ------------------------------------------------------------------------------------
# Java runtime validation
# ------------------------------------------------------------------------------------

try
{
	$OldErrorActionPreference = $ErrorActionPreference

	$ErrorActionPreference = "Continue"

	$JavaVersionOutput = @(
		& $JavaInstallation.Java -version 2>&1
	)

	$JavaExitCode = $LASTEXITCODE

	$ErrorActionPreference = $OldErrorActionPreference

	if ($JavaExitCode -ne 0)
	{
		Write-Fail "java.exe validation failed with exit code $JavaExitCode"
	}

	$JavaVersion = $JavaVersionOutput |
		ForEach-Object {
			$_.ToString()
		} |
		Select-Object -First 1

	Write-OK "Java runtime working"

	Write-Info $JavaVersion
}
catch
{
	$ErrorActionPreference = $OldErrorActionPreference

	Write-Fail "Unable to execute java.exe: $($_.Exception.Message)"
}

# ------------------------------------------------------------------------------------
# Java compiler validation
# ------------------------------------------------------------------------------------

try
{
	$OldErrorActionPreference = $ErrorActionPreference

	$ErrorActionPreference = "Continue"

	$JavacVersionOutput = @(
		& $JavaInstallation.Javac -version 2>&1
	)

	$JavacExitCode = $LASTEXITCODE

	$ErrorActionPreference = $OldErrorActionPreference

	if ($JavacExitCode -ne 0)
	{
		Write-Fail "javac.exe validation failed with exit code $JavacExitCode"
	}

	$JavacVersion = $JavacVersionOutput |
		ForEach-Object {
			$_.ToString()
		} |
		Select-Object -First 1

	Write-OK "Java compiler working"

	Write-Info $JavacVersion
}
catch
{
	$ErrorActionPreference = $OldErrorActionPreference

	Write-Fail "Unable to execute javac.exe: $($_.Exception.Message)"
}



# ====================================================================================
# CLEAN TEMPORARY INSTALLERS
# ====================================================================================

Remove-Item `
	-Path $VisualStudioInstaller `
	-Force `
	-ErrorAction SilentlyContinue

Remove-Item `
	-Path $JavaInstaller `
	-Force `
	-ErrorAction SilentlyContinue

if (Test-Path $TempDir)
{
	$RemainingFiles = Get-ChildItem `
		-Path $TempDir `
		-Force `
		-ErrorAction SilentlyContinue

	if (-not $RemainingFiles)
	{
		Remove-Item `
			-Path $TempDir `
			-Force `
			-ErrorAction SilentlyContinue
	}
}



# ====================================================================================
# DONE
# ====================================================================================

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Green
Write-Host "                     ENVIRONMENT READY" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "  Visual Studio :" -ForegroundColor White
Write-Host "    $VSInstallPath" -ForegroundColor Gray
Write-Host ""

Write-Host "  Java :" -ForegroundColor White
Write-Host "    $($JavaInstallation.JavaHome)" -ForegroundColor Gray
Write-Host ""

Write-Host "  Ghidra :" -ForegroundColor White
Write-Host "    $($AnalyzeHeadless.FullName)" -ForegroundColor Gray
Write-Host ""

Write-Host "  EDK2 :" -ForegroundColor White
Write-Host "    $EDK2Dir" -ForegroundColor Gray
Write-Host ""

Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. .\ScriptBuild01_Analyze_EDK2.ps1" -ForegroundColor Gray
Write-Host "    2. .\ScriptBuild02_Scan_Headers.ps1" -ForegroundColor Gray
Write-Host "    3. .\ScriptBuild03_Build_GDT.ps1" -ForegroundColor Gray
Write-Host "    4. .\ScriptBuild04_GUID_DB.ps1" -ForegroundColor Gray
Write-Host ""
