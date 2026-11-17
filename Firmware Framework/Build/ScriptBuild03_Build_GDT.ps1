# ====================================================================================
# ScriptBuild03_Build_GDT.ps1
# Behemoth - UEFI Ghidra Type Archive Builder
#
# Pipeline role:
#   Script00 -> Prepares the local toolchain and EDK2 source tree.
#   Script01 -> Reports the EDK2 public Include structure (informational only).
#   Script02 -> Selects the supported packages/categories and writes GDT\Scan\EDK2_Headers.txt/GDT\Scan\EDK2_Dependencies.txt
#   Script03 -> Consumes only that Script02 selection and builds Behemoth.gdt.
#   Script04 -> Builds the UEFI GUID database used by Behemoth for GUID resolution.
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
Write-Host "  UEFI Ghidra Type Archive Builder" -ForegroundColor White
Write-Host "  github.com/TheMalwareGuardian/Behemoth" -ForegroundColor DarkGray
Write-Host ""



# ====================================================================================
# PATHS
# ====================================================================================



$Root = $PSScriptRoot

$GDTDir = Join-Path $Root "GDT"

$EDK2Dir = Join-Path $GDTDir "edk2"
$ScanDir = Join-Path $GDTDir "Scan"

$WorkDir    = Join-Path $GDTDir "Work"
$HeadersDir = Join-Path $WorkDir "Headers"
$JavaSrcDir = Join-Path $WorkDir "JavaSrc"
$LogsDir    = Join-Path $WorkDir "Logs"

$GhidraDir = Join-Path $GDTDir "Ghidra"

New-Item -ItemType Directory -Force -Path $WorkDir    | Out-Null
New-Item -ItemType Directory -Force -Path $HeadersDir | Out-Null
New-Item -ItemType Directory -Force -Path $JavaSrcDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogsDir    | Out-Null

$HeadersFile = Join-Path `
	$ScanDir `
	"EDK2_Headers.txt"

$DependenciesFile = Join-Path `
	$ScanDir `
	"EDK2_Dependencies.txt"

$OracleAggregate = Join-Path `
	$HeadersDir `
	"Behemoth_Oracle_Agg.h"

$OracleOutput = Join-Path `
	$HeadersDir `
	"Behemoth_Oracle.i"

$FinalAggregate = Join-Path `
	$HeadersDir `
	"Behemoth_Agg.h"

$PreprocessedI = Join-Path `
	$HeadersDir `
	"Behemoth_Agg.i"

$CleanHeader = Join-Path `
	$HeadersDir `
	"Behemoth_Clean.h"

$ShimHeader = Join-Path `
	$HeadersDir `
	"Behemoth_Ghidra_Types.h"

$JavaSrc = Join-Path `
	$JavaSrcDir `
	"BehemothBuilder.java"

$GDTPathX64 = Join-Path `
	$GDTDir `
	"Behemoth_X64.gdt"

$GDTPathIA32 = Join-Path `
	$GDTDir `
	"Behemoth_IA32.gdt"

$LogPath = Join-Path `
	$LogsDir `
	"Build.log"

$OracleReport = Join-Path `
	$LogsDir `
	"Oracle_Order.txt"

$ViolationReport = Join-Path `
	$LogsDir `
	"Oracle_Violations.txt"

$PromotionReport = Join-Path `
	$LogsDir `
	"Oracle_Promotions.txt"



# ====================================================================================
# LOGGING
# ====================================================================================

foreach ($File in @(
	$LogPath,
	$OracleReport,
	$ViolationReport,
	$PromotionReport
))
{
	if (Test-Path $File)
	{
		Remove-Item `
			$File `
			-Force `
			-ErrorAction SilentlyContinue
	}
}

function Write-Log
{
	param(
		[string]$Message
	)

	$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	Add-Content `
		-Path $LogPath `
		-Value "[$Timestamp] $Message"
}

function Write-Step
{
	param(
		[string]$Number,
		[string]$Message
	)

	Write-Host "[$Number] $Message" -ForegroundColor Cyan

	Write-Log "STEP [$Number] $Message"
}

function Write-OK
{
	param(
		[string]$Message
	)

	Write-Host "  [+] $Message" -ForegroundColor Green

	Write-Log "OK: $Message"
}

function Write-Info
{
	param(
		[string]$Message
	)

	Write-Host "  [-] $Message" -ForegroundColor Gray

	Write-Log "INFO: $Message"
}

function Write-Warn
{
	param(
		[string]$Message
	)

	Write-Host "  [!] $Message" -ForegroundColor Yellow

	Write-Log "WARN: $Message"
}

function Write-Fail
{
	param(
		[string]$Message
	)

	Write-Host "  [FAIL] $Message" -ForegroundColor Red

	Write-Log "FAIL: $Message"

	exit 1
}



# ====================================================================================
# GENERIC COLLECTION HELPERS
# ====================================================================================

function New-StringSet
{
	$Set = [System.Collections.Generic.HashSet[string]]::new(
		[System.StringComparer]::OrdinalIgnoreCase
	)

	return ,$Set
}

function New-StringList
{
	$List = [System.Collections.Generic.List[string]]::new()

	return ,$List
}



# ====================================================================================
# GRAPH HELPERS
# ====================================================================================

function Add-GraphNode
{
	param(
		[hashtable]$Graph,
		[string]$Node
	)

	if (-not $Graph.ContainsKey($Node))
	{
		$Graph[$Node] = New-StringSet
	}
}

function Add-GraphEdge
{
	param(
		[hashtable]$Graph,
		[string]$From,
		[string]$To
	)

	Add-GraphNode `
		-Graph $Graph `
		-Node $From

	Add-GraphNode `
		-Graph $Graph `
		-Node $To

	return $Graph[$From].Add($To)
}

function Test-GraphPath
{
	param(
		[hashtable]$Graph,
		[string]$Start,
		[string]$Target
	)

	if ($Start -eq $Target)
	{
		return $true
	}

	if (-not $Graph.ContainsKey($Start))
	{
		return $false
	}

	$Visited = New-StringSet

	$Queue = [System.Collections.Generic.Queue[string]]::new()

	[void]$Visited.Add($Start)

	$Queue.Enqueue($Start)

	while ($Queue.Count -gt 0)
	{
		$Current = $Queue.Dequeue()

		if (-not $Graph.ContainsKey($Current))
		{
			continue
		}

		foreach ($Next in $Graph[$Current])
		{
			if ($Next -eq $Target)
			{
				return $true
			}

			if ($Visited.Add($Next))
			{
				$Queue.Enqueue($Next)
			}
		}
	}

	return $false
}

function Get-TransitiveClosure
{
	param(
		[hashtable]$Graph,
		[string]$Start
	)

	$Visited = New-StringSet

	$Queue = [System.Collections.Generic.Queue[string]]::new()

	[void]$Visited.Add($Start)

	$Queue.Enqueue($Start)

	while ($Queue.Count -gt 0)
	{
		$Current = $Queue.Dequeue()

		if (-not $Graph.ContainsKey($Current))
		{
			continue
		}

		foreach ($Next in $Graph[$Current])
		{
			if ($Visited.Add($Next))
			{
				$Queue.Enqueue($Next)
			}
		}
	}

	return ,$Visited
}



# ====================================================================================
# HEADER HELPERS
# ====================================================================================

function Convert-ToCanonicalHeader
{
	param(
		[string]$Value
	)

	if ([string]::IsNullOrWhiteSpace($Value))
	{
		return $null
	}

	$Value = $Value.Trim()

	$Value = $Value.Trim('"')
	$Value = $Value.Trim("'")

	$Value = $Value.Replace("\", "/")

	if ($Value -match '([A-Za-z0-9_.+-]+/Include/.+?\.h)')
	{
		return $matches[1]
	}

	return $null
}

function Get-IncludeKey
{
	param(
		[string]$Header
	)

	return (
		$Header -replace '^[^/]+/Include/', ''
	)
}

function Remove-CComments
{
	param(
		[string]$Text
	)

	$Text = [regex]::Replace(
		$Text,
		'/\*.*?\*/',
		'',
		[System.Text.RegularExpressions.RegexOptions]::Singleline
	)

	$Text = [regex]::Replace(
		$Text,
		'//[^\r\n]*',
		''
	)

	return $Text
}



# ====================================================================================
# TOPOLOGICAL SORT
# ====================================================================================

function Get-StableTopologicalOrder
{
	param(
		[System.Collections.Generic.List[string]]$Nodes,
		[hashtable]$Graph,
		[hashtable]$StableOrder
	)

	$InDegree = @{}

	foreach ($Node in $Nodes)
	{
		$InDegree[$Node] = 0
	}

	foreach ($From in $Graph.Keys)
	{
		if (-not $InDegree.ContainsKey($From))
		{
			continue
		}

		foreach ($To in $Graph[$From])
		{
			if ($InDegree.ContainsKey($To))
			{
				$InDegree[$To]++
			}
		}
	}

	$Ready = New-StringList

	foreach ($Node in $Nodes)
	{
		if ($InDegree[$Node] -eq 0)
		{
			$Ready.Add($Node)
		}
	}

	$Result = New-StringList

	while ($Ready.Count -gt 0)
	{
		$Next = @(
			$Ready |
			Sort-Object {

				if ($StableOrder.ContainsKey($_))
				{
					$StableOrder[$_]
				}
				else
				{
					[int]::MaxValue
				}
			}
		)[0]

		[void]$Ready.Remove($Next)

		$Result.Add($Next)

		if (-not $Graph.ContainsKey($Next))
		{
			continue
		}

		foreach ($Target in $Graph[$Next])
		{
			if (-not $InDegree.ContainsKey($Target))
			{
				continue
			}

			$InDegree[$Target]--

			if ($InDegree[$Target] -eq 0)
			{
				$Ready.Add($Target)
			}
		}
	}

	return ,$Result
}



# ====================================================================================
# AGGREGATE GENERATOR
# ====================================================================================

function Write-AggregateHeader
{
	param(
		[string]$Path,
		[System.Collections.Generic.List[string]]$Entries,
		[System.Collections.Generic.HashSet[string]]$ExcludedEntries
	)

	$Lines = New-StringList

	$Lines.Add("#ifndef MDE_CPU_X64")
	$Lines.Add("#define MDE_CPU_X64")
	$Lines.Add("#endif")
	$Lines.Add("")

	$Lines.Add("#ifndef EFIAPI")
	$Lines.Add("#define EFIAPI __cdecl")
	$Lines.Add("#endif")
	$Lines.Add("")

	$Lines.Add("#define IN")
	$Lines.Add("#define OUT")
	$Lines.Add("#define OPTIONAL")
	$Lines.Add("")

	$Lines.Add("/* ============================================================ */")
	$Lines.Add("/* Behemoth automatically generated EDK2 include plan           */")
	$Lines.Add("/* ============================================================ */")
	$Lines.Add("")

	foreach ($Header in $Entries)
	{
		if ($ExcludedEntries.Contains($Header))
		{
			continue
		}

		$IncludeKey = Get-IncludeKey $Header

		$Lines.Add("#include <$IncludeKey>")
	}

	[System.IO.File]::WriteAllLines(
		$Path,
		$Lines.ToArray(),
		[System.Text.Encoding]::ASCII
	)
}



# ====================================================================================
# RUN PREPROCESSOR
# ====================================================================================

function Invoke-BehemothPreprocessor
{
	param(
		[string]$InputHeader,
		[string]$OutputFile,
		[bool]$KeepMarkers,
		[System.Collections.Generic.List[string]]$IncludeArgs,
		[string]$CLPath
	)

	if (Test-Path $OutputFile)
	{
		Remove-Item `
			$OutputFile `
			-Force `
			-ErrorAction SilentlyContinue
	}

	$Args = New-StringList

	$Args.Add("/P")

	if (-not $KeepMarkers)
	{
		$Args.Add("/EP")
	}

	$Args.Add("/Fi$OutputFile")
	$Args.Add("/nologo")
	$Args.Add("/w")

	$Args.Add("/D")
	$Args.Add("_AMD64_")

	$Args.Add("/D")
	$Args.Add("__x86_64__")

	$Args.Add("/D")
	$Args.Add("_WIN32")

	$Args.Add("/D")
	$Args.Add("EFIAPI=__cdecl")

	foreach ($Arg in $IncludeArgs)
	{
		$Args.Add($Arg)
	}

	$Args.Add($InputHeader)

	Push-Location $HeadersDir

	$OldPreference = $ErrorActionPreference

	$ErrorActionPreference = "Continue"

	$Output = & $CLPath @Args 2>&1

	$ExitCode = $LASTEXITCODE

	$ErrorActionPreference = $OldPreference

	Pop-Location

	return [PSCustomObject]@{

		ExitCode = $ExitCode

		Output = (
			$Output |
			Out-String
		)

		FileExists = (
			Test-Path $OutputFile
		)
	}
}



# ====================================================================================
# PREPROCESSOR LINE-MARKER PARSER
# ====================================================================================

function Get-RealHeaderOrder
{
	param(
		[string]$PreprocessedFile,
		[string]$EDK2Dir,
		[System.Collections.Generic.HashSet[string]]$ValidSet
	)

	$FirstPosition = @{}

	$Sequence = New-StringList

	$Position = 0

	$EDK2Normalized = (
		[System.IO.Path]::GetFullPath($EDK2Dir)
	).Replace("\", "/").TrimEnd("/")

	foreach ($Line in [System.IO.File]::ReadLines($PreprocessedFile))
	{
		
		if (
			$Line -notmatch '^\s*#\s*(?:line\s+)?\d+\s+"([^"]+)"'
		)
		{
			continue
		}


		$SourcePath = $matches[1]

		while ($SourcePath.Contains("\\"))
		{
			$SourcePath = $SourcePath.Replace("\\", "\")
		}

		$SourcePath = $SourcePath.Replace("\", "/")

		if (
			-not $SourcePath.StartsWith(
				$EDK2Normalized,
				[System.StringComparison]::OrdinalIgnoreCase
			)
		)
		{
			continue
		}

		$Relative = $SourcePath.Substring(
			$EDK2Normalized.Length
		).TrimStart("/")

		$Relative = $Relative.Replace("\", "/")

		if (-not $ValidSet.Contains($Relative))
		{
			continue
		}

		if (-not $FirstPosition.ContainsKey($Relative))
		{
			$Position++

			$FirstPosition[$Relative] = $Position

			$Sequence.Add($Relative)
		}
	}

	return [PSCustomObject]@{

		FirstPosition = $FirstPosition

		Sequence = $Sequence
	}
}



# ====================================================================================
# FIND OWNER AGGREGATE ENTRY
# ====================================================================================

function Get-HeaderOwnerEntry
{
	param(
		[string]$Header,

		[System.Collections.Generic.List[string]]$OrderedEntries,

		[hashtable]$EntryClosures,

		[System.Collections.Generic.HashSet[string]]$ExcludedEntries
	)

	foreach ($Entry in $OrderedEntries)
	{
		if ($ExcludedEntries.Contains($Entry))
		{
			continue
		}

		if (-not $EntryClosures.ContainsKey($Entry))
		{
			continue
		}

		if ($EntryClosures[$Entry].Contains($Header))
		{
			return $Entry
		}
	}

	return $null
}



# ====================================================================================
# FIND HEADER RESPONSIBLE FOR CL FAILURE
# ====================================================================================

function Find-FailingSelectedHeader
{
	param(
		[string]$CompilerOutput,

		[string]$EDK2Dir,

		[System.Collections.Generic.HashSet[string]]$ValidSet,

		[System.Collections.Generic.List[string]]$ValidHeaders
	)

	$NormalizedEDK2 = (
		[System.IO.Path]::GetFullPath($EDK2Dir)
	).Replace("\", "/").TrimEnd("/")

	$Matches = [regex]::Matches(
		$CompilerOutput,
		'(?im)([A-Za-z]:\\[^\r\n]*?\.h)\(\d+(?:,\d+)?\)'
	)

	foreach ($Match in $Matches)
	{
		$Path = $Match.Groups[1].Value

		$Path = $Path.Replace("\", "/")

		if (
			$Path.StartsWith(
				$NormalizedEDK2,
				[System.StringComparison]::OrdinalIgnoreCase
			)
		)
		{
			$Relative = $Path.Substring(
				$NormalizedEDK2.Length
			).TrimStart("/")


			if ($ValidSet.Contains($Relative))
			{
				return $Relative
			}
		}
	}

	$NormalizedOutput = $CompilerOutput.Replace("\", "/")

	foreach ($Header in $ValidHeaders)
	{
		if ($NormalizedOutput -like "*$Header*")
		{
			return $Header
		}
	}

	return $null
}



# ====================================================================================
# STEP 1
# ====================================================================================

Write-Step "1/6" "Checking environment..."

# ------------------------------------------------------------------------------------
# Ghidra
# ------------------------------------------------------------------------------------

if (-not (Test-Path $GhidraDir))
{
	Write-Fail "Ghidra not found: $GhidraDir"
}

$AnalyzeHeadless = Get-ChildItem `
	-Path $GhidraDir `
	-Recurse `
	-Filter "analyzeHeadless.bat" `
	-ErrorAction SilentlyContinue |
	Select-Object -First 1

if (-not $AnalyzeHeadless)
{
	Write-Fail "Ghidra installation appears incomplete."
}

Write-OK "Ghidra"

# ------------------------------------------------------------------------------------
# EDK2
# ------------------------------------------------------------------------------------

if (-not (Test-Path $EDK2Dir))
{
	Write-Fail "EDK2 not found: $EDK2Dir"
}

if (-not (Test-Path (Join-Path $EDK2Dir "MdePkg\Include")))
{
	Write-Fail "MdePkg\Include not found."
}

Write-OK "EDK2"

# ------------------------------------------------------------------------------------
# Script02
# ------------------------------------------------------------------------------------

if (-not (Test-Path $HeadersFile))
{
	Write-Fail "EDK2_Headers.txt not found. Run Script02 first."
}

if (-not (Test-Path $DependenciesFile))
{
	Write-Fail "EDK2_Dependencies.txt not found. Run Script02 first."
}

Write-OK "Script02 scan data"

# ------------------------------------------------------------------------------------
# Visual Studio
# ------------------------------------------------------------------------------------

$VSWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path $VSWhere))
{
	Write-Fail "vswhere.exe not found."
}

$VSInstallPath = & $VSWhere `
	-latest `
	-products * `
	-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
	-property installationPath

if (-not $VSInstallPath)
{
	Write-Fail "Visual Studio C++ tools not found."
}

$VCVars = Join-Path `
	$VSInstallPath `
	"VC\Auxiliary\Build\vcvars64.bat"

if (-not (Test-Path $VCVars))
{
	Write-Fail "vcvars64.bat not found."
}

Write-OK "Visual Studio"

# ------------------------------------------------------------------------------------
# Java
# ------------------------------------------------------------------------------------

$JavaExe = (
	Get-Command java.exe `
		-ErrorAction SilentlyContinue
).Source

$JavacExe = (
	Get-Command javac.exe `
		-ErrorAction SilentlyContinue
).Source

if (-not $JavaExe -or -not $JavacExe)
{
	$GhidraJava = Get-ChildItem `
		-Path $GhidraDir `
		-Recurse `
		-Filter "java.exe" `
		-ErrorAction SilentlyContinue |
		Where-Object {
			$_.FullName -match "jdk"
		} |
		Select-Object -First 1

	if ($GhidraJava)
	{
		$JavaExe = $GhidraJava.FullName

		$PossibleJavac = Join-Path `
			(Split-Path $JavaExe -Parent) `
			"javac.exe"


		if (Test-Path $PossibleJavac)
		{
			$JavacExe = $PossibleJavac
		}
	}
}

if (-not $JavaExe -or -not $JavacExe)
{
	Write-Fail "Java/Javac not found."
}

Write-OK "Java"



# ====================================================================================
# LOAD SCRIPT02 HEADERS
# ====================================================================================

$AllHeaders = New-StringList

$SeenHeaders = New-StringSet

foreach ($Line in [System.IO.File]::ReadAllLines($HeadersFile))
{
	$Header = Convert-ToCanonicalHeader $Line

	if (
		$Header -and
		$SeenHeaders.Add($Header)
	)
	{
		$AllHeaders.Add($Header)
	}
}

if ($AllHeaders.Count -lt 10)
{
	Write-Fail "Could not parse EDK2_Headers.txt."
}

Write-OK "$($AllHeaders.Count) headers configured"



# ====================================================================================
# STEP 2
# ====================================================================================

Write-Step "2/6" "Loading Visual Studio environment..."

$TempCmd = [System.IO.Path]::GetTempFileName() + ".cmd"

@"
@echo off
call "$VCVars" >nul
set
"@ | Set-Content `
	-Path $TempCmd `
	-Encoding ASCII

$EnvOutput = & cmd.exe /c $TempCmd

Remove-Item `
	$TempCmd `
	-Force `
	-ErrorAction SilentlyContinue

foreach ($Line in $EnvOutput)
{
	if ($Line -match "^([^=]+)=(.*)$")
	{
		Set-Item `
			-Path "Env:$($matches[1])" `
			-Value $matches[2]
	}
}

$CLPath = (
	Get-Command cl.exe `
		-ErrorAction SilentlyContinue
).Source

if (-not $CLPath)
{
	Write-Fail "cl.exe not available after vcvars64.bat."
}

Write-OK "cl.exe loaded"
Write-Info $CLPath



# ====================================================================================
# STEP 3
# ====================================================================================

Write-Step "3/6" "Building EDK2 include and semantic graphs..."

# ------------------------------------------------------------------------------------
# Resolve headers
# ------------------------------------------------------------------------------------

$ValidHeaders = New-StringList

$ValidSet = New-StringSet

$NotFound = 0

foreach ($Header in $AllHeaders)
{
	$FullPath = Join-Path `
		$EDK2Dir `
		($Header.Replace("/", "\"))

	if (Test-Path $FullPath)
	{
		$ValidHeaders.Add($Header)

		[void]$ValidSet.Add($Header)
	}
	else
	{
		$NotFound++
	}
}

Write-Info "Resolved: $($ValidHeaders.Count) headers ($NotFound not found)"

# ------------------------------------------------------------------------------------
# Stable Script02 order
# ------------------------------------------------------------------------------------

$HeaderOrder = @{}

for ($i = 0; $i -lt $ValidHeaders.Count; $i++)
{
	$HeaderOrder[$ValidHeaders[$i]] = $i
}

# ------------------------------------------------------------------------------------
# Include index
# ------------------------------------------------------------------------------------

$IncludeIndex = @{}

foreach ($Header in $ValidHeaders)
{
	$Key = Get-IncludeKey $Header


	if (-not $IncludeIndex.ContainsKey($Key))
	{
		$IncludeIndex[$Key] = New-StringList
	}

	$IncludeIndex[$Key].Add($Header)
}

# ------------------------------------------------------------------------------------
# Explicit include graph
# ------------------------------------------------------------------------------------

$IncludeGraph = @{}

$IncludedBy = @{}

foreach ($Header in $ValidHeaders)
{
	Add-GraphNode `
		-Graph $IncludeGraph `
		-Node $Header

	$IncludedBy[$Header] = New-StringSet
}

$ExplicitEdges = 0

foreach ($Header in $ValidHeaders)
{
	$FullPath = Join-Path `
		$EDK2Dir `
		($Header.Replace("/", "\"))

	$Text = [System.IO.File]::ReadAllText($FullPath)

	$Text = Remove-CComments $Text

	$Matches = [regex]::Matches(
		$Text,
		'(?m)^\s*#\s*include\s*[<"]([^>"]+)[>"]'
	)

	foreach ($Match in $Matches)
	{
		$IncludeKey = $Match.Groups[1].Value.Replace("\", "/")

		if (-not $IncludeIndex.ContainsKey($IncludeKey))
		{
			continue
		}

		if ($IncludeIndex[$IncludeKey].Count -ne 1)
		{
			continue
		}

		$Dependency = $IncludeIndex[$IncludeKey][0]

		if ($Dependency -eq $Header)
		{
			continue
		}

		if (
			Add-GraphEdge `
				-Graph $IncludeGraph `
				-From $Header `
				-To $Dependency
		)
		{
			[void]$IncludedBy[$Dependency].Add($Header)

			$ExplicitEdges++
		}
	}
}

Write-Info "Explicit selected-header include edges: $ExplicitEdges"

# ------------------------------------------------------------------------------------
# Natural roots
# ------------------------------------------------------------------------------------

$NaturalRoots = New-StringList

foreach ($Header in $ValidHeaders)
{
	if ($IncludedBy[$Header].Count -eq 0)
	{
		$NaturalRoots.Add($Header)
	}
}

$NaturalRootsSorted = @(
	$NaturalRoots |
	Sort-Object {
		$HeaderOrder[$_]
	}
)

$NaturalRoots = New-StringList

foreach ($Header in $NaturalRootsSorted)
{
	$NaturalRoots.Add($Header)
}

Write-Info "Natural include roots: $($NaturalRoots.Count)"

# ------------------------------------------------------------------------------------
# Root closures
# ------------------------------------------------------------------------------------

$EntryClosures = @{}

foreach ($RootHeader in $NaturalRoots)
{
	$EntryClosures[$RootHeader] = Get-TransitiveClosure `
		-Graph $IncludeGraph `
		-Start $RootHeader
}

# ------------------------------------------------------------------------------------
# Make sure every selected header is covered.
# ------------------------------------------------------------------------------------

$Covered = New-StringSet

foreach ($RootHeader in $NaturalRoots)
{
	foreach ($Header in $EntryClosures[$RootHeader])
	{
		[void]$Covered.Add($Header)
	}
}

while ($Covered.Count -lt $ValidHeaders.Count)
{
	$BestHeader  = $null
	$BestClosure = $null
	$BestGain    = -1

	foreach ($Header in $ValidHeaders)
	{
		if ($Covered.Contains($Header))
		{
			continue
		}

		$Closure = Get-TransitiveClosure `
			-Graph $IncludeGraph `
			-Start $Header

		$Gain = 0

		foreach ($Member in $Closure)
		{
			if (-not $Covered.Contains($Member))
			{
				$Gain++
			}
		}

		if ($Gain -gt $BestGain)
		{
			$BestHeader  = $Header
			$BestClosure = $Closure
			$BestGain    = $Gain
		}
	}

	if (-not $BestHeader)
	{
		break
	}

	$NaturalRoots.Add($BestHeader)

	$EntryClosures[$BestHeader] = $BestClosure

	foreach ($Member in $BestClosure)
	{
		[void]$Covered.Add($Member)
	}
}

Write-OK "Include context plan created"

Write-Info "Initial aggregate entries: $($NaturalRoots.Count)"

Write-Info "Transitively covered selected headers: $($Covered.Count)/$($ValidHeaders.Count)"

# ------------------------------------------------------------------------------------
# Parse ALL useful semantic dependencies
# ------------------------------------------------------------------------------------

$SemanticDependencies = [System.Collections.Generic.List[object]]::new()

$SemanticSeen = New-StringSet

$AcceptedCount  = 0
$RedundantCount = 0
$RejectedCount  = 0

foreach ($Line in [System.IO.File]::ReadAllLines($DependenciesFile))
{
	if ($Line -notmatch '\[types:\s*([^\]]+)\]')
	{
		continue
	}

	if (
		$Line -match '\[reason:\s*would-create-cycle\]'
	)
	{
		$RejectedCount++

		continue
	}

	if (
		$Line -notmatch '^\s*(.+?\.h)\s*->\s*(.+?\.h)\s+'
	)
	{
		continue
	}

	$Provider = Convert-ToCanonicalHeader $matches[1]

	$Consumer = Convert-ToCanonicalHeader $matches[2]

	if (-not $Provider -or -not $Consumer)
	{
		continue
	}

	if (
		-not $ValidSet.Contains($Provider) -or
		-not $ValidSet.Contains($Consumer)
	)
	{
		continue
	}

	if ($Provider -eq $Consumer)
	{
		continue
	}

	$Types = ""

	if ($Line -match '\[types:\s*([^\]]+)\]')
	{
		$Types = $matches[1].Trim()
	}

	$Reason = "accepted"

	if (
		$Line -match '\[reason:\s*already-satisfied-transitively\]'
	)
	{
		$Reason = "transitive"

		$RedundantCount++
	}
	else
	{
		$AcceptedCount++
	}

	$Key = "$Provider`0$Consumer"

	if ($SemanticSeen.Add($Key))
	{
		$SemanticDependencies.Add(

			[PSCustomObject]@{

				Provider = $Provider

				Consumer = $Consumer

				Types = $Types

				Source = $Reason
			}
		)
	}
}

Write-Info "Semantic dependencies loaded: $($SemanticDependencies.Count)"

Write-Info "  accepted by Script02: $AcceptedCount"

Write-Info "  transitive candidates retained: $RedundantCount"

Write-Info "  cycle-rejected ignored: $RejectedCount"

# ------------------------------------------------------------------------------------
# Compiler include paths
# ------------------------------------------------------------------------------------

$IncludeArgs = New-StringList

$IncludePaths = New-StringSet

foreach ($Header in $ValidHeaders)
{
	$FullPath = Join-Path `
		$EDK2Dir `
		($Header.Replace("/", "\"))

	$HeaderDirectory = Split-Path `
		$FullPath `
		-Parent

	while (
		$HeaderDirectory -and
		$HeaderDirectory.StartsWith(
			$EDK2Dir,
			[System.StringComparison]::OrdinalIgnoreCase
		)
	)
	{
		[void]$IncludePaths.Add($HeaderDirectory)

		if (
			(Split-Path $HeaderDirectory -Leaf) -eq "Include"
		)
		{
			break
		}

		$HeaderDirectory = Split-Path `
			$HeaderDirectory `
			-Parent
	}
}

foreach ($IncludePath in ($IncludePaths | Sort-Object))
{
	$IncludeArgs.Add("/I")
	$IncludeArgs.Add($IncludePath)
}



# ====================================================================================
# STEP 4
# ====================================================================================

Write-Step "4/6" "Resolving real preprocessing order with cl.exe oracle..."

# ------------------------------------------------------------------------------------
# Aggregate entries
# ------------------------------------------------------------------------------------

$AggregateEntries = New-StringList

foreach ($RootHeader in $NaturalRoots)
{
	$AggregateEntries.Add($RootHeader)
}

$AggregateSet = New-StringSet

foreach ($Header in $AggregateEntries)
{
	[void]$AggregateSet.Add($Header)
}

# ------------------------------------------------------------------------------------
# Aggregate dependency graph
# ------------------------------------------------------------------------------------

$AggregateGraph = @{}

foreach ($Header in $AggregateEntries)
{
	Add-GraphNode `
		-Graph $AggregateGraph `
		-Node $Header
}

# ------------------------------------------------------------------------------------
# Stable order
# ------------------------------------------------------------------------------------

$AggregateStableOrder = @{}

for ($i = 0; $i -lt $ValidHeaders.Count; $i++)
{
	$AggregateStableOrder[$ValidHeaders[$i]] = $i
}

# ------------------------------------------------------------------------------------
# Exclusions
# ------------------------------------------------------------------------------------

$ExcludedEntries = New-StringSet

$ExcludedList = New-StringList

# ------------------------------------------------------------------------------------
# Oracle loop
# ------------------------------------------------------------------------------------

$MaxOraclePasses = 50

$OracleStable = $false

$TotalPromotions = 0

$TotalConstraints = 0

$PreviousViolationSignature = $null

for (
	$OraclePass = 1;
	$OraclePass -le $MaxOraclePasses;
	$OraclePass++
)
{
	Write-Info "Oracle pass $OraclePass..."

	# -------------------------------------------------------------------------------
	# Topologically order aggregate entries
	# -------------------------------------------------------------------------------

	$OrderedEntries = Get-StableTopologicalOrder `
		-Nodes $AggregateEntries `
		-Graph $AggregateGraph `
		-StableOrder $AggregateStableOrder

	if ($OrderedEntries.Count -ne $AggregateEntries.Count)
	{
		Write-Fail (
			"Aggregate dependency graph contains a cycle. " +
			"Ordered $($OrderedEntries.Count)/$($AggregateEntries.Count)."
		)
	}

	# -------------------------------------------------------------------------------
	# Write aggregate
	# -------------------------------------------------------------------------------

	Write-AggregateHeader `
		-Path $OracleAggregate `
		-Entries $OrderedEntries `
		-ExcludedEntries $ExcludedEntries

	# -------------------------------------------------------------------------------
	# Preprocess with line markers
	# -------------------------------------------------------------------------------

	$OracleRun = Invoke-BehemothPreprocessor `
		-InputHeader $OracleAggregate `
		-OutputFile $OracleOutput `
		-KeepMarkers $true `
		-IncludeArgs $IncludeArgs `
		-CLPath $CLPath

	# -------------------------------------------------------------------------------
	# Generic preprocessing failure handling
	# -------------------------------------------------------------------------------

	if (
		$OracleRun.ExitCode -ne 0 -or
		-not $OracleRun.FileExists
	)
	{
		$FailedHeader = Find-FailingSelectedHeader `
			-CompilerOutput $OracleRun.Output `
			-EDK2Dir $EDK2Dir `
			-ValidSet $ValidSet `
			-ValidHeaders $ValidHeaders

		if (-not $FailedHeader)
		{
			Write-Host ""
			Write-Host $OracleRun.Output -ForegroundColor Gray
			Write-Host ""

			Write-Fail "Oracle preprocessing failed and failing header could not be identified."
		}

		$Owner = Get-HeaderOwnerEntry `
			-Header $FailedHeader `
			-OrderedEntries $OrderedEntries `
			-EntryClosures $EntryClosures `
			-ExcludedEntries $ExcludedEntries

		if (-not $Owner)
		{
			Write-Host ""
			Write-Host $OracleRun.Output -ForegroundColor Gray
			Write-Host ""

			Write-Fail "Could not determine aggregate owner for failing header: $FailedHeader"
		}

		if ($ExcludedEntries.Add($Owner))
		{
			$ExcludedList.Add($Owner)

			Write-Info "Excluded aggregate entry: $Owner"

			if ($Owner -ne $FailedHeader)
			{
				Write-Info "  failing descendant: $FailedHeader"
			}

			Write-Log "ORACLE EXCLUDED: $Owner"
			Write-Log "FAILING HEADER: $FailedHeader"

			continue
		}

		Write-Fail "Oracle preprocessing still fails inside already excluded context."
	}

	# -------------------------------------------------------------------------------
	# Recover real header order
	# -------------------------------------------------------------------------------

	$RealOrder = Get-RealHeaderOrder `
		-PreprocessedFile $OracleOutput `
		-EDK2Dir $EDK2Dir `
		-ValidSet $ValidSet

	$Positions = $RealOrder.FirstPosition

	Write-Info "  headers observed by preprocessor: $($Positions.Count)/$($ValidHeaders.Count)"

	# -------------------------------------------------------------------------------
	# Oracle sanity check
	# -------------------------------------------------------------------------------

	$ExpectedObserved = (
		$ValidHeaders.Count -
		$ExcludedEntries.Count
	)

	if ($Positions.Count -eq 0)
	{
		Write-Fail (
			"Oracle recovered 0 EDK2 headers from the preprocessor output. " +
			"Refusing false convergence."
		)
	}

	$MinimumObserved = [Math]::Floor(
		$ExpectedObserved * 0.50
	)

	if ($Positions.Count -lt $MinimumObserved)
	{
		Write-Fail (
			"Oracle recovered only " +
			"$($Positions.Count)/$ExpectedObserved expected headers. " +
			"Minimum required for reliable validation: $MinimumObserved."
		)
	}

	# -------------------------------------------------------------------------------
	# Save current real order
	# -------------------------------------------------------------------------------

	$OrderLines = New-StringList

	$OrderLines.Add(
		"Oracle pass: $OraclePass"
	)

	$OrderLines.Add(
		"Observed headers: $($Positions.Count)"
	)

	$OrderLines.Add("")

	$Index = 1

	foreach ($Header in $RealOrder.Sequence)
	{
		$OrderLines.Add(
			("{0,5} : {1}" -f $Index, $Header)
		)

		$Index++
	}

	[System.IO.File]::WriteAllLines(
		$OracleReport,
		$OrderLines.ToArray(),
		[System.Text.Encoding]::UTF8
	)

	# -------------------------------------------------------------------------------
	# Validate semantic dependencies against actual expansion order
	# -------------------------------------------------------------------------------

	$Violations = [System.Collections.Generic.List[object]]::new()

	foreach ($Dependency in $SemanticDependencies)
	{
		$Provider = $Dependency.Provider

		$Consumer = $Dependency.Consumer

		if (
			-not $Positions.ContainsKey($Provider) -or
			-not $Positions.ContainsKey($Consumer)
		)
		{
			continue
		}

		$ProviderPosition = $Positions[$Provider]

		$ConsumerPosition = $Positions[$Consumer]

		if ($ProviderPosition -gt $ConsumerPosition)
		{
			$Violations.Add(

				[PSCustomObject]@{

					Provider = $Provider

					Consumer = $Consumer

					Types = $Dependency.Types

					ProviderPosition = $ProviderPosition

					ConsumerPosition = $ConsumerPosition
				}
			)
		}
	}

	Write-Info "  semantic order violations: $($Violations.Count)"

	# -------------------------------------------------------------------------------
	# Stable = done
	# -------------------------------------------------------------------------------

	if ($Violations.Count -eq 0)
	{
		$OracleStable = $true

		Write-OK "Real preprocessing order satisfies semantic dependencies"

		break
	}

	# -------------------------------------------------------------------------------
	# Save violations
	# -------------------------------------------------------------------------------

	$ViolationLines = New-StringList

	$ViolationLines.Add(
		"Oracle pass: $OraclePass"
	)

	$ViolationLines.Add(
		"Violations: $($Violations.Count)"
	)

	$ViolationLines.Add("")

	foreach (
		$Violation in (
			$Violations |
			Sort-Object ConsumerPosition, ProviderPosition
		)
	)
	{
		$ViolationLines.Add(
			"$($Violation.Provider) -> $($Violation.Consumer)"
		)

		$ViolationLines.Add(
			"    provider position : $($Violation.ProviderPosition)"
		)

		$ViolationLines.Add(
			"    consumer position : $($Violation.ConsumerPosition)"
		)

		$ViolationLines.Add(
			"    types             : $($Violation.Types)"
		)

		$ViolationLines.Add("")
	}

	[System.IO.File]::WriteAllLines(
		$ViolationReport,
		$ViolationLines.ToArray(),
		[System.Text.Encoding]::UTF8
	)

	# -------------------------------------------------------------------------------
	# Detect complete lack of progress
	# -------------------------------------------------------------------------------

	$ViolationSignature = (
		$Violations |
		Sort-Object Provider, Consumer |
		ForEach-Object {
			"$($_.Provider)->$($_.Consumer)"
		}
	) -join "|"

	# -------------------------------------------------------------------------------
	# Fix violations
	# -------------------------------------------------------------------------------

	$ChangesThisPass = 0

	foreach (
		$Violation in (
			$Violations |
			Sort-Object ConsumerPosition, ProviderPosition
		)
	)
	{
		$Provider = $Violation.Provider

		$Consumer = $Violation.Consumer

		# ---------------------------------------------------------------------------
		# Promote provider
		# ---------------------------------------------------------------------------

		if (-not $AggregateSet.Contains($Provider))
		{
			$AggregateEntries.Add($Provider)

			[void]$AggregateSet.Add($Provider)

			Add-GraphNode `
				-Graph $AggregateGraph `
				-Node $Provider

			$EntryClosures[$Provider] = Get-TransitiveClosure `
				-Graph $IncludeGraph `
				-Start $Provider

			$TotalPromotions++

			$ChangesThisPass++

			Add-Content `
				-Path $PromotionReport `
				-Value (
					"PROMOTE: $Provider`r`n" +
					"    because: $Provider -> $Consumer`r`n" +
					"    types: $($Violation.Types)`r`n"
				)

			Write-Log "PROMOTED PROVIDER: $Provider"
		}

		# ---------------------------------------------------------------------------
		# Determine which currently ordered aggregate entry exposes the consumer
		# ---------------------------------------------------------------------------

		$ConsumerOwner = Get-HeaderOwnerEntry `
			-Header $Consumer `
			-OrderedEntries $OrderedEntries `
			-EntryClosures $EntryClosures `
			-ExcludedEntries $ExcludedEntries

		if (-not $ConsumerOwner)
		{
			continue
		}

		# ---------------------------------------------------------------------------
		# Provider is itself the owner
		# ---------------------------------------------------------------------------

		if ($Provider -eq $ConsumerOwner)
		{
			continue
		}

		# ---------------------------------------------------------------------------
		# Already satisfied by aggregate graph?
		# ---------------------------------------------------------------------------

		if (
			Test-GraphPath `
				-Graph $AggregateGraph `
				-Start $Provider `
				-Target $ConsumerOwner
		)
		{
			continue
		}

		# ---------------------------------------------------------------------------
		# Avoid creating aggregate graph cycle
		# ---------------------------------------------------------------------------

		if (
			Test-GraphPath `
				-Graph $AggregateGraph `
				-Start $ConsumerOwner `
				-Target $Provider
		)
		{
			Write-Log (
				"ORACLE CONSTRAINT SKIPPED CYCLE: " +
				"$Provider -> $ConsumerOwner"
			)

			continue
		}

		if (
			Add-GraphEdge `
				-Graph $AggregateGraph `
				-From $Provider `
				-To $ConsumerOwner
		)
		{
			$TotalConstraints++

			$ChangesThisPass++

			Add-Content `
				-Path $PromotionReport `
				-Value (
					"ORDER: $Provider -> $ConsumerOwner`r`n" +
					"    semantic consumer: $Consumer`r`n" +
					"    types: $($Violation.Types)`r`n"
				)

			Write-Log (
				"ORACLE CONSTRAINT: " +
				"$Provider -> $ConsumerOwner " +
				"for $Provider -> $Consumer"
			)
		}
	}

	Write-Info "  new provider promotions: $ChangesThisPass"

	# -------------------------------------------------------------------------------
	# No changes = cannot make further progress.
	# -------------------------------------------------------------------------------

	if ($ChangesThisPass -eq 0)
	{
		Write-Warn "Oracle could not add any new ordering correction."

		if ($PreviousViolationSignature -eq $ViolationSignature)
		{
			Write-Host ""
			Write-Host "  Remaining semantic violations:" -ForegroundColor Yellow

			foreach (
				$Violation in (
					$Violations |
					Select-Object -First 20
				)
			)
			{
				Write-Host (
					"    $($Violation.Provider) -> " +
					"$($Violation.Consumer) " +
					"[$($Violation.Types)]"
				) -ForegroundColor Yellow
			}

			Write-Host ""

			Write-Fail (
				"Preprocessing order stalled. " +
				"See $ViolationReport"
			)
		}
	}

	$PreviousViolationSignature = $ViolationSignature
}

if (-not $OracleStable)
{
	Write-Fail "Oracle did not converge after $MaxOraclePasses passes."
}

Write-OK "Oracle ordering converged"

Write-Info "Provider headers promoted: $TotalPromotions"

Write-Info "Aggregate constraints added: $TotalConstraints"

Write-Info "Final aggregate entries: $($AggregateEntries.Count)"

Write-Info "Excluded aggregate entries: $($ExcludedEntries.Count)"



# ====================================================================================
# STEP 5
# ====================================================================================

Write-Step "5/6" "Generating final preprocessed EDK2 header..."

# ------------------------------------------------------------------------------------
# Final ordering
# ------------------------------------------------------------------------------------

$FinalOrderedEntries = Get-StableTopologicalOrder `
	-Nodes $AggregateEntries `
	-Graph $AggregateGraph `
	-StableOrder $AggregateStableOrder

if (
	$FinalOrderedEntries.Count -ne
	$AggregateEntries.Count
)
{
	Write-Fail "Final aggregate graph contains a cycle."
}

# ------------------------------------------------------------------------------------
# Write final aggregate
# ------------------------------------------------------------------------------------

Write-AggregateHeader `
	-Path $FinalAggregate `
	-Entries $FinalOrderedEntries `
	-ExcludedEntries $ExcludedEntries

# ------------------------------------------------------------------------------------
# Final preprocessing WITHOUT markers
# ------------------------------------------------------------------------------------

$FinalRun = Invoke-BehemothPreprocessor `
	-InputHeader $FinalAggregate `
	-OutputFile $PreprocessedI `
	-KeepMarkers $false `
	-IncludeArgs $IncludeArgs `
	-CLPath $CLPath

if (
	$FinalRun.ExitCode -ne 0 -or
	-not $FinalRun.FileExists
)
{
	Write-Host ""
	Write-Host $FinalRun.Output -ForegroundColor Gray
	Write-Host ""

	Write-Fail "Final preprocessing failed."
}

Write-OK "Final preprocessed header created"

Write-Info $PreprocessedI


# ====================================================================================
# CLEAN PREPROCESSED HEADER
# ====================================================================================

Write-Info "Cleaning preprocessed header..."


# ====================================================================================
# CLEAN PREPROCESSED HEADER
# ====================================================================================

$RawLines = [System.IO.File]::ReadAllLines(
	$PreprocessedI
)


# ====================================================================================
# PASS 1
#
# Remove preprocessor/compiler noise that Ghidra does not need
# ====================================================================================

$Pass1Lines = New-StringList

foreach ($Line in $RawLines)
{
	if ($Line -match '^\s*#\s*line\b')
	{
		continue
	}

	if ($Line -match '^\s*#\s*pragma\b')
	{
		continue
	}

	if ($Line -match '^\s*#\s*\d+\s+"')
	{
		continue
	}

	if ($Line -match '__attribute__')
	{
		$Line = [regex]::Replace(
			$Line,
			'\s*__attribute__\s*\(\(.*?\)\)',
			''
		)

		if ([string]::IsNullOrWhiteSpace($Line))
		{
			continue
		}
	}

	if ($Line -match '^\s*__asm\b')
	{
		continue
	}

	if ($Line -match '^\s*asm\b')
	{
		continue
	}

	$Pass1Lines.Add($Line)
}

Write-Info "Cleaner pass 1: preprocessor/compiler noise removed"


# ====================================================================================
# HELPER
#
# Count parenthesis balance while ignoring parentheses inside strings/chars
# ====================================================================================

function Get-ParenthesisDelta
{
	param(
		[string]$Text
	)

	$Delta = 0

	$InString = $false
	$InChar   = $false
	$Escape   = $false

	for (
		$Index = 0;
		$Index -lt $Text.Length;
		$Index++
	)
	{
		$Character = $Text[$Index]

		if ($Escape)
		{
			$Escape = $false

			continue
		}

		if ($Character -eq '\')
		{
			if ($InString -or $InChar)
			{
				$Escape = $true
			}

			continue
		}

		if (
			$Character -eq '"' -and
			-not $InChar
		)
		{
			$InString = -not $InString

			continue
		}

		if (
			$Character -eq "'" -and
			-not $InString
		)
		{
			$InChar = -not $InChar

			continue
		}

		if ($InString -or $InChar)
		{
			continue
		}

		switch ($Character)
		{
			'('
			{
				$Delta++
			}

			')'
			{
				$Delta--
			}
		}
	}


	return $Delta
}


# ====================================================================================
# PASS 2
#
# Remove unsupported constructs as complete statements.
# ====================================================================================

$Pass2Lines = New-StringList

$SkippingStatement     = $false
$StatementDepth        = 0
$StatementSawOpenParen = $false
$SkippedStatements     = 0


foreach ($Line in $Pass1Lines)
{
	$Trimmed = $Line.Trim()

	if ($SkippingStatement)
	{
		$Delta = Get-ParenthesisDelta $Line

		if ($Delta -gt 0)
		{
			$StatementSawOpenParen = $true
		}

		$StatementDepth += $Delta

		if (
			$StatementSawOpenParen -and
			$StatementDepth -le 0 -and
			$Trimmed -match ';\s*\\?\s*$'
		)
		{
			$SkippingStatement     = $false
			$StatementDepth        = 0
			$StatementSawOpenParen = $false
		}

		continue
	}

	if (
		$Trimmed -match '^(?:static_assert|_Static_assert|STATIC_ASSERT)\s*\('
	)
	{
		$SkippingStatement = $true

		$SkippedStatements++


		$StatementDepth = Get-ParenthesisDelta $Line


		$StatementSawOpenParen = $Line.Contains("(")

		if (
			$StatementSawOpenParen -and
			$StatementDepth -le 0 -and
			$Trimmed -match ';\s*\\?\s*$'
		)
		{
			$SkippingStatement     = $false
			$StatementDepth        = 0
			$StatementSawOpenParen = $false
		}

		continue
	}

	if (
		$Trimmed -match '^VERIFY_SIZE_OF\s*\('
	)
	{
		$SkippingStatement = $true

		$SkippedStatements++

		$StatementDepth = Get-ParenthesisDelta $Line

		$StatementSawOpenParen = $Line.Contains("(")

		if (
			$StatementSawOpenParen -and
			$StatementDepth -le 0 -and
			$Trimmed -match ';\s*\\?\s*$'
		)
		{
			$SkippingStatement     = $false
			$StatementDepth        = 0
			$StatementSawOpenParen = $false
		}

		continue
	}

	$Pass2Lines.Add($Line)
}

if ($SkippingStatement)
{
	Write-Fail (
		"Cleaner reached EOF while skipping an unsupported multi-line statement. " +
		"The generated C would be incomplete."
	)
}

Write-Info "Cleaner pass 2: unsupported complete statements removed: $SkippedStatements"


# ====================================================================================
# PASS 3
#
# Remove compiler-specific decorations WITHOUT deleting the declaration itself
# ====================================================================================

$Pass3Lines = New-StringList

foreach ($Line in $Pass2Lines)
{
	$Current = $Line

	$Previous = $null

	while ($Previous -ne $Current)
	{
		$Previous = $Current

		$Current = [regex]::Replace(
			$Current,
			'__declspec\s*\([^()]*\)',
			''
		)
	}

	$Current = $Current `
		-replace '\b__forceinline\b', '' `
		-replace '\b__inline\b', '' `
		-replace '\b__restrict\b', '' `
		-replace '\b__unaligned\b', ''

	$Pass3Lines.Add($Current)
}

Write-Info "Cleaner pass 3: compiler decorations normalized"


# ====================================================================================
# PASS 4
#
# Final cleanup
# ====================================================================================

$FinalCleanLines = New-StringList

foreach ($Line in $Pass3Lines)
{
	$Trimmed = $Line.Trim()

	if ($Trimmed -eq "\")
	{
		continue
	}

	$FinalCleanLines.Add($Line)
}

Write-Info "Cleaner pass 4: conservative cleanup complete"


# ====================================================================================
# WRITE CLEAN HEADER
# ====================================================================================

[System.IO.File]::WriteAllLines(
	$CleanHeader,
	$FinalCleanLines.ToArray(),
	[System.Text.Encoding]::ASCII
)


# ====================================================================================
# STATISTICS
# ====================================================================================

$TypedefCount = (
	$FinalCleanLines |
	Where-Object {
		$_ -match '\btypedef\b'
	}
).Count

$StructCount = (
	$FinalCleanLines |
	Where-Object {
		$_ -match '\bstruct\b'
	}
).Count

Write-OK "Clean header generated"

Write-Info $CleanHeader

Write-Info "Unsupported multi-line statements removed: $SkippedStatements"

Write-Info "typedef lines: $TypedefCount"

Write-Info "struct lines : $StructCount"



# ====================================================================================
# STEP 6
# ====================================================================================

Write-Step "6/6" "Generating Behemoth X64 and IA32 GDT archives..."


# ====================================================================================
# GHIDRA SHIM
# ====================================================================================

$CleanHeaderFwd = $CleanHeader.Replace("\", "/")

$ShimLines = @(

	"#ifndef BEHEMOTH_GHIDRA_TYPES_H",
	"#define BEHEMOTH_GHIDRA_TYPES_H",
	"",

	"#define EFIAPI",
	"#define IN",
	"#define OUT",
	"#define OPTIONAL",
	"#define CONST const",
	"",

	"typedef unsigned char       BOOLEAN;",
	"typedef signed char         INT8;",
	"typedef unsigned char       UINT8;",
	"typedef short               INT16;",
	"typedef unsigned short      UINT16;",
	"typedef int                 INT32;",
	"typedef unsigned int        UINT32;",
	"typedef long long           INT64;",
	"typedef unsigned long long  UINT64;",
	"#if defined(BEHEMOTH_ARCH_IA32)",
	"typedef unsigned int        UINTN;",
	"typedef int                 INTN;",
	"#else",
	"typedef unsigned long long  UINTN;",
	"typedef long long           INTN;",
	"#endif",
	"typedef unsigned short      CHAR16;",
	"typedef void                VOID;",
	"",

	"typedef UINTN EFI_STATUS;",
	"typedef UINT64 EFI_PHYSICAL_ADDRESS;",
	"typedef UINT64 EFI_VIRTUAL_ADDRESS;",
	"",

	"typedef VOID *EFI_HANDLE;",
	"typedef VOID *EFI_EVENT;",
	"",

	"typedef struct {",
	"    UINT32 Data1;",
	"    UINT16 Data2;",
	"    UINT16 Data3;",
	"    UINT8  Data4[8];",
	"} EFI_GUID;",
	"",

	"#include `"$CleanHeaderFwd`"",
	"",

	"#endif"
)

[System.IO.File]::WriteAllLines(
	$ShimHeader,
	$ShimLines,
	[System.Text.Encoding]::ASCII
)

Write-OK "Shim header generated"

Write-Info $ShimHeader


# ====================================================================================
# FIND GHIDRA JARS
# ====================================================================================

$JarFiles = Get-ChildItem `
	-Path $GhidraDir `
	-Recurse `
	-Filter "*.jar" `
	-ErrorAction SilentlyContinue |
	Where-Object {
		$_.FullName -notlike "*javadoc*"
	} |
	Select-Object -ExpandProperty FullName

if ($JarFiles.Count -eq 0)
{
	Write-Fail "No Ghidra JAR files found."
}

$ClassPath = $JarFiles -join ";"

Write-OK "$($JarFiles.Count) Ghidra JARs found"


# ====================================================================================
# JAVA INCLUDE PATHS
# ====================================================================================

$JavaIncludePaths = New-StringList

$JavaIncludePaths.Add(
	$GDTDir.Replace("\", "/")
)

$JavaIncludePathSet = New-StringSet

foreach ($Header in $ValidHeaders)
{
	$FullPath = Join-Path `
		$EDK2Dir `
		($Header.Replace("/", "\"))

	$HeaderDirectory = Split-Path `
		$FullPath `
		-Parent

	while (
		$HeaderDirectory -and
		$HeaderDirectory.StartsWith(
			$EDK2Dir,
			[System.StringComparison]::OrdinalIgnoreCase
		)
	)
	{
		[void]$JavaIncludePathSet.Add($HeaderDirectory)

		if (
			(Split-Path $HeaderDirectory -Leaf) -eq "Include"
		)
		{
			break
		}

		$HeaderDirectory = Split-Path `
			$HeaderDirectory `
			-Parent
	}
}

foreach ($IncludePath in ($JavaIncludePathSet | Sort-Object))
{
	$JavaIncludePaths.Add(
		$IncludePath.Replace("\", "/")
	)
}


# ====================================================================================
# GENERATE JAVA SOURCE
# ====================================================================================

$ShimFwd = $ShimHeader.Replace("\", "/")

$JavaLines = New-StringList

$JavaLines.Add('import ghidra.GhidraApplicationLayout;')
$JavaLines.Add('import ghidra.framework.Application;')
$JavaLines.Add('import ghidra.framework.HeadlessGhidraApplicationConfiguration;')
$JavaLines.Add('import ghidra.app.util.cparser.C.CParserUtils;')
$JavaLines.Add('import ghidra.program.model.data.*;')
$JavaLines.Add('import ghidra.util.task.TaskMonitor;')
$JavaLines.Add('import java.io.File;')
$JavaLines.Add('import java.util.Iterator;')
$JavaLines.Add("")
$JavaLines.Add('public class BehemothBuilder {')
$JavaLines.Add('    public static void main(String[] args) throws Exception {')
$JavaLines.Add('        if (args.length != 5) { System.err.println("Usage: BehemothBuilder <output.gdt> <languageId> <compilerSpecId> <expectedPointerSize> <arch>"); System.exit(64); }')
$JavaLines.Add('        String outputGDT = args[0]; String languageId = args[1]; String compilerSpecId = args[2]; int expectedPointerSize = Integer.parseInt(args[3]); String arch = args[4];')
$JavaLines.Add('        System.out.println("=== Behemoth GDT Builder [" + arch + "] ===");')
$JavaLines.Add('        Application.initializeApplication(')
$JavaLines.Add('            new GhidraApplicationLayout(),')
$JavaLines.Add('            new HeadlessGhidraApplicationConfiguration()')
$JavaLines.Add('        );')
$JavaLines.Add("        String shimHeader = `"$ShimFwd`";")
$JavaLines.Add('        String[] files = { shimHeader };')
$JavaLines.Add('        String[] includePaths = {')

for (
	$i = 0;
	$i -lt $JavaIncludePaths.Count;
	$i++
)
{
	$Comma = ""

	if (
		$i -lt
		($JavaIncludePaths.Count - 1)
	)
	{
		$Comma = ","
	}


	$JavaLines.Add("            `"$($JavaIncludePaths[$i])`"$Comma")
}

$JavaLines.Add('        };')
$JavaLines.Add('        String[] options;')
$JavaLines.Add('        if ("IA32".equalsIgnoreCase(arch)) {')
$JavaLines.Add('            options = new String[] { "-D_WIN32", "-D_M_IX86", "-DMDE_CPU_IA32", "-DBEHEMOTH_ARCH_IA32", "-DEFIAPI=" };')
$JavaLines.Add('        } else {')
$JavaLines.Add('            options = new String[] { "-D_WIN32", "-D_AMD64_", "-D__x86_64__", "-DMDE_CPU_X64", "-DBEHEMOTH_ARCH_X64", "-DEFIAPI=" };')
$JavaLines.Add('        }')
$JavaLines.Add('        File gdtFile = new File(outputGDT);')
$JavaLines.Add('        if (gdtFile.exists()) {')
$JavaLines.Add('            gdtFile.delete();')
$JavaLines.Add('        }')
$JavaLines.Add('        System.out.println("Parsing: " + shimHeader);')
$JavaLines.Add('        FileDataTypeManager result = CParserUtils.parseHeaderFiles(')
$JavaLines.Add('            new DataTypeManager[0],')
$JavaLines.Add('            files,')
$JavaLines.Add('            includePaths,')
$JavaLines.Add('            options,')
$JavaLines.Add('            outputGDT,')
$JavaLines.Add('            languageId,')
$JavaLines.Add('            compilerSpecId,')
$JavaLines.Add('            TaskMonitor.DUMMY')
$JavaLines.Add('        );')
$JavaLines.Add('        if (result == null) {')
$JavaLines.Add('            System.exit(1);')
$JavaLines.Add('        }')
$JavaLines.Add('        int pointerSize = result.getDataOrganization().getPointerSize();')
$JavaLines.Add('        System.out.println("Language ............ " + languageId); System.out.println("Compiler spec ....... " + compilerSpecId); System.out.println("GDT pointer size .... " + pointerSize + " bytes");')
$JavaLines.Add('        if (pointerSize != expectedPointerSize) { System.err.println("ERROR: GDT pointer size does not match requested ABI."); result.close(); if (gdtFile.exists()) gdtFile.delete(); System.exit(2); }')
$JavaLines.Add('        Iterator<DataType> it = result.getAllDataTypes();')
$JavaLines.Add('        int total = 0;')
$JavaLines.Add('        while (it.hasNext()) {')
$JavaLines.Add('            it.next();')
$JavaLines.Add('            total++;')
$JavaLines.Add('        }')
$JavaLines.Add('        System.out.println("Parsed types: " + total);')
$JavaLines.Add('        result.save();')
$JavaLines.Add('        result.close();')
$JavaLines.Add('        System.out.println("SUCCESS: " + total + " types generated");')
$JavaLines.Add('    }')
$JavaLines.Add('}')

[System.IO.File]::WriteAllLines(
	$JavaSrc,
	$JavaLines.ToArray(),
	[System.Text.Encoding]::ASCII
)

Write-OK "Java source generated"


# ====================================================================================
# COMPILE JAVA
# ====================================================================================

$JavacArgs = @(

	"-proc:none",

	"-cp",

	$ClassPath,

	$JavaSrc
)

& $JavacExe @JavacArgs

$JavacExit = $LASTEXITCODE

if ($JavacExit -ne 0)
{
	Write-Fail "javac compilation failed (exit code $JavacExit)"
}

Write-OK "Java compilation successful"


# ====================================================================================
# RUN GHIDRA PARSER
# ====================================================================================

function Invoke-BehemothGDTBuild
{
	param(
		[string]$Architecture,
		[string]$LanguageId,
		[string]$CompilerSpecId,
		[int]$ExpectedPointerSize,
		[string]$OutputPath
	)

	Write-Host ""
	Write-Host "  [$Architecture]" -ForegroundColor White

	$JavaArgs = @(
		"-cp",
		"$ClassPath;$JavaSrcDir",
		"--add-opens",
		"java.base/java.lang=ALL-UNNAMED",
		"--add-opens",
		"java.base/java.util=ALL-UNNAMED",
		"BehemothBuilder",
		$OutputPath,
		$LanguageId,
		$CompilerSpecId,
		$ExpectedPointerSize.ToString(),
		$Architecture
	)

	& $JavaExe @JavaArgs
	$ExitCode = $LASTEXITCODE
	Write-Info "$Architecture Java exit code: $ExitCode"

	if ($ExitCode -ne 0) { return $false }
	if (-not (Test-Path $OutputPath)) { return $false }
	if ((Get-Item $OutputPath).Length -le 4096) { return $false }
	return $true
}

$X64OK = Invoke-BehemothGDTBuild `
	-Architecture "x64" `
	-LanguageId "x86:LE:64:default" `
	-CompilerSpecId "windows" `
	-ExpectedPointerSize 8 `
	-OutputPath $GDTPathX64

if (-not $X64OK)
{
	Write-Fail "Behemoth_X64.gdt generation failed."
}

$IA32OK = Invoke-BehemothGDTBuild `
	-Architecture "IA32" `
	-LanguageId "x86:LE:32:default" `
	-CompilerSpecId "windows" `
	-ExpectedPointerSize 4 `
	-OutputPath $GDTPathIA32

if (-not $IA32OK)
{
	Write-Fail "Behemoth_IA32.gdt generation failed."
}

Write-Host ""



# ====================================================================================
# RESULT
# ====================================================================================

$SizeX64KB = [Math]::Round((Get-Item $GDTPathX64).Length / 1KB, 1)
$SizeIA32KB = [Math]::Round((Get-Item $GDTPathIA32).Length / 1KB, 1)

Write-Host "=============================================================" -ForegroundColor Green
Write-Host "              BEHEMOTH GDT ARCHIVES GENERATED" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  X64 archive       : $GDTPathX64" -ForegroundColor Green
Write-Host "  X64 pointer size  : 8 bytes" -ForegroundColor Green
Write-Host "  X64 size          : $SizeX64KB KB" -ForegroundColor Green
Write-Host ""
Write-Host "  IA32 archive      : $GDTPathIA32" -ForegroundColor Green
Write-Host "  IA32 pointer size : 4 bytes" -ForegroundColor Green
Write-Host "  IA32 size         : $SizeIA32KB KB" -ForegroundColor Green
Write-Host ""
Write-Host "  Selected headers   : $($ValidHeaders.Count)" -ForegroundColor Green
Write-Host "  Aggregate entries  : $($AggregateEntries.Count)" -ForegroundColor Green
Write-Host "  Provider promotions: $TotalPromotions" -ForegroundColor Green
Write-Host "  Ordering edges     : $TotalConstraints" -ForegroundColor Green
Write-Host "  Excluded entries   : $($ExcludedEntries.Count)" -ForegroundColor Green
Write-Host ""
Write-Host "  Oracle order:" -ForegroundColor Gray
Write-Host "    $OracleReport" -ForegroundColor Gray
Write-Host ""
Write-Host "  Promotions:" -ForegroundColor Gray
Write-Host "    $PromotionReport" -ForegroundColor Gray
Write-Host ""
