# ====================================================================================
# ScriptBuild02_Scan_Headers.ps1
# Behemoth - Minimal EDK2 Header Scanner & Dependency Resolver
#
# Purpose:
# Build the compact, deterministic EDK2 header set consumed by Behemoth when generating its UEFI-focused Ghidra Data Type Archive. This stage deliberately targets the public UEFI/PI-facing include surface. It is not intended to model every package, private include directory, library implementation, test tree, mock tree, or third-party dependency in EDK2.
#
# Selected packages:
#   - MdePkg
#   - MdeModulePkg
#   - SecurityPkg
#   - UefiCpuPkg
#   - NetworkPkg
#   - ShellPkg
#   - CryptoPkg
#
# Selected include categories:
#   - Uefi
#   - Pi
#   - Ppi
#   - Protocol
#   - Guid
#   - IndustryStandard
#   - Register
#   - UniversalPayload
#   - X64
#
# Dependency model:
#   1. Discover selected EDK2 headers in a stable semantic order.
#   2. Resolve authoritative explicit #include dependencies.
#   3. Parse typedef declarations and named C type definitions.
#   4. Discover semantic type-dependency candidates globally.
#   5. Resolve semantic candidates conservatively.
#   6. Perform a stable topological sort.
#   7. Validate the result and export the scan data used by Script03.
#
# Outputs:
#   GDT\Scan\EDK2_Headers.txt
#   GDT\Scan\EDK2_Dependencies.txt
#
# ====================================================================================



param(
	[string]$EDK2Path
)

$ErrorActionPreference = "Stop"



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
Write-Host "  Minimal EDK2 Header Scanner & Dependency Resolver" -ForegroundColor White
Write-Host "  github.com/TheMalwareGuardian/Behemoth" -ForegroundColor DarkGray
Write-Host ""



# ====================================================================================
# PATHS
# ====================================================================================

if (-not $EDK2Path)
{
	$EDK2Path = Join-Path $PSScriptRoot "GDT\edk2"
}

$EDK2Path = [System.IO.Path]::GetFullPath($EDK2Path).TrimEnd("\", "/")

if (!(Test-Path $EDK2Path))
{
	Write-Host "  [x] EDK2 not found at: $EDK2Path" -ForegroundColor Red
	exit 1
}

$ScanDir       = Join-Path $PSScriptRoot "GDT\Scan"
$OutFile       = Join-Path $ScanDir "EDK2_Headers.txt"
$DependencyLog = Join-Path $ScanDir "EDK2_Dependencies.txt"

New-Item -ItemType Directory -Force -Path $ScanDir | Out-Null

Write-Host "  Scanning: $EDK2Path" -ForegroundColor Cyan
Write-Host ""



# ====================================================================================
# CONFIGURATION
# ====================================================================================

$Packages = @(
	"MdePkg",
	"MdeModulePkg",
	"SecurityPkg",
	"UefiCpuPkg",
	"NetworkPkg",
	"ShellPkg",
	"CryptoPkg",
	"StandaloneMmPkg",
	"TcgTpmPkg",
	"FmpDevicePkg",
	"IntelFsp2Pkg",
	"IntelFsp2WrapperPkg",
	"PcAtChipsetPkg",
	"UefiPayloadPkg",
	"PrmPkg"
)

$Categories = @(
	"Uefi",
	"Pi",
	"Ppi",
	"Protocol",
	"Guid",
	"IndustryStandard",
	"Register",
	"UniversalPayload",
	"X64",
	"Ia32"
)



# ====================================================================================
# GENERIC HELPERS
# ====================================================================================

function Get-RelativeEDK2Path
{
	param(
		[Parameter(Mandatory)]
		[string]$FullPath
	)

	$Rel = $FullPath.Substring($EDK2Path.Length).TrimStart("\", "/")

	return $Rel.Replace("\", "/")
}

function Get-IncludeKey
{
	param(
		[Parameter(Mandatory)]
		[string]$HeaderPath
	)

	$Marker = "/Include/"

	$Index = $HeaderPath.IndexOf(
		$Marker,
		[System.StringComparison]::OrdinalIgnoreCase
	)

	if ($Index -lt 0)
	{
		return $null
	}

	return $HeaderPath.Substring($Index + $Marker.Length)
}

function Get-HeaderIncludes
{
	param(
		[Parameter(Mandatory)]
		[string]$FullPath
	)

	$Includes = [System.Collections.Generic.List[string]]::new()

	foreach ($Line in [System.IO.File]::ReadLines($FullPath))
	{
		if ($Line -match '^\s*#\s*include\s*[<"]([^>"]+)[>"]')
		{
			$Includes.Add(
				$Matches[1].Replace("\", "/")
			)
		}
	}

	return $Includes
}

function Remove-CComments
{
	param(
		[Parameter(Mandatory)]
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

function Remove-PreprocessorLines
{
	param(
		[Parameter(Mandatory)]
		[string]$Text
	)

	$Lines = $Text -split "`r?`n"

	$Output = [System.Collections.Generic.List[string]]::new()

	$InsideDirective = $false

	foreach ($Line in $Lines)
	{
		if ($InsideDirective)
		{
			if ($Line.TrimEnd().EndsWith("\"))
			{
				continue
			}

			$InsideDirective = $false
			continue
		}

		if ($Line -match '^\s*#')
		{
			if ($Line.TrimEnd().EndsWith("\"))
			{
				$InsideDirective = $true
			}

			continue
		}

		$Output.Add($Line)
	}

	return ($Output -join "`n")
}



# ====================================================================================
# C DECLARATION HELPERS
# ====================================================================================

function Get-TypedefStatements
{
	param(
		[Parameter(Mandatory)]
		[string]$Text
	)

	$Statements = [System.Collections.Generic.List[string]]::new()

	$Matches = [regex]::Matches(
		$Text,
		'\btypedef\b'
	)

	foreach ($Match in $Matches)
	{
		$Start = $Match.Index

		$BraceDepth   = 0
		$ParenDepth   = 0
		$BracketDepth = 0

		$InString     = $false
		$InChar       = $false
		$Escape       = $false

		$End = -1

		for ($i = $Start; $i -lt $Text.Length; $i++)
		{
			$Ch = $Text[$i]

			if ($InString)
			{
				if ($Escape)
				{
					$Escape = $false
					continue
				}

				if ($Ch -eq '\')
				{
					$Escape = $true
					continue
				}

				if ($Ch -eq '"')
				{
					$InString = $false
				}

				continue
			}

			if ($InChar)
			{
				if ($Escape)
				{
					$Escape = $false
					continue
				}

				if ($Ch -eq '\')
				{
					$Escape = $true
					continue
				}

				if ($Ch -eq "'")
				{
					$InChar = $false
				}

				continue
			}

			switch ($Ch)
			{
				'"'
				{
					$InString = $true
					continue
				}

				"'"
				{
					$InChar = $true
					continue
				}

				'{'
				{
					$BraceDepth++
					continue
				}

				'}'
				{
					if ($BraceDepth -gt 0)
					{
						$BraceDepth--
					}

					continue
				}

				'('
				{
					$ParenDepth++
					continue
				}

				')'
				{
					if ($ParenDepth -gt 0)
					{
						$ParenDepth--
					}

					continue
				}

				'['
				{
					$BracketDepth++
					continue
				}

				']'
				{
					if ($BracketDepth -gt 0)
					{
						$BracketDepth--
					}

					continue
				}

				';'
				{
					if (
						$BraceDepth   -eq 0 -and
						$ParenDepth   -eq 0 -and
						$BracketDepth -eq 0
					)
					{
						$End = $i
					}
				}
			}

			if ($End -ge 0)
			{
				break
			}
		}

		if ($End -ge $Start)
		{
			$Statement = $Text.Substring(
				$Start,
				($End - $Start + 1)
			)

			$Statements.Add($Statement)
		}
	}

	return $Statements
}

function Get-TypedefDeclaredNames
{
	param(
		[Parameter(Mandatory)]
		[string]$Statement
	)

	$Names = [System.Collections.Generic.HashSet[string]]::new(
		[System.StringComparer]::Ordinal
	)

	$Normalized = $Statement.Trim()

	$FunctionPointerPattern =
		'\(\s*(?:(?:EFIAPI|__cdecl|__stdcall|__fastcall|__thiscall)\s*)*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)'

	$FunctionPointerMatches = [regex]::Matches(
		$Normalized,
		$FunctionPointerPattern
	)

	if ($FunctionPointerMatches.Count -gt 0)
	{
		foreach ($Match in $FunctionPointerMatches)
		{
			[void]$Names.Add(
				$Match.Groups[1].Value
			)
		}

		return $Names
	}

	$LastBrace = $Normalized.LastIndexOf("}")

	if ($LastBrace -ge 0)
	{
		$Tail = $Normalized.Substring($LastBrace + 1)

		$Tail = $Tail.Trim()
		$Tail = $Tail.TrimEnd(";").Trim()

		foreach ($Part in ($Tail -split ","))
		{
			$Candidate = $Part.Trim()

			if (
				$Candidate -match
				'(?:\*+\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*$'
			)
			{
				[void]$Names.Add(
					$Matches[1]
				)
			}
		}

		if ($Names.Count -gt 0)
		{
			return $Names
		}
	}

	$WithoutSemicolon = $Normalized.TrimEnd(";").Trim()

	if (
		$WithoutSemicolon -match
		'([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*$'
	)
	{
		$Candidate = $Matches[1]

		$Reserved = @(
			"typedef",
			"struct",
			"union",
			"enum",
			"const",
			"volatile",
			"signed",
			"unsigned",
			"short",
			"long",
			"void",
			"char",
			"int",
			"float",
			"double"
		)

		if ($Reserved -notcontains $Candidate)
		{
			[void]$Names.Add($Candidate)
		}
	}

	return $Names
}

function Get-NamedTagDefinitions
{
	param(
		[Parameter(Mandatory)]
		[string]$Text
	)

	$Names = [System.Collections.Generic.HashSet[string]]::new(
		[System.StringComparer]::Ordinal
	)

	$Pattern =
		'\b(?:struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{'

	foreach ($Match in [regex]::Matches($Text, $Pattern))
	{
		[void]$Names.Add(
			$Match.Groups[1].Value
		)
	}

	return $Names
}

function Get-DefinedTypes
{
	param(
		[Parameter(Mandatory)]
		[string]$FullPath
	)

	$Types = [System.Collections.Generic.HashSet[string]]::new(
		[System.StringComparer]::Ordinal
	)

	$Text = [System.IO.File]::ReadAllText($FullPath)

	$Text = Remove-CComments $Text
	$Text = Remove-PreprocessorLines $Text

	$TypedefStatements = Get-TypedefStatements $Text

	foreach ($Statement in $TypedefStatements)
	{
		$DeclaredNames = Get-TypedefDeclaredNames $Statement

		foreach ($Name in $DeclaredNames)
		{
			[void]$Types.Add($Name)
		}
	}

	$TagDefinitions = Get-NamedTagDefinitions $Text

	foreach ($Name in $TagDefinitions)
	{
		[void]$Types.Add($Name)
	}

	return $Types
}

function Get-IdentifierTokens
{
	param(
		[Parameter(Mandatory)]
		[string]$FullPath
	)

	$Tokens = [System.Collections.Generic.HashSet[string]]::new(
		[System.StringComparer]::Ordinal
	)

	$Text = [System.IO.File]::ReadAllText($FullPath)

	$Text = Remove-CComments $Text
	$Text = Remove-PreprocessorLines $Text

	foreach ($Match in [regex]::Matches(
		$Text,
		'\b[A-Za-z_][A-Za-z0-9_]*\b'
	))
	{
		[void]$Tokens.Add($Match.Value)
	}

	return $Tokens
}



# ====================================================================================
# GRAPH HELPERS
# ====================================================================================

function Test-GraphPath
{
	param(
		[Parameter(Mandatory)]
		[string]$Start,

		[Parameter(Mandatory)]
		[string]$Target,

		[Parameter(Mandatory)]
		[hashtable]$Dependents
	)

	if ($Start -eq $Target)
	{
		return $true
	}

	$Visited = [System.Collections.Generic.HashSet[string]]::new(
		[System.StringComparer]::OrdinalIgnoreCase
	)

	$Queue = [System.Collections.Generic.Queue[string]]::new()

	$Queue.Enqueue($Start)
	[void]$Visited.Add($Start)

	while ($Queue.Count -gt 0)
	{
		$Current = $Queue.Dequeue()

		foreach ($Next in $Dependents[$Current])
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

function Add-GraphEdge
{
	param(
		[Parameter(Mandatory)]
		[string]$Before,

		[Parameter(Mandatory)]
		[string]$After,

		[Parameter(Mandatory)]
		[hashtable]$DependencyGraph,

		[Parameter(Mandatory)]
		[hashtable]$Dependents
	)

	if ($Before -eq $After)
	{
		return $false
	}

	if ($DependencyGraph[$After].Add($Before))
	{
		[void]$Dependents[$Before].Add($After)

		return $true
	}

	return $false
}



# ====================================================================================
# PHASE 1 - DISCOVER HEADERS
# ====================================================================================

Write-Host "[1/7] Discovering selected EDK2 headers..." -ForegroundColor White

$FoundPackages  = [System.Collections.Generic.List[string]]::new()
$Headers        = [System.Collections.Generic.List[object]]::new()
$DiscoveryOrder = 0

foreach ($Pkg in $Packages)
{
	$IncDir = Join-Path $EDK2Path "$Pkg\Include"

	if (!(Test-Path $IncDir))
	{
		continue
	}

	$PkgCount = 0

	$CoreHeaders = @(
		Get-ChildItem `
			-Path $IncDir `
			-Filter "*.h" `
			-File `
			-ErrorAction SilentlyContinue |
		Sort-Object Name
	)

	foreach ($H in $CoreHeaders)
	{
		$Rel = Get-RelativeEDK2Path $H.FullName

		$Headers.Add(
			[PSCustomObject]@{
				Package        = $Pkg
				Category       = "Core"
				Relative       = $Rel
				FullPath       = $H.FullName
				IncludeKey     = Get-IncludeKey $Rel
				DiscoveryOrder = $DiscoveryOrder
			}
		)

		$DiscoveryOrder++
		$PkgCount++
	}

	foreach ($Cat in $Categories)
	{
		$CatDir = Join-Path $IncDir $Cat

		if (!(Test-Path $CatDir))
		{
			continue
		}

		$CatHeaders = @(
			Get-ChildItem `
				-Path $CatDir `
				-Filter "*.h" `
				-Recurse `
				-File `
				-ErrorAction SilentlyContinue |
			Sort-Object FullName
		)

		foreach ($H in $CatHeaders)
		{
			$Rel = Get-RelativeEDK2Path $H.FullName

			$Headers.Add(
				[PSCustomObject]@{
					Package        = $Pkg
					Category       = $Cat
					Relative       = $Rel
					FullPath       = $H.FullName
					IncludeKey     = Get-IncludeKey $Rel
					DiscoveryOrder = $DiscoveryOrder
				}
			)

			$DiscoveryOrder++
			$PkgCount++
		}
	}

	if ($PkgCount -gt 0)
	{
		$FoundPackages.Add($Pkg)

		Write-Host "  [+] $Pkg : $PkgCount headers" -ForegroundColor Green
	}
}

if ($Headers.Count -eq 0)
{
	Write-Host "  [x] No selected headers found." -ForegroundColor Red
	exit 1
}

Write-Host ""
Write-Host "  [+] Total selected: $($Headers.Count) headers" -ForegroundColor Green
Write-Host ""



# ====================================================================================
# PHASE 2 - BUILD HEADER INDEX
# ====================================================================================

Write-Host "[2/7] Building header index..." -ForegroundColor White

$HeaderByRelative = @{}
$HeaderByKey      = @{}
$HeaderMetadata   = @{}

foreach ($Header in $Headers)
{
	$HeaderByRelative[$Header.Relative] = $Header
	$HeaderMetadata[$Header.Relative]   = $Header

	if ($Header.IncludeKey)
	{
		if (!$HeaderByKey.ContainsKey($Header.IncludeKey))
		{
			$HeaderByKey[$Header.IncludeKey] =
				[System.Collections.Generic.List[object]]::new()
		}

		$HeaderByKey[$Header.IncludeKey].Add($Header)
	}
}

Write-Host "  [+] $($HeaderByRelative.Count) selected headers indexed" -ForegroundColor Green
Write-Host "  [-] $($HeaderByKey.Count) unique include paths" -ForegroundColor DarkGray
Write-Host ""


# ====================================================================================
# INITIALIZE GRAPH
# ====================================================================================

$DependencyGraph = @{}

$Dependents = @{}

foreach ($Header in $Headers)
{
	$DependencyGraph[$Header.Relative] =
		[System.Collections.Generic.HashSet[string]]::new(
			[System.StringComparer]::OrdinalIgnoreCase
		)

	$Dependents[$Header.Relative] =
		[System.Collections.Generic.HashSet[string]]::new(
			[System.StringComparer]::OrdinalIgnoreCase
		)
}

$ExplicitEvidence = [System.Collections.Generic.List[object]]::new()
$AcceptedSemantic = [System.Collections.Generic.List[object]]::new()
$RejectedSemantic = [System.Collections.Generic.List[object]]::new()



# ====================================================================================
# PHASE 3 - EXPLICIT INCLUDE DEPENDENCIES
# ====================================================================================

Write-Host "[3/7] Resolving explicit #include dependencies..." -ForegroundColor White

$ExplicitDependencies = 0
$AmbiguousIncludes    = 0
$ExternalIncludes     = 0

foreach ($Header in $Headers)
{
	foreach ($Include in (Get-HeaderIncludes $Header.FullPath))
	{
		if (!$HeaderByKey.ContainsKey($Include))
		{
			$ExternalIncludes++
			continue
		}

		$Candidates = @($HeaderByKey[$Include])

		if ($Candidates.Count -ne 1)
		{
			$AmbiguousIncludes++
			continue
		}

		$Provider = $Candidates[0].Relative
		$Consumer = $Header.Relative

		if ($Provider -eq $Consumer)
		{
			continue
		}

		if (Add-GraphEdge `
			-Before $Provider `
			-After $Consumer `
			-DependencyGraph $DependencyGraph `
			-Dependents $Dependents)
		{
			$ExplicitDependencies++

			$ExplicitEvidence.Add(
				[PSCustomObject]@{
					Type   = "EXPLICIT"
					Symbol = $Include
					Before = $Provider
					After  = $Consumer
				}
			)
		}
	}
}

Write-Host "  [+] Explicit dependencies: $ExplicitDependencies" -ForegroundColor Green

if ($AmbiguousIncludes -gt 0)
{
	Write-Host "  [-] Ambiguous includes ignored: $AmbiguousIncludes" -ForegroundColor DarkGray
}

if ($ExternalIncludes -gt 0)
{
	Write-Host "  [-] Includes outside selected set: $ExternalIncludes" -ForegroundColor DarkGray
}

Write-Host ""



# ====================================================================================
# PHASE 4 - ANALYZE TYPE DEFINITIONS AND USES
# ====================================================================================

Write-Host "[4/7] Analyzing type definitions and uses..." -ForegroundColor White

$TypeDefinitions    = @{}
$HeaderDefinedTypes = @{}
$HeaderTokens       = @{}

# ------------------------------------------------------------------------
# PASS 1:
# Parse all definitions first
# ------------------------------------------------------------------------

foreach ($Header in $Headers)
{
	$DefinedTypes = Get-DefinedTypes $Header.FullPath

	$HeaderDefinedTypes[$Header.Relative] = $DefinedTypes

	foreach ($TypeName in $DefinedTypes)
	{
		if (!$TypeDefinitions.ContainsKey($TypeName))
		{
			$TypeDefinitions[$TypeName] =
				[System.Collections.Generic.List[string]]::new()
		}

		if (!$TypeDefinitions[$TypeName].Contains($Header.Relative))
		{
			$TypeDefinitions[$TypeName].Add($Header.Relative)
		}
	}
}

$UniqueTypes    = @{}
$AmbiguousTypes = 0

foreach ($TypeName in $TypeDefinitions.Keys)
{
	$Providers = @($TypeDefinitions[$TypeName])

	if ($Providers.Count -eq 1)
	{
		$UniqueTypes[$TypeName] = $Providers[0]
	}
	else
	{
		$AmbiguousTypes++
	}
}

# ------------------------------------------------------------------------
# PASS 2:
# Extract identifier tokens from every header independently
# ------------------------------------------------------------------------

foreach ($Header in $Headers)
{
	$HeaderTokens[$Header.Relative] =
		Get-IdentifierTokens $Header.FullPath
}

Write-Host "  [+] Type definitions: $($TypeDefinitions.Count)" -ForegroundColor Green
Write-Host "  [+] Unique type definitions: $($UniqueTypes.Count)" -ForegroundColor Green

if ($AmbiguousTypes -gt 0)
{
	Write-Host "  [-] Ambiguous type definitions ignored: $AmbiguousTypes" -ForegroundColor DarkGray
}


# ====================================================================================
# BUILD ALL SEMANTIC CANDIDATES
# ====================================================================================

$SemanticCandidateMap = @{}

foreach ($Header in $Headers)
{
	$Consumer = $Header.Relative
	$Tokens   = $HeaderTokens[$Consumer]

	foreach ($Token in $Tokens)
	{
		if (!$UniqueTypes.ContainsKey($Token))
		{
			continue
		}

		$Provider = $UniqueTypes[$Token]

		if ($Provider -eq $Consumer)
		{
			continue
		}

		if ($DependencyGraph[$Consumer].Contains($Provider))
		{
			continue
		}

		$Key = "$Provider`0$Consumer"

		if (!$SemanticCandidateMap.ContainsKey($Key))
		{
			$SemanticCandidateMap[$Key] =
				[PSCustomObject]@{
					Before  = $Provider
					After   = $Consumer
					Symbols = [System.Collections.Generic.HashSet[string]]::new(
						[System.StringComparer]::Ordinal
					)
				}
		}

		[void]$SemanticCandidateMap[$Key].Symbols.Add($Token)
	}
}

$SemanticCandidates = @($SemanticCandidateMap.Values)

Write-Host "  [+] Semantic candidates: $($SemanticCandidates.Count)" -ForegroundColor Green
Write-Host ""



# ====================================================================================
# PHASE 5 - RESOLVE SEMANTIC DEPENDENCIES
# ====================================================================================

Write-Host "[5/7] Resolving semantic dependencies..." -ForegroundColor White

$SortedSemanticCandidates = @(
	$SemanticCandidates |
	Sort-Object `
		@{ Expression = { $HeaderMetadata[$_.Before].DiscoveryOrder } },
		@{ Expression = { $HeaderMetadata[$_.After].DiscoveryOrder } }
)

$SemanticDependencies = 0
$SemanticRejected     = 0
$SemanticRedundant    = 0

foreach ($Candidate in $SortedSemanticCandidates)
{
	$Provider = $Candidate.Before
	$Consumer = $Candidate.After

	$Symbols = @(
		$Candidate.Symbols |
		Sort-Object
	)

	$SymbolText = $Symbols -join ", "

	if (Test-GraphPath `
		-Start $Provider `
		-Target $Consumer `
		-Dependents $Dependents)
	{
		$SemanticRedundant++

		$RejectedSemantic.Add(
			[PSCustomObject]@{
				Before  = $Provider
				After   = $Consumer
				Symbols = $SymbolText
				Reason  = "already-satisfied-transitively"
			}
		)

		continue
	}

	if (Test-GraphPath `
		-Start $Consumer `
		-Target $Provider `
		-Dependents $Dependents)
	{
		$SemanticRejected++

		$RejectedSemantic.Add(
			[PSCustomObject]@{
				Before  = $Provider
				After   = $Consumer
				Symbols = $SymbolText
				Reason  = "would-create-cycle"
			}
		)

		continue
	}

	if (Add-GraphEdge `
		-Before $Provider `
		-After $Consumer `
		-DependencyGraph $DependencyGraph `
		-Dependents $Dependents)
	{
		$SemanticDependencies++

		$AcceptedSemantic.Add(
			[PSCustomObject]@{
				Before  = $Provider
				After   = $Consumer
				Symbols = $SymbolText
			}
		)
	}
}

Write-Host "  [+] Accepted semantic dependencies: $SemanticDependencies" -ForegroundColor Green
Write-Host "  [-] Redundant semantic dependencies: $SemanticRedundant" -ForegroundColor DarkGray
Write-Host "  [-] Rejected semantic dependencies: $SemanticRejected" -ForegroundColor DarkGray
Write-Host ""



# ====================================================================================
# PHASE 6 - STABLE TOPOLOGICAL SORT
# ====================================================================================

Write-Host "[6/7] Stable topological sort..." -ForegroundColor White

$InDegree = @{}

foreach ($Header in $Headers)
{
	$InDegree[$Header.Relative] =
		$DependencyGraph[$Header.Relative].Count
}

$Ready = [System.Collections.Generic.List[string]]::new()

foreach ($Header in $Headers)
{
	if ($InDegree[$Header.Relative] -eq 0)
	{
		$Ready.Add($Header.Relative)
	}
}

$OrderedHeaders = [System.Collections.Generic.List[string]]::new()

while ($Ready.Count -gt 0)
{
	$Next = $Ready |
		Sort-Object {
			$HeaderMetadata[$_].DiscoveryOrder
		} |
		Select-Object -First 1

	[void]$Ready.Remove($Next)

	$OrderedHeaders.Add($Next)

	foreach ($Dependent in $Dependents[$Next])
	{
		$InDegree[$Dependent]--

		if ($InDegree[$Dependent] -eq 0)
		{
			$Ready.Add($Dependent)
		}
	}
}

$BlockedHeaders = @(
	$Headers |
	Where-Object {
		$InDegree[$_.Relative] -gt 0
	} |
	Sort-Object DiscoveryOrder
)

if ($BlockedHeaders.Count -eq 0)
{
	Write-Host "  [+] Dependency graph sorted completely" -ForegroundColor Green
}
else
{
	Write-Host "  [!] Blocked headers: $($BlockedHeaders.Count)" -ForegroundColor Yellow
	Write-Host "      They may be cycle members or downstream of a cycle." -ForegroundColor DarkGray

	foreach ($Header in $BlockedHeaders)
	{
		if (!$OrderedHeaders.Contains($Header.Relative))
		{
			$OrderedHeaders.Add($Header.Relative)
		}
	}
}

Write-Host "  [+] Ordered headers: $($OrderedHeaders.Count)" -ForegroundColor Green
Write-Host ""



# ====================================================================================
# PHASE 7 - VALIDATE
# ====================================================================================

Write-Host "[7/7] Validating generated order..." -ForegroundColor White

if ($OrderedHeaders.Count -ne $Headers.Count)
{
	Write-Host "  [x] Internal header count mismatch." -ForegroundColor Red
	Write-Host "      Discovered: $($Headers.Count)" -ForegroundColor Red
	Write-Host "      Ordered   : $($OrderedHeaders.Count)" -ForegroundColor Red
	exit 1
}

$FinalPosition = @{}

for ($i = 0; $i -lt $OrderedHeaders.Count; $i++)
{
	$FinalPosition[$OrderedHeaders[$i]] = $i
}

$OrderingErrors = [System.Collections.Generic.List[object]]::new()

foreach ($Evidence in $ExplicitEvidence)
{
	if (
		$FinalPosition[$Evidence.Before] -ge
		$FinalPosition[$Evidence.After]
	)
	{
		$OrderingErrors.Add(
			[PSCustomObject]@{
				Type    = "EXPLICIT"
				Before  = $Evidence.Before
				After   = $Evidence.After
				Symbols = $Evidence.Symbol
			}
		)
	}
}

foreach ($Evidence in $AcceptedSemantic)
{
	if (
		$FinalPosition[$Evidence.Before] -ge
		$FinalPosition[$Evidence.After]
	)
	{
		$OrderingErrors.Add(
			[PSCustomObject]@{
				Type    = "SEMANTIC"
				Before  = $Evidence.Before
				After   = $Evidence.After
				Symbols = $Evidence.Symbols
			}
		)
	}
}

if ($OrderingErrors.Count -eq 0)
{
	Write-Host "  [+] Dependency order validated" -ForegroundColor Green
}
else
{
	Write-Host "  [!] Ordering errors: $($OrderingErrors.Count)" -ForegroundColor Yellow
}

Write-Host ""



# ====================================================================================
# WRITE EDK2_HEADERS.TXT
# ====================================================================================

$Final = [System.Collections.Generic.List[string]]::new()

$Final.Add('$EDK2Packages = @(')

for ($i = 0; $i -lt $FoundPackages.Count; $i++)
{
	if ($i -lt ($FoundPackages.Count - 1))
	{
		$Comma = ","
	}
	else
	{
		$Comma = ""
	}

	$Line = "`t`"$($FoundPackages[$i])`"$Comma"

	$Final.Add($Line)
}

$Final.Add(")")
$Final.Add("")

$Final.Add('$AllHeaders = @(')
$Final.Add("")
$Final.Add("`t# Dependency-ordered EDK2 headers")
$Final.Add("`t#")
$Final.Add("`t# Ordering:")
$Final.Add("`t#   1. Stable semantic discovery order")
$Final.Add("`t#   2. Explicit #include dependencies")
$Final.Add("`t#   3. Automatically inferred type dependencies")
$Final.Add("")

for ($i = 0; $i -lt $OrderedHeaders.Count; $i++)
{
	if ($i -lt ($OrderedHeaders.Count - 1))
	{
		$Comma = ","
	}
	else
	{
		$Comma = ""
	}

	$Line = "`t`"$($OrderedHeaders[$i])`"$Comma"

	$Final.Add($Line)
}

$Final.Add(")")

[System.IO.File]::WriteAllLines(
	$OutFile,
	$Final.ToArray(),
	[System.Text.UTF8Encoding]::new($false)
)



# ====================================================================================
# DEPENDENCY REPORT
# ====================================================================================

$Report = [System.Collections.Generic.List[string]]::new()

$Report.Add("Behemoth - EDK2 Header Dependency Report")
$Report.Add("========================================")
$Report.Add("")

$Report.Add("EDK2 root                     : $EDK2Path")
$Report.Add("Headers selected              : $($Headers.Count)")
$Report.Add("Packages selected             : $($FoundPackages.Count)")
$Report.Add("Explicit dependencies         : $ExplicitDependencies")
$Report.Add("Type definitions              : $($TypeDefinitions.Count)")
$Report.Add("Unique type definitions       : $($UniqueTypes.Count)")
$Report.Add("Ambiguous type definitions    : $AmbiguousTypes")
$Report.Add("Semantic candidates           : $($SemanticCandidates.Count)")
$Report.Add("Accepted semantic dependencies: $SemanticDependencies")
$Report.Add("Redundant semantic candidates : $SemanticRedundant")
$Report.Add("Rejected semantic candidates  : $SemanticRejected")
$Report.Add("Ambiguous includes            : $AmbiguousIncludes")
$Report.Add("External includes             : $ExternalIncludes")
$Report.Add("Blocked headers               : $($BlockedHeaders.Count)")
$Report.Add("Ordering errors               : $($OrderingErrors.Count)")
$Report.Add("")



# ====================================================================================
# TYPE PROVIDER DIAGNOSTICS
# ====================================================================================

$Report.Add("Type Provider Diagnostics")
$Report.Add("-------------------------")
$Report.Add("")

foreach ($TypeName in $DiagnosticTypes)
{
	if ($TypeDefinitions.ContainsKey($TypeName))
	{
		$Providers = @($TypeDefinitions[$TypeName])

		$ProviderText = $Providers -join ", "

		$Line = "{0} -> {1}" -f $TypeName, $ProviderText

		$Report.Add($Line)
	}
	else
	{
		$Line = "{0} -> NOT DETECTED" -f $TypeName

		$Report.Add($Line)
	}
}



# ====================================================================================
# FINAL HEADER ORDER
# ====================================================================================

$Report.Add("")
$Report.Add("Final Header Order")
$Report.Add("------------------")
$Report.Add("")

for ($i = 0; $i -lt $OrderedHeaders.Count; $i++)
{
	$Line = "{0,4}  {1}" -f ($i + 1), $OrderedHeaders[$i]

	$Report.Add($Line)
}



# ====================================================================================
# EXPLICIT DEPENDENCIES
# ====================================================================================

$Report.Add("")
$Report.Add("Explicit Dependencies")
$Report.Add("---------------------")
$Report.Add("")

foreach ($Evidence in @(
	$ExplicitEvidence |
	Sort-Object Before, After, Symbol
))
{
	$Line = "{0} -> {1}    [include: {2}]" -f `
		$Evidence.Before,
		$Evidence.After,
		$Evidence.Symbol

	$Report.Add($Line)
}



# ====================================================================================
# ACCEPTED SEMANTIC DEPENDENCIES
# ====================================================================================

$Report.Add("")
$Report.Add("Accepted Semantic Dependencies")
$Report.Add("------------------------------")
$Report.Add("")

foreach ($Evidence in @(
	$AcceptedSemantic |
	Sort-Object Before, After
))
{
	$Line = "{0} -> {1}    [types: {2}]" -f `
		$Evidence.Before,
		$Evidence.After,
		$Evidence.Symbols

	$Report.Add($Line)
}



# ====================================================================================
# REJECTED SEMANTIC CANDIDATES
# ====================================================================================

$Report.Add("")
$Report.Add("Rejected Semantic Candidates")
$Report.Add("----------------------------")
$Report.Add("")

foreach ($Evidence in @(
	$RejectedSemantic |
	Sort-Object Reason, Before, After
))
{
	$Line = "{0} -> {1}    [types: {2}] [reason: {3}]" -f `
		$Evidence.Before,
		$Evidence.After,
		$Evidence.Symbols,
		$Evidence.Reason

	$Report.Add($Line)
}



# ====================================================================================
# BLOCKED HEADERS
# ====================================================================================

if ($BlockedHeaders.Count -gt 0)
{
	$Report.Add("")
	$Report.Add("Blocked Headers")
	$Report.Add("---------------")
	$Report.Add("")

	foreach ($Header in $BlockedHeaders)
	{
		$Report.Add($Header.Relative)
	}
}



# ====================================================================================
# ORDERING ERRORS
# ====================================================================================

if ($OrderingErrors.Count -gt 0)
{
	$Report.Add("")
	$Report.Add("Ordering Errors")
	$Report.Add("---------------")
	$Report.Add("")

	foreach ($Entry in $OrderingErrors)
	{
		$Line = "{0}: {1} -> {2}    [{3}]" -f `
			$Entry.Type,
			$Entry.Before,
			$Entry.After,
			$Entry.Symbols

		$Report.Add($Line)
	}
}



# ====================================================================================
# KEY HEADER POSITIONS
# ====================================================================================

$Report.Add("")
$Report.Add("Key Header Positions")
$Report.Add("--------------------")
$Report.Add("")

foreach ($Rel in $DiagnosticHeaders)
{
	if ($FinalPosition.ContainsKey($Rel))
	{
		$Position = $FinalPosition[$Rel] + 1

		$Line = "{0,4}  {1}" -f $Position, $Rel

		$Report.Add($Line)
	}
}

[System.IO.File]::WriteAllLines(
	$DependencyLog,
	$Report.ToArray(),
	[System.Text.UTF8Encoding]::new($false)
)



# ====================================================================================
# SUMMARY
# ====================================================================================

Write-Host "=============================================================" -ForegroundColor DarkGray
Write-Host "                    SCAN COMPLETE" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor DarkGray
Write-Host ""

Write-Host "  Headers             : $($Headers.Count)" -ForegroundColor Cyan
Write-Host "  Packages            : $($FoundPackages.Count)" -ForegroundColor Cyan
Write-Host "  Explicit deps       : $ExplicitDependencies" -ForegroundColor Cyan
Write-Host "  Type definitions    : $($TypeDefinitions.Count)" -ForegroundColor Cyan
Write-Host "  Unique types        : $($UniqueTypes.Count)" -ForegroundColor Cyan
Write-Host "  Semantic candidates : $($SemanticCandidates.Count)" -ForegroundColor Cyan
Write-Host "  Semantic accepted   : $SemanticDependencies" -ForegroundColor Cyan
Write-Host "  Semantic redundant  : $SemanticRedundant" -ForegroundColor Cyan
Write-Host "  Semantic rejected   : $SemanticRejected" -ForegroundColor Cyan
Write-Host "  Blocked             : $($BlockedHeaders.Count)" -ForegroundColor Cyan
Write-Host "  Order errors        : $($OrderingErrors.Count)" -ForegroundColor Cyan
Write-Host ""

Write-Host "  [+] Header list:" -ForegroundColor Green
Write-Host "      $OutFile" -ForegroundColor DarkGray
Write-Host ""

Write-Host "  [+] Dependency report:" -ForegroundColor Green
Write-Host "      $DependencyLog" -ForegroundColor DarkGray
Write-Host ""

if (
	$BlockedHeaders.Count -eq 0 -and
	$OrderingErrors.Count -eq 0
)
{
	Write-Host "  [+] Dependency ordering completed successfully" -ForegroundColor Green
}
else
{
	Write-Host "  [!] Review dependency report before building the GDT" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Next: validate diagnostic type providers and dependency order." -ForegroundColor Gray
Write-Host ""
