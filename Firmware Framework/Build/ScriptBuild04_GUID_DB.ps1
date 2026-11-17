# ====================================================================================
# ScriptBuild04_GUID_DB.ps1
# Behemoth - EDK2 GUID Database Generator
#
# Inputs:
#   GDT\Scan\EDK2_Headers.txt
#
# Sources:
#   GUID macros/initializers found in selected headers
#   DEC [Guids], [Protocols], and [Ppis] sections from packages represented by the selected headers
#
# Output:
#   GDT\GUIDs\Behemoth_GUIDs.ini
#
# ====================================================================================



Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step
{
	param([string]$Text)
	Write-Host $Text -ForegroundColor Cyan
}

function Write-OK
{
	param([string]$Text)
	Write-Host "  [+] $Text" -ForegroundColor Green
}

function Write-Info
{
	param([string]$Text)
	Write-Host "  [-] $Text" -ForegroundColor Gray
}

function Write-Fail
{
	param([string]$Text)
	Write-Host "  [X] $Text" -ForegroundColor Red
	exit 1
}

function Normalize-Path
{
	param([string]$Path)

	if ([string]::IsNullOrWhiteSpace($Path))
	{
		return $null
	}

	return [System.IO.Path]::GetFullPath(
		$Path.Trim().Trim('"')
	)
}

function Find-EDK2Root
{
	$GDTDir  = Join-Path $PSScriptRoot "GDT"
	$EDK2Dir = Join-Path $GDTDir "edk2"

	if (-not (Test-Path -LiteralPath $EDK2Dir -PathType Container))
	{
		Write-Fail "EDK2 directory not found: $EDK2Dir"
	}

	return (Resolve-Path -LiteralPath $EDK2Dir).Path
}

function Find-ScanFile
{
	$GDTDir      = Join-Path $PSScriptRoot "GDT"
	$ScanDir     = Join-Path $GDTDir "Scan"
	$HeadersFile = Join-Path $ScanDir "EDK2_Headers.txt"

	if (-not (Test-Path -LiteralPath $HeadersFile -PathType Leaf))
	{
		Write-Fail "Script02 header selection not found: $HeadersFile"
	}

	return (Resolve-Path -LiteralPath $HeadersFile).Path
}

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

	if (
		$Value -match
		'(?i)([A-Za-z0-9_.+-]+/(?:[^\s<>:"|?*]+/)*[^/\s<>:"|?*]+\.h)'
	)
	{
		return $matches[1]
	}

	return $null
}

function Get-HeaderPaths
{
	param(
		[string]$ListPath,
		[string]$Root
	)

	$Result = New-Object System.Collections.Generic.List[string]

	$Seen = New-Object `
		'System.Collections.Generic.HashSet[string]' `
		([System.StringComparer]::OrdinalIgnoreCase)

	foreach ($Raw in [System.IO.File]::ReadAllLines($ListPath))
	{
		$Header = Convert-ToCanonicalHeader $Raw

		if ([string]::IsNullOrWhiteSpace($Header))
		{
			continue
		}

		$Candidate = Join-Path `
			$Root `
			($Header.Replace("/", "\"))

		if (
			(Test-Path -LiteralPath $Candidate -PathType Leaf) -and
			$Seen.Add($Candidate)
		)
		{
			$Result.Add(
				(Normalize-Path $Candidate)
			)
		}
	}

	return @($Result)
}

function Get-PackageRoot
{
	param(
		[string]$Header,
		[string]$Root
	)

	$RootFull   = (Normalize-Path $Root).TrimEnd('\') + '\'
	$HeaderFull = Normalize-Path $Header

	if (
		-not $HeaderFull.StartsWith(
			$RootFull,
			[System.StringComparison]::OrdinalIgnoreCase
		)
	)
	{
		return $null
	}

	$Relative = $HeaderFull.Substring(
		$RootFull.Length
	)

	$First = (
		$Relative -split '[\\/]'
	)[0]

	if ([string]::IsNullOrWhiteSpace($First))
	{
		return $null
	}

	$Package = Join-Path `
		$Root `
		$First

	if (Test-Path -LiteralPath $Package -PathType Container)
	{
		return (Normalize-Path $Package)
	}

	return $null
}

function Convert-CGuidInitializer
{
	param(
		[string]$Initializer
	)

	if ([string]::IsNullOrWhiteSpace($Initializer))
	{
		return $null
	}

	$Value = $Initializer

	$Value = [regex]::Replace(
		$Value,
		'/\*.*?\*/',
		'',
		[System.Text.RegularExpressions.RegexOptions]::Singleline
	)

	$Value = [regex]::Replace(
		$Value,
		'//.*$',
		'',
		[System.Text.RegularExpressions.RegexOptions]::Multiline
	)

	$Numbers = @(
		[regex]::Matches(
			$Value,
			'(?i)(?:0x[0-9a-f]+|\b\d+\b)'
		) |
		ForEach-Object {
			$_.Value
		}
	)

	if ($Numbers.Count -lt 11)
	{
		return $null
	}

	try
	{
		$Base = if ($Numbers[0] -match '(?i)^0x')
		{
			16
		}
		else
		{
			10
		}

		$D1 = [Convert]::ToUInt32(
			($Numbers[0] -replace '(?i)^0x', ''),
			$Base
		)

		$Base = if ($Numbers[1] -match '(?i)^0x')
		{
			16
		}
		else
		{
			10
		}

		$D2 = [Convert]::ToUInt16(
			($Numbers[1] -replace '(?i)^0x', ''),
			$Base
		)

		$Base = if ($Numbers[2] -match '(?i)^0x')
		{
			16
		}
		else
		{
			10
		}

		$D3 = [Convert]::ToUInt16(
			($Numbers[2] -replace '(?i)^0x', ''),
			$Base
		)

		$Bytes = @()

		for ($Index = 3; $Index -lt 11; $Index++)
		{
			$Base = if ($Numbers[$Index] -match '(?i)^0x')
			{
				16
			}
			else
			{
				10
			}

			$Bytes += [Convert]::ToByte(
				($Numbers[$Index] -replace '(?i)^0x', ''),
				$Base
			)
		}

		return (
			'{0:x8}-{1:x4}-{2:x4}-{3:x2}{4:x2}-{5:x2}{6:x2}{7:x2}{8:x2}{9:x2}{10:x2}' -f
				$D1,
				$D2,
				$D3,
				$Bytes[0],
				$Bytes[1],
				$Bytes[2],
				$Bytes[3],
				$Bytes[4],
				$Bytes[5],
				$Bytes[6],
				$Bytes[7]
		)
	}
	catch
	{
		return $null
	}
}

function Add-GuidRecord
{
	param(
		[hashtable]$Records,
		[string]$Name,
		[string]$Guid,
		[string]$Kind,
		[string]$Source
	)

	if (
		[string]::IsNullOrWhiteSpace($Name) -or
		[string]::IsNullOrWhiteSpace($Guid)
	)
	{
		return
	}

	$NameClean = $Name.Trim()
	$GuidClean = $Guid.Trim('{}').ToLowerInvariant()

	try
	{
		[void][Guid]::Parse($GuidClean)
	}
	catch
	{
		return
	}

	$Key = $NameClean.ToUpperInvariant()

	if (-not $Records.ContainsKey($Key))
	{
		$Records[$Key] = [ordered]@{
			Name    = $NameClean
			Guid    = $GuidClean
			Kind    = $Kind
			Sources = New-Object `
				'System.Collections.Generic.HashSet[string]' `
				([System.StringComparer]::OrdinalIgnoreCase)
		}
	}

	[void]$Records[$Key].Sources.Add(
		$Source
	)
}

function Scan-HeaderGuids
{
	param(
		[string]$Header,
		[hashtable]$Records,
		[string]$Root
	)

	$Text = [System.IO.File]::ReadAllText(
		$Header
	)

	$Relative = $Header

	try
	{
		$Relative = [System.IO.Path]::GetRelativePath(
			$Root,
			$Header
		)
	}
	catch
	{
	}

	$DefinePattern = (
		'(?ms)^[ \t]*#\s*define\s+' +
		'([A-Za-z_][A-Za-z0-9_]*(?:GUID|Guid|GuidValue|_ID))\s+' +
		'(\{.*?\}\s*\})'
	)

	foreach ($Match in [regex]::Matches(
		$Text,
		$DefinePattern
	))
	{
		$Guid = Convert-CGuidInitializer `
			$Match.Groups[2].Value

		if ($Guid)
		{
			Add-GuidRecord `
				$Records `
				$Match.Groups[1].Value `
				$Guid `
				"HeaderMacro" `
				$Relative
		}
	}

	$VariablePattern = (
		'(?ms)\b(?:STATIC\s+)?(?:CONST\s+)?EFI_GUID\s+' +
		'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*' +
		'(\{.*?\}\s*\})\s*;'
	)

	foreach ($Match in [regex]::Matches(
		$Text,
		$VariablePattern
	))
	{
		$Guid = Convert-CGuidInitializer `
			$Match.Groups[2].Value

		if ($Guid)
		{
			Add-GuidRecord `
				$Records `
				$Match.Groups[1].Value `
				$Guid `
				"HeaderVariable" `
				$Relative
		}
	}
}

function Get-HeaderTypeCandidates
{
	param(
		[string]$Header
	)

	$Text = [System.IO.File]::ReadAllText($Header)

	$Clean = [regex]::Replace(
		$Text,
		'/\*.*?\*/',
		' ',
		[System.Text.RegularExpressions.RegexOptions]::Singleline
	)

	$Clean = [regex]::Replace(
		$Clean,
		'//.*$',
		' ',
		[System.Text.RegularExpressions.RegexOptions]::Multiline
	)

	$Types = New-Object System.Collections.Generic.List[string]

	$Seen = New-Object `
		'System.Collections.Generic.HashSet[string]' `
		([System.StringComparer]::Ordinal)

	$ForwardPattern = (
		'(?ms)\btypedef\s+(?:struct|union)\s+' +
		'_[A-Za-z_][A-Za-z0-9_]*\s+' +
		'([A-Za-z_][A-Za-z0-9_]*)\s*;'
	)

	foreach ($Match in [regex]::Matches(
		$Clean,
		$ForwardPattern
	))
	{
		$Name = $Match.Groups[1].Value

		if (
			$Name -match '(?i)(?:PROTOCOL|PPI)$' -and
			$Seen.Add($Name)
		)
		{
			$Types.Add($Name)
		}
	}

	$TypedefPattern = (
		'(?ms)\btypedef\s+(?:struct|union)' +
		'(?:\s+_[A-Za-z_][A-Za-z0-9_]*)?\s*' +
		'\{.*?\}\s*' +
		'([A-Za-z_][A-Za-z0-9_]*)\s*;'
	)

	foreach ($Match in [regex]::Matches(
		$Clean,
		$TypedefPattern
	))
	{
		$Name = $Match.Groups[1].Value

		if (
			$Name -match '(?i)(?:PROTOCOL|PPI)$' -and
			$Seen.Add($Name)
		)
		{
			$Types.Add($Name)
		}
	}

	return @($Types)
}

function Convert-IdentifierToTokens
{
	param(
		[string]$Value
	)

	if ([string]::IsNullOrWhiteSpace($Value))
	{
		return @()
	}

	$Name = $Value

	$Name = $Name -replace '^(?i)g', ''
	$Name = $Name -replace '(?i)Guid$', ''
	$Name = $Name -replace '(?i)_GUID$', ''

	$Name = $Name -replace '(?i)Protocol$', ''
	$Name = $Name -replace '(?i)Ppi$', ''

	$Name = $Name -replace '(?i)_PROTOCOL$', ''
	$Name = $Name -replace '(?i)_PPI$', ''

	$Name = [regex]::Replace(
		$Name,
		'([a-z0-9])([A-Z])',
		'$1_$2'
	)

	$Name = [regex]::Replace(
		$Name,
		'([A-Z]+)([A-Z][a-z])',
		'$1_$2'
	)

	return @(
		($Name -split '[^A-Za-z0-9]+') |
		Where-Object {
			-not [string]::IsNullOrWhiteSpace($_) -and
			$_ -notmatch '^(?i)(EFI|EDKII|GUID|PROTOCOL|PPI)$'
		} |
		ForEach-Object {
			$_.ToUpperInvariant()
		}
	)
}

function Get-NameSimilarity
{
	param(
		[string]$GuidName,
		[string]$TypeName
	)

	$GuidTokens = @(
		Convert-IdentifierToTokens $GuidName
	)

	$TypeTokens = @(
		Convert-IdentifierToTokens $TypeName
	)

	if (
		$GuidTokens.Count -eq 0 -or
		$TypeTokens.Count -eq 0
	)
	{
		return 0
	}

	$GuidSet = New-Object `
		'System.Collections.Generic.HashSet[string]' `
		([System.StringComparer]::OrdinalIgnoreCase)

	$TypeSet = New-Object `
		'System.Collections.Generic.HashSet[string]' `
		([System.StringComparer]::OrdinalIgnoreCase)

	foreach ($Token in $GuidTokens)
	{
		[void]$GuidSet.Add($Token)
	}

	foreach ($Token in $TypeTokens)
	{
		[void]$TypeSet.Add($Token)
	}

	$Intersection = 0

	foreach ($Token in $GuidSet)
	{
		if ($TypeSet.Contains($Token))
		{
			$Intersection++
		}
	}

	if ($Intersection -eq 0)
	{
		return 0
	}

	$Union = (
		$GuidSet.Count +
		$TypeSet.Count -
		$Intersection
	)

	if ($Union -le 0)
	{
		return 0
	}

	return (
		[double]$Intersection /
		[double]$Union
	)
}

function Add-TypeCandidate
{
	param(
		[hashtable]$Map,
		[string]$GuidName,
		[string]$TypeName,
		[string]$Source,
		[string]$Method,
		[double]$Score
	)

	if (
		[string]::IsNullOrWhiteSpace($GuidName) -or
		[string]::IsNullOrWhiteSpace($TypeName)
	)
	{
		return
	}

	$Key = $GuidName.ToUpperInvariant()

	if (-not $Map.ContainsKey($Key))
	{
		$Map[$Key] = New-Object `
			System.Collections.Generic.List[object]
	}

	$Map[$Key].Add(
		[pscustomobject]@{
			GuidName = $GuidName
			TypeName = $TypeName
			Source   = $Source
			Method   = $Method
			Score    = $Score
		}
	)
}

function Build-GuidTypeMap
{
	param(
		[string[]]$Headers,
		[hashtable]$Records,
		[string]$Root
	)

	$TypeIndex = @{}

	foreach ($Header in $Headers)
	{
		$Relative = $Header

		try
		{
			$Relative = [System.IO.Path]::GetRelativePath(
				$Root,
				$Header
			)
		}
		catch
		{
		}

		$Types = @(
			Get-HeaderTypeCandidates $Header
		)

		foreach ($Type in $Types)
		{
			$Key = $Type.ToUpperInvariant()

			if (-not $TypeIndex.ContainsKey($Key))
			{
				$TypeIndex[$Key] = [ordered]@{
					Name    = $Type
					Kind    = $null
					Sources = New-Object `
						'System.Collections.Generic.HashSet[string]' `
						([System.StringComparer]::OrdinalIgnoreCase)
				}

				if ($Type -match '(?i)_PROTOCOL$')
				{
					$TypeIndex[$Key].Kind = "Protocols"
				}
				elseif ($Type -match '(?i)_PPI$')
				{
					$TypeIndex[$Key].Kind = "Ppis"
				}
			}

			[void]$TypeIndex[$Key].Sources.Add(
				$Relative
			)
		}
	}

	$ProtocolRecords = @(
		$Records.Values |
			Where-Object {
				$_.Kind -eq "Protocols"
			}
	)

	$PpiRecords = @(
		$Records.Values |
			Where-Object {
				$_.Kind -eq "Ppis"
			}
	)

	$ProtocolTypes = @(
		$TypeIndex.Values |
			Where-Object {
				$_.Kind -eq "Protocols"
			}
	)

	$PpiTypes = @(
		$TypeIndex.Values |
			Where-Object {
				$_.Kind -eq "Ppis"
			}
	)

	$Resolved   = @{}
	$Ambiguous  = 0
	$Unresolved = 0


	foreach ($Record in $Records.Values)
	{
		if (
			$Record.Kind -ne "Protocols" -and
			$Record.Kind -ne "Ppis"
		)
		{
			continue
		}

		$CandidateTypes = @(
			$TypeIndex.Values |
				Where-Object {
					$_.Kind -eq $Record.Kind
				}
		)

		if ($CandidateTypes.Count -eq 0)
		{
			$Unresolved++
			continue
		}

		$Tokens = @(
			Convert-IdentifierToTokens $Record.Name
		)

		$DirectType = $null

		if ($Tokens.Count -gt 0)
		{
			$Prefix = "EFI"

			if ($Record.Name -match '^(?i)gEdkii')
			{
				$Prefix = "EDKII"
			}
			elseif ($Record.Name -match '^(?i)gEfi')
			{
				$Prefix = "EFI"
			}

			$Suffix = if ($Record.Kind -eq "Protocols")
			{
				"PROTOCOL"
			}
			else
			{
				"PPI"
			}

			$DirectType = (
				$Prefix +
				"_" +
				($Tokens -join "_") +
				"_" +
				$Suffix
			)
		}

		if (-not [string]::IsNullOrWhiteSpace($DirectType))
		{
			$DirectKey = $DirectType.ToUpperInvariant()

			if (
				$TypeIndex.ContainsKey($DirectKey) -and
				$TypeIndex[$DirectKey].Kind -eq $Record.Kind
			)
			{
				$Resolved[$Record.Name.ToUpperInvariant()] =
					[pscustomobject]@{
						GuidName = $Record.Name
						TypeName = $TypeIndex[$DirectKey].Name
						Method   = "CanonicalName"
						Score    = 1.0
					}

				continue
			}
		}

		$Scored = New-Object System.Collections.Generic.List[object]

		foreach ($TypeRecord in $CandidateTypes)
		{
			$Score = Get-NameSimilarity `
				$Record.Name `
				$TypeRecord.Name

			if ($Score -le 0)
			{
				continue
			}

			$Scored.Add(
				[pscustomobject]@{
					Type  = $TypeRecord.Name
					Score = [double]$Score
				}
			)
		}

		if ($Scored.Count -eq 0)
		{
			$Unresolved++
			continue
		}

		$ScoredArray = @(
			$Scored.ToArray()
		)

		$Best = @(
			$ScoredArray |
				Sort-Object `
					@{
						Expression = "Score"
						Descending = $true
					},
					@{
						Expression = "Type"
						Descending = $false
					}
		)

		if ($Best.Count -eq 0)
		{
			$Unresolved++
			continue
		}

		$BestScore = [double]$Best[0].Score

		if ($BestScore -lt 0.75)
		{
			$Unresolved++
			continue
		}

		$BestMatches = @(
			$Best |
				Where-Object {
					[math]::Abs(
						[double]$_.Score -
						$BestScore
					) -lt 0.000001
				}
		)

		if ($BestMatches.Count -ne 1)
		{
			$Ambiguous++
			continue
		}

		$Resolved[$Record.Name.ToUpperInvariant()] =
			[pscustomobject]@{
				GuidName = $Record.Name
				TypeName = $BestMatches[0].Type
				Method   = "GlobalNameCorrelation"
				Score    = $BestScore
			}
	}

	Write-Host (
		"      Protocol GUIDs ......... {0}" -f
		$ProtocolRecords.Count
	)

	Write-Host (
		"      PPI GUIDs .............. {0}" -f
		$PpiRecords.Count
	)

	Write-Host (
		"      Protocol types ......... {0}" -f
		$ProtocolTypes.Count
	)

	Write-Host (
		"      PPI types .............. {0}" -f
		$PpiTypes.Count
	)

	Write-Host (
		"      Ambiguous .............. {0}" -f
		$Ambiguous
	)

	Write-Host (
		"      Unresolved ............. {0}" -f
		$Unresolved
	)


	return $Resolved
}

function Scan-DecFile
{
	param(
		[string]$Dec,
		[hashtable]$Records,
		[string]$Root
	)

	$Section = ""
	$Relative = $Dec

	try
	{
		$Relative = [System.IO.Path]::GetRelativePath(
			$Root,
			$Dec
		)
	}
	catch
	{
	}

	foreach ($Raw in Get-Content -LiteralPath $Dec)
	{
		$Line = (
			$Raw -replace '#.*$', ''
		).Trim()

		if ([string]::IsNullOrWhiteSpace($Line))
		{
			continue
		}

		if ($Line -match '^\[(.+?)\]$')
		{
			$Section = $Matches[1].Trim()
			continue
		}

		$BaseSection = (
			$Section -split '\.'
		)[0]

		if (
			$BaseSection -notin @(
				"Guids",
				"Protocols",
				"Ppis"
			)
		)
		{
			continue
		}

		if (
			$Line -match
			'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\{.*\})\s*$'
		)
		{
			$Guid = Convert-CGuidInitializer `
				$Matches[2]

			if ($Guid)
			{
				Add-GuidRecord `
					$Records `
					$Matches[1] `
					$Guid `
					$BaseSection `
					$Relative
			}
		}
	}
}



# ====================================================================================
# BANNER
# ====================================================================================

Clear-Host

Write-Host ""
Write-Host "  ######  ####### ##   ## ####### ###    ###  ######  ######## ##   ## " -ForegroundColor DarkRed
Write-Host "  ##   ## ##      ##   ## ##      ####  #### ##    ##    ##    ##   ## " -ForegroundColor DarkRed
Write-Host "  ######  #####   ####### #####   ## #### ## ##    ##    ##    ####### " -ForegroundColor Red
Write-Host "  ##   ## ##      ##   ## ##      ##  ##  ## ##    ##    ##    ##   ## " -ForegroundColor DarkRed
Write-Host "  ######  ####### ##   ## ####### ##      ##  ######     ##    ##   ## " -ForegroundColor DarkRed
Write-Host ""
Write-Host "  EDK2 GUID Database Generator" -ForegroundColor White
Write-Host "  github.com/TheMalwareGuardian/Behemoth" -ForegroundColor DarkGray
Write-Host ""



# ====================================================================================
# [1/6] RESOLVE SCRIPT02 SCOPE
# ====================================================================================

Write-Step "[1/6] Resolving Script02 scope"

$EDK2 = Find-EDK2Root
$Scan = Find-ScanFile

Write-Host (
	"      EDK2 root .............. {0}" -f
	$EDK2
)

Write-Host (
	"      Header selection ....... {0}" -f
	$Scan
)



# ====================================================================================
# [2/6] LOAD SELECTED HEADERS
# ====================================================================================

Write-Step "[2/6] Loading selected headers"

$Headers = @(
	Get-HeaderPaths `
		$Scan `
		$EDK2
)

if ($Headers.Count -eq 0)
{
	Write-Fail "Script02 header list resolved to zero existing headers."
}

$Packages = @(
	$Headers |
	ForEach-Object {
		Get-PackageRoot `
			$_ `
			$EDK2
	} |
	Where-Object {
		$_
	} |
	Select-Object -Unique
)

Write-Host (
	"      Selected headers ....... {0}" -f
	$Headers.Count
)

Write-Host (
	"      Selected packages ...... {0}" -f
	$Packages.Count
)



# ====================================================================================
# [3/6] EXTRACT GUIDS FROM SELECTED HEADERS
# ====================================================================================

Write-Step "[3/6] Extracting GUIDs from selected headers"

$Records = @{}

foreach ($Header in $Headers)
{
	Scan-HeaderGuids `
		$Header `
		$Records `
		$EDK2
}

$HeaderCount = $Records.Count

Write-Host (
	"      Header GUID symbols .... {0}" -f
	$HeaderCount
)



# ====================================================================================
# [4/6] EXTRACT PACKAGE DEC GUIDS
# ====================================================================================

Write-Step "[4/6] Extracting package DEC GUIDs"

$DecFiles = @(
	$Packages |
	ForEach-Object {
		Get-ChildItem `
			-LiteralPath $_ `
			-Filter "*.dec" `
			-File `
			-Recurse `
			-ErrorAction SilentlyContinue
	} |
	Select-Object `
		-ExpandProperty FullName `
		-Unique
)

foreach ($Dec in $DecFiles)
{
	Scan-DecFile `
		$Dec `
		$Records `
		$EDK2
}

Write-Host (
	"      DEC files .............. {0}" -f
	$DecFiles.Count
)

Write-Host (
	"      Total GUID symbols ..... {0}" -f
	$Records.Count
)



# ====================================================================================
# [5/6] CORRELATE GUIDS WITH PROTOCOL/PPI TYPES
# ====================================================================================

Write-Step "[5/6] Correlating GUIDs with Protocol/PPI types"

$TypeMap = Build-GuidTypeMap `
	$Headers `
	$Records `
	$EDK2

Write-Host (
	"      Type associations ...... {0}" -f
	$TypeMap.Count
)



# ====================================================================================
# [6/6] WRITE DATABASE
# ====================================================================================

Write-Step "[6/6] Writing Behemoth GUID database"

$GDTDir = Join-Path `
	$PSScriptRoot `
	"GDT"

$GUIDDir = Join-Path `
	$GDTDir `
	"GUIDs"

$OutputPath = Join-Path `
	$GUIDDir `
	"Behemoth_GUIDs.ini"

if (-not (Test-Path -LiteralPath $GUIDDir))
{
	New-Item `
		-ItemType Directory `
		-Path $GUIDDir `
		-Force |
	Out-Null
}

$Lines = New-Object `
	System.Collections.Generic.List[string]

$Lines.Add(
	"; ========================================================================"
)

$Lines.Add(
	"; Behemoth GUID Database"
)

$Lines.Add(
	"; Generated from the EDK2 scope selected by Script02"
)

$Lines.Add(
	"; Do not edit manually"
)

$Lines.Add(
	"; ========================================================================"
)

$Lines.Add("")



# ====================================================================================
# GUID DATABASE
# ====================================================================================

$Lines.Add(
	"[EDK2]"
)

foreach (
	$Record in (
		$Records.Values |
		Sort-Object Name, Guid
	)
)
{
	$Lines.Add(
		(
			"{0,-64} = {{{1}}}" -f
			$Record.Name,
			$Record.Guid
		)
	)
}

$Lines.Add("")



# ====================================================================================
# GUID -> TYPE ASSOCIATIONS
# ====================================================================================

$Lines.Add(
	"[Types]"
)

foreach ($Key in ($TypeMap.Keys | Sort-Object))
{
	$Item   = $TypeMap[$Key]
	$Record = $Records[$Key]

	if ($Record)
	{
		$Lines.Add(
			(
				"{0} = {1}" -f
				$Record.Name,
				$Item.TypeName
			)
		)
	}
}

$Lines.Add("")



# ====================================================================================
# METADATA
# ====================================================================================

$Lines.Add(
	"[Metadata]"
)

$Lines.Add(
	(
		"GeneratedUTC = {0}" -f
		[DateTime]::UtcNow.ToString(
			"yyyy-MM-ddTHH:mm:ssZ"
		)
	)
)

$Lines.Add(
	(
		"SelectedHeaders = {0}" -f
		$Headers.Count
	)
)

$Lines.Add(
	(
		"SelectedPackages = {0}" -f
		$Packages.Count
	)
)

$Lines.Add(
	(
		"DECFiles = {0}" -f
		$DecFiles.Count
	)
)

$Lines.Add(
	(
		"GUIDSymbols = {0}" -f
		$Records.Count
	)
)

$Lines.Add(
	(
		"TypeAssociations = {0}" -f
		$TypeMap.Count
	)
)

[System.IO.File]::WriteAllLines(
	$OutputPath,
	$Lines,
	[System.Text.UTF8Encoding]::new($false)
)


Write-Host (
	"      Output .................. {0}" -f
	$OutputPath
)

Write-Host (
	"      GUID symbols ............ {0}" -f
	$Records.Count
)

Write-Host (
	"      Type associations ....... {0}" -f
	$TypeMap.Count
)

Write-Host ""
Write-Host "========================================================================"
Write-Host " Finished"
Write-Host "========================================================================"
