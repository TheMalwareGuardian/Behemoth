# ====================================================================================
# ScriptBuild01_Analyze_EDK2.ps1
# Behemoth - Minimal EDK2 Structure Analyzer
#
# Purpose:
# Inspect the local EDK2 source tree downloaded by Script00 and produce a simple, human-readable inventory of its public Include structure.
#
# Output:
#   GDT\Analysis\EDK2_Structure.txt
#
# ====================================================================================



$ErrorActionPreference = "Stop"



# ====================================================================================
# PATHS
# ====================================================================================

$Root = $PSScriptRoot

$GDTDir      = Join-Path $Root "GDT"
$EDK2Dir     = Join-Path $GDTDir "edk2"
$AnalysisDir = Join-Path $GDTDir "Analysis"

$StructureReport = Join-Path $AnalysisDir "EDK2_Structure.txt"



# ====================================================================================
# DISPLAY HELPERS
# ====================================================================================

function Write-Step
{
	param(
		[string]$Text
	)

	Write-Host $Text -ForegroundColor Cyan
}

function Write-OK
{
	param(
		[string]$Text
	)

	Write-Host "  [+] $Text" -ForegroundColor Green
}

function Write-Info
{
	param(
		[string]$Text
	)

	Write-Host "  [-] $Text" -ForegroundColor Gray
}

function Write-Fail
{
	param(
		[string]$Text
	)

	Write-Host "  [X] $Text" -ForegroundColor Red
	exit 1
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
Write-Host "  Minimal EDK2 Structure Analyzer" -ForegroundColor White
Write-Host "  github.com/TheMalwareGuardian/Behemoth" -ForegroundColor DarkGray
Write-Host ""



# ====================================================================================
# [1/4] VALIDATE EDK2
# ====================================================================================

Write-Step "[1/4] Checking EDK2 source tree..."

if (-not (Test-Path $EDK2Dir))
{
	Write-Fail "EDK2 directory not found: $EDK2Dir"
}

$EDK2Dir = (Resolve-Path $EDK2Dir).Path

$Packages = @(
	Get-ChildItem `
		-Path $EDK2Dir `
		-Directory `
		-ErrorAction SilentlyContinue |
	Where-Object {
		$_.Name -like "*Pkg"
	} |
	Sort-Object Name
)

if ($Packages.Count -eq 0)
{
	Write-Fail "No EDK2 packages found"
}

if (-not (Test-Path $AnalysisDir))
{
	New-Item `
		-ItemType Directory `
		-Path $AnalysisDir `
		-Force |
		Out-Null
}

Write-OK "EDK2 source tree found"
Write-Info $EDK2Dir
Write-Info "$($Packages.Count) packages found"



# ====================================================================================
# [2/4] ANALYZE PUBLIC INCLUDE STRUCTURE
# ====================================================================================

Write-Step "[2/4] Analyzing package Include structure..."

$PackageData  = @()
$CategoryData = @()

foreach ($Package in $Packages)
{
	$IncludePath = Join-Path $Package.FullName "Include"

	$IncludeHeaders     = @()
	$RootIncludeHeaders = @()
	$Categories         = @()

	if (Test-Path $IncludePath)
	{
		$IncludeHeaders = @(
			Get-ChildItem `
				-Path $IncludePath `
				-Recurse `
				-File `
				-Filter "*.h" `
				-ErrorAction SilentlyContinue
		)

		$RootIncludeHeaders = @(
			Get-ChildItem `
				-Path $IncludePath `
				-File `
				-Filter "*.h" `
				-ErrorAction SilentlyContinue
		)

		$Categories = @(
			Get-ChildItem `
				-Path $IncludePath `
				-Directory `
				-ErrorAction SilentlyContinue |
			Sort-Object Name
		)

		foreach ($Category in $Categories)
		{
			$Headers = @(
				Get-ChildItem `
					-Path $Category.FullName `
					-Recurse `
					-File `
					-Filter "*.h" `
					-ErrorAction SilentlyContinue
			)

			$CategoryData += [PSCustomObject]@{
				Package  = $Package.Name
				Category = $Category.Name
				Headers  = $Headers.Count
			}
		}
	}

	$PackageData += [PSCustomObject]@{
		Package            = $Package.Name
		HasInclude         = (Test-Path $IncludePath)
		IncludeHeaders     = $IncludeHeaders.Count
		RootIncludeHeaders = $RootIncludeHeaders.Count
		Categories         = $Categories.Count
	}
}

$PackagesWithInclude = @(
	$PackageData |
	Where-Object {
		$_.HasInclude
	}
)

$UniqueCategories = @(
	$CategoryData |
	Group-Object Category |
	ForEach-Object {
		[PSCustomObject]@{
			Category = $_.Name
			Packages = $_.Count
			Headers  = (
				$_.Group |
				Measure-Object Headers -Sum
			).Sum
		}
	} |
	Sort-Object Category
)

$TotalIncludeHeaders = (
	$PackageData |
	Measure-Object IncludeHeaders -Sum
).Sum

$TotalRootHeaders = (
	$PackageData |
	Measure-Object RootIncludeHeaders -Sum
).Sum

if ($null -eq $TotalIncludeHeaders)
{
	$TotalIncludeHeaders = 0
}

if ($null -eq $TotalRootHeaders)
{
	$TotalRootHeaders = 0
}

Write-OK "Public Include structure analyzed"
Write-Info "$($PackagesWithInclude.Count) packages contain Include\"
Write-Info "$($UniqueCategories.Count) unique Include categories found"
Write-Info "$TotalIncludeHeaders headers found under Include\"



# ====================================================================================
# [3/4] GENERATE STRUCTURE REPORT
# ====================================================================================

Write-Step "[3/4] Generating structure report..."

$Report = [System.Collections.Generic.List[string]]::new()

$Report.Add("BEHEMOTH - EDK2 STRUCTURE")
$Report.Add("========================")
$Report.Add("")
$Report.Add("EDK2 root              : $EDK2Dir")
$Report.Add("Packages               : $($PackageData.Count)")
$Report.Add("Packages with Include\ : $($PackagesWithInclude.Count)")
$Report.Add("Include categories     : $($UniqueCategories.Count)")
$Report.Add("Headers under Include\ : $TotalIncludeHeaders")
$Report.Add("Headers directly there : $TotalRootHeaders")
$Report.Add("")

$Report.Add("PACKAGES")
$Report.Add("--------")
$Report.Add("")

$PackageTable = (
	$PackageData |
	Format-Table `
		Package,
		HasInclude,
		IncludeHeaders,
		RootIncludeHeaders,
		Categories `
		-AutoSize |
	Out-String `
		-Width 4096
).TrimEnd()

foreach ($Line in ($PackageTable -split "`r?`n"))
{
	$Report.Add($Line)
}

$Report.Add("")
$Report.Add("")
$Report.Add("INCLUDE CATEGORIES")
$Report.Add("------------------")
$Report.Add("")

if ($UniqueCategories.Count -eq 0)
{
	$Report.Add("None detected.")
}
else
{
	$CategoryTable = (
		$UniqueCategories |
		Format-Table `
			Category,
			Packages,
			Headers `
			-AutoSize |
		Out-String `
			-Width 4096
	).TrimEnd()

	foreach ($Line in ($CategoryTable -split "`r?`n"))
	{
		$Report.Add($Line)
	}
}

$Report.Add("")
$Report.Add("")
$Report.Add("PACKAGE INCLUDE STRUCTURE")
$Report.Add("-------------------------")
$Report.Add("")

foreach ($Package in $PackagesWithInclude)
{
	$Report.Add($Package.Package)

	$Entries = @(
		$CategoryData |
		Where-Object {
			$_.Package -eq $Package.Package
		} |
		Sort-Object Category
	)

	$PackageInfo = $PackageData |
		Where-Object {
			$_.Package -eq $Package.Package
		} |
		Select-Object -First 1

	if ($PackageInfo.RootIncludeHeaders -gt 0)
	{
		$Report.Add(
			"  [root]  $($PackageInfo.RootIncludeHeaders) headers"
		)
	}

	foreach ($Entry in $Entries)
	{
		$Report.Add(
			("  {0,-24} {1,5} headers" -f $Entry.Category, $Entry.Headers)
		)
	}

	$Report.Add("")
}

[System.IO.File]::WriteAllLines(
	$StructureReport,
	$Report.ToArray(),
	[System.Text.UTF8Encoding]::new($false)
)

Write-OK "Structure report generated"
Write-Info $StructureReport



# ====================================================================================
# [4/4] SUMMARY
# ====================================================================================

Write-Step "[4/4] Analysis summary..."

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Green
Write-Host "                   EDK2 ANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "  Source:" -ForegroundColor White
Write-Host "    $EDK2Dir" -ForegroundColor Gray
Write-Host ""

Write-Host "  Packages               : $($PackageData.Count)" -ForegroundColor White
Write-Host "  Packages with Include\ : $($PackagesWithInclude.Count)" -ForegroundColor White
Write-Host "  Include categories     : $($UniqueCategories.Count)" -ForegroundColor White
Write-Host "  Headers under Include\ : $TotalIncludeHeaders" -ForegroundColor White
Write-Host "  Root Include headers   : $TotalRootHeaders" -ForegroundColor White
Write-Host ""

Write-Host "  Report:" -ForegroundColor White
Write-Host "    $StructureReport" -ForegroundColor Gray
Write-Host ""

Write-Host "  Script01 is informational only." -ForegroundColor DarkGray
Write-Host "  Header selection is defined explicitly by Script02." -ForegroundColor DarkGray
Write-Host ""

Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""
