# ***🛠️ Behemoth - Build***



<p align="center">
	<img src="../../Images/Illustrations/Behemoth_Build.png">
</p>



<p align="center">
	<i>
		Before looking for vulnerabilities, Behemoth needs to understand the environment in which UEFI software is developed. Build prepares that knowledge by processing EDK2 and its headers to generate reusable types and GUID information for the following stages.
	</i>
</p>



---
---
---



## ***📑 Table of Contents***

<ul>
	<li><a href="#Overview">Overview</a></li>
	<li><a href="#Pipeline">Build Pipeline</a></li>
	<li><a href="#Output">Output</a></li>
	<li><a href="#Next">Next Stage</a></li>
</ul>



---
---
---



<div id='Overview'/>

## ***🔬 Overview***

A freshly imported EFI binary contains little semantic information. Structures become offsets, protocols become anonymous pointers, and GUIDs frequently appear only as raw data.

Build creates the reusable knowledge required to reduce that gap. It does not hunt vulnerabilities; it prepares the material Behemoth will later use to understand the target.



---
---
---



<div id='Pipeline'/>

## ***⚙️ Build Pipeline***

``` text
Script00_Setup_Environment.ps1
            |
ScriptBuild01_Analyze_EDK2.ps1
            |
ScriptBuild02_Scan_Headers.ps1
            |
ScriptBuild03_Build_GDT.ps1
            |
ScriptBuild04_GUID_DB.ps1
```

- ***Setup Environment***: Prepares the dependencies required by Behemoth.
- ***Analyze EDK2***: Processes the EDK2 source tree for useful UEFI information.
- ***Scan Headers***: Extracts relevant structures and definitions.
- ***Build GDT***: Generates Ghidra Data Type information.
- ***GUID DB***: Builds reusable knowledge for resolving known UEFI GUIDs.



---
---
---



<div id='Output'/>

## ***📦 Output***

``` text
  EDK2 + Headers + UEFI Definitions
                  |
                  v
        Types + GUID Knowledge
                  |
                  v
        Behemoth Analysis Base
```



---
---
---



<div id='Next'/>

## ***➡️ Next Stage***

``` text
Build  ──>  Evolve  ──>  Hunt  ──>  Inspect  ──>  Weaponize
```

Build creates the knowledge. Evolve applies it to the binary.
