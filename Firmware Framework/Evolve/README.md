# ***🧬 Behemoth - Evolve***



<p align="center">
	<img src="../../Images/Illustrations/Behemoth_Evolve.png">
</p>



<p align="center">
	<i>
		Opening an EFI binary in Ghidra gives us code, but not necessarily meaning. Evolve takes the knowledge generated during Build and applies it to the target so that the decompiler begins to represent UEFI concepts instead of only generic pointers, offsets, and indirect calls.
	</i>
</p>



---
---
---



## ***📑 Table of Contents***

<ul>
	<li><a href="#Overview">Overview</a></li>
	<li><a href="#Pipeline">Evolve Pipeline</a></li>
	<li><a href="#Retyping">Retyping the Binary</a></li>
	<li><a href="#Next">Next Stage</a></li>
</ul>



---
---
---



<div id='Overview'/>

## ***🔬 Overview***

Build generated the UEFI knowledge. Evolve uses it against the program
loaded in Ghidra.

``` text
        Raw EFI Binary
              |
              v
       Ghidra Analysis
              |
              v
  UEFI Object / Type Recovery
              |
              v
      Improved Pseudocode
```

The objective is not to reconstruct the original source code, but to
reduce the semantic distance between raw decompiler output and the
structures used by the original firmware.



---
---
---



<div id='Pipeline'/>

## ***⚙️ Evolve Pipeline***

``` text
Script00BehemothTypeUniverse.java
            |
Script01BehemothObjectFinder.java
            |
Script02BehemothRetyper.java
```

- ***Type Universe***: Makes the generated UEFI type information available.
- ***Object Finder***: Searches for objects associated with known UEFI concepts.
- ***Retyper***: Applies recovered type information to improve Ghidra's decompilation.



---
---
---



<div id='Retyping'/>

## ***🧩 Retyping the Binary***

An operation initially represented as an anonymous pointer plus offsets can become recognizable as a UEFI service, protocol, structure, or field after the correct type information is applied.

Note: Retyping remains reverse-engineered evidence. Important assumptions must still be verified against the surrounding code and references.



---
---
---



<div id='Next'/>

## ***➡️ Next Stage***

``` text
Build  ──>  Evolve  ──>  Hunt  ──>  Inspect  ──>  Weaponize
```

Evolve improves what Ghidra understands. Hunt uses that understanding
to search for evidence.
