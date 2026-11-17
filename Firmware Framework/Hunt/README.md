# ***🔎 Behemoth - Hunt***



<p align="center">
	<img src="../../Images/Illustrations/Behemoth_Hunt.png">
</p>



<p align="center">
	<i>
		Finding a suspicious pattern is not the same as proving a vulnerability. Hunt automates the search for security-relevant behaviors inside EFI applications and drivers and points the researcher toward code that deserves deeper analysis.
	</i>
</p>



---
---
---



## ***📑 Table of Contents***

<ul>
	<li><a href="#Overview">Overview</a></li>
	<li><a href="#Hunters">Hunters</a></li>
	<li><a href="#Evidence">Evidence, Not Verdicts</a></li>
	<li><a href="#Human">Human Logic</a></li>
	<li><a href="#Next">Next Stage</a></li>
</ul>



---
---
---



<div id='Overview'/>

## ***🔬 Overview***

Behemoth Hunters are designed to answer:

> Where should I look?

> Why is this code interesting?

They expose functions, objects, relationships, and data usage associated with behaviors that frequently matter during firmware vulnerability research.



---
---
---



<div id='Hunters'/>

## ***🏹 Hunters***

``` text
Script00BehemothVariableHunter.java
            |
Script01BehemothShellCommandHunter.java
            |
Script02BehemothCustomImageLoadHunter.java
```

- ***Behemoth Variable Hunter***: Identifies UEFI variable operations and interesting uses of returned data and sizes.
- ***Behemoth Shell Command Hunter***: Identifies shell command surfaces and potentially security-relevant operations.
- ***Behemoth Custom Image Load Hunter***: Identifies EFI image-loading behavior and relationships around operations such as LoadImage() and StartImage().



---
---
---



<div id='Evidence'/>

## ***🧭 Evidence, Not Verdicts***

A Hunter finding is an indicator, not a vulnerability conclusion.

``` text
Interesting Behavior
        |
        v
Security-Relevant Evidence
        |
        v
Reverse Engineering Required
```

When run against a vulnerable binary whose flaw matches the behavior being modeled, a Hunter can point directly toward the relevant code. The same Hunter can then be used against other EFI binaries to search for comparable evidence.

That does not mean every matching pattern is vulnerable. It means Behemoth has identified a place worth investigating.



---
---
---



<div id='Human'/>

## ***🧠 Human Logic***

After a finding, the researcher still needs to determine:

- ***Reachability***: Can the path actually be reached?
- ***Control***: Can an attacker influence the relevant data?
- ***Validation***: Are the values checked before use?
- ***Context***: Which structures and trust boundaries are involved?
- ***Exploitability***: Can the behavior actually be abused?
- ***Impact***: What does successful abuse provide?

Behemoth narrows the search space. Human reasoning determines what the evidence means.



---
---
---



<div id='Next'/>

## ***➡️ Next Stage***

``` text
Hunt Finding
    |
    v
Reverse Engineering
    |
    v
Human + AI-Assisted Analysis
    |
    v
Validation / Exploitability
```

Hunt finds the trail. Inspect follows it.
