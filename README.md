# ***🦣 Behemoth: Hunting UEFI Firmware Vulnerabilities Across the Boot Chain***



<p align="center">
	<img src="Images/Logos/Logo_Behemoth.png">
</p>



<p align="center">
	<i>
		Behemoth is a Ghidra-based UEFI vulnerability research framework that builds its knowledge directly from EDK2 source, reconstructs firmware semantics, hunts for security-relevant behaviors, and assists the researcher in investigating potential vulnerabilities.
	</i>
</p>



---
---
---



## ***📑 Table of Contents***

* [What is Behemoth?](#WhatIsThis)
* [Research Pipeline](#ResearchPipeline)
* [Getting Started](#GettingStarted)

---

* [Using Behemoth.gdt in Ghidra](#UsinginGhidra)
* [Types Included](#TypesIncluded)

---

* [Hunting Vulnerabilities](#Hunting)
* [Security Research Context](#SecurityResearch)

---

* [Research & Case Studies](#Research)

---

* [Use Behemoth as the Foundation of Your Own Product](#Product)



---
---
---



<div id='WhatIsThis'/>

## ***📘 What is Behemoth?***

The UEFI security research tooling ecosystem around Ghidra has historically depended on a handful of projects to make firmware analysis practical:

- [efiSeek](https://github.com/DSecurity/efiSeek): the original Ghidra plugin for UEFI analysis, long considered the standard for loading and navigating EFI binaries inside Ghidra. It shipped a pre-built type archive called `Behemotx32/x64.gdt` that resolved UEFI structures automatically. It is now unmaintained and does not compile against recent Ghidra versions.
- [efiXplorer](https://github.com/REhints/efiXplorer): the current standard for UEFI analysis, actively maintained and feature-rich. Requires IDA Pro.
- [ghidra-firmware-utils](https://github.com/al3xtjames/ghidra-firmware-utils): Ghidra plugin for parsing UEFI firmware volumes and capsules.
- [UEFITool](https://github.com/LongSoft/UEFITool): the standard tool for extracting and inspecting UEFI firmware images.

Some of these projects ship or depend on `.gdt` type archives to give Ghidra the vocabulary it needs to understand UEFI structures. The problem is that these archives are static snapshots. They get out of date, they were built against specific EDK2 revisions, and importing them into a current Ghidra project does not guarantee they reflect the types and structures you actually want to analyze.

***Behemoth takes a different approach: it generates that knowledge directly from source.***

Pull the EDK2 headers you want, build the type information, and generate a `.gdt` that reflects the source used during the analysis. No static snapshots and no guessing whether the types are right.

But generating an up-to-date type archive only solves the first problem.

Having the correct structures does not automatically identify where they are used in a stripped EFI binary. Recovering those objects does not automatically tell us which code paths are security relevant. And finding a suspicious operation does not automatically tell us whether it is actually vulnerable.

That is where Behemoth evolved from a **Ghidra Type Archive Builder** into a complete **UEFI vulnerability research pipeline**.



---
---
---



<div id='ResearchPipeline'/>

## ***🔁 Research Pipeline***

Behemoth divides the research process into four stages:

### ***🛠️ Build***

Build the knowledge required to understand UEFI.

Behemoth processes EDK2 source and headers to generate Ghidra types, GUID information, and other reusable analysis resources.

```text
EDK2 + Headers
    |
    v
Types + GUIDs + UEFI Knowledge
```

### ***🧬 Evolve***

Apply that knowledge to the target.

Once an EFI application or driver is loaded into Ghidra, Behemoth identifies relevant UEFI objects and retypes the program to transform generic decompiler output into something closer to the original firmware semantics.

```text
Raw EFI
    |
    v
Object Discovery
    |
    v
Retyping
    |
    v
UEFI-Aware Pseudocode
```

### ***🔎 Hunt***

Search the evolved binary for security-relevant behavior.

Hunters analyze specific vulnerability surfaces and expose the functions, data relationships, and operations that deserve additional investigation.

```text
    UEFI-Aware Program
            |
            v
         Hunters
            |
            v
Security-Relevant Evidence
```

***A Hunter finding is an indicator, not proof of a vulnerability.***

### ***🧠 Inspect***

Investigate the evidence.

Inspect takes the output produced by Hunt and moves back into deeper reverse engineering: callers, callees, structures, data provenance, validation, reachability, attacker control, and exploitability. Ghidra can also be connected to an AI model through MCP to assist this process.

```text
    Hunter Finding
          |
          v
Human + AI-Assisted RE
          |
          v
      Validation
          |
          v
    Exploitability
```

***Automation finds the trail. Reverse engineering determines where it leads.***

### ***⚔️ Weaponize***

Turn the validated vulnerability into a practical exploitation path.

Once a finding has been understood and validated, Weaponize moves the research into dynamic analysis. The target UEFI application is debugged to reproduce the vulnerable condition, validate the assumptions made during static analysis, understand the resulting primitive, and determine whether it can be turned into a reliable exploit.

```text
Validated Vulnerability
          |
          v
    UEFI Debugging
          |
          v
  Primitive Analysis
          |
          v
 Exploit Development
          |
          v
  Boot Chain Impact
```

Behemoth does not stop at finding the bug. The final objective is to understand whether the vulnerability can be reproduced, controlled, and exploited.

***Automation finds the trail. Reverse engineering validates it. Exploitation proves where it leads.***



---
---
---



<div id='GettingStarted'/>

## ***💻 Getting Started***

The first stage of Behemoth builds the UEFI knowledge required by the rest of the framework.

To generate `Behemoth.gdt`, follow these steps:

1. Open PowerShell as Administrator:
	- Open PowerShell by searching for it in the Start Menu.
	- Right-click PowerShell and select ***Run as Administrator***.

2. Set the Execution Policy (Optional):
	- If you encounter an error related to script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

3. Navigate to the Script Directory:
	- Use the `cd` command to navigate to the folder containing the script.

4. Execute the Build pipeline.

5. Wait for completion:
	- The required EDK2 information is processed and the corresponding Ghidra analysis resources are generated.

Once Build is complete, the generated knowledge can be used by the remaining Behemoth stages.



---
---
---



<div id='UsinginGhidra'/>

## ***🐉 Using Behemoth.gdt in Ghidra***

1. Open Ghidra and load your `.efi` file.
2. Open the "Data Type Manager" panel (`Window -> Data Type Manager`).
3. Click the archive icon ▼ -> "Open File Archive..."
4. Select `Behemoth.gdt`.
5. All generated UEFI types are now available.
6. Apply them with "Retype Variable".

Key types to apply at the EFI entry point:

| Parameter | Type |
|---|---|
| `param_1` | `EFI_HANDLE` |
| `param_2` | `EFI_SYSTEM_TABLE *` |

Once `param_2` is typed as `EFI_SYSTEM_TABLE *`, the decompiler can begin resolving accesses through the System Table and expose meaningful UEFI structures and service calls.

This manual process also illustrates the problem solved by the **Evolve** stage: Behemoth can use the generated type universe to automatically recover and apply part of this semantic information across the program.



---
---
---



<div id='TypesIncluded'/>

## ***🧩 Types Included***

Behemoth generates its type universe from multiple EDK2 packages, including `MdePkg`, `MdeModulePkg`, `NetworkPkg`, `ShellPkg`, `SecurityPkg`, `CryptoPkg`, and more.

The generated archive includes, among others:

- **Core tables**: `EFI_SYSTEM_TABLE`, `EFI_BOOT_SERVICES`, `EFI_RUNTIME_SERVICES`
- **Base types**: `EFI_STATUS`, `EFI_HANDLE`, `EFI_GUID`, `EFI_TIME`, `EFI_DEVICE_PATH_PROTOCOL`
- **Protocols**: `EFI_LOADED_IMAGE_PROTOCOL`, `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, `EFI_BLOCK_IO_PROTOCOL`, `EFI_SECURITY2_ARCH_PROTOCOL`, `EFI_GRAPHICS_OUTPUT_PROTOCOL`, `EFI_HASH2_PROTOCOL`, `EFI_PKCS7_VERIFY_PROTOCOL`, and more
- **PI types**: `EFI_MM_SYSTEM_TABLE`, `EFI_PEI_SERVICES`

The exact generated type universe depends on the EDK2 source and packages processed during Build.



---
---
---



<div id='Hunting'/>

## ***🏹 Hunting Vulnerabilities***

Once the target has been retyped and its UEFI semantics recovered, Behemoth can begin searching for behaviors commonly associated with interesting vulnerability surfaces.

The current Hunters focus on areas such as:

- ***UEFI Variables***: Identify variable access and determine how returned data and sizes are subsequently used.
- ***Shell Commands***: Identify available commands and operations that may expose dangerous or security-sensitive functionality.
- ***Custom Image Loading***: Identify paths where another EFI image or payload appears to be located, loaded, or executed.

When executed against a vulnerable binary whose vulnerability matches one of these behaviors, a Hunter can point directly toward the code responsible for the issue. But Behemoth deliberately stops before making the final conclusion.

There are many ways to implement custom payload loading, variable handling, shell functionality, or other firmware behaviors. Static analysis is not an exact science, and no general-purpose script can model every vendor implementation. A finding therefore means: "This code deserves investigation.



---
---
---



<div id='SecurityResearch'/>

## ***👾 Security Research Context***

Behemoth is built for UEFI vulnerability research, specifically for identifying and investigating patterns such as:

- ***Unsigned image loading***: a signed EFI component loads another image or payload from an insufficiently trusted source.
- ***Missing security-state validation***: security-sensitive behavior occurs without the expected platform or Secure Boot state checks.
- ***UEFI variable abuse***: attacker-influenced variable data reaches security-sensitive operations.
- ***Memory-safety conditions***: externally influenced sizes, offsets, pointers, or buffers reach potentially unsafe memory operations.
- ***Shell attack surfaces***: commands expose functionality whose validation or authorization needs additional review.
- ***Custom payload loaders***: proprietary loading mechanisms introduce alternative paths for executing EFI content.
- ***Unchecked service/protocol results***: returned objects or pointers are consumed without sufficient validation.

After Hunt identifies an interesting path, the researcher still needs to answer:

- ***Reachability***: Can the code actually execute under attacker-relevant conditions?
- ***Control***: Which inputs can be influenced?
- ***Validation***: What checks constrain those inputs?
- ***Trust***: Where does the data originate?
- ***Primitive***: What security capability does the behavior provide?
- ***Exploitability***: Can the primitive be reliably abused?
- ***Impact***: What happens if exploitation succeeds?

This is the final purpose of Behemoth:

```text
Build the knowledge.
Evolve the binary.
Hunt the evidence.
Inspect the behavior.
Find what others missed.
```



---
---
---



<div id='Research'/>

## ***📚 Research & Case Studies***

Behemoth is designed around a research workflow that has been applied to real UEFI vulnerability research and exploit development.

The following repositories provide additional material, vulnerability case studies, and targets (real vulnerable binaries) that complement the Behemoth pipeline.

### ***🔬 UEFI Vulnerability Research and Exploit Development***

[***UEFI Vulnerability Research and Exploit Development***](https://github.com/TheMalwareGuardian/UEFI-Vulnerability-Research-and-Exploit-Development)

A collection of UEFI vulnerability research covering real vulnerabilities, reverse engineering, vulnerability discovery, and exploit development.

### ***🎯 Bring Your Own Vulnerable UEFI Application***

[***Awesome Bring Your Own Vulnerable UEFI Application***](https://github.com/TheMalwareGuardian/Awesome-Bring-Your-Own-Vulnerable-UEFI-Application)

A curated collection of resources focused on UEFI vulnerabilities, bringing together research, write-ups, vulnerable applications, exploitation techniques, and other material useful for studying vulnerability discovery and exploitation in the UEFI ecosystem.



---
---
---



<div id='Product'/>

## ***🚀 Use Behemoth as the Foundation of Your Own Product***

Are you an independent security researcher? Someone just getting started in UEFI vulnerability research? A small security team? Or perhaps a company that sees a business opportunity in automated firmware vulnerability discovery?

**Well, here's the foundation of your product.**

Behemoth gives you a starting point for building a professional platform focused on automatically discovering vulnerabilities in UEFI binaries, similar in purpose to the kinds of solutions developed by specialized firmware security companies such as [Binarly](https://www.binarly.io/) or [Eclypsium](https://eclypsium.com/).

I'm giving you the foundation so you don't have to build everything from scratch.

You already have the infrastructure for generating UEFI types, recovering firmware semantics, analyzing binaries with Ghidra, identifying security-relevant behavior, and investigating potential vulnerabilities. Now it's up to you.

Want to detect additional vulnerability classes? Write more Hunters. Want to automate more of the research process? Extend the pipeline. Want to build your own commercial firmware vulnerability discovery product? **Take Behemoth as your starting point and build on top of it.**

**I'm giving you the foundation. You build the product.**

<p align="center">
	<img src="Images/Illustrations/BehemothFoundationAsProduct.png">
</p>
