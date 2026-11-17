
### Proposal title

Behemoth: Hunting UEFI Firmware Vulnerabilities Across the Boot Chain

### Session type

Talk (40 minutes)

### Abstract

UEFI firmware is the foundation of trust for every modern system, yet it remains one of the least audited attack surfaces. Vulnerabilities in UEFI components can allow attackers to subvert Secure Boot, persist below the operating system, and survive full disk wipes - effectively owning the machine before any security software loads.

In this talk, we introduce Behemoth, the result of years of research into UEFI internals and firmware exploitation. Built on top of Ghidra, Behemoth transforms stripped UEFI binaries into analyzable targets by automatically applying EDK2 type information and firmware knowledge, allowing researchers to understand unfamiliar binaries in minutes instead of hours. On top of this enriched representation, the framework integrates custom analysis modules that rapidly identify dangerous vulnerability patterns across DXE drivers and UEFI applications, including unsafe parsing routines, loading of external payloads without signature verification, insecure NVRAM variable handling, and memory corruption conditions in boot-time services.

We will demonstrate how Behemoth was used to discover real vulnerabilities in commercial firmware, walking through the analysis pipeline from firmware extraction to confirmed exploitable conditions. The talk will cover common vulnerability patterns found across different vendors, how these flaws can be chained to compromise the boot process, and how Secure Boot bypasses emerge from implementation mistakes rather than cryptographic weaknesses. Attendees will leave with a practical understanding of UEFI vulnerability research methodology and access to the open-source tooling presented.

### Innovation

Existing open-source tooling for UEFI firmware analysis in Ghidra focuses primarily on known-signature detection. No publicly available framework combines automated large-scale type reconstruction with vulnerability pattern detection specifically designed for offensive UEFI firmware research. Behemoth fills this gap.

Rather than treating Ghidra as a generic disassembler that happens to open UEFI binaries, Behemoth builds a UEFI-native analysis environment on top of it - automatically applying EDK2 type information, resolving protocol interactions, and then running targeted detection modules against the enriched representation to surface real vulnerability patterns.

The vulnerability patterns detected by Behemoth are not theoretical. They are derived from hands-on research that has led to multiple CVEs in commercial firmware, including CVE-2024-7344, CVE-2025-3052, and CVE-2025-4275. Each detection module exists because a real exploitable condition was found, analyzed, and generalized into a reusable check.

Behemoth is also designed to be extensible. New detection modules can be added as new vulnerability classes are discovered, making it a living framework that evolves with the UEFI threat landscape rather than a static tool tied to known issues.

The framework and its analysis modules will be released as open-source, providing the hardware security community with practical offensive tooling for UEFI firmware vulnerability research that currently does not exist in the public domain.

### Live Demos

Yes, the talk includes three live demonstrations:

Demo 1 - Type Reconstruction (during "Behemoth: Type Reconstruction Pipeline" section)
Starting from a real stripped DXE driver imported into Ghidra with no type information, we run Behemoth's type reconstruction pipeline live. The audience sees the before and after: a binary full of unnamed pointers and opaque structures transformed into a fully annotated target with resolved EFI service calls, labeled GUIDs, and typed protocol structures in real time.

Demo 2 - Vulnerability Detection (during "Vulnerability Detection Modules" section)
Using a binary associated with a confirmed CVE, we run Behemoth's detection modules live against the type-enriched representation. The audience sees how the framework flags the vulnerable code paths, pinpoints the exact exploitable conditions, and outputs structured findings linking specific functions to the identified vulnerability patterns.

Demo 3 - Writing a Custom Detection Module (during "Extending Behemoth" section)
We build a simple detection module from scratch during the talk, targeting a specific vulnerability pattern. The module is written as a self-contained Ghidra script, loaded into Behemoth, and executed against a firmware binary, demonstrating how researchers can extend the framework to hunt for new vulnerability classes.

### Full Technical Details

Behemoth is a modular vulnerability research framework built on top of Ghidra, designed to transform the manual and time-consuming process of UEFI firmware reverse engineering into a systematic, scalable analysis pipeline. It operates across multiple stages: type reconstruction, vulnerability pattern detection, and structured reporting.

- Type Reconstruction

UEFI binaries are PE executables. Once stripped of symbols, all EFI protocol structures, boot and runtime service calls, and GUID references appear as raw pointers and constants, making meaningful analysis extremely slow. Behemoth solves this by parsing EDK2 header files (MdePkg, MdeModulePkg, ...) to build a comprehensive Ghidra Data Type Archive containing all core EFI types: EFI_BOOT_SERVICES, EFI_RUNTIME_SERVICES, EFI_SYSTEM_TABLE, protocol structures such as EFI_LOADED_IMAGE_PROTOCOL, EFI_SIMPLE_FILE_SYSTEM_PROTOCOL, and EFI_BLOCK_IO_PROTOCOL, along with associated enumerations and constants.

Once the archive is applied, Behemoth automatically identifies the EFI entry point signature (EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)) and types the entry function parameters. From there, it propagates types through the call graph: resolving BootServices and RuntimeServices pointer accesses, applying correct function pointer types to each service call (gBS->LocateProtocol, gBS->HandleProtocol, gRT->GetVariable, gRT->SetVariable, etc.), and matching embedded byte patterns against the EDK2 GUID database to label every protocol being installed, located, or consumed.

The result is that a binary full of unnamed function pointers and opaque structures becomes fully annotated with meaningful type information, reducing manual reverse engineering time from hours to minutes per binary. This process scales across entire firmware images when combined with extraction tools such as UEFITool.

- Vulnerability Detection Modules

On top of the type-enriched representation, Behemoth runs detection modules that identify specific vulnerability patterns. Every module exists because a real exploitable condition was found, analyzed, and generalized into a reusable check. Current modules include:

Unsigned Payload Loading - Detects UEFI applications or DXE drivers that load and execute external payloads from disk via EFI_SIMPLE_FILE_SYSTEM_PROTOCOL or from firmware volumes without performing Authenticode signature verification through EFI_SECURITY2_ARCH_PROTOCOL or equivalent mechanisms.

Insecure NVRAM Variable Handling - Identifies calls to gRT->GetVariable where NVRAM variables are read and their values subsequently used in unsafe ways: as sizes in memory operations (memcpy, CopyMem) without bounds checking, as offsets in pointer arithmetic without validation, or as control flow conditions without sanitization. Since NVRAM variables can be modified by an attacker with OS-level privileges, any unvalidated consumption of their content at firmware level becomes a reliable exploitation vector.

Memory Corruption in Boot Services - Detects patterns where boot-time memory allocations (gBS->AllocatePool, gBS->AllocatePages) are followed by memory copy operations using sizes derived from untrusted input such as parsed headers, file content, or NVRAM data without adequate validation. This covers buffer overflow conditions in the pre-OS environment where no ASLR, DEP, or stack canaries are enforced.

Unsafe Parsing Routines - Identifies functions that process structured data formats (PE/COFF headers, capsule headers, firmware volume headers, custom vendor formats) where field values such as sizes, offsets, and counts are used directly in pointer arithmetic or memory operations without sanitization.

- Real-World Validation

Behemoth has been validated by analyzing binaries associated with confirmed CVEs in commercial firmware, successfully identifying the vulnerable code paths and enabling the development of working exploits:

CVE-2024-7344 - Discovered in Howyar SysReturn, where a Microsoft-signed UEFI application loaded an external payload without signature verification. Behemoth's unsigned payload loading module directly identifies this pattern.

CVE-2025-3052 - Discovered in a DT Research UEFI application, where an attacker-controllable NVRAM variable value was used as a base address and a specific offset relative to it was nullified, providing an arbitrary write primitive. Behemoth's insecure NVRAM variable handling module flags this pattern by detecting unvalidated variable content flowing into pointer arithmetic and memory write operations.

- Extensibility

Behemoth is designed so that new detection modules can be added as new vulnerability classes are discovered. Each module is a self-contained Ghidra script that operates on the typed representation and outputs structured findings. The framework evolves with the UEFI threat landscape rather than remaining tied to a fixed set of known patterns.

- Release

The framework, all detection modules, the type archive builder, and documentation will be released as open-source on GitHub, timed to coincide with the presentation.

### Flow Of The Talk

Introduction: The UEFI Attack Surface (5 min)

- Why UEFI firmware remains one of the most critical and least audited attack surfaces in modern systems
- Brief overview of the boot chain: power-on, PEI, DXE, BDS, OS load
- What an attacker gains by compromising this layer: persistence below the operating system, Secure Boot bypass, survival across disk wipes and OS reinstalls
- The current state of public tooling and why existing approaches focus on known-signature detection rather than vulnerability discovery

The Problem: Reverse Engineering Stripped UEFI Binaries (5 min)

- What a stripped UEFI PE binary looks like in Ghidra without type information: unnamed pointers, opaque structures, unresolved service calls
- Why manual analysis takes hours per binary and cannot scale across full firmware images containing hundreds of modules
- Side-by-side comparison of an unannotated binary versus the same binary after Behemoth type reconstruction

Behemoth: Type Reconstruction Pipeline (8 min)

- Building Ghidra Data Type Archives from EDK2 headers
- Automatic entry point identification and parameter typing
- Type propagation through BootServices and RuntimeServices
- GUID matching and protocol labeling
- Live demo: running the full type reconstruction on a real stripped DXE driver, showing the transformation in Ghidra in real time

Vulnerability Detection Modules (12 min)

- How detection modules operate on the type-enriched representation
- Walkthrough of each module with real code examples:
	- Unsigned payload loading and the CVE-2024-7344 pattern: a signed UEFI application loading external PE images from the ESP without Authenticode verification
	- Insecure NVRAM variable handling: variables read via GetVariable and their values subsequently used in unsafe ways as sizes in memory operations, offsets in pointer arithmetic, or control flow conditions without validation
	- Memory corruption through untrusted sizes in AllocatePool/AllocatePages flows in a pre-OS environment without ASLR or DEP
	- Unsafe parsing routines and the CVE-2025-3052 pattern: an attacker-controllable NVRAM variable value used as a base address with a specific offset nullified, providing an arbitrary write primitive
- How each module was derived from a real confirmed vulnerability and generalized into a reusable check
- Live demo: running the detection modules against a known vulnerable binary, showing how Behemoth flags the vulnerable code paths and pinpoints the exact exploitable conditions in Ghidra

Chaining Findings: From Individual Bugs to Boot Compromise (5 min)

- How individual vulnerability findings chain together to achieve full Secure Boot bypass
- Why boot compromise comes from implementation mistakes
- References to how Behemoth identified the vulnerable code paths and enabled the development of working exploits

Extending Behemoth (3 min)

- How to write a custom detection module targeting a new vulnerability pattern
- Live demo: building a simple module from scratch and running it against a firmware binary
- How the community can contribute new modules as new vulnerability classes are discovered

Conclusions and Release (2 min)

- Key takeaways for firmware security researchers and hardware vendors
- Open-source release: GitHub repository, documentation, and getting started

Q&A

### Select Relevant Tags for Your Submission

Reverse Engineering

### Additional Speaker

-
