# ***⚔️ Behemoth - Weaponize***



<p align="center">
    <img src="../../Images/Illustrations/Behemoth_Weaponize.png">
</p>



<p align="center">
    <i>
        Finding a vulnerability is not the end of the research process. Once a suspicious behavior has been identified, investigated, and validated, the next step is to reproduce it dynamically, understand the resulting primitive, and determine whether it can be turned into a reliable exploit. Weaponize represents the final stage of the Behemoth research pipeline: moving from vulnerability discovery to UEFI exploit development.
    </i>
</p>



---
---
---



## ***📑 Table of Contents***

* [Overview](#Overview)
* [Debugging UEFI Applications](#Debugging)
* [Exploitation Techniques](#Exploitation)
* [Boot Chain Exploitation](#BootChain)



---
---
---



<div id='Overview'/>

## ***⚔️ Overview***

Behemoth helps reduce a large EFI binary into a much smaller set of security-relevant behaviors. By the time a finding reaches this stage, the previous phases should have already answered increasingly specific questions:

```text
BUILD
|
|  What does the analysis environment need to know?
v
EVOLVE
|
|  What does this binary actually represent?
v
HUNT
|
|  Which behaviors deserve investigation?
v
INSPECT
|
|  Is this behavior actually vulnerable?
v
WEAPONIZE
    |
    |  Can the vulnerability be reproduced and exploited?
    v
Exploit
```

Weaponize is where static analysis meets dynamic analysis.

At this point, knowing that a vulnerable condition exists is no longer enough. The next step is to observe that condition while the firmware is actually running, reproduce it under controlled conditions, and understand exactly what level of control it gives us.

From there, you can naturally move toward exploitation: turning that control into a useful primitive and determining what that primitive can achieve in the context of the UEFI boot environment.



---
---
---



<div id='Debugging'/>

## ***🐛 Debugging UEFI Applications***

That transition starts with debugging.

Static analysis can tell us where the vulnerable path is and why it looks exploitable, but dynamic analysis allows us to actually follow that path as it executes. We can observe the relevant state, validate assumptions made during reverse engineering, trigger the vulnerable condition, and understand how the application behaves when it occurs.

To make that part of the process easier, the following project provides a practical environment and methodology for debugging UEFI applications during vulnerability research and malware analysis:

[***Debugging UEFI Applications for Vulnerability Research and Malware Analysis***](https://github.com/TheMalwareGuardian/Debugging-UEFI-Applications-for-Vulnerability-Research-and-Malware-Analysis)

The goal is to move from something we understood statically in Ghidra to something we can reproduce and study at runtime:

```text
Static Finding
      |
      v
Dynamic Reproduction
      |
      v
UEFI Debugging
      |
      v
Runtime Behavior
      |
      v
Exploitation Primitive
```

Once that primitive is understood, the question changes again. We are no longer asking whether the vulnerability exists, but what we can actually do with it.



---
---
---



<div id='Exploitation'/>

## ***💥 Exploitation Techniques***

This is where exploit development begins.

Different vulnerabilities provide different primitives, and those primitives do not necessarily translate directly into the same security impact. Depending on where the vulnerability exists and what can be controlled, reaching the final objective may require additional exploitation techniques.

During our UEFI research, we have developed and documented several of these techniques for situations where the primitive obtained from a vulnerability needs to be transformed into something useful in the boot environment.

### [***Exploitation Technique: UEFI Secure Boot Bypass via gSecurity2 Corruption***](https://github.com/TheMalwareGuardian/Exploitation-Technique-UEFI-SecureBoot-Bypass-gSecurity2-Corruption)

A technique focused on corrupting the UEFI security architecture state associated with image verification, providing a path from memory corruption to Secure Boot bypass.

### [***Exploitation Technique: Variable Shadowing (NVRAM Design Flaw)***](https://github.com/TheMalwareGuardian/Exploitation-Technique-UEFI-NVRAM-Variable-Shadowing)

A technique based on manipulating how security-relevant UEFI variables are represented and consumed, allowing the effective state observed during the boot process to differ from the expected NVRAM state.

### [***Exploitation Technique: Disabling Linux Kernel Lockdown via MokSBStateRT***](https://github.com/TheMalwareGuardian/Exploitation-Technique-UEFI-MokSBStateRT-Lockdown-Bypass)

A technique exploring the interaction between UEFI state, MokSBStateRT, and Linux boot-chain security mechanisms to extend firmware-level control into later stages of the Linux boot process.



---
---
---



<div id='BootChain'/>

## ***🔗 Boot Chain Exploitation***

These techniques represent the bridge between obtaining a primitive and turning it into meaningful security impact. But even a working EFI exploit is not necessarily the end of the story. In many cases, the interesting question is what that control allows us to do after the vulnerable EFI component has finished its job.

That takes the research beyond the individual EFI application and into the complete boot chain.

A vulnerability may initially provide execution or control inside a single firmware component, but its real impact depends on how that control interacts with what comes next: subsequent EFI applications, boot managers, operating system loaders, and eventually the kernel.

The following research explores that transition across both Windows and Linux boot environments:

[***UEFI Boot Chain Exploitation - Windows & Linux***](https://github.com/TheMalwareGuardian/Paper-UEFI-Bootchain-Exploitation-Windows-Linux)
