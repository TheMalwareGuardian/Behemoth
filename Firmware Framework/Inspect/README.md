# ***🧠 Behemoth - Inspect***



<p align="center">
	<img src="../../Images/Illustrations/Behemoth_Inspect.png">
</p>



<p align="center">
	<i>
		Once Behemoth has found an interesting trail, the next step is to understand what the code is actually doing. Inspect combines traditional reverse engineering with optional AI assistance, allowing the researcher to explore Hunt findings directly from the Ghidra analysis environment. This README uses Ghidra + GhidraMCP + Claude Desktop as the reference workflow.
	</i>
</p>



---
---
---



## ***📑 Table of Contents***

<ul>
	<li><a href="#Overview">Overview</a></li>
	<li><a href="#GhidraMCP">GhidraMCP</a></li>
	<li><a href="#Connection">Connecting Ghidra to
Claude</a></li>
	<li><a href="#Workflow">Analysis Workflow</a></li>
	<li><a href="#Validation">Human Validation</a></li>
</ul>



---
---
---



<div id='Overview'/>

## ***🔬 Overview***

Inspect is not about asking an AI:

> Is this firmware vulnerable?

The objective is to give the model access to reverse-engineering context so it can assist while navigating functions, references, structures, and decompiled code.

``` text
Behemoth Hunt
    |
    v
Interesting Evidence
    |
    v
Ghidra <──> GhidraMCP <──> Claude
    |
    v
Human Validation
```



---
---
---



<div id='GhidraMCP'/>

## ***🔌 GhidraMCP***

[GhidraMCP](https://github.com/LaurieWired/GhidraMCP) provides a bridge between Ghidra and MCP-compatible AI clients.

Instead of repeatedly copying isolated pseudocode into an LLM, the model can interact with the analysis exposed by GhidraMCP to inspect functions, follow references, explore callers/callees, understand structures, correlate findings, and test analysis hypotheses.



---
---
---



<div id='Connection'/>

## ***⚙️ Connecting Ghidra to Claude***

### ***1. Download GhidraMCP***

``` text
https://github.com/LaurieWired/GhidraMCP
```

### ***2. Install the Ghidra Extension***

From Ghidra:

``` text
File -> Install Extensions -> +
```

Select the GhidraMCP extension archive and enable the plugin according to the installed release.

### ***3. Install MCP***

``` bash
pip install "mcp[cli]"
```

If required:

``` bash
pip install mcp
```

### ***4. Configure Claude Desktop***

Edit the Claude Desktop local MCP configuration:

``` json
{
"mcpServers": {
	"ghidra": {
	"command": "python",
	"args": [
		"PATH_TO_GHIDRAMCP/bridge_mcp_ghidra.py",
		"--ghidra-server",
		"http://127.0.0.1:8080/"
	]
	}
}
}
```

Replace the executable and GhidraMCP path with the values for your environment, then restart Claude Desktop.

### ***5. Connect***

Open the target in Ghidra, start the GhidraMCP server, and verify that the Ghidra MCP tools are available from Claude.



---
---
---



<div id='Workflow'/>

## ***🔁 Analysis Workflow***

Inspect should start from concrete Hunt evidence.

If `BehemothCustomImageLoadHunter` identifies:

``` text
FUN_000014a0
	|
	+-- LoadImage(...)
	|
	+-- StartImage(...)
```

use that finding as the investigation anchor:

``` text
Analyze this function and its surrounding code.

Trace the origin of the DevicePath passed to LoadImage.

Show the callers and callees involved in this path.

Identify validation performed before the image is loaded.

Determine which relevant values may be externally controlled.

Try to disprove the current vulnerability hypothesis using program evidence.
```

The objective is not to make the model guess. It is to use AI as another interface for exploring the evidence already available inside Ghidra.



---
---
---



<div id='Validation'/>

## ***🧠 Human Validation***

LLM output is not ground truth. A model can misunderstand pseudocode, infer an incorrect type, miss validation elsewhere, or overstate a relationship.

``` text
AI-Assisted Hypothesis
        |
        v
Ghidra Evidence
        |
        v
Manual Reverse Engineering
        |
        v
Reachability + Control + Validation
        |
        v
Exploitability
```

Behemoth uses automation and AI to reduce repetitive work and narrow the search space.

**The final step is still reverse engineering.**
