// Discovers dangerous UEFI Shell commands, command descriptors, handlers, and associated firmware capabilities.
// @author TheMalwareGuardian
// @category UEFI

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

import java.util.*;
import java.util.regex.*;

public class ScriptHunt01BehemothShellCommandHunter extends GhidraScript {

	private static final int DECOMPILE_TIMEOUT = 30;
	private static final int MAX_STRING_CHARS = 64;
	private static final int MAX_HANDLER_REFS = 32;
	private static final int MAX_TABLE_PTR_HITS = 64;
	private static final int MAX_DESCRIPTOR_SLOTS = 6;
	private static final int MAX_CODE_XREFS_PER_COMMAND = 64;

	private static final boolean DEBUG_HANDLER = false;

	enum Severity { CRITICAL, HIGH, MEDIUM, LOW }

	static class CmdSpec {
		final Severity sev;
		final String reason;
		CmdSpec(Severity sev, String reason) { this.sev = sev; this.reason = reason; }
	}

	private static final Map<String, CmdSpec> CATALOG = new LinkedHashMap<>();
	static {

		CATALOG.put("mm", new CmdSpec(Severity.CRITICAL,
			"Memory Modify: arbitrary read/write of system memory, I/O ports, PCI/PCIe config and MMIO"));
		CATALOG.put("load", new CmdSpec(Severity.CRITICAL,
			"Loads and starts a UEFI driver image from a file (arbitrary code in firmware context)"));
		CATALOG.put("loadpcirom", new CmdSpec(Severity.CRITICAL,
			"Loads a PCI option ROM image (untrusted OpROM code execution)"));

		CATALOG.put("dmem", new CmdSpec(Severity.HIGH,
			"Dumps arbitrary memory (secret and layout disclosure)"));
		CATALOG.put("setvar", new CmdSpec(Severity.HIGH,
			"Creates, deletes or overwrites UEFI variables (NVRAM tampering)"));
		CATALOG.put("dmpstore", new CmdSpec(Severity.HIGH,
			"Dumps and can restore all UEFI variables (bulk NVRAM read / rewrite)"));
		CATALOG.put("bcfg", new CmdSpec(Severity.HIGH,
			"Modifies Boot#### / Driver#### options and order (boot persistence)"));
		CATALOG.put("dblk", new CmdSpec(Severity.HIGH,
			"Reads raw blocks from block devices (filesystem bypass, disk disclosure)"));
		CATALOG.put("hexedit", new CmdSpec(Severity.HIGH,
			"In-place hex editor for files, block devices and memory"));

		CATALOG.put("pci", new CmdSpec(Severity.MEDIUM,
			"Reads PCI configuration space (hardware inventory / info disclosure)"));
		CATALOG.put("memmap", new CmdSpec(Severity.MEDIUM,
			"Reveals the physical memory map"));
		CATALOG.put("smbiosview", new CmdSpec(Severity.MEDIUM,
			"Reveals SMBIOS platform data"));
		CATALOG.put("drvcfg", new CmdSpec(Severity.MEDIUM,
			"Invokes driver configuration entry points"));
		CATALOG.put("edit", new CmdSpec(Severity.MEDIUM,
			"Full-screen editor able to create and overwrite files"));
		CATALOG.put("ifconfig", new CmdSpec(Severity.MEDIUM,
			"Configures network interfaces (enables egress)"));
		CATALOG.put("ping", new CmdSpec(Severity.MEDIUM,
			"Network reachability (egress signal)"));
		CATALOG.put("tftp", new CmdSpec(Severity.MEDIUM,
			"Transfers files over the network (exfiltration / staging)"));
		CATALOG.put("http", new CmdSpec(Severity.MEDIUM,
			"Transfers files over HTTP (exfiltration / staging)"));

		CATALOG.put("dh", new CmdSpec(Severity.LOW,
			"Lists handles and installed protocols (reconnaissance)"));
		CATALOG.put("devices", new CmdSpec(Severity.LOW,
			"Enumerates devices (reconnaissance)"));
	}

	static class CodeTarget {
		Address slot;
		Address target;
		Function function;
		String symbol;
		int relativeSlot;
		int score;
		boolean executable;
		final List<String> why = new ArrayList<>();
	}

	static class DescriptorInfo {
		Address address;
		final List<CodeTarget> targets = new ArrayList<>();
	}

	static class Handler {
		Function function;
		Address rawTarget;
		String rawSymbol;
		Function registrar;
		String site;
		String method;
		int confidence;
		final Set<String> capabilities = new LinkedHashSet<>();

		String key() {
			return (function == null ? "?" : function.getEntryPoint().toString());
		}
	}

	static class Finding {
		String command;
		CmdSpec spec;
		final List<Address> stringAddresses = new ArrayList<>();
		final Map<String, Handler> handlers = new LinkedHashMap<>();
		Map<String, DescriptorInfo> descriptors = new LinkedHashMap<>();
	}

	private final Map<String, String> decompiled = new HashMap<>();
	private final Map<String, Function> functionsByName = new HashMap<>();
	private final Map<String, Finding> findings = new LinkedHashMap<>();
	private DecompInterface decompiler;

	private java.io.PrintWriter report;
	private String reportPath;

	@Override
	public void println(String message) {
		super.println(message);
		if (report != null) report.println(message);
	}

	private void openReport() {
		try {
			String name = currentProgram.getName();
			java.io.File dir = new java.io.File(System.getProperty("user.home"));
			java.io.File f = new java.io.File(dir, name + ".behemoth-shell.txt");
			report = new java.io.PrintWriter(new java.io.FileWriter(f));
			reportPath = f.getAbsolutePath();
		} catch (Exception e) {
			report = null;
			reportPath = null;
		}
	}

	private void closeReport() {
		if (report != null) { report.flush(); report.close(); report = null; }
		if (reportPath != null)
			super.println("[+] Full report written to: " + reportPath);
	}

	private int functionsVisited;
	private int functionsDecompiled;

	@Override
	public void run() throws Exception {
		openReport();
		printHeader();

		decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		if (!decompiler.openProgram(currentProgram)) {
			printerr("[X] Could not initialize the decompiler.");
			closeReport();
			return;
		}

		try {
			decompileProgram();
			scanForCommands();
			resolveHandlers();
			printReport();
		} finally {
			decompiler.dispose();
			closeReport();
		}
	}

	private void printHeader() {
		println("========================================================================");
		println(" BEHEMOTH - UEFI SHELL DANGEROUS-COMMAND HUNTER");
		println("========================================================================");
		println(" Target        " + currentProgram.getName());
		println(" Architecture  " +
			(currentProgram.getDefaultPointerSize() == 8 ? "X64" :
			currentProgram.getDefaultPointerSize() == 4 ? "IA32" : "Unknown"));
		println(" Analysis      READ-ONLY");
		println("========================================================================");
		println("");
	}

	private void decompileProgram() {
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Function f = it.next();
			functionsVisited++;
			DecompileResults dr = decompiler.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
			if (dr == null || !dr.decompileCompleted() || dr.getDecompiledFunction() == null) continue;
			functionsDecompiled++;
			decompiled.put(f.getEntryPoint().toString(), dr.getDecompiledFunction().getC());
			functionsByName.put(f.getName(), f);
		}
	}

	private String decompiledC(Function f) {
		if (f == null) return null;
		String key = f.getEntryPoint().toString();
		String c = decompiled.get(key);
		if (c != null) return c;
		DecompileResults dr = decompiler.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
		if (dr == null || !dr.decompileCompleted() || dr.getDecompiledFunction() == null) return null;
		c = dr.getDecompiledFunction().getC();
		decompiled.put(key, c);
		return c;
	}

	private void scanForCommands() {
		Memory mem = currentProgram.getMemory();
		for (Map.Entry<String, CmdSpec> e : CATALOG.entrySet()) {
			if (monitor.isCancelled()) break;
			String cmd = e.getKey();
			byte[] pattern = char16WithTerminator(cmd);
			byte[] masks = fullMask(pattern.length);

			Address at = currentProgram.getMinAddress();
			while (at != null && !monitor.isCancelled()) {
				Address found = mem.findBytes(at, pattern, masks, true, monitor);
				if (found == null) break;

				if (isStringStart(mem, found)) {
					Finding f = findings.computeIfAbsent(cmd, k -> {
						Finding nf = new Finding();
						nf.command = k;
						nf.spec = e.getValue();
						return nf;
					});
					if (!f.stringAddresses.contains(found)) f.stringAddresses.add(found);
				}
				at = found.add(2);
			}
		}
	}

	private boolean isStringStart(Memory mem, Address found) {
		try {
			Address prev = found.subtract(2);
			int lo = mem.getByte(prev) & 0xff;
			int hi = mem.getByte(prev.add(1)) & 0xff;
			if (hi == 0 && isIdentByte(lo)) return false;
		} catch (Exception ex) {

		}
		return true;
	}

	private static boolean isIdentByte(int b) {
		return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') ||
			(b >= 'a' && b <= 'z') || b == '_';
	}

	private void resolveHandlers() {
		for (Finding f : findings.values()) {
			if (monitor.isCancelled()) break;
			for (Address strAddr : f.stringAddresses) {
				resolveHandlerForString(f, strAddr);
				if (f.handlers.size() >= MAX_HANDLER_REFS) break;
			}
		}
	}

	private void resolveHandlerForString(Finding f, Address strAddr) {
		ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(strAddr);
		Set<String> seenFunctions = new HashSet<>();

		if (DEBUG_HANDLER) {
			int refCount = 0;
			ReferenceIterator di = currentProgram.getReferenceManager().getReferencesTo(strAddr);
			for (Reference r : (Iterable<Reference>) () -> di) {
				refCount++;
				Function rf = getFunctionContaining(r.getFromAddress());
				println("[hdlr] " + f.command + " @ " + strAddr + " <- ref from " +
					r.getFromAddress() + " in " +
					(rf == null ? "<no function>" : displayFunction(rf)));
			}
			if (refCount == 0)
				println("[hdlr] " + f.command + " @ " + strAddr + " <- NO Ghidra references");
		}

		for (Reference ref : (Iterable<Reference>) () -> refs) {
			if (monitor.isCancelled()) break;
			Function rf = getFunctionContaining(ref.getFromAddress());
			if (rf == null) continue;
			if (!seenFunctions.add(rf.getEntryPoint().toString())) continue;

			String c = decompiledC(rf);
			if (c == null) continue;

			for (String hexForm : addressHexForms(strAddr)) {
				for (String line : c.split("\\R")) {
					if (!containsAddressForm(line, hexForm)) continue;
					String call = enclosingCallContaining(line, hexForm);
					if (call == null) continue;
					Function handler = firstFunctionArg(call, hexForm);
					if (handler == null) continue;
					recordHandler(f, handler, rf, line.trim(), "direct registrar xref");
				}
			}
		}

		for (Map.Entry<String, String> entry : decompiled.entrySet()) {
			String c = entry.getValue();
			if (!c.contains("ShellCommandRegisterCommandName")) continue;
			Function rf = functionAt(entry.getKey());
			if (rf == null) continue;

			Matcher m = Pattern.compile("ShellCommandRegisterCommandName\\s*\\(").matcher(c);
			while (m.find()) {
				int open = c.indexOf('(', m.end() - 1);
				int close = findMatchingParen(c, open);
				if (open < 0 || close < 0) continue;

				String argsRegion = c.substring(open + 1, close);
				boolean matchesName = false;
				String matchedForm = null;
				for (String hexForm : addressHexForms(strAddr)) {
					if (containsAddressForm(argsRegion, hexForm)) {
						matchesName = true;
						matchedForm = hexForm;
						break;
					}
				}
				if (!matchesName) continue;

				List<String> args = splitArgs(argsRegion);
				if (args.size() >= 2) {

					Function handler = argToFunction(args.get(1));
					if (handler == null && matchedForm != null)
						handler = firstFunctionArg(argsRegion, matchedForm);
					if (handler != null)
						recordHandler(f, handler, rf,
							"ShellCommandRegisterCommandName(...)", "named registrar");
				}
			}
		}

		recoverHandlersFromCommandTables(f, strAddr);
	}

	private void recoverHandlersFromCommandTables(Finding f, Address strAddr) {
		int ps = currentProgram.getDefaultPointerSize();
		if (ps != 4 && ps != 8) return;

		LinkedHashSet<Address> descriptors = new LinkedHashSet<>();

		ReferenceIterator ri =
			currentProgram.getReferenceManager().getReferencesTo(strAddr);

		for (Reference r : (Iterable<Reference>) () -> ri) {
			Address from = r.getFromAddress();
			if (from == null) continue;

			Function owner = getFunctionContaining(from);
			if (owner == null) {

				descriptors.add(from);
			}
		}

		if (descriptors.isEmpty())
			descriptors.addAll(findRawStringPointerLocations(strAddr, ps));

		Set<String> commandCodeFunctions = codeFunctionsReferencing(strAddr);

		if (DEBUG_HANDLER) {
			println("[hdlr] " + f.command + " @ " + strAddr +
				" descriptors=" + descriptors.size() +
				", code-functions=" + commandCodeFunctions.size());
		}

		for (Address descriptor : descriptors) {
			resolveDescriptor(f, strAddr, descriptor, ps, commandCodeFunctions);
		}
	}

	private Set<Address> findRawStringPointerLocations(Address strAddr, int ps) {
		LinkedHashSet<Address> out = new LinkedHashSet<>();
		Memory mem = currentProgram.getMemory();

		byte[] ptrPattern = pointerBytes(strAddr.getOffset(), ps);
		byte[] mask = fullMask(ptrPattern.length);

		Address cursor = currentProgram.getMinAddress();
		int hits = 0;

		while (cursor != null && hits < MAX_TABLE_PTR_HITS && !monitor.isCancelled()) {
			Address at = mem.findBytes(cursor, ptrPattern, mask, true, monitor);
			if (at == null) break;
			out.add(at);
			hits++;
			cursor = safeNext(at);
		}
		return out;
	}

	private Set<String> codeFunctionsReferencing(Address strAddr) {
		LinkedHashSet<String> out = new LinkedHashSet<>();
		ReferenceIterator refs =
			currentProgram.getReferenceManager().getReferencesTo(strAddr);

		int count = 0;
		for (Reference r : (Iterable<Reference>) () -> refs) {
			if (count++ >= MAX_CODE_XREFS_PER_COMMAND) break;
			Function fn = getFunctionContaining(r.getFromAddress());
			if (fn != null)
				out.add(fn.getEntryPoint().toString());
		}
		return out;
	}

	static class DescriptorCandidate {
		Address slot;
		Address targetAddress;
		Function function;
		String symbol;
		int relativeSlot;
		int score;
		boolean executable;
		final List<String> why = new ArrayList<>();
	}

	private void resolveDescriptor(Finding f,
								Address strAddr,
								Address descriptor,
								int ps,
								Set<String> commandCodeFunctions) {

		List<DescriptorCandidate> candidates = new ArrayList<>();

		for (int slotIndex = 1; slotIndex <= 2; slotIndex++) {
			Address slot;
			try {
				slot = descriptor.add((long) slotIndex * ps);
			} catch (Exception ex) {
				continue;
			}

			Long raw = readPointer(slot, ps);
			if (raw == null || raw == 0) continue;

			Address target;
			try {
				target = currentProgram.getAddressFactory()
					.getDefaultAddressSpace().getAddress(raw);
			} catch (Exception ex) {
				continue;
			}

			MemoryBlock block = currentProgram.getMemory().getBlock(target);
			boolean executable = block != null && block.isExecute();
			Function exact = getFunctionAt(target);
			Function containing = getFunctionContaining(target);

			DescriptorCandidate dc = new DescriptorCandidate();
			dc.slot = slot;
			dc.targetAddress = target;
			dc.relativeSlot = slotIndex;
			dc.executable = executable;
			dc.function = exact != null ? exact : containing;
			dc.symbol = symbolNameAt(target);

			if (executable) {
				dc.score += 30;
				dc.why.add("executable target");
			}

			if (exact != null) {
				dc.score += 25;
				dc.why.add("exact function entry");
			} else if (containing != null) {
				dc.score += 10;
				dc.why.add("inside defined function");
			} else if (executable) {
				dc.score += 10;
				dc.why.add("code target not defined as Function");
			}

			if (dc.function != null &&
				commandCodeFunctions.contains(dc.function.getEntryPoint().toString())) {
				dc.score += 100;
				dc.why.add("function references command string");
			}

			if (dc.function != null &&
				functionCallsAny(dc.function, commandCodeFunctions)) {
				dc.score += 35;
				dc.why.add("calls command-correlated function");
			}

			candidates.add(dc);
		}

		if (candidates.isEmpty()) {
			if (DEBUG_HANDLER)
				println("[hdlr] " + f.command + " descriptor @" + descriptor +
					" -> no readable code-target fields");
			return;
		}

		boolean hasExecutableTarget = false;
		for (DescriptorCandidate c : candidates)
			if (c.executable) hasExecutableTarget = true;

		if (!hasExecutableTarget) {
			if (DEBUG_HANDLER)
				printDescriptorCandidates(f.command, descriptor, candidates);
			return;
		}

		candidates.sort((a, b) -> Integer.compare(b.score, a.score));

		recordDescriptorEvidence(f, descriptor, candidates);

		DescriptorCandidate best = candidates.get(0);
		DescriptorCandidate second = candidates.size() > 1 ? candidates.get(1) : null;

		boolean correlated =
			best.why.contains("function references command string");

		boolean uniquelyExact =
			best.why.contains("exact function entry") &&
			(second == null || !second.why.contains("exact function entry"));

		if (correlated || uniquelyExact) {
			String evidence =
				"descriptor @" + descriptor +
				", handler-ptr @" + best.slot +
				", target " + best.targetAddress +
				", score " + best.score +
				" [" + String.join("; ", best.why) + "]";

			if (best.function != null && best.function.getEntryPoint().equals(best.targetAddress)) {
				recordHandler(f, best.function, null, evidence,
					correlated ? "xref-correlated table" : "descriptor handler",
					best.score);
			} else {
				recordRawHandler(f, best.targetAddress, best.symbol, evidence,
					correlated ? "xref-correlated table" : "descriptor handler",
					best.score);
			}
		}

		if (DEBUG_HANDLER)
			printDescriptorCandidates(f.command, descriptor, candidates);
	}

	private void recordDescriptorEvidence(Finding f,
										Address descriptor,
										List<DescriptorCandidate> candidates) {
		if (f.descriptors == null)
			f.descriptors = new LinkedHashMap<>();

		DescriptorInfo di = new DescriptorInfo();
		di.address = descriptor;

		for (DescriptorCandidate c : candidates) {
			CodeTarget ct = new CodeTarget();
			ct.slot = c.slot;
			ct.target = c.targetAddress;
			ct.relativeSlot = c.relativeSlot;
			ct.symbol = c.symbol;
			ct.executable = c.executable;
			ct.function = c.function;
			ct.score = c.score;
			ct.why.addAll(c.why);
			di.targets.add(ct);
		}

		f.descriptors.put(descriptor.toString(), di);
	}

	private String symbolNameAt(Address a) {
		if (a == null) return null;
		Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
		if (s != null) return s.getName();
		Function exact = getFunctionAt(a);
		if (exact != null) return exact.getName();
		return null;
	}

	private void recordRawHandler(Finding f,
								Address target,
								String symbol,
								String site,
								String method,
								int confidence) {
		if (target == null) return;

		Handler h = new Handler();
		h.rawTarget = target;
		h.rawSymbol = symbol;
		h.site = site;
		h.method = method;
		h.confidence = confidence;

		Handler existing = f.handlers.get(h.key());
		if (existing == null || confidence > existing.confidence)
			f.handlers.put(h.key(), h);
	}

	private boolean functionCallsAny(Function fn, Set<String> targetEntries) {
		if (fn == null || targetEntries == null || targetEntries.isEmpty())
			return false;

		InstructionIterator it =
			currentProgram.getListing().getInstructions(fn.getBody(), true);

		while (it.hasNext()) {
			Instruction ins = it.next();
			for (Reference r : ins.getReferencesFrom()) {
				if (!r.getReferenceType().isCall()) continue;
				Address to = r.getToAddress();
				if (to != null && targetEntries.contains(to.toString()))
					return true;
			}
		}
		return false;
	}

	private void printDescriptorCandidates(String command,
										Address descriptor,
										List<DescriptorCandidate> candidates) {
		println("[hdlr] descriptor targets for " + command + " @" + descriptor);
		for (DescriptorCandidate c : candidates) {
			println("[hdlr]   +" + String.format("0x%02x", c.relativeSlot *
				currentProgram.getDefaultPointerSize()) +
				" @" + c.slot +
				" -> " + c.targetAddress +
				" (" + (c.symbol == null ? "<no symbol>" : c.symbol) + ")" +
				" exec=" + c.executable +
				" score=" + c.score +
				" [" + String.join("; ", c.why) + "]");
		}
	}

	private Address safeNext(Address a) {
		try {
			return a.add(1);
		} catch (Exception ex) {
			return null;
		}
	}

	private byte[] pointerBytes(long value, int pointerSize) {
		byte[] out = new byte[pointerSize];
		for (int i = 0; i < pointerSize; i++)
			out[i] = (byte) ((value >>> (8 * i)) & 0xff);
		return out;
	}

	private Long readPointer(Address at, int pointerSize) {
		try {
			long v = 0;
			for (int i = 0; i < pointerSize; i++)
				v |= ((long) currentProgram.getMemory().getByte(at.add(i)) & 0xffL) << (8 * i);
			return v;
		} catch (Exception ex) {
			return null;
		}
	}

	private Function functionAtOffset(long off) {
		try {
			Address a = currentProgram.getAddressFactory()
				.getDefaultAddressSpace().getAddress(off);
			if (a == null) return null;
			return currentProgram.getFunctionManager().getFunctionAt(a);
		} catch (Exception ex) {
			return null;
		}
	}

	private boolean containsAddressForm(String text, String hexForm) {
		if (text == null || hexForm == null) return false;
		String t = text.toLowerCase(Locale.ROOT);
		String h = hexForm.toLowerCase(Locale.ROOT);
		return t.contains(h) || t.contains("0x" + h);
	}

	private void recordHandler(Finding f, Function handler, Function registrar,
							String site, String method) {
		recordHandler(f, handler, registrar, site, method, 0);
	}

	private void recordHandler(Finding f, Function handler, Function registrar,
							String site, String method, int confidence) {
		if (handler == null) return;

		Handler h = new Handler();
		h.function = handler;
		h.registrar = registrar;
		h.site = site;
		h.method = method;
		h.confidence = confidence;
		h.capabilities.addAll(inspectHandlerCapabilities(handler));

		Handler existing = f.handlers.get(h.key());
		if (existing == null) {
			f.handlers.put(h.key(), h);
		} else {
			if (existing.registrar == null && registrar != null)
				existing.registrar = registrar;

			if (confidence > existing.confidence) {
				existing.site = site;
				existing.method = method;
				existing.confidence = confidence;
			} else {
				if (existing.site == null && site != null) existing.site = site;
				if (existing.method == null && method != null) existing.method = method;
			}

			existing.capabilities.addAll(h.capabilities);
		}
	}

	private Set<String> inspectHandlerCapabilities(Function handler) {
		Set<String> caps = new LinkedHashSet<>();
		String c = decompiledC(handler);
		if (c == null) return caps;

		if (Pattern.compile("\\b(IoRead(8|16|32|64)|IoWrite(8|16|32|64)|__inbyte|__outbyte|CpuIo)\\b")
				.matcher(c).find())
			caps.add("I/O port access");
		if (Pattern.compile("\\b(MmioRead(8|16|32|64)|MmioWrite(8|16|32|64))\\b").matcher(c).find())
			caps.add("MMIO access");
		if (Pattern.compile("\\b(PciRead|PciWrite|PciSegment|Pci(Cfg|Config|Io))\\b").matcher(c).find())
			caps.add("PCI config access");
		if (c.contains("SetVariable")) caps.add("UEFI variable write");
		if (Pattern.compile("\\b(CopyMem|SetMem|memcpy|memset|memmove)\\b").matcher(c).find())
			caps.add("bulk memory copy/fill");

		if (Pattern.compile("\\*\\s*\\([^)]*\\*\\)\\s*\\(?[A-Za-z0-9_]+(?:\\s*\\+\\s*[^)]+)?\\)?\\s*=")
				.matcher(c).find())
			caps.add("pointer write observed [weak]");
		if (Pattern.compile("\\b(LoadImage|StartImage)\\b").matcher(c).find())
			caps.add("image load/start");
		return caps;
	}

	private String displayHandler(Handler h) {
		if (h == null) return "<null>";
		if (h.function != null) return displayFunction(h.function);
		if (h.rawTarget != null) {
			if (h.rawSymbol != null)
				return h.rawSymbol + " @ " + h.rawTarget;
			return h.rawTarget.toString();
		}
		return "<unresolved>";
	}

	private String resolutionLabel(Handler h) {
		if (h == null || h.method == null) return "HANDLER_CANDIDATE";
		if ("xref-correlated table".equals(h.method)) return "HANDLER_RESOLVED";
		if ("descriptor handler".equals(h.method)) return "HANDLER_CANDIDATE";
		if ("command table".equals(h.method)) return "TABLE_RESOLVED";
		if ("named registrar".equals(h.method)) return "REGISTRAR_RESOLVED";
		if ("direct registrar xref".equals(h.method)) return "REGISTRAR_RESOLVED";
		return "HANDLER_CANDIDATE";
	}

	private static String jsonEsc(String s) {
		if (s == null) return "";
		StringBuilder b = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':  b.append("\\\""); break;
				case '\\': b.append("\\\\"); break;
				case '\n': b.append("\\n"); break;
				case '\r': b.append("\\r"); break;
				case '\t': b.append("\\t"); break;
				default: if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
			}
		}
		return b.toString();
	}

	private String finding(String severity, String name, String description, String location) {
		StringBuilder b = new StringBuilder("{");
		b.append("\"severity\": \"").append(jsonEsc(severity)).append("\", ");
		b.append("\"name\": \"").append(jsonEsc(name)).append("\", ");
		b.append("\"description\": \"").append(jsonEsc(description)).append("\"");
		if (location != null) b.append(", \"location\": \"").append(jsonEsc(location)).append("\"");
		return b.append("}").toString();
	}

	private void writeJsonReport(String suffix, String detector, String summaryJson, java.util.List<String> objs) {
		try {
			String name = currentProgram.getName();
			java.io.File f = new java.io.File(System.getProperty("user.home"), name + suffix);
			java.io.PrintWriter w = new java.io.PrintWriter(new java.io.FileWriter(f));
			StringBuilder b = new StringBuilder("{\n");
			b.append("  \"target\": \"").append(jsonEsc(name)).append("\",\n");
			b.append("  \"detector\": \"").append(jsonEsc(detector)).append("\",\n");
			if (summaryJson != null) b.append("  \"summary\": ").append(summaryJson).append(",\n");
			b.append("  \"findings\": [");
			for (int i = 0; i < objs.size(); i++) b.append(i == 0 ? "\n    " : ",\n    ").append(objs.get(i));
			b.append(objs.isEmpty() ? "]\n}\n" : "\n  ]\n}\n");
			w.print(b.toString());
			w.flush(); w.close();
			super.println("[+] JSON report written to: " + f.getAbsolutePath());
		} catch (Exception e) { /* best effort */ }
	}

	private void printReport() {
		List<Finding> ordered = new ArrayList<>(findings.values());
		ordered.sort(Comparator.comparingInt(a -> a.spec.sev.ordinal()));

		int crit = 0, high = 0, med = 0, low = 0;
		for (Finding f : ordered) {
			switch (f.spec.sev) {
				case CRITICAL: crit++; break;
				case HIGH: high++; break;
				case MEDIUM: med++; break;
				case LOW: low++; break;
			}
		}

		if (ordered.isEmpty()) {
			println(" No catalogued dangerous shell commands were found in this image.");
		} else {
			println(" DANGEROUS COMMANDS FOUND");
			println("------------------------------------------------------------------------");
			for (Finding f : ordered) {
				println("");
				println(" [" + f.spec.sev + "] " + f.command);
				println("   Reason      " + f.spec.reason);

				StringBuilder addrs = new StringBuilder();
				for (Address a : f.stringAddresses) {
					if (addrs.length() > 0) addrs.append(", ");
					addrs.append(a.toString());
				}
				println("   Name at     " + addrs);
				println("");

				boolean hasDescriptor = f.descriptors != null && !f.descriptors.isEmpty();

				if (!hasDescriptor && f.handlers.isEmpty()) {
					println("   Resolution  PRESENCE_ONLY");
					println("   Handler     unresolved");
					println("     Evidence  command-name string present; registration/table relationship not recovered");
				} else {
					if (hasDescriptor) {
						println("   Resolution  TABLE_RESOLVED");
						for (DescriptorInfo di : f.descriptors.values()) {
							println("   Descriptor  " + di.address);
							for (CodeTarget ct : di.targets) {
								String off = String.format("+0x%02x",
									ct.relativeSlot * currentProgram.getDefaultPointerSize());
								println("     Code target " + off);
								println("       Address     " + ct.target);
								println("       Symbol      " +
									(ct.symbol == null ? "<undefined>" : ct.symbol));
								println("       Executable  " + (ct.executable ? "yes" : "no"));
							}
						}
					}

					if (f.handlers.isEmpty()) {
						println("");
						println("   Handler     unresolved");
						println("     Evidence  descriptor recovered, but code-target role is not uniquely proven");
					} else {
						println("");
						int handlerIndex = 0;
						for (Handler h : f.handlers.values()) {
							if (handlerIndex++ > 0) println("");
							println("   Handler     " + displayHandler(h));
							println("     Resolution  " + resolutionLabel(h));
							if (h.method != null)
								println("     Method      " + h.method);
							if (h.registrar != null)
								println("     Registrar   " + displayFunction(h.registrar));
							if (h.site != null)
								println("     Evidence    " + h.site);
							List<String> strongCaps = new ArrayList<>();
							for (String cap : h.capabilities)
								if (!cap.contains("[weak]")) strongCaps.add(cap);
							if (!strongCaps.isEmpty())
								println("     Capability  " + String.join(", ", strongCaps) + "  (hint)");
						}
					}
				}
			}
		}

		println("");
		println("========================================================================");
		println(" SUMMARY");
		println("========================================================================");
		println("");
		println(" Analysis");
		println("   Functions .......... " + functionsDecompiled + " / " + functionsVisited);
		println("   Catalog size ....... " + CATALOG.size() + " dangerous commands");
		println("");
		println(" Findings");
		println("   Total .............. " + ordered.size());
		println("   CRITICAL ........... " + crit);
		println("   HIGH ............... " + high);
		println("   MEDIUM ............. " + med);
		println("   LOW ................ " + low);

		int resolved = 0;
		int tableResolved = 0;
		int registrarResolved = 0;
		int handlerResolved = 0;

		for (Finding f : ordered) {
			boolean table = f.descriptors != null && !f.descriptors.isEmpty();
			boolean registrar = false;

			if (table) tableResolved++;
			if (!f.handlers.isEmpty()) {
				handlerResolved++;
				for (Handler h : f.handlers.values()) {
					if ("named registrar".equals(h.method) ||
						"direct registrar xref".equals(h.method)) registrar = true;
				}
			}
			if (registrar) registrarResolved++;
			if (table || !f.handlers.isEmpty()) resolved++;
		}

		println("");
		println(" Resolution");
		println("   Descriptor/table ... " + tableResolved);
		println("   Handler candidate .. " + handlerResolved);
		println("   Registrar .......... " + registrarResolved);
		println("   Presence only ...... " + (ordered.size() - resolved));

		Severity highestConfirmed = null;
		for (Finding f : ordered) {
			boolean confirmed = (f.descriptors != null && !f.descriptors.isEmpty()) ||
								!f.handlers.isEmpty();
			if (!confirmed) continue;
			if (highestConfirmed == null ||
				f.spec.sev.ordinal() < highestConfirmed.ordinal())
				highestConfirmed = f.spec.sev;
		}

		println("   Highest confirmed .. " +
			(highestConfirmed == null ? "none" : highestConfirmed.toString()));
		println("");

		String verdict;

		int confirmedCritical = 0;
		int confirmedHigh = 0;
		int confirmedMedium = 0;
		int confirmedLow = 0;

		for (Finding f : ordered) {
			boolean confirmed = (f.descriptors != null && !f.descriptors.isEmpty()) ||
								!f.handlers.isEmpty();
			if (!confirmed) continue;
			switch (f.spec.sev) {
				case CRITICAL: confirmedCritical++; break;
				case HIGH: confirmedHigh++; break;
				case MEDIUM: confirmedMedium++; break;
				case LOW: confirmedLow++; break;
			}
		}

		if (confirmedCritical > 0 || confirmedHigh > 0)
			verdict = "FAIL - dangerous shell command exposure confirmed";
		else if (confirmedMedium > 0 || confirmedLow > 0)
			verdict = "WARN - dangerous command exposure confirmed; review before signing";
		else if (!ordered.isEmpty())
			verdict = "WARN - dangerous command names present, but registration/reachability is unconfirmed";
		else
			verdict = "PASS - no catalogued dangerous commands";

		println(" VERDICT");
		println("   " + verdict);
		println("");
		println(" Validation");
		println("   TABLE_RESOLVED proves a command descriptor with executable code targets.");
		println("   Handler candidate is reported only when one target is structurally distinguished.");
		println("   Presence-only findings are candidates, not proof of command reachability.");
		println("   Validate shell reachability and execution path before final judgement.");
		println("");
		println("========================================================================");

		java.util.List<String> fj = new java.util.ArrayList<>();
		for (Finding f : ordered) {
			boolean isResolved = (f.descriptors != null && !f.descriptors.isEmpty()) || !f.handlers.isEmpty();
			String desc = f.spec.reason + (isResolved
				? " [resolution: " + ((f.descriptors != null && !f.descriptors.isEmpty()) ? "descriptor/table" : "handler") + "]"
				: " [presence-only: registration/reachability unconfirmed]");
			String loc = f.stringAddresses.isEmpty() ? null : f.stringAddresses.get(0).toString();
			fj.add(finding(f.spec.sev.toString().toLowerCase(Locale.ROOT), f.command, desc, loc));
		}
		String sum = String.format("{\"critical\": %d, \"high\": %d, \"medium\": %d, \"low\": %d, \"total\": %d}",
			crit, high, med, low, ordered.size());
		writeJsonReport(".behemoth-shell.json", "behemoth-shell", sum, fj);

	}

	private String enclosingCallContaining(String line, String needle) {
		Matcher m = Pattern.compile("\\b([A-Za-z_][A-Za-z0-9_]*)\\s*\\(").matcher(line);
		while (m.find()) {
			int open = line.indexOf('(', m.end() - 1);
			int close = findMatchingParen(line, open);
			if (open < 0 || close < 0) continue;
			String inside = line.substring(open + 1, close);
			if (inside.contains(needle)) return inside;
		}
		return null;
	}

	private Function firstFunctionArg(String argsRegion, String nameNeedle) {
		for (String arg : splitArgs(argsRegion)) {
			if (arg.contains(nameNeedle)) continue;
			Function fn = argToFunction(arg);
			if (fn != null) return fn;
		}
		return null;
	}

	private Function argToFunction(String arg) {
		if (arg == null) return null;

		String a = arg.trim();

		for (int i = 0; i < 4; i++) {
			String b = a.replaceFirst("^\\([^()]*\\)\\s*", "").trim();
			if (b.equals(a)) break;
			a = b;
		}
		a = a.replace("&", "").trim();

		Matcher fm = Pattern.compile("\\bFUN_([0-9A-Fa-f]+)\\b").matcher(a);
		if (fm.find()) {
			Function fn = functionAt(fm.group(1));
			if (fn != null) return fn;
		}

		Matcher id = Pattern.compile("^([A-Za-z_][A-Za-z0-9_]*)$").matcher(a);
		if (id.find() && functionsByName.containsKey(id.group(1)))
			return functionsByName.get(id.group(1));

		Matcher raw = Pattern.compile("(?i)(?:0x)?([0-9a-f]{4,16})").matcher(a);
		while (raw.find()) {
			try {
				long off = Long.parseUnsignedLong(raw.group(1), 16);
				Function fn = functionAtOffset(off);
				if (fn != null) return fn;
			} catch (NumberFormatException ignored) {
			}
		}

		return null;
	}

	private List<String> addressHexForms(Address a) {
		long off = a.getOffset();
		List<String> forms = new ArrayList<>();
		forms.add(String.format("%08x", off));
		forms.add(Long.toHexString(off));
		LinkedHashSet<String> dedup = new LinkedHashSet<>(forms);
		return new ArrayList<>(dedup);
	}

	private Function functionAt(String hexOrKey) {
		try {
			Address ad = currentProgram.getAddressFactory()
				.getDefaultAddressSpace().getAddress(hexOrKey);
			return currentProgram.getFunctionManager().getFunctionAt(ad);
		} catch (Exception e) {
			return null;
		}
	}

	private static byte[] char16WithTerminator(String s) {
		byte[] out = new byte[(s.length() + 1) * 2];
		for (int i = 0; i < s.length(); i++) {
			out[i * 2] = (byte) s.charAt(i);
			out[i * 2 + 1] = 0;
		}
		out[s.length() * 2] = 0;
		out[s.length() * 2 + 1] = 0;
		return out;
	}

	private static byte[] fullMask(int len) {
		byte[] m = new byte[len];
		Arrays.fill(m, (byte) 0xff);
		return m;
	}

	@SuppressWarnings("unused")
	private String readChar16(Address a) {
		Memory mem = currentProgram.getMemory();
		StringBuilder sb = new StringBuilder();
		try {
			for (int i = 0; i < MAX_STRING_CHARS; i++) {
				int lo = mem.getByte(a.add(i * 2L)) & 0xff;
				int hi = mem.getByte(a.add(i * 2L + 1)) & 0xff;
				if (lo == 0 && hi == 0) break;
				sb.append(hi == 0 && lo >= 0x20 && lo < 0x7f ? (char) lo : '?');
			}
		} catch (MemoryAccessException ex) {

		}
		return sb.toString();
	}

	private String displayFunction(Function f) {
		if (f == null) return "?";
		String name = f.getName();
		String addr = f.getEntryPoint().toString();
		if (name != null && name.matches("(?i)FUN_0*" + Pattern.quote(addr))) return name;
		return name + " @ " + addr;
	}

	private static int findMatchingParen(String s, int open) {
		if (open < 0 || open >= s.length()) return -1;
		int depth = 0;
		boolean str = false, chr = false, esc = false;
		for (int i = open; i < s.length(); i++) {
			char c = s.charAt(i);
			if (esc) { esc = false; continue; }
			if ((str || chr) && c == '\\') { esc = true; continue; }
			if (!chr && c == '"') { str = !str; continue; }
			if (!str && c == '\'') { chr = !chr; continue; }
			if (str || chr) continue;
			if (c == '(') depth++;
			else if (c == ')' && --depth == 0) return i;
		}
		return -1;
	}

	private static List<String> splitArgs(String s) {
		List<String> out = new ArrayList<>();
		int p = 0, b = 0, r = 0, start = 0;
		boolean str = false, chr = false, esc = false;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (esc) { esc = false; continue; }
			if ((str || chr) && c == '\\') { esc = true; continue; }
			if (!chr && c == '"') { str = !str; continue; }
			if (!str && c == '\'') { chr = !chr; continue; }
			if (str || chr) continue;
			if (c == '(') p++;
			else if (c == ')') p--;
			else if (c == '[') b++;
			else if (c == ']') b--;
			else if (c == '{') r++;
			else if (c == '}') r--;
			else if (c == ',' && p == 0 && b == 0 && r == 0) {
				out.add(s.substring(start, i).trim());
				start = i + 1;
			}
		}
		out.add(s.substring(start).trim());
		return out;
	}
}
