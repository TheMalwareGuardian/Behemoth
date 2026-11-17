// Discovers UEFI NVRAM variables, read/write operations, field usage, and NVRAM-derived memory accesses.
// @author TheMalwareGuardian
// @category UEFI

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.*;
import java.util.regex.*;

public class ScriptHunt00BehemothVariableHunter extends GhidraScript {

	private static final int DECOMPILE_TIMEOUT = 30;
	private static final int MAX_INTERPROC_DEPTH = 1;
	private static final int MAX_EVENTS_PER_VARIABLE = 200;

	private static final boolean ANALYZE_POINTER_USE = true;

	private static final boolean POINTER_TAINT_CONSUMERS = false;

	private static final boolean DEBUG_POINTER_TAINT = false;
	private static final int MAX_POINTER_TAINT_PASSES = 8;

	private static final long EFI_VARIABLE_NON_VOLATILE = 0x01L;
	private static final long EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x02L;
	private static final long EFI_VARIABLE_RUNTIME_ACCESS = 0x04L;
	private static final long EFI_VARIABLE_HARDWARE_ERROR_RECORD = 0x08L;
	private static final long EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x10L;
	private static final long EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x20L;
	private static final long EFI_VARIABLE_APPEND_WRITE = 0x40L;
	private static final long EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS = 0x80L;

	enum EvidenceKind {
		FIELD_READ, FIELD_WRITE, CONTROL, GLOBAL_WRITE, DIRECT_CALL,
		MEMORY_SINK, UEFI_SINK, POINTER_SINK, RETURN, SIZE_OBSERVATION,
		GLOBAL_CONSUMER
	}

	static class VarOp {
		String service;
		String rawService;
		Function function;
		String name;
		String guid;
		String attributes;
		Long attributesValue;
		String dataSize;
		String data;
		String raw;

		String key() { return normalizeIdentity(name) + "|" + normalizeIdentity(guid); }
	}

	static class VariableRecord {
		final List<VarOp> reads = new ArrayList<>();
		final List<VarOp> writes = new ArrayList<>();
	}

	static class FieldAccess {
		String offset;
		boolean read;
		boolean write;
		String assignedVariable;
		String writeValue;
		String writeClass;
		String writeSource;
		boolean rhsIsStringLiteral;
	}

	static class Evidence {
		EvidenceKind kind;
		Function function;
		int depth;
		String field;
		String value;
		String expression;
		String detail;

		String writeValue;
		String writeClass;
		String writeSource;
		String phase = "UNKNOWN";
		int lineIndex = -1;
		int sequence = -1;

		String key() {
			return kind + "|" + (function == null ? "?" : function.getEntryPoint()) + "|" +
				depth + "|" + safe(field) + "|" + safe(value) + "|" +
				safe(expression) + "|" + safe(detail);
		}
	}

	static class DerivedMemoryAccess {
		boolean write;
		String offset;
		String value;
		String functionName;
		String instructionAddress;
		String instruction;
		String pcode;
		String base;
		String provenance;

		String key() {
			return (write ? "W" : "R") + "|" + safe(offset) + "|" +
				safe(instructionAddress) + "|" + safe(pcode);
		}
	}

	static class DirectCall { String name; List<String> args; }

	static class Analysis {
		VarOp read;
		final Set<String> bufferAliases = new LinkedHashSet<>();
		final Set<String> sizeAliases = new LinkedHashSet<>();
		final Map<String, Set<String>> fieldValues = new LinkedHashMap<>();
		final List<Evidence> evidence = new ArrayList<>();
		final Set<String> fieldReads = new TreeSet<>();
		final Set<String> fieldWrites = new TreeSet<>();
		final List<DerivedMemoryAccess> derivedMemoryAccesses = new ArrayList<>();
		String returnedStorage;
		boolean returnedValueUsedAsPointer;

		boolean controlsBranch;
		boolean reachesGlobal;
		boolean reachesMemorySink;
		boolean reachesUefiSink;
		boolean usedAsPointer;
		boolean crossesFunction;
		boolean evidenceTruncated;

		int sequenceCounter;
	}

	private final List<VarOp> operations = new ArrayList<>();
	private final Map<String, VariableRecord> records = new LinkedHashMap<>();
	private final Map<String, String> decompiled = new HashMap<>();
	private final Map<String, Function> functionsByName = new HashMap<>();
	private final Map<String, HighFunction> highFunctions = new HashMap<>();
	private final List<Analysis> analyses = new ArrayList<>();

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
			java.io.File f = new java.io.File(dir, name + ".behemoth-variables.txt");
			report = new java.io.PrintWriter(new java.io.FileWriter(f));
			reportPath = f.getAbsolutePath();
		} catch (Exception e) {
			report = null;
			reportPath = null;
		}
	}

	private void closeReport() {
		if (report != null) {
			report.flush();
			report.close();
			report = null;
		}
		if (reportPath != null)
			super.println("[+] Full report written to: " + reportPath);
	}

	private int functionsVisited;
	private int functionsDecompiled;
	private int decompileFailures;

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
			correlate();
			analyzeReads();
			int findings = printVariableReports();
			printSummary(findings);
		} finally {
			decompiler.dispose();
			closeReport();
		}
	}

	private void printHeader() {
		println("========================================================================");
		println(" BEHEMOTH - UEFI VARIABLE HUNTER");
		println("========================================================================");
		println(" Target        " + currentProgram.getName());
		println(" Architecture  " +
			(currentProgram.getDefaultPointerSize() == 8 ? "X64" :
			currentProgram.getDefaultPointerSize() == 4 ? "IA32" : "Unknown"));
		println(" Pointer Size  " + currentProgram.getDefaultPointerSize());
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
			if (dr == null || !dr.decompileCompleted() || dr.getDecompiledFunction() == null) {
				decompileFailures++;
				continue;
			}

			functionsDecompiled++;
			String c = dr.getDecompiledFunction().getC();
			String key = f.getEntryPoint().toString();
			decompiled.put(key, c);
			functionsByName.put(f.getName(), f);
			HighFunction hf = dr.getHighFunction();
			if (hf != null) highFunctions.put(key, hf);

			for (String svc : new String[] {
					"GetVariable", "SetVariable", "GetNextVariableName", "QueryVariableInfo",
					"SmmGetVariable", "SmmSetVariable", "SmmGetNextVariableName",
					"SmmQueryVariableInfo" }) {
				discoverService(f, c, svc);
			}
		}
	}

	private HighFunction getHighFunction(Function f) {
		if (f == null) return null;
		String key = f.getEntryPoint().toString();
		HighFunction hf = highFunctions.get(key);
		if (hf != null) return hf;

		DecompileResults dr = decompiler.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
		if (dr == null || !dr.decompileCompleted()) return null;
		hf = dr.getHighFunction();
		if (hf != null) highFunctions.put(key, hf);
		return hf;
	}

	private void discoverService(Function f, String c, String service) {
		Pattern p = Pattern.compile(
			"(?s)(?:\\(\\*\\s*)?(?:gRT|[A-Za-z_][A-Za-z0-9_]*)\\s*->\\s*" +
			Pattern.quote(service) + "\\s*\\)?\\s*\\(");

		Matcher m = p.matcher(c);
		while (m.find()) {
			int open = c.indexOf('(', m.end() - 1);
			if (open < 0) continue;
			int close = findMatchingParen(c, open);
			if (close < 0) continue;

			List<String> args = splitArgs(c.substring(open + 1, close));
			VarOp op = parseOperation(service, f, args, c.substring(m.start(), close + 1));
			if (op != null) operations.add(op);
		}
	}

	private VarOp parseOperation(String rawService, Function f, List<String> a, String raw) {
		String service = normalizeService(rawService);
		if (service == null) return null;

		VarOp op = new VarOp();
		op.service = service;
		op.rawService = rawService;
		op.function = f;
		op.raw = oneLine(raw);

		if ("GetVariable".equals(service)) {
			if (a.size() < 5) return null;
			op.name = clean(a.get(0));
			op.guid = clean(a.get(1));
			op.attributes = clean(a.get(2));
			op.dataSize = clean(a.get(3));
			op.data = clean(a.get(4));
		} else if ("SetVariable".equals(service)) {
			if (a.size() < 5) return null;
			op.name = clean(a.get(0));
			op.guid = clean(a.get(1));
			op.attributes = clean(a.get(2));
			op.attributesValue = parseAttributes(op.attributes);
			op.dataSize = clean(a.get(3));
			op.data = clean(a.get(4));
		} else if ("GetNextVariableName".equals(service)) {
			if (a.size() < 3) return null;
			op.dataSize = clean(a.get(0));
			op.name = clean(a.get(1));
			op.guid = clean(a.get(2));
		} else if ("QueryVariableInfo".equals(service)) {
			if (a.isEmpty()) return null;
			op.name = "<QueryVariableInfo>";
			op.guid = "<none>";
			op.attributes = clean(a.get(0));
			op.attributesValue = parseAttributes(op.attributes);
		} else {
			return null;
		}
		return op;
	}

	private static String normalizeService(String s) {
		if (s == null) return null;
		if (s.endsWith("GetNextVariableName")) return "GetNextVariableName";
		if (s.endsWith("QueryVariableInfo")) return "QueryVariableInfo";
		if (s.endsWith("GetVariable")) return "GetVariable";
		if (s.endsWith("SetVariable")) return "SetVariable";
		return null;
	}

	private void correlate() {
		for (VarOp op : operations) {
			if (!"GetVariable".equals(op.service) && !"SetVariable".equals(op.service)) continue;
			VariableRecord r = records.computeIfAbsent(op.key(), k -> new VariableRecord());
			if ("GetVariable".equals(op.service)) r.reads.add(op);
			else r.writes.add(op);
		}
	}

	private void analyzeReads() {
		for (VariableRecord record : records.values()) {
			for (VarOp read : record.reads) {
				Analysis a = new Analysis();
				a.read = read;

				String c = decompiled.get(read.function.getEntryPoint().toString());
				if (c == null) continue;

				a.bufferAliases.addAll(extractPointerRoots(read.data));
				a.sizeAliases.addAll(extractVariableTokens(read.dataSize));

				discoverBufferAliases(c, a.bufferAliases);
				if (ANALYZE_POINTER_USE) analyzeReturnedValuePointerUses(read, a);
				analyzeBufferFunction(read.function, c, a, 0, a.bufferAliases, true);
				analyzeGlobalBuffer(read, a);

				analyses.add(a);
			}
		}
	}

	private void analyzeReturnedValuePointerUses(VarOp read, Analysis a) {
		Address storage = parseGlobalStorageAddress(read.data);
		if (storage == null || read.function == null) return;

		a.returnedStorage = storage.toString();

		LinkedHashMap<String, DerivedMemoryAccess> unique = new LinkedHashMap<>();

		LinkedHashSet<Function> targets = new LinkedHashSet<>();
		targets.add(read.function);
		Set<Function> refFns = POINTER_TAINT_CONSUMERS ? functionsReferencing(storage)
													: java.util.Collections.emptySet();
		targets.addAll(refFns);

		if (DEBUG_POINTER_TAINT)
			println("[taint] storage=" + storage + " referencing functions=" + refFns.size() +
				" (analyzing " + targets.size() + " incl. reader)");

		for (Function f : targets) {
			if (f == null) continue;
			taintPointerUsesInFunction(f, storage, unique);
		}

		a.derivedMemoryAccesses.addAll(unique.values());
		a.returnedValueUsedAsPointer = !a.derivedMemoryAccesses.isEmpty();
	}

	private Set<Function> functionsReferencing(Address storage) {
		LinkedHashSet<Function> out = new LinkedHashSet<>();
		try {
			ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(storage);
			for (Reference ref : (Iterable<Reference>) () -> refs) {
				Function f = getFunctionContaining(ref.getFromAddress());
				if (f != null) out.add(f);
			}
		} catch (Exception ex) {

		}
		return out;
	}

	private void taintPointerUsesInFunction(
			Function f, Address storage, Map<String, DerivedMemoryAccess> unique) {

		HighFunction hf = getHighFunction(f);
		if (hf == null) return;

		Map<Varnode, Long> taintedPointers = new IdentityHashMap<>();
		Map<Varnode, String> provenance = new IdentityHashMap<>();

		if (DEBUG_POINTER_TAINT) {
			int shown = 0;
			Iterator<PcodeOpAST> di = hf.getPcodeOps();
			while (di.hasNext() && shown < 12) {
				PcodeOpAST op = di.next();
				boolean touches = false;
				for (int i = 0; i < op.getNumInputs(); i++) {
					Varnode in = op.getInput(i);
					if (in == null) continue;
					if (storage.equals(resolvePcodeAddress(in))) { touches = true; break; }
					if (in.isAddress() && storage.equals(in.getAddress())) { touches = true; break; }
					if (in.isConstant() && in.getOffset() == storage.getOffset()) { touches = true; break; }
				}
				if (touches) {
					println("[taint-op] " + displayFunction(f) + ": " + op.toString());
					shown++;
				}
			}
		}

		for (int pass = 0; pass < MAX_POINTER_TAINT_PASSES; pass++) {
			boolean changed = false;
			Iterator<PcodeOpAST> it = hf.getPcodeOps();

			while (it.hasNext()) {
				PcodeOpAST op = it.next();
				int opc = op.getOpcode();
				Varnode out = op.getOutput();

				if (opc == PcodeOp.LOAD && out != null && op.getNumInputs() >= 2) {
					Address loaded = resolvePcodeAddress(op.getInput(1));
					if (storage.equals(loaded) && !taintedPointers.containsKey(out)) {
						taintedPointers.put(out, 0L);
						provenance.put(out, storage + " <- GetVariable.Data");
						changed = true;
					}
				}

				if ((opc == PcodeOp.COPY || opc == PcodeOp.INT_ADD ||
					opc == PcodeOp.PTRADD || opc == PcodeOp.PTRSUB)) {
					for (int i = 0; i < op.getNumInputs(); i++) {
						Varnode in = op.getInput(i);
						if (in != null && in.isAddress() && storage.equals(in.getAddress())
								&& !taintedPointers.containsKey(in)) {
							taintedPointers.put(in, 0L);
							provenance.put(in, storage + " <- GetVariable.Data");
							changed = true;
						}
					}
				}

				if ((opc == PcodeOp.COPY || opc == PcodeOp.CAST) &&
					out != null && op.getNumInputs() >= 1) {
					Varnode in = op.getInput(0);
					if (taintedPointers.containsKey(in) && !taintedPointers.containsKey(out)) {
						taintedPointers.put(out, taintedPointers.get(in));
						provenance.put(out, provenance.get(in));
						changed = true;
					}
				}

				if (opc == PcodeOp.MULTIEQUAL && out != null) {
					Long common = null;
					String prov = null;
					boolean all = op.getNumInputs() > 0;
					for (int i = 0; i < op.getNumInputs(); i++) {
						Varnode in = op.getInput(i);
						if (!taintedPointers.containsKey(in)) { all = false; break; }
						Long off = taintedPointers.get(in);
						if (common == null) { common = off; prov = provenance.get(in); }
						else if (!common.equals(off)) { all = false; break; }
					}
					if (all && common != null && !taintedPointers.containsKey(out)) {
						taintedPointers.put(out, common);
						provenance.put(out, prov);
						changed = true;
					}
				}

				if ((opc == PcodeOp.INT_ADD || opc == PcodeOp.PTRADD || opc == PcodeOp.PTRSUB) &&
					out != null) {
					PointerArithmetic pa = recoverPointerArithmetic(op, taintedPointers, provenance);
					if (pa != null && !taintedPointers.containsKey(out)) {
						taintedPointers.put(out, pa.offset);
						provenance.put(out, pa.provenance);
						changed = true;
					}
				}
			}
			if (!changed) break;
		}

		if (DEBUG_POINTER_TAINT)
			println("[taint]   " + displayFunction(f) + ": seeded roots/tainted varnodes=" +
				taintedPointers.size());

		int hits = 0;
		Iterator<PcodeOpAST> it = hf.getPcodeOps();
		while (it.hasNext()) {
			PcodeOpAST op = it.next();
			int opc = op.getOpcode();

			Varnode pointer;
			boolean write;
			String value = null;

			if (opc == PcodeOp.STORE && op.getNumInputs() >= 3) {
				pointer = op.getInput(1);
				write = true;
				value = formatVarnodeValue(op.getInput(2));
			} else if (opc == PcodeOp.LOAD && op.getNumInputs() >= 2) {
				pointer = op.getInput(1);
				write = false;
			} else {
				continue;
			}

			if (!taintedPointers.containsKey(pointer)) continue;

			if (pointer.isAddress() && storage.equals(pointer.getAddress())) continue;

			hits++;

			long off = taintedPointers.get(pointer);
			Address at = op.getSeqnum().getTarget();

			DerivedMemoryAccess dma = new DerivedMemoryAccess();
			dma.write = write;
			dma.offset = formatSignedOffset(off);
			dma.value = value;
			dma.functionName = displayFunction(f);
			dma.instructionAddress = at == null ? "?" : at.toString();
			Instruction ins = at == null ? null :
				currentProgram.getListing().getInstructionAt(at);
			dma.instruction = ins == null ? "<instruction unavailable>" : ins.toString();
			dma.pcode = op.toString();
			dma.base = storage.toString();
			dma.provenance =
				"NVRAM value <- " + storage + " <- GetVariable.Data -> " +
				(off == 0 ? "*" : "*(base" + formatSignedOffset(off) + ")");
			unique.put(dma.key(), dma);
		}

		if (DEBUG_POINTER_TAINT && hits > 0)
			println("[taint]   " + displayFunction(f) + ": tainted memory accesses=" + hits);
	}

	static class PointerArithmetic { long offset; String provenance; }

	private PointerArithmetic recoverPointerArithmetic(
			PcodeOpAST op, Map<Varnode, Long> tainted, Map<Varnode, String> provenance) {
		if (op.getNumInputs() < 2) return null;
		Varnode base = op.getInput(0);
		Varnode delta = op.getInput(1);
		if (!tainted.containsKey(base) || !delta.isConstant()) return null;

		long add = delta.getOffset();
		if (op.getOpcode() == PcodeOp.PTRADD) {
			if (op.getNumInputs() < 3 || !op.getInput(2).isConstant()) return null;
			add *= op.getInput(2).getOffset();
		}
		PointerArithmetic pa = new PointerArithmetic();
		pa.offset = tainted.get(base) + add;
		pa.provenance = provenance.get(base);
		return pa;
	}

	private Address parseGlobalStorageAddress(String expr) {
		if (expr == null) return null;
		Matcher m = Pattern.compile("(?i)\\b_?DAT_([0-9a-f]+)\\b").matcher(expr);
		if (!m.find()) return null;
		try {
			long off = Long.parseUnsignedLong(m.group(1), 16);
			return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
		} catch (Exception ex) {
			return null;
		}
	}

	private Address resolvePcodeAddress(Varnode vn) {
		if (vn == null) return null;
		if (vn.isAddress()) return vn.getAddress();
		if (vn.isConstant()) {
			try {
				return currentProgram.getAddressFactory()
					.getDefaultAddressSpace().getAddress(vn.getOffset());
			} catch (Exception ex) { return null; }
		}
		PcodeOp def = vn.getDef();
		if (def == null) return null;
		if ((def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST) &&
			def.getNumInputs() >= 1)
			return resolvePcodeAddress(def.getInput(0));
		return null;
	}

	private void discoverBufferAliases(String c, Set<String> aliases) {
		String[] lines = c.split("\\R");
		for (int pass = 0; pass < 3; pass++) {
			boolean changed = false;
			for (String raw : lines) {
				String s = raw.trim();
				Matcher m = Pattern.compile(
					"^([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(?:\\([^;=]+\\)\\s*)?&?" +
					"([A-Za-z_][A-Za-z0-9_]*)\\s*;$").matcher(s);
				if (!m.find()) continue;
				String lhs = m.group(1);
				String rhs = m.group(2);
				if (aliases.contains(rhs) && aliases.add(lhs)) changed = true;
			}
			if (!changed) break;
		}
	}

	private void analyzeBufferFunction(Function f, String c, Analysis a, int depth,
									Set<String> aliases, boolean isReader) {
		if (a.evidence.size() >= MAX_EVENTS_PER_VARIABLE) return;

		String[] lines = c.split("\\R");
		Set<String> derivedValues = new LinkedHashSet<>();
		int getVariableLine = isReader ? findGetVariableLine(lines, a.read) : -1;

		for (int lineNo = 0; lineNo < lines.length; lineNo++) {
			String s = lines[lineNo].trim();
			if (s.isEmpty()) continue;

			for (String alias : aliases) {
				FieldAccess access = parseFieldAccess(s, alias);
				if (access == null) continue;

				String phase = isReader ? phaseForLine(lineNo, getVariableLine) : "CROSS-FUNCTION";
				if (!isReader) a.crossesFunction = true;

				if (access.write) {

					if (!isReader && access.rhsIsStringLiteral) {

					} else {
						a.fieldWrites.add(access.offset);
						Evidence ew = addEvidenceReturning(a, EvidenceKind.FIELD_WRITE, f, depth,
							access.offset, null, s, "write TO NVRAM-backed buffer field");
						if (ew != null) {
							ew.writeValue = access.writeValue;
							ew.writeClass = access.writeClass;
							ew.writeSource = access.writeSource;
							ew.lineIndex = lineNo;
							ew.phase = phase;
						}
					}
				}

				if (access.read) {
					a.fieldReads.add(access.offset);
					if (access.assignedVariable != null) {
						derivedValues.add(access.assignedVariable);
						a.fieldValues.computeIfAbsent(access.offset, k -> new LinkedHashSet<>())
							.add(access.assignedVariable);
					}

					Evidence er = addEvidenceReturning(a, EvidenceKind.FIELD_READ, f, depth,
						access.offset, access.assignedVariable, s,
						"value loaded FROM NVRAM-backed buffer field");
					if (er != null) { er.lineIndex = lineNo; er.phase = phase; }

					if (looksConditional(s)) {
						a.controlsBranch = true;
						Evidence ec = addEvidenceReturning(a, EvidenceKind.CONTROL, f, depth,
							access.offset, access.assignedVariable, s,
							"NVRAM field is read directly by a conditional");
						if (ec != null) { ec.lineIndex = lineNo; ec.phase = phase; }
					}

					if (access.assignedVariable != null &&
						access.assignedVariable.matches("_?DAT_[0-9A-Fa-f]+")) {
						followGlobalContinuation(access.assignedVariable, access.offset, f, a);
					}
				}
			}
		}

		propagateDerivedScalars(lines, derivedValues, a);
		classifyDerivedUses(f, lines, derivedValues, a, depth);
		observeSizeUses(f, lines, a, depth);
	}

	private void analyzeGlobalBuffer(VarOp read, Analysis a) {
		Set<String> globalRoots = new LinkedHashSet<>();
		for (String t : extractPointerRoots(read.data))
			if (t.matches("_?DAT_[0-9A-Fa-f]+")) globalRoots.add(t);
		if (globalRoots.isEmpty()) return;

		String readerKey = read.function == null ? null : read.function.getEntryPoint().toString();

		for (Map.Entry<String, String> entry : decompiled.entrySet()) {
			if (a.evidence.size() >= MAX_EVENTS_PER_VARIABLE) break;
			if (entry.getKey().equals(readerKey)) continue;

			Function f = functionAt(entry.getKey());
			if (f == null) continue;

			Set<String> aliases = new LinkedHashSet<>(globalRoots);
			discoverBufferAliases(entry.getValue(), aliases);
			analyzeBufferFunction(f, entry.getValue(), a, 0, aliases, false);
		}
	}

	private Function functionAt(String key) {
		try {
			Address ad = currentProgram.getAddressFactory()
				.getDefaultAddressSpace().getAddress(key);
			return currentProgram.getFunctionManager().getFunctionAt(ad);
		} catch (Exception e) {
			return null;
		}
	}

	private FieldAccess parseFieldAccess(String s, String alias) {
		if (alias == null || alias.isEmpty()) return null;
		String q = Pattern.quote(alias);

		String offset = null;
		int occurrence = -1;

		Matcher deref = Pattern.compile(
			"\\*\\s*\\([^)]*\\*\\)\\s*\\(?(?<![A-Za-z0-9_])" + q +
			"(?![A-Za-z0-9_])(?:\\s*\\+\\s*([A-Za-z0-9_]+))?\\)?").matcher(s);
		if (deref.find()) {
			occurrence = deref.start();
			offset = normOff(deref.group(1));
		}

		if (offset == null) {
			Matcher member = Pattern.compile(
				"(?<![A-Za-z0-9_])" + q + "\\s*(?:->|\\.)\\s*([A-Za-z_][A-Za-z0-9_]*)").matcher(s);
			if (member.find()) {
				occurrence = member.start();
				offset = memberOff(member.group(1));
			}
		}

		if (offset == null) return null;

		FieldAccess fa = new FieldAccess();
		fa.offset = offset;

		int eq = topLevelAssignmentIndex(s);
		if (eq >= 0 && occurrence < eq) {
			fa.write = true;
			String rhs = s.substring(eq + 1).trim();
			if (rhs.endsWith(";")) rhs = rhs.substring(0, rhs.length() - 1).trim();
			fa.writeValue = rhs;
			fa.writeClass = classifyWriteValue(rhs);
			fa.writeSource = classifyWriteSource(rhs);
			fa.rhsIsStringLiteral = looksLikeStringLiteral(rhs);
		}
		if (eq < 0 || occurrence > eq) {
			fa.read = true;
			if (eq >= 0) {
				String lhs = s.substring(0, eq).trim();
				if (lhs.matches("[A-Za-z_][A-Za-z0-9_]*")) fa.assignedVariable = lhs;
			}
		}
		if (!fa.write && !fa.read) fa.read = true;
		return fa;
	}

	private String normOff(String token) {
		if (token == null) return "+0x0";
		if (token.matches("(?i)0x[0-9a-f]+")) return "+" + token.toLowerCase(Locale.ROOT);
		if (token.matches("\\d+")) {
			try { return "+0x" + Long.toHexString(Long.parseLong(token)); }
			catch (Exception e) {  }
		}
		return "+<" + token + ">";
	}

	private String memberOff(String member) {
		Matcher x = Pattern.compile("(?i)^field_0x([0-9a-f]+)$").matcher(member);
		if (x.matches()) return "+0x" + x.group(1).toLowerCase(Locale.ROOT);
		return "->" + member;
	}

	private boolean looksLikeStringLiteral(String rhs) {
		if (rhs == null) return false;
		return Pattern.compile("(?i)(?:^|[^A-Za-z0-9_])L?\"").matcher(rhs).find();
	}

	private String classifyWriteValue(String rhs) {
		if (rhs == null) return "UNKNOWN";
		String x = stripCasts(rhs).trim();
		if (isZeroLike(x)) return "NULLIFICATION / RESET";
		if (x.matches("(?i)(?:0x[0-9a-f]+|[0-9]+|'.*')")) return "CONSTANT INITIALIZATION";
		if (x.matches("(?i)(?:L)?\".*\"")) return "CONSTANT INITIALIZATION";
		if (containsBufferFieldExpression(x)) return "FIELD-TO-FIELD COPY / TRANSFORM";
		if (x.matches(".*\\b_?DAT_[0-9A-Fa-f]+\\b.*")) return "GLOBAL-TO-FIELD COPY / TRANSFORM";
		if (x.matches("[A-Za-z_][A-Za-z0-9_]*")) return "VALUE COPY";
		return "COMPUTED VALUE";
	}

	private String classifyWriteSource(String rhs) {
		if (rhs == null) return "unknown";
		String x = stripCasts(rhs).trim();
		if (isZeroLike(x)) return "constant zero";
		if (x.matches("(?i)(?:0x[0-9a-f]+|[0-9]+|'.*')")) return "constant";
		if (containsBufferFieldExpression(x)) return "another NVRAM-buffer field/expression";
		if (x.matches(".*\\b_?DAT_[0-9A-Fa-f]+\\b.*")) return "global/static state";
		if (x.matches("[A-Za-z_][A-Za-z0-9_]*")) return "local/parameter value";
		return "computed expression";
	}

	private boolean containsBufferFieldExpression(String x) {
		if (x == null) return false;
		if (x.matches(".*\\*\\s*\\([^)]*\\*\\)\\s*\\([^)]*\\+\\s*(?:0x[0-9A-Fa-f]+|\\d+)\\).*"))
			return true;
		return x.matches(".*[A-Za-z_][A-Za-z0-9_]*\\s*(?:->|\\.)\\s*field_0x[0-9A-Fa-f]+.*");
	}

	private static boolean isZeroLike(String x) {
		if (x == null) return false;
		String n = x.replaceAll("\\s+", "");
		return n.equals("0") || n.equalsIgnoreCase("0x0") || n.equalsIgnoreCase("NULL") ||
			n.equals("(void*)0") || n.matches("\\([^)]*\\*\\)0(?:x0)?");
	}

	private static String stripCasts(String x) {
		if (x == null) return "";
		String out = x.trim();
		for (int i = 0; i < 4; i++) {
			String next = out.replaceFirst("^\\([^()]+\\)\\s*", "");
			if (next.equals(out)) break;
			out = next.trim();
		}
		return out;
	}

	private int findGetVariableLine(String[] lines, VarOp read) {
		String variableName = cleanVariableName(read.name);
		for (int i = 0; i < lines.length; i++) {
			String s = lines[i];
			if (s.contains("GetVariable") &&
				("<unknown>".equals(variableName) || s.contains(variableName)))
				return i;
		}
		for (int i = 0; i < lines.length; i++)
			if (lines[i].contains("GetVariable")) return i;
		return -1;
	}

	private String phaseForLine(int line, int getVariableLine) {
		if (getVariableLine < 0 || line < 0) return "UNKNOWN";
		if (line < getVariableLine) return "PRE-GETVARIABLE";
		if (line == getVariableLine) return "GETVARIABLE";
		return "POST-GETVARIABLE";
	}

	private void followGlobalContinuation(String global, String field, Function source, Analysis a) {
		for (Map.Entry<String, String> entry : decompiled.entrySet()) {
			Address fa;
			try {
				fa = currentProgram.getAddressFactory().getDefaultAddressSpace()
					.getAddress(entry.getKey());
			} catch (AddressFormatException ex) { continue; }

			Function f = currentProgram.getFunctionManager().getFunctionAt(fa);
			if (f == null || f.equals(source)) continue;

			String[] lines = entry.getValue().split("\\R");
			for (int i = 0; i < lines.length; i++) {
				String s = lines[i].trim();
				if (!containsToken(s, global)) continue;
				if (s.replaceAll("\\s+", "").contains("&" + global)) continue;

				String role = "global value consumed";
				if (looksConditional(s)) role = "global value controls conditional";
				else if (memorySink(s) != null) role = "global value reaches " + memorySink(s);
				else {
					DirectCall dc = parseDirectCall(s);
					if (dc != null) role = "global value reaches direct call " + dc.name;
				}

				Evidence e = addEvidenceReturning(a, EvidenceKind.GLOBAL_CONSUMER, f, 1,
					field, global, s, global + " -> " + role);
				if (e != null) { e.lineIndex = i; e.phase = "CROSS-FUNCTION"; }
			}
		}
	}

	private void propagateDerivedScalars(String[] lines, Set<String> values, Analysis a) {
		for (int pass = 0; pass < 3; pass++) {
			boolean changed = false;
			for (String raw : lines) {
				String s = raw.trim();
				Matcher m = Pattern.compile("^([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.+);$").matcher(s);
				if (!m.find()) continue;
				String lhs = m.group(1);
				String rhs = m.group(2);
				if (rhs.contains("*(") || rhs.matches(".*\\[[^]]+\\].*")) continue;
				String source = firstToken(rhs, values);
				if (source == null) continue;
				if (!isSimpleScalarExpression(rhs, source)) continue;
				if (values.add(lhs)) changed = true;
			}
			if (!changed) break;
		}
	}

	private boolean isSimpleScalarExpression(String rhs, String source) {
		String x = rhs.trim().replaceAll("\\([^()]*\\)", "").trim();
		if (x.equals(source)) return true;
		String q = Pattern.quote(source);
		return x.matches(q + "\\s*[+\\-&|^]\\s*(?:0x[0-9A-Fa-f]+|\\d+)") ||
			x.matches("(?:0x[0-9A-Fa-f]+|\\d+)\\s*[+&|^]\\s*" + q);
	}

	private void classifyDerivedUses(Function f, String[] lines, Set<String> values,
									Analysis a, int depth) {
		for (String raw : lines) {
			if (a.evidence.size() >= MAX_EVENTS_PER_VARIABLE) break;
			String s = raw.trim();
			String source = firstToken(s, values);
			if (source == null) continue;

			if (looksConditional(s)) {
				a.controlsBranch = true;
				addEvidence(a, EvidenceKind.CONTROL, f, depth, fieldForValue(a, source), source, s,
					"NVRAM FIELD-derived scalar influences control flow");
			}
			if (looksGlobalWrite(s, values)) {
				a.reachesGlobal = true;
				addEvidence(a, EvidenceKind.GLOBAL_WRITE, f, depth, fieldForValue(a, source), source, s,
					"NVRAM FIELD-derived scalar is stored in global/static state");
			}
			String mem = memorySink(s);
			if (mem != null) {
				a.reachesMemorySink = true;
				addEvidence(a, EvidenceKind.MEMORY_SINK, f, depth, fieldForValue(a, source), source, s,
					"FIELD-derived scalar reaches " + mem);
			}
			String uefi = uefiSink(s);
			if (uefi != null) {
				a.reachesUefiSink = true;
				addEvidence(a, EvidenceKind.UEFI_SINK, f, depth, fieldForValue(a, source), source, s,
					"FIELD-derived scalar reaches typed UEFI member " + uefi);
			}
			if (isDereferencedValue(s, source)) {
				a.usedAsPointer = true;
				addEvidence(a, EvidenceKind.POINTER_SINK, f, depth, fieldForValue(a, source), source, s,
					"FIELD-derived scalar is used as an address/pointer");
			}
			if (s.startsWith("return ") && containsToken(s, source)) {
				addEvidence(a, EvidenceKind.RETURN, f, depth, fieldForValue(a, source), source, s,
					"FIELD-derived scalar reaches return value");
			}

			if (depth < MAX_INTERPROC_DEPTH) {
				DirectCall dc = parseDirectCall(s);
				if (dc != null) {
					Function callee = functionsByName.get(dc.name);
					if (callee != null && !callee.equals(f)) {
						for (int i = 0; i < dc.args.size(); i++) {
							if (!containsToken(dc.args.get(i), source)) continue;
							if (dc.args.get(i).replaceAll("\\s+", "").contains("&" + source)) continue;
							addEvidence(a, EvidenceKind.DIRECT_CALL, f, depth,
								fieldForValue(a, source), source, s,
								"FIELD-derived scalar -> " + dc.name + " argument[" + i + "]");
							analyzeCalleeParameter(callee, i, a, depth + 1, fieldForValue(a, source));
						}
					}
				}
			}
		}
	}

	private void analyzeCalleeParameter(Function callee, int paramIndex, Analysis a,
										int depth, String originatingField) {
		String c = decompiled.get(callee.getEntryPoint().toString());
		if (c == null) return;

		Parameter[] params = callee.getParameters();
		String paramName = paramIndex < params.length ? params[paramIndex].getName() : null;
		if (paramName == null || paramName.isEmpty()) paramName = "param_" + (paramIndex + 1);

		String[] lines = c.split("\\R");
		Set<String> values = new LinkedHashSet<>();
		values.add(paramName);

		for (int pass = 0; pass < 2; pass++) {
			boolean changed = false;
			for (String raw : lines) {
				String s = raw.trim();
				Matcher m = Pattern.compile("^([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.+);$").matcher(s);
				if (!m.find()) continue;
				String lhs = m.group(1);
				String rhs = m.group(2);
				String source = firstToken(rhs, values);
				if (source == null) continue;
				if (rhs.contains("*(") || rhs.matches(".*\\[[^]]+\\].*")) continue;
				if (!isSimpleScalarExpression(rhs, source)) continue;
				if (values.add(lhs)) changed = true;
			}
			if (!changed) break;
		}

		for (String raw : lines) {
			String s = raw.trim();
			String source = firstToken(s, values);
			if (source == null) continue;

			if (looksConditional(s)) {
				a.controlsBranch = true; a.crossesFunction = true;
				addEvidence(a, EvidenceKind.CONTROL, callee, depth, originatingField, source, s,
					"FIELD-derived argument influences callee control flow");
			}
			if (looksGlobalWrite(s, values)) {
				a.reachesGlobal = true; a.crossesFunction = true;
				addEvidence(a, EvidenceKind.GLOBAL_WRITE, callee, depth, originatingField, source, s,
					"FIELD-derived argument reaches callee global/static state");
			}
			String mem = memorySink(s);
			if (mem != null) {
				a.reachesMemorySink = true; a.crossesFunction = true;
				addEvidence(a, EvidenceKind.MEMORY_SINK, callee, depth, originatingField, source, s,
					"FIELD-derived argument reaches " + mem + " in callee");
			}
			if (!looksLikeFunctionSignature(s) && isDereferencedValue(s, source)) {
				a.usedAsPointer = true; a.crossesFunction = true;
				addEvidence(a, EvidenceKind.POINTER_SINK, callee, depth, originatingField, source, s,
					"FIELD-derived argument is used as address/pointer in callee");
			}
		}
	}

	private void observeSizeUses(Function f, String[] lines, Analysis a, int depth) {
		for (String size : a.sizeAliases) {
			for (String raw : lines) {
				String s = raw.trim();
				if (!containsToken(s, size)) continue;
				if (s.matches(".*\\b" + Pattern.quote(size) + "\\s*;") && !s.contains("=")) continue;
				if (s.contains("GetVariable")) continue;

				String mem = memorySink(s);
				if (mem != null) {
					addEvidence(a, EvidenceKind.SIZE_OBSERVATION, f, depth, null, size, s,
						"DataSize participates in " + mem + " (reported separately; NOT NVRAM Data taint)");
				}
			}
		}
	}

	private int printVariableReports() {
		int index = 1;
		int fieldAnalyzed = 0;

		println(" VARIABLE SERVICES");
		println("------------------------------------------------------------------------");
		println(" GetVariable ............... " + countServiceSuffix("GetVariable"));
		println(" SetVariable ............... " + countServiceSuffix("SetVariable"));
		println(" GetNextVariableName ....... " + countServiceSuffix("GetNextVariableName"));
		println(" QueryVariableInfo ......... " + countServiceSuffix("QueryVariableInfo"));
		println(" Variable identities ....... " + records.size());
		printOtherVariableServices();

		for (VariableRecord record : records.values()) {
			VarOp ex = !record.reads.isEmpty() ? record.reads.get(0) :
					(!record.writes.isEmpty() ? record.writes.get(0) : null);
			if (ex == null) continue;

			Analysis a = mergeRecordAnalyses(record);
			boolean hasFields = a != null && (!a.fieldReads.isEmpty() || !a.fieldWrites.isEmpty());
			if (hasFields) fieldAnalyzed++;

			println("");
			println("========================================================================");
			println(String.format(" [%02d] %s", index++, cleanVariableName(ex.name)));
			println("========================================================================");
			println(" GUID        " + safe(ex.guid));

			if (!record.reads.isEmpty()) {
				println("");
				println(" GETVARIABLE");
				for (VarOp read : record.reads) {
					println("   Function    " + displayFunction(read.function) +
						("GetVariable".equals(read.rawService) ? "" : "  [" + read.rawService + "]"));
					println("   Data        " + safe(read.data));
					println("   DataSize    " + safe(read.dataSize));
					println("   Attributes  " +
						(looksNull(read.attributes) ? "not requested" : safe(read.attributes)));
					if (record.reads.size() > 1) println("");
				}
			}

			println("");
			println(" SETVARIABLE");
			if (record.writes.isEmpty()) {
				println("   Not found in this module.");
			} else {
				for (VarOp write : record.writes) {
					println("   Function    " + displayFunction(write.function) +
						("SetVariable".equals(write.rawService) ? "" : "  [" + write.rawService + "]"));
					println("   Data        " + safe(write.data));
					println("   DataSize    " + safe(write.dataSize));
					println("   Attributes  " + describeAttributes(write.attributes, write.attributesValue));
					printAttributeFlags(write.attributesValue);
					println("");
				}
			}

			if (a != null && a.returnedStorage != null) {
				println("");
				println(" RETURNED VALUE (global Data storage)");
				println("   Storage     " + a.returnedStorage);
				println("   Semantics   " + (a.returnedValueUsedAsPointer ?
					"used as pointer/address value  [NVRAM-DERIVED MEMORY ACCESS]" :
					"pointer/address use not proven"));

				if (!a.derivedMemoryAccesses.isEmpty()) {
					println("");
					println(" NVRAM-DERIVED MEMORY ACCESSES");
					println("   The value read from this NVRAM variable is used as an address.");
					println("   Writes here are attacker-influenced if the variable is writable.");
					for (DerivedMemoryAccess dma : a.derivedMemoryAccesses) {
						println("");
						println("   [" + (dma.write ? "WRITE" : "READ") + "  NVRAM_VALUE " + dma.offset + "]");
						if (dma.write) println("      Value       " + safe(dma.value));
						println("      Function    " + safe(dma.functionName));
						println("      Location    " + safe(dma.instructionAddress));
						println("      Instruction " + safe(dma.instruction));
						println("      P-code      " + safe(dma.pcode));
						println("      Provenance  " + safe(dma.provenance));
					}
				}
			}

			boolean hasReader = !record.reads.isEmpty();
			boolean pointerProven = a != null && a.returnedValueUsedAsPointer;
			boolean provenanceUnproven =
				a != null && a.returnedStorage != null && !a.returnedValueUsedAsPointer;
			if (!pointerProven && (hasReader || hasFields)) {
				println("");
				if (provenanceUnproven) {
					println(" OBSERVED OFFSET ACCESSES");
					println("   Provenance   unresolved (Data holds a pointer; deref not proven)");
				} else {
					println(" FIELDS (Data buffer)");
				}
				if (!hasFields) {
					println("   No field-level accesses recovered.");
				} else {
					for (String off : sortedOffsets(union(a.fieldReads, a.fieldWrites))) {
						boolean read = a.fieldReads.contains(off);
						boolean write = a.fieldWrites.contains(off);
						String access = read && write ? "READ/WRITE" : read ? "READ" : "WRITE";
						println("");
						println("   " + off + "   " + access);

						if (read) {
							List<String> uses = conciseUseDetails(a, off);
							println("      READ");
							for (String use : uses)
								println("         " + use);
						}

						if (write) {
							println("      WRITE");
							for (String line : groupedWriteLines(a, off))
								println("         " + line);
						}

						String pattern = fieldPattern(a, off);
						if (pattern != null) println("      Pattern: " + pattern);
					}
				}
			}

			List<String> prop = propagationLines(a);
			if (!prop.isEmpty()) {
				println("");
				println(" SUBSEQUENT USE / PROPAGATION");
				for (String line : prop) println("   " + line);
			}

			List<Evidence> sizeEv = evidenceOfKind(a, EvidenceKind.SIZE_OBSERVATION);
			if (!sizeEv.isEmpty()) {
				println("");
				println(" DATASIZE (separate from Data taint)");
				for (Evidence e : sizeEv)
					println("   " + displayFunction(e.function) + " - " + safe(e.detail));
			}

			println("");
			println(" ATTRIBUTES");
			println("   GetVariable   " +
				(anyAttributesRequested(record) ? "requested" : "not requested"));
			if (record.writes.isEmpty()) {
				println("   SetVariable   unavailable (writer not found in this module)");
			} else {
				printWriterAttributeSummary(record);
			}

			if (a != null && a.evidenceTruncated) {
				println("");
				println("   [!] Evidence truncated at " + MAX_EVENTS_PER_VARIABLE +
					" events; more uses exist than shown.");
			}
		}

		return fieldAnalyzed;
	}

	private List<String> conciseUseDetails(Analysis a, String off) {
		LinkedHashSet<String> out = new LinkedHashSet<>();
		LinkedHashSet<String> globals = new LinkedHashSet<>();
		LinkedHashSet<String> consumers = new LinkedHashSet<>();
		boolean conditional = false, pointer = false, memory = false;

		for (Evidence e : a.evidence) {
			if (!off.equals(e.field)) continue;
			if (e.kind == EvidenceKind.CONTROL) conditional = true;
			if (e.kind == EvidenceKind.POINTER_SINK) pointer = true;
			if (e.kind == EvidenceKind.MEMORY_SINK) memory = true;
			if (e.kind == EvidenceKind.GLOBAL_CONSUMER) {
				if (e.value != null && !e.value.trim().isEmpty()) globals.add(e.value.trim());
				if (e.function != null) consumers.add(e.function.getName());
				if (looksPointerish(e.expression)) pointer = true;
			}
			if (e.kind == EvidenceKind.DIRECT_CALL && e.function != null)
				consumers.add(e.function.getName());
		}

		if (!globals.isEmpty()) out.add("-> global: " + String.join(", ", globals));
		if (conditional) out.add("-> conditional/control flow");
		if (!consumers.isEmpty())
			out.add("-> " + consumers.size() + " consumer function(s): " + compactNames(consumers, 6));
		if (pointer) out.add("-> address/buffer use");
		if (hasSizeArithmeticForOffset(a, off)) out.add("-> size/arithmetic use");
		if (memory) out.add("-> memory-operation use");
		return new ArrayList<>(out);
	}

	private List<String> groupedWriteLines(Analysis a, String off) {

		LinkedHashMap<String, WriteGroup> groups = new LinkedHashMap<>();

		for (Evidence e : a.evidence) {
			if (e.kind != EvidenceKind.FIELD_WRITE || !off.equals(e.field)) continue;

			String value = safe(e.writeValue);
			String cls = safe(e.writeClass);
			String key = value + "|" + cls;

			WriteGroup g = groups.get(key);
			if (g == null) {
				g = new WriteGroup();
				g.value = value;
				g.writeClass = cls;
				groups.put(key, g);
			}
			g.phases.add(safe(e.phase));
			if (e.function != null) g.functions.add(displayFunction(e.function));

			if (g.code == null && e.expression != null && !e.expression.trim().isEmpty())
				g.code = e.expression.trim();
		}

		List<String> out = new ArrayList<>();
		for (WriteGroup g : groups.values()) {
			String shownValue = g.value.isEmpty() ? "<value unresolved>" : g.value;
			StringBuilder sb = new StringBuilder();
			sb.append(shownValue).append("  [").append(g.writeClass);
			sb.append(", ").append(String.join("/", g.phases)).append("]");
			if (!g.functions.isEmpty()) {
				int n = g.functions.size();
				sb.append("  (").append(n).append(n == 1 ? " function: " : " functions: ")
					.append(compactNames(g.functions, 6)).append(")");
			}
			out.add(sb.toString());

			if (g.code != null)
				out.add("  code: " + g.code);
		}
		return out;
	}

	static class WriteGroup {
		String value;
		String writeClass;
		String code;
		final LinkedHashSet<String> phases = new LinkedHashSet<>();
		final LinkedHashSet<String> functions = new LinkedHashSet<>();
	}

	private String fieldPattern(Analysis a, String off) {
		boolean preWrite = false, postWrite = false, postRead = false, postClear = false;
		for (Evidence e : a.evidence) {
			if (!off.equals(e.field)) continue;
			if (e.kind == EvidenceKind.FIELD_READ && "POST-GETVARIABLE".equals(e.phase))
				postRead = true;
			if (e.kind == EvidenceKind.FIELD_WRITE) {
				if ("PRE-GETVARIABLE".equals(e.phase)) preWrite = true;
				if ("POST-GETVARIABLE".equals(e.phase)) {
					postWrite = true;
					if ("NULLIFICATION / RESET".equals(e.writeClass)) postClear = true;
				}
			}
		}
		if (postRead && postClear) return "CONSUME-AND-CLEAR candidate";
		if (preWrite && postRead) return "PREPARE-BUFFER -> GETVARIABLE -> CONSUME";
		if (preWrite) return "PRE-GETVARIABLE buffer initialization";
		if (postWrite) return "POST-GETVARIABLE state update";
		return null;
	}

	private List<String> propagationLines(Analysis a) {
		List<String> out = new ArrayList<>();
		if (a == null) return out;
		for (Evidence e : a.evidence) {
			if (e.kind == EvidenceKind.GLOBAL_WRITE)
				out.add(safe(e.field) + " -> global/static state (" + displayFunction(e.function) + ")");
			else if (e.kind == EvidenceKind.GLOBAL_CONSUMER)
				out.add(safe(e.field) + " -> " + safe(e.value) + " -> " + displayFunction(e.function));
			else if (e.kind == EvidenceKind.DIRECT_CALL)
				out.add(safe(e.field) + " -> " + shortCallDescription(e));
			else if (e.kind == EvidenceKind.RETURN)
				out.add(safe(e.field) + " -> return value (" + displayFunction(e.function) + ")");
		}
		LinkedHashSet<String> dedup = new LinkedHashSet<>(out);
		return new ArrayList<>(dedup);
	}

	private void printWriterAttributeSummary(VariableRecord record) {
		printState("NON_VOLATILE", hasWriterAttribute(record, EFI_VARIABLE_NON_VOLATILE));
		printState("BOOTSERVICE_ACCESS", hasWriterAttribute(record, EFI_VARIABLE_BOOTSERVICE_ACCESS));
		printState("RUNTIME_ACCESS", hasWriterAttribute(record, EFI_VARIABLE_RUNTIME_ACCESS));
		printState("HARDWARE_ERROR_RECORD", hasWriterAttribute(record, EFI_VARIABLE_HARDWARE_ERROR_RECORD));
		printState("Authenticated", hasAuthenticatedWriter(record));
		printState("APPEND_WRITE", hasWriterAttribute(record, EFI_VARIABLE_APPEND_WRITE));
		if (hasMixedVolatileWrites(record))
			println("   [!] Mixed volatile / non-volatile writers (shadowing candidate).");
	}

	private void printState(String label, boolean yes) {
		println(String.format("   %-23s %s", label, yes ? "YES" : "NO"));
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

	private void printSummary(int fieldAnalyzed) {
		int pointerVariables = 0, derivedReads = 0, derivedWrites = 0;
		for (Analysis aa : analyses) {
			if (aa.returnedValueUsedAsPointer) pointerVariables++;
			for (DerivedMemoryAccess dma : aa.derivedMemoryAccesses) {
				if (dma.write) derivedWrites++; else derivedReads++;
			}
		}
		println("");
		println("========================================================================");
		println(" SUMMARY");
		println("========================================================================");
		println(" Functions ............... " + functionsDecompiled + " / " + functionsVisited +
			" (failed: " + decompileFailures + ")");
		println(" GetVariable ............. " + countServiceSuffix("GetVariable"));
		println(" SetVariable ............. " + countServiceSuffix("SetVariable"));
		println(" GetNextVariableName ..... " + countServiceSuffix("GetNextVariableName"));
		println(" QueryVariableInfo ....... " + countServiceSuffix("QueryVariableInfo"));
		println(" Variable identities ..... " + records.size());
		println(" Field-analyzed .......... " + fieldAnalyzed);
		println(" NVRAM-derived pointers .. " + pointerVariables);
		println(" Derived memory reads .... " + derivedReads);
		println(" Derived memory writes ... " + derivedWrites);
		println(" Mutations ............... 0 (read-only)");

		java.util.List<String> fj = new java.util.ArrayList<>();
		for (Analysis a : analyses) {
			if (a == null || a.read == null || !a.returnedValueUsedAsPointer) continue;
			int w = 0, r = 0; String loc = null;
			for (DerivedMemoryAccess dma : a.derivedMemoryAccesses) {
				if (dma.write) w++; else r++;
				if (loc == null) loc = dma.instructionAddress;
			}
			String var = cleanVariableName(a.read.name);
			String desc = "NVRAM variable value is used as a memory address (" + w + " write(s), " + r +
				" read(s)); attacker-influenced if the variable is writable. GUID " + safe(a.read.guid) + ".";
			fj.add(finding(w > 0 ? "high" : "medium", "NVRAM-derived memory access: " + var, desc, loc));
		}
		String sum = String.format(
			"{\"getVariable\": %d, \"setVariable\": %d, \"identities\": %d, \"nvramDerivedPointers\": %d, \"derivedReads\": %d, \"derivedWrites\": %d}",
			countServiceSuffix("GetVariable"), countServiceSuffix("SetVariable"),
			records.size(), pointerVariables, derivedReads, derivedWrites);
		writeJsonReport(".behemoth-variables.json", "behemoth-variables", sum, fj);
	}

	private void printOtherVariableServices() {
		boolean any = false;
		for (VarOp op : operations) {
			if (!"GetNextVariableName".equals(op.service) && !"QueryVariableInfo".equals(op.service))
				continue;
			if (!any) { println(""); println(" OTHER VARIABLE SERVICES"); any = true; }
			println("   " + op.rawService + " - " + displayFunction(op.function));
			println("      " + safe(op.raw));
		}
	}

	private Analysis mergeRecordAnalyses(VariableRecord record) {
		Analysis out = null;
		for (VarOp read : record.reads) {
			Analysis a = findAnalysis(read);
			if (a == null) continue;
			if (out == null) { out = new Analysis(); out.read = read; }
			out.fieldReads.addAll(a.fieldReads);
			out.fieldWrites.addAll(a.fieldWrites);
			for (Map.Entry<String, Set<String>> e : a.fieldValues.entrySet())
				out.fieldValues.computeIfAbsent(e.getKey(), k -> new LinkedHashSet<>())
					.addAll(e.getValue());
			for (DerivedMemoryAccess dma : a.derivedMemoryAccesses) {
				boolean exists = false;
				for (DerivedMemoryAccess old : out.derivedMemoryAccesses)
					if (old.key().equals(dma.key())) { exists = true; break; }
				if (!exists) out.derivedMemoryAccesses.add(dma);
			}
			if (out.returnedStorage == null) out.returnedStorage = a.returnedStorage;
			out.returnedValueUsedAsPointer |= a.returnedValueUsedAsPointer;
			out.evidence.addAll(a.evidence);
			out.controlsBranch |= a.controlsBranch;
			out.reachesGlobal |= a.reachesGlobal;
			out.reachesMemorySink |= a.reachesMemorySink;
			out.reachesUefiSink |= a.reachesUefiSink;
			out.usedAsPointer |= a.usedAsPointer;
			out.crossesFunction |= a.crossesFunction;
			out.evidenceTruncated |= a.evidenceTruncated;
		}
		return out;
	}

	private Analysis findAnalysis(VarOp op) {
		for (Analysis a : analyses) if (a.read == op) return a;
		return null;
	}

	private List<Evidence> evidenceOfKind(Analysis a, EvidenceKind kind) {
		List<Evidence> out = new ArrayList<>();
		if (a == null) return out;
		for (Evidence e : a.evidence) if (e.kind == kind) out.add(e);
		return out;
	}

	private boolean hasSizeArithmeticForOffset(Analysis a, String off) {
		for (Evidence e : a.evidence) {
			if (!off.equals(e.field)) continue;
			if (e.kind != EvidenceKind.GLOBAL_CONSUMER && e.kind != EvidenceKind.DIRECT_CALL) continue;
			String x = safe(e.expression);
			if (looksPointerish(x)) continue;
			if (x.contains(" / ") || x.contains(" % ") || x.contains(" * ")) return true;
		}
		return false;
	}

	private static boolean looksPointerish(String expr) {
		String x = safe(expr).toLowerCase(Locale.ROOT);
		return x.contains("(char *)") || x.contains("(byte *)") || x.contains("(undefined1 *)") ||
			x.contains("(uint *)") || x.contains("(ushort *)") || x.contains("(uintn *)") ||
			x.contains("buffer") || x.contains("memory");
	}

	private void addEvidence(Analysis a, EvidenceKind kind, Function f, int depth,
							String field, String value, String expression, String detail) {
		addEvidenceReturning(a, kind, f, depth, field, value, expression, detail);
	}

	private Evidence addEvidenceReturning(Analysis a, EvidenceKind kind, Function f, int depth,
										String field, String value, String expression, String detail) {
		if (a.evidence.size() >= MAX_EVENTS_PER_VARIABLE) { a.evidenceTruncated = true; return null; }

		Evidence e = new Evidence();
		e.kind = kind;
		e.function = f;
		e.depth = depth;
		e.field = field;
		e.value = value;
		e.expression = oneLine(expression);
		e.detail = detail;
		e.sequence = a.sequenceCounter++;

		String key = e.key();
		for (Evidence old : a.evidence) if (old.key().equals(key)) return old;
		a.evidence.add(e);
		return e;
	}

	private String fieldForValue(Analysis a, String value) {
		for (Map.Entry<String, Set<String>> e : a.fieldValues.entrySet())
			if (e.getValue().contains(value)) return e.getKey();
		return "?";
	}

	private boolean anyAttributesRequested(VariableRecord record) {
		for (VarOp r : record.reads) if (!looksNull(r.attributes)) return true;
		return false;
	}

	private boolean hasWriterAttribute(VariableRecord record, long flag) {
		for (VarOp w : record.writes)
			if (w.attributesValue != null && (w.attributesValue & flag) != 0) return true;
		return false;
	}

	private boolean hasAuthenticatedWriter(VariableRecord record) {
		long mask = EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
					EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
					EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS;
		return hasWriterAttribute(record, mask);
	}

	private boolean hasMixedVolatileWrites(VariableRecord record) {
		boolean vol = false, nv = false;
		for (VarOp w : record.writes) {
			if (w.attributesValue == null) continue;
			if ((w.attributesValue & EFI_VARIABLE_NON_VOLATILE) != 0) nv = true; else vol = true;
		}
		return vol && nv;
	}

	private void printAttributeFlags(Long value) {
		if (value == null) { println("   Flags       unresolved"); return; }
		List<String> flags = new ArrayList<>();
		if ((value & EFI_VARIABLE_NON_VOLATILE) != 0) flags.add("NON_VOLATILE");
		if ((value & EFI_VARIABLE_BOOTSERVICE_ACCESS) != 0) flags.add("BOOTSERVICE_ACCESS");
		if ((value & EFI_VARIABLE_RUNTIME_ACCESS) != 0) flags.add("RUNTIME_ACCESS");
		if ((value & EFI_VARIABLE_HARDWARE_ERROR_RECORD) != 0) flags.add("HARDWARE_ERROR_RECORD");
		if ((value & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) != 0) flags.add("AUTHENTICATED_WRITE_ACCESS");
		if ((value & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0)
			flags.add("TIME_BASED_AUTHENTICATED_WRITE_ACCESS");
		if ((value & EFI_VARIABLE_APPEND_WRITE) != 0) flags.add("APPEND_WRITE");
		if ((value & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0)
			flags.add("ENHANCED_AUTHENTICATED_ACCESS");
		println("   Flags       " + (flags.isEmpty() ? "<none>" : String.join(" | ", flags)));
	}

	private static String describeAttributes(String expr, Long value) {
		if (value == null) return safe(expr) + " [unresolved]";
		List<String> flags = new ArrayList<>();
		flags.add((value & EFI_VARIABLE_NON_VOLATILE) != 0 ? "NON_VOLATILE" : "VOLATILE");
		if ((value & EFI_VARIABLE_BOOTSERVICE_ACCESS) != 0) flags.add("BOOTSERVICE_ACCESS");
		if ((value & EFI_VARIABLE_RUNTIME_ACCESS) != 0) flags.add("RUNTIME_ACCESS");
		if ((value & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) != 0) flags.add("AUTHENTICATED_WRITE");
		if ((value & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0)
			flags.add("TIME_BASED_AUTHENTICATED_WRITE");
		if ((value & EFI_VARIABLE_APPEND_WRITE) != 0) flags.add("APPEND_WRITE");
		if ((value & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0)
			flags.add("ENHANCED_AUTHENTICATED_ACCESS");
		return String.format("%s -> 0x%x [%s]", safe(expr), value, String.join(" | ", flags));
	}

	private static Long parseAttributes(String expression) {
		if (expression == null) return null;
		String s = expression.trim()
			.replaceAll("\\((?:UINT32|UINTN|int|long|ulong|undefined4|undefined8)\\)", "");

		LinkedHashMap<String, Long> names = new LinkedHashMap<>();
		names.put("EFI_VARIABLE_NON_VOLATILE", EFI_VARIABLE_NON_VOLATILE);
		names.put("EFI_VARIABLE_BOOTSERVICE_ACCESS", EFI_VARIABLE_BOOTSERVICE_ACCESS);
		names.put("EFI_VARIABLE_RUNTIME_ACCESS", EFI_VARIABLE_RUNTIME_ACCESS);
		names.put("EFI_VARIABLE_HARDWARE_ERROR_RECORD", EFI_VARIABLE_HARDWARE_ERROR_RECORD);
		names.put("EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS", EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS);
		names.put("EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
				EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS);
		names.put("EFI_VARIABLE_APPEND_WRITE", EFI_VARIABLE_APPEND_WRITE);
		names.put("EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS", EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS);

		for (Map.Entry<String, Long> e : names.entrySet())
			s = s.replaceAll("(?i)\\b" + Pattern.quote(e.getKey()) + "\\b",
				"0x" + Long.toHexString(e.getValue()));

		s = stripOuter(s.trim());
		long value = 0;
		boolean any = false;
		for (String part : s.split("\\|")) {
			String t = stripOuter(part.trim()).replaceAll("[uUlL]+$", "");
			if (t.isEmpty()) continue;
			try {
				long v;
				if (t.matches("(?i)0x[0-9a-f]+")) v = Long.parseUnsignedLong(t.substring(2), 16);
				else if (t.matches("[0-9]+")) v = Long.parseLong(t);
				else return null;
				value |= v; any = true;
			} catch (Exception e) { return null; }
		}
		return any ? value : null;
	}

	private static boolean looksConditional(String s) {
		return s.matches("^(if|while|switch)\\s*\\(.*") ||
			s.matches("^for\\s*\\(.*") || s.contains(" ? ");
	}

	private static boolean looksGlobalWrite(String s, Set<String> values) {
		Matcher m = Pattern.compile("^_?DAT_[0-9A-Fa-f]+\\s*=\\s*(.+);$").matcher(s);
		return m.find() && firstToken(m.group(1), values) != null;
	}

	private static String memorySink(String s) {
		String[] names = { "CopyMem", "SetMem", "memcpy", "memmove", "memset",
						"AllocatePool", "AllocatePages" };
		for (String n : names)
			if (s.contains(n + "(") || s.contains("->" + n)) return n;
		return null;
	}

	private static String uefiSink(String s) {
		Matcher m = Pattern.compile(
			"\\b(?:gBS|gRT|gST|g[A-Za-z0-9_]+)\\s*->\\s*([A-Za-z_][A-Za-z0-9_]*)").matcher(s);
		return m.find() ? m.group(1) : null;
	}

	private static boolean isDereferencedValue(String s, String value) {
		String q = Pattern.quote(value);
		return Pattern.compile(
			"\\*\\s*\\([^)]*\\*\\)\\s*\\(?" + q + "\\b|\\*\\s*" + q + "\\b|\\b" + q + "\\s*\\[")
			.matcher(s).find();
	}

	private static boolean looksLikeFunctionSignature(String s) {
		return s.matches("^(?:[A-Za-z_][A-Za-z0-9_]*(?:\\s*\\*)?\\s+)+" +
			"(?:FUN_|UefiMain)[A-Za-z0-9_]*\\s*\\(.*\\)\\s*$");
	}

	private DirectCall parseDirectCall(String s) {
		Matcher m = Pattern.compile("\\b((?:FUN_|UefiMain)[A-Za-z0-9_]*)\\s*\\(").matcher(s);
		if (!m.find()) return null;
		String name = m.group(1);
		int open = s.indexOf('(', m.start(1) + name.length());
		if (open < 0) return null;
		int close = findMatchingParen(s, open);
		if (close < 0) return null;
		DirectCall d = new DirectCall();
		d.name = name;
		d.args = splitArgs(s.substring(open + 1, close));
		return d;
	}

	private String shortCallDescription(Evidence e) {
		Matcher m = Pattern.compile(
			"->\\s*((?:FUN_|UefiMain)[A-Za-z0-9_]*)\\s+argument\\[(\\d+)\\]").matcher(safe(e.detail));
		if (m.find()) return m.group(1) + " arg[" + m.group(2) + "]";
		return safe(e.detail);
	}

	private static Set<String> extractPointerRoots(String expression) {
		Set<String> out = new LinkedHashSet<>();
		if (expression == null) return out;
		Matcher dat = Pattern.compile("\\b_?DAT_[0-9A-Fa-f]+\\b").matcher(expression);
		while (dat.find()) out.add(dat.group());
		if (!out.isEmpty()) return out;
		Matcher id = Pattern.compile("\\b[A-Za-z_][A-Za-z0-9_]*\\b").matcher(expression);
		while (id.find()) { String t = id.group(); if (!isTypeNoise(t)) out.add(t); }
		return out;
	}

	private static Set<String> extractVariableTokens(String expression) {
		Set<String> out = new LinkedHashSet<>();
		if (expression == null) return out;
		Matcher id = Pattern.compile("\\b[A-Za-z_][A-Za-z0-9_]*\\b").matcher(expression);
		while (id.find()) {
			String t = id.group();
			if (!isTypeNoise(t) && !t.startsWith("DAT_") && !t.startsWith("_DAT_")) out.add(t);
		}
		return out;
	}

	private static boolean isTypeNoise(String t) {
		String x = t.toLowerCase(Locale.ROOT);
		return x.equals("void") || x.equals("char") || x.equals("short") || x.equals("int") ||
			x.equals("long") || x.equals("ulong") || x.equals("uint") || x.equals("uintn") ||
			x.equals("uint32") || x.equals("uint64") || x.equals("byte") ||
			x.startsWith("undefined") || x.startsWith("efi_");
	}

	private static String firstToken(String text, Set<String> tokens) {
		for (String t : tokens) if (containsToken(text, t)) return t;
		return null;
	}

	private static boolean containsToken(String text, String token) {
		if (text == null || token == null || token.isEmpty()) return false;
		return Pattern.compile("(?<![A-Za-z0-9_])" + Pattern.quote(token) + "(?![A-Za-z0-9_])")
			.matcher(text).find();
	}

	private static int topLevelAssignmentIndex(String s) {
		int par = 0, br = 0;
		boolean str = false, chr = false, esc = false;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (esc) { esc = false; continue; }
			if ((str || chr) && c == '\\') { esc = true; continue; }
			if (!chr && c == '"') { str = !str; continue; }
			if (!str && c == '\'') { chr = !chr; continue; }
			if (str || chr) continue;
			if (c == '(') par++;
			else if (c == ')') par--;
			else if (c == '[') br++;
			else if (c == ']') br--;
			else if (c == '=' && par == 0 && br == 0) {
				char prev = i > 0 ? s.charAt(i - 1) : '\0';
				char next = i + 1 < s.length() ? s.charAt(i + 1) : '\0';

				if (next != '=' &&
					prev != '=' && prev != '!' && prev != '<' && prev != '>' &&
					prev != '+' && prev != '-' && prev != '*' && prev != '/' &&
					prev != '%' && prev != '&' && prev != '|' && prev != '^')
					return i;
			}
		}
		return -1;
	}

	private static String stripOuter(String s) {
		String x = s;
		while (x.length() >= 2 && x.charAt(0) == '(' && findMatchingParen(x, 0) == x.length() - 1)
			x = x.substring(1, x.length() - 1).trim();
		return x;
	}

	private static int findMatchingParen(String s, int open) {
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

	private int countServiceSuffix(String suffix) {
		int n = 0;
		for (VarOp op : operations)
			if (op.rawService != null && op.rawService.endsWith(suffix)) n++;
		return n;
	}

	private List<String> sortedOffsets(Collection<String> input) {
		List<String> out = new ArrayList<>(input);
		out.sort((x, y) -> {
			int c = Long.compareUnsigned(parseOffsetNumber(x), parseOffsetNumber(y));
			return c != 0 ? c : x.compareTo(y);
		});
		return out;
	}

	private long parseOffsetNumber(String off) {
		if (off == null) return Long.MAX_VALUE;
		String x = off.replace("+", "").trim();
		try {
			if (x.toLowerCase(Locale.ROOT).startsWith("0x"))
				return Long.parseUnsignedLong(x.substring(2), 16);
			return Long.parseLong(x);
		} catch (Exception ex) {
			return Long.MAX_VALUE;
		}
	}

	private static <T> Set<T> union(Set<T> a, Set<T> b) {
		LinkedHashSet<T> out = new LinkedHashSet<>(a);
		out.addAll(b);
		return out;
	}

	private String compactNames(Collection<String> names, int max) {
		List<String> n = new ArrayList<>(names);
		if (n.size() <= max) return String.join(", ", n);
		return String.join(", ", n.subList(0, max)) + " (+" + (n.size() - max) + " more)";
	}

	private String displayFunction(Function f) {
		if (f == null) return "?";
		String name = f.getName();
		String addr = f.getEntryPoint().toString();
		if (name != null && name.matches("(?i)FUN_0*" + Pattern.quote(addr))) return name;
		return name + " @ " + addr;
	}

	private String cleanVariableName(String s) {
		if (s == null) return "<unknown>";
		Matcher m = Pattern.compile("L?\"([^\"]+)\"").matcher(s);
		if (m.find()) return m.group(1);
		return s.trim().isEmpty() ? "<unknown>" : s.trim();
	}

	private String formatVarnodeValue(Varnode vn) {
		if (vn == null) return "?";
		if (vn.isConstant()) return "0x" + Long.toHexString(vn.getOffset());
		return vn.toString();
	}

	private String formatSignedOffset(long off) {
		if (off == 0) return "+0x0";
		return off > 0 ? "+0x" + Long.toHexString(off) : "-0x" + Long.toHexString(-off);
	}

	private static boolean looksNull(String s) {
		if (s == null) return false;
		String x = s.replaceAll("\\s+", "")
			.replace("(void*)", "").replace("(UINT32*)", "").replace("(undefined4*)", "");
		return x.equals("0") || x.equalsIgnoreCase("0x0") || x.equalsIgnoreCase("NULL");
	}

	private static String normalizeIdentity(String s) {
		if (s == null) return "?";
		String x = s.replaceAll("\\s+", "").replace("&", "").toLowerCase(Locale.ROOT);
		while (x.matches("^\\([^()]+\\).+")) x = x.replaceFirst("^\\([^()]+\\)", "");
		return x;
	}

	private static String clean(String s) { return oneLine(s).trim(); }

	private static String oneLine(String s) {
		if (s == null) return "?";
		return s.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
	}

	private static String safe(String s) { return s == null ? "?" : s; }
}
