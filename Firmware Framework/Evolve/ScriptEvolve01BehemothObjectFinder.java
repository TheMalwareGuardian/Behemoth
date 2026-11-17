// Recovers callable objects, structural/signature candidates, GUID provenance, and interface storage.
// @author TheMalwareGuardian
// @category UEFI

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.mem.Memory;

import java.io.*;
import java.util.*;

public class ScriptEvolve01BehemothObjectFinder extends GhidraScript {

	static final int MAX_UNWRAP_DEPTH = 32;
	static final int MAX_BASE_DEPTH = 24;
	static final int MAX_DECOMPILE_SECONDS = 30;
	static final int MIN_STRONG_OFFSETS = 2;

	int bsHandleProtocolOffset() { return programPointerSize == 8 ? 0x98 : 0x4c; }
	int bsOpenProtocolOffset()   { return programPointerSize == 8 ? 0x118 : 0x8c; }
	int bsLocateProtocolOffset() { return programPointerSize == 8 ? 0x140 : 0xa0; }

	static class MethodModel {
		String owner, ownerPath, field, declared, name, ret;
		int offset;
		List<String> args = new ArrayList<>();
		List<DataType> argTypes = new ArrayList<>();
		DataType returnType;
		boolean varargs;

		String proto() {
			return ret + " " + name + "(" +
				String.join(", ", args) +
				(varargs ? (args.isEmpty() ? "..." : ", ...") : "") + ")";
		}
	}

	static class StructModel {
		String name, path;
		int length;
		boolean union;
		Map<Integer,List<MethodModel>> methods = new TreeMap<>();
		TreeSet<Integer> fingerprint = new TreeSet<>();

		int callableCount() {
			int n = 0;
			for (List<MethodModel> x : methods.values()) n += x.size();
			return n;
		}

		String fp() {
			StringJoiner j = new StringJoiner(",", "{", "}");
			for (int x : fingerprint) j.add(String.format("%X", x));
			return j.toString();
		}
	}

	static class BaseExpr {
		String key;
		String display;
		Address globalAddress;
		Varnode root;
		boolean global;
	}

	static class CallObs {
		Address callAddress;
		Address functionAddress;
		String functionName;
		String baseKey, baseDisplay;
		long offset;
		int argCount;
		List<Varnode> args = new ArrayList<>();
		Varnode output;
		String targetText;
	}

	static class ProvenanceObs {
		Address callAddress;
		Address functionAddress;
		String functionName;
		String service;
		String serviceObjectKey;
		String guid;
		String guidName;
		String expectedType;
		String interfaceKey;
		String interfaceDisplay;
		String linkedObjectKey;
		String linkedObjectDisplay;
		String linkMethod;
		String interfaceTrace;
		String pcodeDiagnostic;
		String recoveredStorage;
		String recoveredStorageKind;
		String recoveredStorageType;
		String storageDiagnostic;
	}

	static class ObjectObs {
		String key, display;
		boolean global;
		Address globalAddress;
		TreeSet<Integer> offsets = new TreeSet<>();
		List<CallObs> calls = new ArrayList<>();
	}

	static class Match {
		StructModel model;
		int overlap, missingObserved, extraModel;
		int arityMatches, arityConflicts, arityUnknown;
		int concreteArgExact, concreteArgCompatible, concreteArgConflict;
		int thisMatches;
		int returnExact, returnCompatible, returnConflict;
		double coverageObserved, coverageModel;
		boolean exact;

		int concretePositive() {
			return concreteArgExact + concreteArgCompatible + thisMatches +
				returnExact + returnCompatible;
		}

		String signatureEvidence() {
			int observedCalls = arityMatches + arityConflicts + arityUnknown;
			boolean allRecoveredArityMatches =
				observedCalls > 0 && arityConflicts == 0 &&
				arityMatches >= Math.max(MIN_STRONG_OFFSETS, observedCalls - arityUnknown);

			if (overlap >= MIN_STRONG_OFFSETS && allRecoveredArityMatches)
				return "STRONG";

			if (overlap >= MIN_STRONG_OFFSETS &&
				(arityMatches > 0 || concretePositive() > 0))
				return "SUPPORTED";

			return "WEAK";
		}

		String identityEvidence(int candidateCount) {
			if (candidateCount == 1 && overlap >= MIN_STRONG_OFFSETS && missingObserved == 0)
				return "STRONG";

			if (overlap >= MIN_STRONG_OFFSETS && missingObserved == 0)
				return "AMBIGUOUS";

			if (overlap > 0)
				return "SUPPORTED";

			return "WEAK";
		}

		String rankText(int candidateCount) {
			return String.format(
				Locale.ROOT,
				"overlap=%d observedCoverage=%.2f modelCoverage=%.2f " +
				"arity=%d match/%d conflict/%d unknown " +
				"argType=%d exact/%d compatible/%d conflict this=%d " +
				"returnType=%d exact/%d compatible/%d conflict " +
				"missingObserved=%d extraModel=%d identity=%s signature=%s%s",
				overlap, coverageObserved, coverageModel,
				arityMatches, arityConflicts, arityUnknown,
				concreteArgExact, concreteArgCompatible, concreteArgConflict,
				thisMatches,
				returnExact, returnCompatible, returnConflict,
				missingObserved, extraModel,
				identityEvidence(candidateCount), signatureEvidence(),
				exact ? " EXACT" : ""
			);
		}
	}

	DataTypeManager src;
	String srcName;
	int programPointerSize;

	Map<String,StructModel> structs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	Map<Integer,List<MethodModel>> byOffset = new TreeMap<>();
	Map<String,ObjectObs> objects = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	List<ProvenanceObs> provenance = new ArrayList<>();
	Map<String,String> guidNames = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	Map<String,String> guidTypes = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	String guidDbSource = "none";

	int datatypeCount;
	int callableStructCount;
	int callableFieldCount;
	int functionsVisited;
	int functionsDecompiled;
	int indirectCalls;
	int modeledCalls;

	DecompInterface decompiler;
	Function activeFunction;

	public void run() throws Exception {
		println("========================================================================");
		println(" Behemoth - Object Finder");
		println("========================================================================\n");

		if (currentProgram == null) {
			printerr("No program is open.");
			return;
		}

		programPointerSize = currentProgram.getDefaultPointerSize();
		String expectedArchive =
			programPointerSize == 8 ? "Behemoth_X64" :
			programPointerSize == 4 ? "Behemoth_IA32" : null;

		if (expectedArchive == null) {
			printerr("Unsupported program pointer size: " + programPointerSize +
				". Expected 8 (X64) or 4 (IA32).");
			return;
		}

		src = findBehemoth(expectedArchive);
		if (src == null) {
			printerr(expectedArchive + " datatype archive not found. Open " +
				expectedArchive + ".gdt in Data Type Manager and rerun.");
			return;
		}

		srcName = safeName(src);

		println("[1/7] Loading architecture-matched Behemoth universe");
		println("----------------------------------------------------------------------");
		println("      Program ................. " + currentProgram.getName());
		println("      Pointer size ............ " + programPointerSize + " bytes");
		println("      Required archive ........ " + expectedArchive);
		println("      Source .................. " + srcName + "\n");

		println("[2/7] Indexing callable structures");
		println("----------------------------------------------------------------------");
		buildTypeUniverse();
		println("      Data types .............. " + datatypeCount);
		println("      Callable structures ..... " + callableStructCount);
		println("      Callable fields ......... " + callableFieldCount);
		println("      Callable offsets ........ " + byOffset.size() + "\n");

		println("[3/7] Decompiling functions and recovering CALLIND objects");
		println("----------------------------------------------------------------------");
		setupDecompiler();
		scanProgram();

		println("      Functions visited ....... " + functionsVisited);
		println("      Functions decompiled .... " + functionsDecompiled);
		println("      Indirect calls .......... " + indirectCalls);
		println("      Modeled object calls .... " + modeledCalls);
		println("      Candidate objects ....... " + objects.size() + "\n");

		println("[4/7] Building observed object fingerprints");
		println("----------------------------------------------------------------------");
		int multi = 0;
		for (ObjectObs o : objects.values()) if (o.offsets.size() >= 2) multi++;
		println("      Objects with 2+ offsets . " + multi);
		println("      Strong-match threshold .. " + MIN_STRONG_OFFSETS + " observed offsets\n");

		println("[5/7] Matching against Behemoth callable structures");
		println("----------------------------------------------------------------------");
		int matched = 0;
		for (ObjectObs o : objects.values()) {
			if (!matches(o).isEmpty()) matched++;
		}
		println("      Objects with candidates . " + matched + "/" + objects.size() + "\n");

		println("[6/7] Recovering UEFI protocol provenance");
		println("----------------------------------------------------------------------");
		loadGuidDatabase();
		recoverProtocolProvenance();

		int linked = 0, named = 0;
		for (ProvenanceObs p : provenance) {
			if (p.linkedObjectKey != null) linked++;
			if (p.guidName != null) named++;
		}
		println("      GUID database ........... " + guidDbSource);
		println("      Protocol service calls .. " + provenance.size());
		println("      GUID names resolved ..... " + named);
		println("      GUID type mappings ...... " + guidTypes.size());
		println("      Interface objects linked  " + linked + "\n");

		println("[7/7] Writing report");
		println("----------------------------------------------------------------------");
		File report = new File(System.getProperty("user.home"), "Behemoth_Object_Finder.txt");
		writeReport(report);
		println("      Report saved: " + report.getAbsolutePath() + "\n");

		println("========================================================================");
		println(" Results");
		println("========================================================================");
		println("      Callable structs   " + callableStructCount);
		println("      Callable fields    " + callableFieldCount);
		println("      Functions          " + functionsDecompiled + "/" + functionsVisited);
		println("      CALLIND            " + indirectCalls);
		println("      Modeled calls      " + modeledCalls);
		println("      Candidate objects  " + objects.size());
		println("      Provenance calls   " + provenance.size());
		println("========================================================================");
	}

	DataTypeManager findBehemoth(String expectedArchive) {
		try {
			DataTypeManagerService s =
				state.getTool().getService(DataTypeManagerService.class);
			if (s == null) return null;

			DataTypeManager[] managers = s.getDataTypeManagers();
			if (managers == null) return null;

			String wanted = expectedArchive.toLowerCase(Locale.ROOT);

			for (DataTypeManager d : managers) {
				if (d == null) continue;
				if (d == currentProgram.getDataTypeManager()) continue;

				String n = safeName(d).toLowerCase(Locale.ROOT);
				if (n.equals(wanted) || n.equals(wanted + ".gdt")) return d;
			}
		}
		catch (Throwable t) {
			printerr("Could not enumerate Data Type Managers: " + t.getMessage());
		}
		return null;
	}

	String safeName(DataTypeManager d) {
		try { return d.getName(); }
		catch (Throwable t) { return "<unnamed>"; }
	}

	void buildTypeUniverse() {
		Iterator<DataType> it = src.getAllDataTypes();

		while (it.hasNext() && !monitor.isCancelled()) {
			DataType d = it.next();
			if (d == null) continue;
			datatypeCount++;

			if (!(d instanceof Structure) && !(d instanceof Union)) continue;

			Composite c = (Composite)d;
			StructModel s = new StructModel();
			s.name = d.getName();
			s.path = path(d);
			s.length = length(d);
			s.union = d instanceof Union;

			DataTypeComponent[] components;
			try { components = c.getDefinedComponents(); }
			catch (Throwable t) { components = c.getComponents(); }

			for (DataTypeComponent x : components) {
				if (x == null) continue;

				FunctionDefinition fd = unwrapFunction(x.getDataType());
				if (fd == null) continue;

				MethodModel m = new MethodModel();
				m.owner = s.name;
				m.ownerPath = s.path;
				m.field = fieldName(x);
				m.offset = x.getOffset();
				m.declared = display(x.getDataType());
				m.name = fd.getName();
				m.returnType = fd.getReturnType();
				m.ret = display(m.returnType);

				ParameterDefinition[] args = fd.getArguments();
				if (args != null) {
					for (ParameterDefinition p : args) {
						if (p == null) continue;
						DataType pdt = p.getDataType();
						m.argTypes.add(pdt);
						String t = display(pdt);
						String n = p.getName();
						m.args.add(n == null || n.isBlank() ? t : t + " " + n);
					}
				}

				try { m.varargs = fd.hasVarArgs(); }
				catch (Throwable t) {}

				s.methods.computeIfAbsent(m.offset, k -> new ArrayList<>()).add(m);
				s.fingerprint.add(m.offset);
				byOffset.computeIfAbsent(m.offset, k -> new ArrayList<>()).add(m);
				callableFieldCount++;
			}

			if (!s.fingerprint.isEmpty()) {
				callableStructCount++;
				structs.put(s.path, s);
			}
		}
	}

	FunctionDefinition unwrapFunction(DataType d) {
		Set<DataType> seen =
			Collections.newSetFromMap(new IdentityHashMap<DataType,Boolean>());

		for (int i = 0; i < MAX_UNWRAP_DEPTH && d != null; i++) {
			if (!seen.add(d)) return null;
			if (d instanceof FunctionDefinition) return (FunctionDefinition)d;
			if (d instanceof TypeDef) {
				d = ((TypeDef)d).getBaseDataType();
				continue;
			}
			if (d instanceof Pointer) {
				d = ((Pointer)d).getDataType();
				continue;
			}
			return null;
		}
		return null;
	}

	void setupDecompiler() {
		decompiler = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		decompiler.setOptions(options);
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");

		if (!decompiler.openProgram(currentProgram)) {
			throw new RuntimeException("Could not initialize Ghidra decompiler.");
		}
	}

	void scanProgram() {
		FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);

		while (fit.hasNext() && !monitor.isCancelled()) {
			Function f = fit.next();
			if (f == null || f.isThunk()) continue;
			functionsVisited++;

			DecompileResults dr =
				decompiler.decompileFunction(f, MAX_DECOMPILE_SECONDS, monitor);

			if (dr == null || !dr.decompileCompleted()) continue;

			HighFunction hf = dr.getHighFunction();
			if (hf == null) continue;

			functionsDecompiled++;
			activeFunction = f;

			Iterator<PcodeOpAST> ops = hf.getPcodeOps();
			while (ops.hasNext() && !monitor.isCancelled()) {
				PcodeOpAST op = ops.next();
				if (op.getOpcode() != PcodeOp.CALLIND) continue;

				indirectCalls++;
				processCallInd(f, op);
			}
		}
	}

	void processCallInd(Function f, PcodeOpAST call) {
		if (call.getNumInputs() < 1) return;

		Varnode target = call.getInput(0);
		TargetExpr te = resolveTarget(target, 0, new HashSet<Varnode>());
		if (te == null || te.base == null) return;

		long rawOffset = te.offset;
		if (rawOffset < 0 || rawOffset > Integer.MAX_VALUE) return;
		if ((rawOffset % programPointerSize) != 0) return;

		int off = (int)rawOffset;

		CallObs co = new CallObs();
		co.callAddress = call.getSeqnum().getTarget();
		co.functionAddress = f.getEntryPoint();
		co.functionName = f.getName();
		co.baseKey = te.base.key;
		co.baseDisplay = te.base.display;
		co.offset = off;
		co.argCount = Math.max(0, call.getNumInputs() - 1);
		for (int ai = 1; ai < call.getNumInputs(); ai++) {
			co.args.add(call.getInput(ai));
		}
		co.output = call.getOutput();
		co.targetText = target.toString();

		ObjectObs obj = objects.computeIfAbsent(co.baseKey, k -> {
			ObjectObs o = new ObjectObs();
			o.key = te.base.key;
			o.display = te.base.display;
			o.global = te.base.global;
			o.globalAddress = te.base.globalAddress;
			return o;
		});

		obj.offsets.add(off);
		obj.calls.add(co);
		modeledCalls++;
	}

	boolean isBootServicesModel(StructModel m) {
		if (m == null || m.name == null) return false;
		String n = m.name.replaceFirst("^_+", "").toUpperCase(Locale.ROOT);
		return n.equals("EFI_BOOT_SERVICES");
	}

	boolean bootServicesCandidate(ObjectObs obj) {
		if (obj == null) return false;
		for (Match m : matches(obj)) {
			if (!isBootServicesModel(m.model)) continue;
			String sig = m.signatureEvidence();
			String id = m.identityEvidence(matches(obj).size());
			if ("STRONG".equals(id) || "STRONG".equals(sig) || "SUPPORTED".equals(sig))
				return true;
		}
		return false;
	}

	void recoverProtocolProvenance() {
		provenance.clear();
		for (ObjectObs obj : objects.values()) {
			if (!bootServicesCandidate(obj)) continue;
			for (CallObs c : obj.calls) {
				int guidArg = -1, interfaceArg = -1;
				String service = null;
				if (c.offset == bsHandleProtocolOffset()) {
					service = "HandleProtocol"; guidArg = 1; interfaceArg = 2;
				}
				else if (c.offset == bsOpenProtocolOffset()) {
					service = "OpenProtocol"; guidArg = 1; interfaceArg = 2;
				}
				else if (c.offset == bsLocateProtocolOffset()) {
					service = "LocateProtocol"; guidArg = 0; interfaceArg = 2;
				}
				else continue;

				ProvenanceObs p = new ProvenanceObs();
				p.callAddress = c.callAddress;
				p.functionAddress = c.functionAddress;
				p.functionName = c.functionName;
				p.service = service;
				p.serviceObjectKey = obj.key;

				Function provenanceFunction =
					currentProgram.getFunctionManager().getFunctionAt(c.functionAddress);
				if (provenanceFunction != null) activeFunction = provenanceFunction;

				if (guidArg < c.args.size()) {
					Address ga = resolvePointerAddress(c.args.get(guidArg), 0, new HashSet<Varnode>());
					if (ga != null) {
						p.guid = readEfiGuid(ga);
						if (p.guid != null) {
							p.guidName = guidNames.get(p.guid);
							if (p.guidName != null) p.expectedType = guidTypes.get(p.guidName);
						}
					}
				}

				if (interfaceArg < c.args.size()) {
					BaseExpr dst = resolveOutputDestination(c.args.get(interfaceArg), 0, new HashSet<Varnode>());
					if (dst != null) {
						p.interfaceKey = dst.key;
						p.interfaceDisplay = dst.display;
						ObjectObs linkedObj = objects.get(dst.key);
						if (linkedObj != null) {
							p.linkedObjectKey = linkedObj.key;
							p.linkedObjectDisplay = linkedObj.display;
							p.linkMethod = "DIRECT_IDENTITY";
						}
					}
				}

				if (interfaceArg >= 0 && interfaceArg < c.args.size()) {
					AddrExpr storage = normalizeAddressExpr(
						c.args.get(interfaceArg), 0, new HashSet<Varnode>());
					if (storage != null) {
						p.recoveredStorage = addressExprDisplay(storage);
						p.recoveredStorageKind = storageKind(storage);
						if (p.expectedType != null)
							p.recoveredStorageType = p.expectedType + " *";

						ObjectObs directStorage = objectFromStorageExpr(storage);
						if (p.linkedObjectKey == null && directStorage != null) {
							p.linkedObjectKey = directStorage.key;
							p.linkedObjectDisplay = directStorage.display;
							p.linkMethod = "DIRECT_STORAGE_IDENTITY";
						}
					}
				}

				if (interfaceArg >= 0 && interfaceArg < c.args.size() &&
					("HIGH".equals(p.recoveredStorageKind) ||
					"REGISTER".equals(p.recoveredStorageKind) ||
					p.recoveredStorageKind == null)) {
					p.storageDiagnostic = buildStorageDiagnostic(
						c.args.get(interfaceArg), c.callAddress);
				}

				if (p.linkedObjectKey == null && interfaceArg >= 0 &&
					interfaceArg < c.args.size()) {
					TraceLink traced = traceInterfaceOutput(
						c.args.get(interfaceArg), c.callAddress);
					if (traced != null) {
						p.interfaceTrace = traced.trace;
						if (traced.object != null) {
							p.linkedObjectKey = traced.object.key;
							p.linkedObjectDisplay = traced.object.display;
							p.linkMethod = "INTERFACE_DATAFLOW";
						}
					}
				}

				provenance.add(p);
			}
		}
		provenance.sort(Comparator.comparing(x -> x.callAddress));
	}

	String vn(Varnode v) {
		if (v == null) return "null";
		StringBuilder b = new StringBuilder();
		try {
			b.append(v.toString());
			b.append(" size=").append(v.getSize());
			HighVariable h = v.getHigh();
			if (h != null) {
				b.append(" high=");
				String n = h.getName();
				b.append(n == null ? "<unnamed>" : n);
				try {
					Varnode r = h.getRepresentative();
					if (r != null) b.append(" rep=").append(r.toString());
				}
				catch (Throwable ignored) {}
			}
			PcodeOp d = v.getDef();
			if (d != null) {
				b.append(" def=").append(pcodeName(d.getOpcode()));
				if (d.getSeqnum() != null && d.getSeqnum().getTarget() != null)
					b.append("@").append(d.getSeqnum().getTarget());
			}
		}
		catch (Throwable t) {
			b.append(" <describe-error>");
		}
		return b.toString();
	}

	String pcodeName(int opcode) {
		try {
			return PcodeOp.getMnemonic(opcode);
		}
		catch (Throwable t) {
			return "OP_" + opcode;
		}
	}

	String opLine(PcodeOp op) {
		if (op == null) return "<null-op>";
		StringBuilder b = new StringBuilder();
		try {
			Address a = op.getSeqnum() == null ? null : op.getSeqnum().getTarget();
			b.append(a == null ? "????????" : a.toString());
			b.append("  ").append(pcodeName(op.getOpcode())).append("  ");
			Varnode out = op.getOutput();
			b.append(out == null ? "<no-output>" : vn(out));
			b.append(" <- ");
			for (int i = 0; i < op.getNumInputs(); i++) {
				if (i != 0) b.append(" | ");
				b.append(vn(op.getInput(i)));
			}
		}
		catch (Throwable t) {
			b.append("<op-describe-error>");
		}
		return b.toString();
	}

	void backwardDiagnostic(
			Varnode v, int depth, int maxDepth,
			Set<Varnode> seen, List<String> out) {
		if (v == null || depth > maxDepth || !seen.add(v)) return;
		PcodeOp def = v.getDef();
		if (def == null) {
			out.add(indent(depth) + "LEAF " + vn(v));
			return;
		}
		out.add(indent(depth) + opLine(def));
		for (int i = 0; i < def.getNumInputs(); i++)
			backwardDiagnostic(def.getInput(i), depth + 1, maxDepth, seen, out);
	}

	void forwardDiagnostic(
			Varnode v, int depth, int maxDepth,
			Set<Varnode> seen, List<String> out) {
		if (v == null || depth > maxDepth || !seen.add(v)) return;
		Iterator<PcodeOp> descendants = v.getDescendants();
		while (descendants != null && descendants.hasNext()) {
			PcodeOp op = descendants.next();
			if (op == null) continue;
			out.add(indent(depth) + opLine(op));
			Varnode o = op.getOutput();
			if (o != null)
				forwardDiagnostic(o, depth + 1, maxDepth, seen, out);
		}
	}

	String indent(int n) {
		StringBuilder b = new StringBuilder();
		for (int i = 0; i < n; i++) b.append("  ");
		return b.toString();
	}

	String buildProvenancePcodeDiagnostic(
			Varnode interfaceArg, Address callAddress) {
		StringBuilder out = new StringBuilder();
		out.append("Interface argument: ").append(vn(interfaceArg)).append("\\n");

		try {
			BaseExpr base = baseFromVarnode(interfaceArg);
			out.append("Base identity: ")
			.append(base == null || base.key == null ? "unresolved" : base.key)
			.append("\\n");
		}
		catch (Throwable t) {
			out.append("Base identity: <error>\\n");
		}

		List<String> back = new ArrayList<String>();
		backwardDiagnostic(
			interfaceArg, 0, 12, new HashSet<Varnode>(), back);
		out.append("BACKWARD SLICE\\n");
		for (String x : back) out.append("  ").append(x).append("\\n");

		List<String> fwd = new ArrayList<String>();
		forwardDiagnostic(
			interfaceArg, 0, 12, new HashSet<Varnode>(), fwd);
		out.append("FORWARD SLICE\\n");
		for (String x : fwd) out.append("  ").append(x).append("\\n");

		if (activeFunction != null) {
			try {
				DecompInterface di = new DecompInterface();
				di.openProgram(currentProgram);
				DecompileResults dr =
					di.decompileFunction(activeFunction, 60, monitor);
				if (dr != null && dr.decompileCompleted() &&
					dr.getHighFunction() != null) {
					ArrayList<PcodeOpAST> nearby = new ArrayList<PcodeOpAST>();
					Iterator<PcodeOpAST> it = dr.getHighFunction().getPcodeOps();
					while (it.hasNext()) {
						PcodeOpAST op = it.next();
						if (op == null || op.getSeqnum() == null) continue;
						Address a = op.getSeqnum().getTarget();
						if (a == null || callAddress == null) continue;
						long delta;
						try {
							delta = a.subtract(callAddress);
						}
						catch (Throwable ignored) {
							continue;
						}
						if (delta >= -0x30 && delta <= 0x50)
							nearby.add(op);
					}
					out.append("NEARBY PCODE [-0x30,+0x50]\\n");
					for (PcodeOpAST op : nearby)
						out.append("  ").append(opLine(op)).append("\\n");
				}
				di.dispose();
			}
			catch (Throwable t) {
				out.append("NEARBY PCODE <decompile-error>\\n");
			}
		}

		return out.toString();
	}

	static class TraceLink {
		ObjectObs object;
		String trace;
	}

	static class AddrExpr {
		Address constantAddress;
		String baseKey;
		long offset;
		String display;
	}

	String varnodeShallow(Varnode v) {
		if (v == null) return "<null>";
		StringBuilder b = new StringBuilder();
		try { b.append(v.toString()); } catch (Throwable t) { b.append("<varnode>"); }
		try {
			Address a = v.getAddress();
			if (a != null) {
				b.append(" space=").append(a.getAddressSpace().getName());
				b.append(" addr=").append(a);
				b.append(" mem=").append(a.isMemoryAddress());
				b.append(" stack=").append(a.isStackAddress());
				b.append(" reg=").append(a.isRegisterAddress());
				if (a.isRegisterAddress()) {
					Register r = null;
					try { r = currentProgram.getRegister(a, v.getSize()); }
					catch (Throwable ignored) {}
					b.append(" regName=").append(r == null ? "<unresolved>" : r.getName());
					if (r != null) {
						Register top = r;
						while (top.getParentRegister() != null)
							top = top.getParentRegister();
						b.append(" regTop=").append(top.getName());
					}
				}
			}
		} catch (Throwable ignored) {}
		b.append(" size=").append(v.getSize());
		return b.toString();
	}

	String describeVarnode(Varnode v) {
		if (v == null) return "<null>";
		StringBuilder b = new StringBuilder(varnodeShallow(v));
		try {
			HighVariable h = v.getHigh();
			if (h != null) {
				b.append(" high=").append(h.getName());
				Varnode rep = h.getRepresentative();
				if (rep != null && rep != v)
					b.append(" rep={").append(varnodeShallow(rep)).append("}");
			}
		} catch (Throwable ignored) {}
		return b.toString();
	}

	String describePcodeOp(PcodeOp op) {
		if (op == null) return "<no-def>";
		StringBuilder b = new StringBuilder();
		try {
			b.append(op.getMnemonic());
			if (op.getSeqnum() != null)
				b.append(" @ ").append(op.getSeqnum().getTarget());
		} catch (Throwable ignored) {}
		b.append(" out={").append(varnodeShallow(op.getOutput())).append("}");
		for (int i = 0; i < op.getNumInputs(); i++)
			b.append(" in[").append(i).append("]={")
			.append(varnodeShallow(op.getInput(i))).append("}");
		return b.toString();
	}

	void describeBackwardDefinition(Varnode v, int depth, Set<Varnode> seen, StringBuilder out) {
		if (v == null || depth > 10 || !seen.add(v)) return;
		String pad = String.join("", Collections.nCopies(depth, "  "));
		out.append(pad).append("VN ").append(describeVarnode(v)).append("\\n");
		PcodeOp d = v.getDef();
		out.append(pad).append("DEF ").append(describePcodeOp(d)).append("\\n");
		if (d == null) return;
		for (int i = 0; i < d.getNumInputs(); i++)
			describeBackwardDefinition(d.getInput(i), depth + 1, seen, out);
	}

	String buildStorageDiagnostic(Varnode interfaceArg, Address callAddress) {
		StringBuilder out = new StringBuilder();
		out.append("call=").append(callAddress).append("\\n");
		out.append("Interface** raw: ").append(describeVarnode(interfaceArg)).append("\\n");
		out.append("Backward definition chain:\\n");
		describeBackwardDefinition(interfaceArg, 0, new HashSet<Varnode>(), out);
		return out.toString();
	}

	boolean isStackPointerRegister(Register r) {
		if (r == null) return false;
		try {
			Register x = r;
			while (x.getParentRegister() != null) x = x.getParentRegister();
			String n = x.getName();
			if (n == null) n = r.getName();
			if (n == null) return false;
			n = n.toUpperCase(Locale.ROOT);
			if (programPointerSize == 8)
				return n.equals("RSP") || r.getName().equalsIgnoreCase("RSP");
			if (programPointerSize == 4)
				return n.equals("ESP") || r.getName().equalsIgnoreCase("ESP");
			return n.equals("SP") || n.equals("RSP") || n.equals("ESP");
		}
		catch (Throwable t) {
			String n = r.getName();
			return n != null && (n.equalsIgnoreCase("RSP") ||
				n.equalsIgnoreCase("ESP") || n.equalsIgnoreCase("SP"));
		}
	}

	long signedPointerOffset(long raw) {
		if (programPointerSize == 4) return (long)(int)(raw & 0xffffffffL);
		return raw;
	}

	AddrExpr stackExprFromSpRelative(Varnode v) {
		if (v == null || activeFunction == null) return null;
		PcodeOp d = v.getDef();
		if (d == null || d.getOpcode() != PcodeOp.PTRSUB || d.getNumInputs() < 2)
			return null;
		Varnode base = d.getInput(0), disp = d.getInput(1);
		if (base == null || disp == null || !disp.isConstant()) return null;

		Register reg = null;
		try {
			Address a = base.getAddress();
			if (a != null && a.isRegisterAddress())
				reg = currentProgram.getRegister(a, base.getSize());
		} catch (Throwable ignored) {}
		if (reg == null || !isStackPointerRegister(reg)) return null;

		long rawDisp = signedPointerOffset(disp.getOffset());

		try {
			HighVariable h = v.getHigh();
			if (h != null) {
				Varnode rep = h.getRepresentative();
				if (rep != null) {
					Address a = rep.getAddress();
					if (a != null && a.isStackAddress()) {
						AddrExpr e = new AddrExpr();
						e.baseKey = "STACK:" + activeFunction.getEntryPoint() + ":" + a;
						e.offset = 0;
						e.display = addressExprDisplay(e);
						return e;
					}
				}
			}
		} catch (Throwable ignored) {}

		try {
			StackFrame frame = activeFunction.getStackFrame();
			if (frame != null) {
				for (Variable var : frame.getStackVariables()) {
					if (var != null && var.isStackVariable() &&
						((long)var.getStackOffset()) == rawDisp) {
						AddrExpr e = new AddrExpr();
						e.baseKey = "STACK:" + activeFunction.getEntryPoint() +
							":Stack[" + String.format("0x%X", var.getStackOffset()) + "]";
						e.offset = 0;
						e.display = addressExprDisplay(e);
						return e;
					}
				}
			}
		} catch (Throwable ignored) {}
		return null;
	}

	AddrExpr normalizeAddressExpr(Varnode v, int depth, Set<Varnode> seen) {

		AddrExpr v78stack = stackExprFromSpRelative(v);
		if (v78stack != null) return v78stack;

		if (v != null && depth <= 24) {
			PcodeOp v75def = v.getDef();
			if (v75def != null && v75def.getOpcode() == PcodeOp.PTRSUB &&
				v75def.getNumInputs() >= 2) {
				Varnode v75base = v75def.getInput(0);
				Varnode v75off  = v75def.getInput(1);

				if (v75base != null && v75off != null &&
					v75base.isConstant() && v75off.isConstant() &&
					v75base.getOffset() == 0) {
					try {
						Address v75addr = currentProgram.getAddressFactory()
							.getDefaultAddressSpace().getAddress(v75off.getOffset());
						AddrExpr v75r = new AddrExpr();
						v75r.constantAddress = v75addr;
						v75r.offset = 0;
						return v75r;
					}
					catch (Throwable ignored) {}
				}

				if (v75base != null && v75off != null && v75off.isConstant()) {
					try {
						HighVariable v75h = v75base.getHigh();
						Varnode v75rep = (v75h != null) ? v75h.getRepresentative() : null;
						Varnode v75basis = (v75rep != null) ? v75rep : v75base;
						if (v75basis.isAddress()) {
							Address v75a = v75basis.getAddress();
							if (v75a != null && v75a.isStackAddress()) {
								AddrExpr v75r = new AddrExpr();
								v75r.baseKey = "STACK:" + activeFunction.getEntryPoint() +
									":" + v75a.toString();
								v75r.offset = v75off.getOffset();
								return v75r;
							}
							if (v75a != null && v75a.isRegisterAddress()) {
								Register v76reg = null;
								try {
									v76reg = currentProgram.getRegister(v75a, v75basis.getSize());
								}
								catch (Throwable ignored) {}

								if (v76reg != null && isStackPointerRegister(v76reg)) {
									AddrExpr v75r = new AddrExpr();
									v75r.baseKey = "STACK:" +
										(activeFunction == null ? "?" :
										activeFunction.getEntryPoint().toString()) +
										":SP";
									v75r.offset = signedPointerOffset(v75off.getOffset());
									v75r.display = addressExprDisplay(v75r);
									return v75r;
								}

								AddrExpr v75r = new AddrExpr();
								v75r.baseKey = "REGISTER:" + activeFunction.getEntryPoint() +
									":" + (v76reg != null ? v76reg.getName() : v75a.toString());
								v75r.offset = signedPointerOffset(v75off.getOffset());
								v75r.display = addressExprDisplay(v75r);
								return v75r;
							}
						}
					}
					catch (Throwable ignored) {}
				}
			}
		}

		if (v == null || depth > 24 || !seen.add(v)) return null;

		try {
			if (v.isAddress()) {
				AddrExpr a = new AddrExpr();
				a.constantAddress = v.getAddress();
				a.display = "RAM:" + v.getAddress();
				return a;
			}

			PcodeOp def = v.getDef();
			if (def != null) {
				int op = def.getOpcode();

				if (op == PcodeOp.COPY || op == PcodeOp.CAST ||
					op == PcodeOp.INDIRECT) {
					return normalizeAddressExpr(
						def.getInput(0), depth + 1, new HashSet<Varnode>(seen));
				}

				if (op == PcodeOp.PTRSUB || op == PcodeOp.INT_ADD) {
					AddrExpr b = normalizeAddressExpr(
						def.getInput(0), depth + 1, new HashSet<Varnode>(seen));
					Long off = constValue(def.getInput(1));
					if (b != null && off != null) {
						b.offset += off.longValue();
						b.display = addressExprDisplay(b);
						return b;
					}

					b = normalizeAddressExpr(
						def.getInput(1), depth + 1, new HashSet<Varnode>(seen));
					off = constValue(def.getInput(0));
					if (b != null && off != null) {
						b.offset += off.longValue();
						b.display = addressExprDisplay(b);
						return b;
					}
				}

				if (op == PcodeOp.PTRADD) {
					AddrExpr b = normalizeAddressExpr(
						def.getInput(0), depth + 1, new HashSet<Varnode>(seen));
					Long index = constValue(def.getInput(1));
					Long scale = constValue(def.getInput(2));
					if (b != null && index != null && scale != null) {
						b.offset += index.longValue() * scale.longValue();
						b.display = addressExprDisplay(b);
						return b;
					}
				}
			}

			BaseExpr base = baseFromVarnode(v);
			if (base != null && base.key != null) {
				AddrExpr a = new AddrExpr();
				a.baseKey = base.key;
				a.offset = 0;
				a.display = addressExprDisplay(a);
				return a;
			}
		}
		catch (Throwable t) {
			return null;
		}

		return null;
	}

	String addressExprDisplay(AddrExpr a) {
		if (a == null) return "unresolved";
		if (a.constantAddress != null) {
			long off = a.offset;
			if (off == 0) return "RAM:" + a.constantAddress;
			return "RAM:" + a.constantAddress +
				(off >= 0 ? "+" : "") + String.format("0x%X", off);
		}
		if (a.baseKey != null) {
			return a.baseKey +
				(a.offset == 0 ? "" :
					((a.offset >= 0 ? "+" : "") +
					String.format("0x%X", a.offset)));
		}
		return "unresolved";
	}

	boolean sameAddressExpr(AddrExpr a, AddrExpr b) {
		if (a == null || b == null) return false;

		if (a.constantAddress != null && b.constantAddress != null) {
			try {
				Address aa = a.constantAddress.add(a.offset);
				Address bb = b.constantAddress.add(b.offset);
				return aa.equals(bb);
			}
			catch (Throwable t) {
				return false;
			}
		}

		return a.baseKey != null && b.baseKey != null &&
			a.baseKey.equals(b.baseKey) && a.offset == b.offset;
	}

	Long constValue(Varnode v) {
		if (v == null || !v.isConstant()) return null;
		return Long.valueOf(v.getOffset());
	}

	ObjectObs objectFromValueVarnode(Varnode value) {
		if (value == null) return null;
		try {
			BaseExpr b = baseFromVarnode(value);
			if (b != null && b.key != null) {
				ObjectObs o = objects.get(b.key);
				if (o != null) return o;
			}
		}
		catch (Throwable t) {
		}
		return null;
	}

	ObjectObs findUniqueCompatibleObjectAfter(
			Address callAddress, String expectedType) {
		if (activeFunction == null || callAddress == null) return null;

		ObjectObs only = null;
		for (ObjectObs o : objects.values()) {
			if (!objectUsedAfterAcquisitionInFunction(
					o, activeFunction.getEntryPoint(), callAddress))
				continue;
			if (expectedType != null &&
				!objectHasCandidateType(o, expectedType))
				continue;
			if (only != null && !only.key.equals(o.key))
				return null;
			only = o;
		}
		return only;
	}

	TraceLink traceInterfaceOutput(
			Varnode interfaceArg, Address callAddress, String expectedType) {
		TraceLink result = new TraceLink();
		AddrExpr target = normalizeAddressExpr(
			interfaceArg, 0, new HashSet<Varnode>());

		if (target == null) {
			result.trace = "Interface** storage unresolved";
			return result;
		}

		result.trace = "storage=" + addressExprDisplay(target);

		if (activeFunction == null || activeFunction.getEntryPoint() == null)
			return result;

		DecompileResults dr = null;
		try {
			DecompInterface di = new DecompInterface();
			di.openProgram(currentProgram);
			dr = di.decompileFunction(activeFunction, 60, monitor);
			di.dispose();
		}
		catch (Throwable t) {
			return result;
		}

		if (dr == null || !dr.decompileCompleted() ||
			dr.getHighFunction() == null)
			return result;

		HighFunction hf = dr.getHighFunction();
		Iterator<PcodeOpAST> it = hf.getPcodeOps();

		ObjectObs unique = null;
		int matchingLoads = 0;
		int resolvedLoads = 0;

		while (it.hasNext()) {
			PcodeOpAST op = it.next();
			if (op == null || op.getSeqnum() == null) continue;

			Address at = op.getSeqnum().getTarget();
			if (at == null || at.compareTo(callAddress) <= 0) continue;

			if (op.getOpcode() != PcodeOp.LOAD || op.getNumInputs() < 2)
				continue;

			AddrExpr loadAddr = normalizeAddressExpr(
				op.getInput(1), 0, new HashSet<Varnode>());
			if (!sameAddressExpr(target, loadAddr))
				continue;

			matchingLoads++;

			Varnode out = op.getOutput();
			ObjectObs candidate = objectFromValueVarnode(out);
			if (candidate == null) continue;

			if (expectedType != null &&
				!objectHasCandidateType(candidate, expectedType))
				continue;

			resolvedLoads++;
			if (unique != null && !unique.key.equals(candidate.key)) {
				result.trace += "; loads=" + matchingLoads +
					"; multiple-compatible-objects";
				return result;
			}
			unique = candidate;
		}

		if (unique == null && expectedType != null) {
			ObjectObs fallback =
				findUniqueCompatibleObjectAfter(callAddress, expectedType);
			if (fallback != null) {
				result.object = fallback;
				result.trace += "; loads=" + matchingLoads +
					"; resolvedLoads=" + resolvedLoads +
					"; compatible-post-call=1";
				return result;
			}
		}

		result.object = unique;
		result.trace += "; loads=" + matchingLoads +
			"; resolvedLoads=" + resolvedLoads;
		return result;
	}

	String storageKind(AddrExpr a) {
		if (a == null) return "UNRESOLVED";
		if (a.constantAddress != null) return "GLOBAL";
		if (a.baseKey != null) {
			String k = a.baseKey.toUpperCase(Locale.ROOT);
			if (k.contains("STACK")) return "STACK";
			if (k.contains("REGISTER")) return "REGISTER";
			if (k.contains("UNIQUE")) return "UNIQUE";
			return "HIGH";
		}
		return "UNRESOLVED";
	}

	ObjectObs objectFromStorageExpr(AddrExpr a) {
		if (a == null) return null;

		if (a.constantAddress != null) {
			try {
				Address x = a.constantAddress.add(a.offset);
				ObjectObs o = objects.get("GLOBAL:" + x.toString());
				if (o != null) return o;
			}
			catch (Throwable ignored) {}
		}

		if (a.baseKey != null && a.offset == 0) {
			ObjectObs o = objects.get(a.baseKey);
			if (o != null) return o;
		}
		return null;
	}

	boolean transparentValueOp(int opcode) {
		return opcode == PcodeOp.COPY ||
			opcode == PcodeOp.CAST ||
			opcode == PcodeOp.INDIRECT ||
			opcode == PcodeOp.MULTIEQUAL;
	}

	ObjectObs followValueToObject(
			Varnode seed, Address callAddress, StringBuilder trace) {
		if (seed == null) return null;

		ArrayDeque<Varnode> q = new ArrayDeque<Varnode>();
		HashSet<Varnode> seen = new HashSet<Varnode>();
		q.add(seed);

		ObjectObs unique = null;
		int visited = 0;

		while (!q.isEmpty() && visited < 256) {
			Varnode v = q.removeFirst();
			if (v == null || !seen.add(v)) continue;
			visited++;

			ObjectObs o = objectFromValueVarnode(v);
			if (o != null) {
				if (unique != null && !unique.key.equals(o.key)) {
					trace.append("; multiple-object-identities");
					return null;
				}
				unique = o;
			}

			Iterator<PcodeOp> it = v.getDescendants();
			while (it != null && it.hasNext()) {
				PcodeOp op = it.next();
				if (op == null || op.getSeqnum() == null) continue;
				Address at = op.getSeqnum().getTarget();
				if (at != null && callAddress != null &&
					at.compareTo(callAddress) < 0)
					continue;

				int opc = op.getOpcode();
				if (transparentValueOp(opc)) {
					Varnode out = op.getOutput();
					if (out != null) q.addLast(out);
				}
			}
		}

		trace.append("; ssaVisited=").append(visited);
		return unique;
	}

	boolean indirectBelongsToCall(PcodeOp op, Address callAddress) {
		if (op == null || callAddress == null ||
			op.getOpcode() != PcodeOp.INDIRECT || op.getNumInputs() < 2)
			return false;

		Varnode effect = op.getInput(1);
		if (effect == null) return false;

		try {
			if (effect.isConstant()) {
				long wanted = callAddress.getOffset();
				if (effect.getOffset() == wanted) return true;
			}
		} catch (Throwable ignored) {}

		try {
			PcodeOp d = effect.getDef();
			if (d != null && d.getSeqnum() != null &&
				callAddress.equals(d.getSeqnum().getTarget()))
				return true;
		} catch (Throwable ignored) {}

		return false;
	}

	TraceLink traceInterfaceOutput(
			Varnode interfaceArg, Address callAddress) {
		TraceLink result = new TraceLink();
		AddrExpr target = normalizeAddressExpr(
			interfaceArg, 0, new HashSet<Varnode>());

		if (target == null) {
			result.trace = "Interface** storage unresolved";
			return result;
		}

		StringBuilder tr = new StringBuilder();
		tr.append("storage=").append(addressExprDisplay(target));
		tr.append("; kind=").append(storageKind(target));

		if (activeFunction == null || activeFunction.getEntryPoint() == null) {
			result.trace = tr.toString();
			return result;
		}

		DecompInterface di = new DecompInterface();
		try {
			di.openProgram(currentProgram);
			DecompileResults dr =
				di.decompileFunction(activeFunction, 60, monitor);
			if (dr == null || !dr.decompileCompleted() ||
				dr.getHighFunction() == null) {
				result.trace = tr.append("; decompile-failed").toString();
				return result;
			}

			HighFunction hf = dr.getHighFunction();
			Iterator<PcodeOpAST> it = hf.getPcodeOps();
			ArrayList<Varnode> seeds = new ArrayList<Varnode>();
			int loads = 0;
			int indirects = 0;

			while (it.hasNext()) {
				PcodeOpAST op = it.next();
				if (op == null || op.getSeqnum() == null) continue;

				Address at = op.getSeqnum().getTarget();
				if (at == null || at.compareTo(callAddress) < 0) continue;

				if (op.getOpcode() == PcodeOp.LOAD &&
					op.getNumInputs() >= 2) {
					AddrExpr a = normalizeAddressExpr(
						op.getInput(1), 0, new HashSet<Varnode>());
					if (sameAddressExpr(target, a) && op.getOutput() != null) {
						loads++;
						seeds.add(op.getOutput());
					}
				}

				if (op.getOpcode() == PcodeOp.INDIRECT &&
					op.getOutput() != null) {
					boolean callEffect = indirectBelongsToCall(op, callAddress);
					AddrExpr outStorage = normalizeAddressExpr(
						op.getOutput(), 0, new HashSet<Varnode>());
					boolean same = sameAddressExpr(target, outStorage);

					if (!same) {
						try {
							HighVariable h = op.getOutput().getHigh();
							if (h != null && h.getRepresentative() != null) {
								AddrExpr rep = normalizeAddressExpr(
									h.getRepresentative(), 0,
									new HashSet<Varnode>());
								same = sameAddressExpr(target, rep);
							}
						}
						catch (Throwable ignored) {}
					}

					if (same || callEffect) {
						indirects++;
						seeds.add(op.getOutput());
					}
				}
			}

			ObjectObs unique = null;
			int resolvedSeeds = 0;
			for (Varnode seed : seeds) {
				StringBuilder one = new StringBuilder();
				ObjectObs o = followValueToObject(seed, callAddress, one);
				if (o == null) continue;
				resolvedSeeds++;

				if (unique != null && !unique.key.equals(o.key)) {
					result.trace = tr.append("; loads=").append(loads)
						.append("; indirects=").append(indirects)
						.append("; resolvedSeeds=").append(resolvedSeeds)
						.append("; multiple-dataflow-objects").toString();
					return result;
				}
				unique = o;
			}

			result.object = unique;
			tr.append("; loads=").append(loads);
			tr.append("; indirects=").append(indirects);
			tr.append("; seeds=").append(seeds.size());
			tr.append("; resolvedSeeds=").append(resolvedSeeds);
			result.trace = tr.toString();
			return result;
		}
		catch (Throwable t) {
			result.trace = tr.append("; trace-error=").append(
				t.getClass().getSimpleName()).toString();
			return result;
		}
		finally {
			try { di.dispose(); } catch (Throwable ignored) {}
		}
	}

	String canonicalTypeName(String name) {
		if (name == null) return "";
		return name.replaceFirst("^_+", "").trim().toUpperCase(Locale.ROOT);
	}

	boolean objectHasCandidateType(ObjectObs obj, String expectedType) {
		if (obj == null || expectedType == null) return false;
		String wanted = canonicalTypeName(expectedType);
		if (wanted.isEmpty()) return false;

		for (Match m : matches(obj)) {
			if (m == null || m.model == null) continue;
			if (wanted.equals(canonicalTypeName(m.model.name))) return true;
		}
		return false;
	}

	boolean objectUsedAfterAcquisitionInFunction(
			ObjectObs obj, Address functionAddress, Address acquisitionAddress) {
		if (obj == null || functionAddress == null || acquisitionAddress == null)
			return false;

		for (CallObs oc : obj.calls) {
			if (oc == null || oc.functionAddress == null || oc.callAddress == null)
				continue;
			if (!functionAddress.equals(oc.functionAddress)) continue;
			if (oc.callAddress.compareTo(acquisitionAddress) > 0) return true;
		}
		return false;
	}

	ObjectObs findUniqueProvenanceObject(ProvenanceObs p) {
		if (p == null || p.expectedType == null ||
			p.functionAddress == null || p.callAddress == null)
			return null;

		ObjectObs only = null;

		for (ObjectObs candidate : objects.values()) {
			if (!objectUsedAfterAcquisitionInFunction(
					candidate, p.functionAddress, p.callAddress))
				continue;

			if (!objectHasCandidateType(candidate, p.expectedType))
				continue;

			if (only != null && !only.key.equals(candidate.key))
				return null;

			only = candidate;
		}

		return only;
	}

	BaseExpr resolveOutputDestination(Varnode v, int depth, Set<Varnode> seen) {
		if (v == null || depth > MAX_BASE_DEPTH || !seen.add(v)) return null;
		PcodeOp d = v.getDef();
		if (d != null) {
			switch (d.getOpcode()) {
				case PcodeOp.COPY:
				case PcodeOp.CAST:
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT:
					return resolveOutputDestination(d.getInput(0), depth + 1, seen);
				case PcodeOp.PTRSUB:
				case PcodeOp.PTRADD: {
					BaseExpr b = baseFromVarnode(v);
					if (b != null) return b;
					break;
				}
				default:
					break;
			}
		}
		BaseExpr b = baseFromVarnode(v);
		if (b != null) return b;
		return baseFromStorage(v, depth + 1, seen);
	}

	Address resolvePointerAddress(Varnode v, int depth, Set<Varnode> seen) {
		if (v == null || depth > MAX_BASE_DEPTH || !seen.add(v)) return null;
		if (v.isAddress()) {
			Address a = v.getAddress();
			if (a != null && a.isMemoryAddress()) return a;
		}
		if (v.isConstant()) {
			try { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v.getOffset()); }
			catch (Throwable t) { return null; }
		}
		PcodeOp d = v.getDef();
		if (d == null) return null;
		switch (d.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return resolvePointerAddress(d.getInput(0), depth + 1, seen);
			case PcodeOp.PTRSUB:
			case PcodeOp.INT_ADD: {
				if (d.getNumInputs() < 2) return null;
				Address a = resolvePointerAddress(d.getInput(0), depth + 1, new HashSet<Varnode>(seen));
				Long k = constant(d.getInput(1));
				if (a == null || k == null) return null;
				try { return a.add(k); } catch (Throwable t) { return null; }
			}
			case PcodeOp.PTRADD: {
				if (d.getNumInputs() < 3) return null;
				Address a = resolvePointerAddress(d.getInput(0), depth + 1, new HashSet<Varnode>(seen));
				Long i = constant(d.getInput(1));
				Long z = constant(d.getInput(2));
				if (a == null || i == null || z == null) return null;
				try { return a.add(i * z); } catch (Throwable t) { return null; }
			}
			default:
				return null;
		}
	}

	String readEfiGuid(Address a) {
		if (a == null) return null;
		try {
			Memory mem = currentProgram.getMemory();
			byte[] b = new byte[16];
			for (int i = 0; i < 16; i++) b[i] = mem.getByte(a.add(i));
			long d1 = ((long)b[0] & 0xff) | (((long)b[1] & 0xff) << 8) |
					(((long)b[2] & 0xff) << 16) | (((long)b[3] & 0xff) << 24);
			int d2 = (b[4] & 0xff) | ((b[5] & 0xff) << 8);
			int d3 = (b[6] & 0xff) | ((b[7] & 0xff) << 8);
			return String.format(Locale.ROOT,
				"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				d1, d2, d3, b[8]&0xff, b[9]&0xff, b[10]&0xff, b[11]&0xff,
				b[12]&0xff, b[13]&0xff, b[14]&0xff, b[15]&0xff);
		}
		catch (Throwable t) { return null; }
	}

	void loadGuidDatabase() {
		guidNames.clear();
		guidTypes.clear();
		guidDbSource = "none";

		File selected;

		try {
			selected = askFile(
				"Select Behemoth GUID Database",
				"Select Behemoth_GUIDs.ini"
			);
		}
		catch (Throwable t) {
			printerr("Could not select GUID database: " + t.getMessage());
			return;
		}

		if (selected == null || !selected.isFile()) {
			return;
		}

		try (BufferedReader r = new BufferedReader(
				new InputStreamReader(new FileInputStream(selected), "UTF-8"))) {

			String section = "";
			String line;

			while ((line = r.readLine()) != null) {
				line = line.trim();

				if (line.isEmpty() || line.startsWith("#") || line.startsWith(";"))
					continue;

				if (line.startsWith("[") && line.endsWith("]")) {
					section = line.substring(1, line.length() - 1).trim();
					continue;
				}

				int eq = line.indexOf('=');
				if (eq <= 0) continue;

				String key = line.substring(0, eq).trim();
				String value = line.substring(eq + 1).trim();

				if ("EDK2".equalsIgnoreCase(section)) {
					String guid = value.replace("{", "").replace("}", "")
						.trim().toLowerCase(Locale.ROOT);

					if (guid.matches(
							"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
						guidNames.putIfAbsent(guid, key);
					}
				}
				else if ("Types".equalsIgnoreCase(section)) {
					if (!key.isEmpty() && !value.isEmpty())
						guidTypes.putIfAbsent(key, value);
				}
			}

			guidDbSource = selected.getAbsolutePath() + " (" +
				guidNames.size() + " GUIDs, " +
				guidTypes.size() + " type associations)";
		}
		catch (Throwable t) {
			guidNames.clear();
			guidTypes.clear();
			guidDbSource = "none";
			printerr("Could not read GUID database " +
				selected.getAbsolutePath() + ": " + t.getMessage());
		}
	}

	static class TargetExpr {
		BaseExpr base;
		long offset;
	}

	TargetExpr resolveTarget(Varnode v, int depth, Set<Varnode> seen) {
		if (v == null || depth > MAX_BASE_DEPTH || !seen.add(v)) return null;

		PcodeOp def = v.getDef();
		if (def == null) return null;

		switch (def.getOpcode()) {
			case PcodeOp.LOAD: {
				if (def.getNumInputs() < 2) return null;
				return resolveAddressExpr(def.getInput(1), depth + 1, seen);
			}

			case PcodeOp.CAST:
			case PcodeOp.COPY:
			case PcodeOp.INDIRECT:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT: {
				if (def.getNumInputs() < 1) return null;
				return resolveTarget(def.getInput(0), depth + 1, seen);
			}

			default:
				return null;
		}
	}

	TargetExpr resolveAddressExpr(Varnode v, int depth, Set<Varnode> seen) {
		if (v == null || depth > MAX_BASE_DEPTH || !seen.add(v)) return null;

		PcodeOp def = v.getDef();

		if (def != null) {
			switch (def.getOpcode()) {
				case PcodeOp.PTRADD: {
					if (def.getNumInputs() < 3) return null;

					TargetExpr base = resolvePointerValue(
						def.getInput(0), depth + 1, seen
					);
					Long index = constant(def.getInput(1));
					Long scale = constant(def.getInput(2));

					if (base == null || index == null || scale == null) return null;
					base.offset += index * scale;
					return base;
				}

				case PcodeOp.PTRSUB:
				case PcodeOp.INT_ADD: {
					if (def.getNumInputs() < 2) return null;

					TargetExpr a = resolvePointerValue(
						def.getInput(0), depth + 1, seen
					);
					Long b = constant(def.getInput(1));

					if (a != null && b != null) {
						a.offset += b;
						return a;
					}

					TargetExpr bbase = resolvePointerValue(
						def.getInput(1), depth + 1, seen
					);
					Long ac = constant(def.getInput(0));

					if (bbase != null && ac != null) {
						bbase.offset += ac;
						return bbase;
					}

					return null;
				}

				case PcodeOp.CAST:
				case PcodeOp.COPY:
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT:
					return resolveAddressExpr(def.getInput(0), depth + 1, seen);

				default:
					break;
			}
		}

		return resolvePointerValue(v, depth + 1, seen);
	}

	TargetExpr resolvePointerValue(Varnode v, int depth, Set<Varnode> seen) {
		if (v == null || depth > MAX_BASE_DEPTH || !seen.add(v)) return null;

		PcodeOp def = v.getDef();

		if (def != null) {
			switch (def.getOpcode()) {
				case PcodeOp.LOAD: {
					if (def.getNumInputs() < 2) return null;

					BaseExpr base = baseFromStorage(def.getInput(1), depth + 1,
						new HashSet<Varnode>(seen));
					if (base == null) return null;

					TargetExpr r = new TargetExpr();
					r.base = base;
					r.offset = 0;
					return r;
				}

				case PcodeOp.CAST:
				case PcodeOp.COPY:
				case PcodeOp.INDIRECT:
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT:
					return resolvePointerValue(def.getInput(0), depth + 1, seen);

				default:
					break;
			}
		}

		BaseExpr base = baseFromVarnode(v);
		if (base == null) return null;

		TargetExpr r = new TargetExpr();
		r.base = base;
		r.offset = 0;
		return r;
	}

	BaseExpr baseFromStorage(Varnode storage, int depth, Set<Varnode> seen) {
		if (storage == null || depth > MAX_BASE_DEPTH) return null;

		if (storage.isAddress()) {
			Address a = storage.getAddress();
			if (a != null && a.isMemoryAddress()) {
				BaseExpr b = new BaseExpr();
				b.global = true;
				b.globalAddress = a;
				b.key = "GLOBAL:" + a.toString();
				b.display = symbolOrAddress(a);
				b.root = storage;
				return b;
			}
		}

		PcodeOp def = storage.getDef();
		if (def != null) {
			switch (def.getOpcode()) {
				case PcodeOp.COPY:
				case PcodeOp.CAST:
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT:
					return baseFromStorage(def.getInput(0), depth + 1, seen);
				default:
					break;
			}
		}

		return baseFromVarnode(storage);
	}

	BaseExpr baseFromVarnode(Varnode v) {
		if (v == null) return null;

		HighVariable h = v.getHigh();
		if (h != null) {
			String n = h.getName();
			if (n != null && !n.isBlank()) {
				BaseExpr b = new BaseExpr();
				b.root = v;

				Varnode rep = null;
				Address repAddr = null;
				try {
					rep = h.getRepresentative();
					if (rep != null) repAddr = rep.getAddress();
				}
				catch (Throwable t) {}

				if (repAddr != null && repAddr.isMemoryAddress()) {
					b.global = true;
					b.key = "GLOBAL:" + repAddr.toString();
					b.display = n + " @ " + repAddr;
				}
				else {
					b.global = false;

					String functionId = activeFunction == null
						? "?"
						: activeFunction.getEntryPoint().toString();

					String storageId = highStorageId(h);
					b.key = "HIGH:" + functionId + ":" + storageId;
					b.display = n + " @ function " + functionId + " [" + storageId + "]";
				}

				return b;
			}
		}

		if (v.isAddress()) {
			Address a = v.getAddress();
			if (a != null && a.isMemoryAddress()) {
				BaseExpr b = new BaseExpr();
				b.global = true;
				b.globalAddress = a;
				b.root = v;
				b.key = "GLOBAL:" + a.toString();
				b.display = symbolOrAddress(a);
				return b;
			}
		}

		return null;
	}

	String highStorageId(HighVariable h) {
		if (h == null) return "unknown";

		try {
			Varnode r = h.getRepresentative();
			if (r != null) {
				Address a = r.getAddress();
				String space = a == null ? "?" : a.getAddressSpace().getName();
				String addr = a == null ? "?" : a.toString();
				return space + ":" + addr + ":size=" + r.getSize();
			}
		}
		catch (Throwable t) {}

		String n = h.getName();
		return "name=" + (n == null ? "<unnamed>" : n);
	}

	Long constant(Varnode v) {
		if (v == null) return null;
		if (v.isConstant()) return v.getOffset();

		PcodeOp d = v.getDef();
		if (d == null) return null;

		switch (d.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				if (d.getNumInputs() >= 1) return constant(d.getInput(0));
				break;
		}
		return null;
	}

	String symbolOrAddress(Address a) {
		try {
			Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
			if (s != null) return s.getName() + " @ " + a;
		}
		catch (Throwable t) {}
		return a.toString();
	}

	DataType peel(DataType d) {
		Set<DataType> seen = Collections.newSetFromMap(new IdentityHashMap<DataType,Boolean>());
		while (d instanceof TypeDef && seen.add(d)) d = ((TypeDef)d).getBaseDataType();
		return d;
	}

	boolean isPointerType(DataType d) {
		d = peel(d);
		return d instanceof Pointer;
	}

	boolean isVoidType(DataType d) {
		d = peel(d);
		if (d == null) return false;
		String n = d.getName();
		return "void".equalsIgnoreCase(n);
	}

	boolean sameObservedObject(Varnode v, ObjectObs o) {
		if (v == null || o == null) return false;
		BaseExpr b = baseFromVarnode(v);
		return b != null && o.key.equals(b.key);
	}

	String canonicalTypeName(DataType d) {
		if (d == null) return "";
		d = peel(d);
		if (d == null) return "";

		if (d instanceof Pointer) {
			DataType p = peel(((Pointer)d).getDataType());
			return canonicalTypeName(p) + "*";
		}

		String n = d.getName();
		if (n == null) return "";
		return n.replaceFirst("^_+", "").replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
	}

	boolean isUndefinedLike(DataType d) {
		if (d == null) return true;
		d = peel(d);
		if (d == null) return true;
		String n = d.getName();
		if (n == null) return true;
		String x = n.toLowerCase(Locale.ROOT);
		return x.startsWith("undefined") || x.equals("byte") || x.equals("word") ||
			x.equals("dword") || x.equals("qword");
	}

	DataType observedType(Varnode v) {
		if (v == null) return null;
		HighVariable h = v.getHigh();
		if (h == null) return null;
		try { return h.getDataType(); }
		catch (Throwable x) { return null; }
	}

	int pointerDepth(DataType d) {
		int depth = 0;
		Set<DataType> seen = Collections.newSetFromMap(new IdentityHashMap<DataType,Boolean>());
		d = peel(d);
		while (d instanceof Pointer && seen.add(d)) {
			depth++;
			d = peel(((Pointer)d).getDataType());
		}
		return depth;
	}

	int concreteTypeEvidence(DataType expected, DataType observed) {
		if (expected == null || observed == null) return 0;
		expected = peel(expected);
		observed = peel(observed);
		if (expected == null || observed == null) return 0;
		if (isUndefinedLike(observed)) return 0;

		String e = canonicalTypeName(expected);
		String o = canonicalTypeName(observed);
		if (!e.isEmpty() && e.equals(o)) return 2;

		int ep = pointerDepth(expected);
		int op = pointerDepth(observed);

		if (ep > 0 || op > 0) {
			if (ep == 0 || op == 0) return -1;
			if (ep != op) return -1;

			DataType eb = expected;
			DataType ob = observed;
			while (peel(eb) instanceof Pointer) eb = ((Pointer)peel(eb)).getDataType();
			while (peel(ob) instanceof Pointer) ob = ((Pointer)peel(ob)).getDataType();
			eb = peel(eb);
			ob = peel(ob);

			if (eb == null || ob == null || isUndefinedLike(ob)) return 0;

			String en = canonicalTypeName(eb);
			String on = canonicalTypeName(ob);
			if (!en.isEmpty() && en.equals(on)) return 2;

			if ("VOID".equals(en) || "VOID".equals(on)) return 0;

			return -1;
		}

		int el = expected.getLength();
		int ol = observed.getLength();
		if (el > 0 && ol > 0) {
			if (el == ol) return 1;
			return -1;
		}
		return 0;
	}

	int positiveThis(MethodModel method, CallObs call, ObjectObs o) {
		if (method.argTypes.isEmpty() || call.args.isEmpty()) return 0;
		DataType first = peel(method.argTypes.get(0));
		if (!(first instanceof Pointer)) return 0;

		DataType pointee = peel(((Pointer)first).getDataType());
		if (pointee == null) return 0;

		String expected = pointee.getName();
		String owner = method.owner;
		if (expected == null || owner == null) return 0;

		String a = expected.replaceFirst("^_+", "");
		String b = owner.replaceFirst("^_+", "");
		if (!a.equalsIgnoreCase(b)) return 0;

		return sameObservedObject(call.args.get(0), o) ? 1 : 0;
	}

	void addArgumentEvidence(Match m, MethodModel method, CallObs call) {
		int n = Math.min(method.argTypes.size(), call.args.size());
		for (int i = 0; i < n; i++) {
			int ev = concreteTypeEvidence(method.argTypes.get(i), observedType(call.args.get(i)));
			if (ev == 2) m.concreteArgExact++;
			else if (ev == 1) m.concreteArgCompatible++;
			else if (ev < 0) m.concreteArgConflict++;
		}
	}

	void addReturnEvidence(Match m, MethodModel method, CallObs call) {
		if (method.returnType == null || isVoidType(method.returnType) || call.output == null) return;
		int ev = concreteTypeEvidence(method.returnType, observedType(call.output));
		if (ev == 2) m.returnExact++;
		else if (ev == 1) m.returnCompatible++;
		else if (ev < 0) m.returnConflict++;
	}

	List<Match> matches(ObjectObs o) {
		List<Match> result = new ArrayList<>();
		if (o.offsets.isEmpty()) return result;

		for (StructModel s : structs.values()) {
			int overlap = 0;
			for (int x : o.offsets) if (s.fingerprint.contains(x)) overlap++;
			if (overlap == 0) continue;

			int missingObserved = o.offsets.size() - overlap;
			int extraModel = s.fingerprint.size() - overlap;

			Match m = new Match();
			m.model = s;
			m.overlap = overlap;
			m.missingObserved = missingObserved;
			m.extraModel = extraModel;
			m.coverageObserved = overlap / (double)o.offsets.size();
			m.coverageModel = overlap / (double)s.fingerprint.size();
			m.exact = missingObserved == 0 && extraModel == 0;

			for (CallObs call : o.calls) {
				List<MethodModel> methods = s.methods.get((int)call.offset);
				if (methods == null || methods.isEmpty()) {
					m.arityUnknown++;
					continue;
				}

				boolean exactArity = false;
				boolean candidateExpectsArgs = false;
				MethodModel best = null;
				int bestRank = Integer.MIN_VALUE;

				for (MethodModel method : methods) {
					int fixed = method.args.size();
					if (fixed > 0) candidateExpectsArgs = true;

					boolean arityOk =
						(!method.varargs && call.argCount == fixed) ||
						(method.varargs && call.argCount >= fixed);

					int exactTypes = 0, compatibleTypes = 0, conflicts = 0;
					int n = Math.min(method.argTypes.size(), call.args.size());
					for (int ai = 0; ai < n; ai++) {
						int ev = concreteTypeEvidence(
							method.argTypes.get(ai), observedType(call.args.get(ai)));
						if (ev == 2) exactTypes++;
						else if (ev == 1) compatibleTypes++;
						else if (ev < 0) conflicts++;
					}

					int rank = (arityOk ? 100000 : 0) +
							exactTypes * 100 +
							compatibleTypes * 10 -
							conflicts;

					if (rank > bestRank) {
						bestRank = rank;
						best = method;
					}

					if (arityOk) exactArity = true;
				}

				if (exactArity) {
					m.arityMatches++;
				}
				else if (call.argCount == 0 && candidateExpectsArgs) {
					m.arityUnknown++;
				}
				else {
					m.arityConflicts++;
				}

				if (best != null) {
					addArgumentEvidence(m, best, call);
					m.thisMatches += positiveThis(best, call, o);
					addReturnEvidence(m, best, call);
				}
			}

			if (o.offsets.size() == 1) {
				if (!m.exact) continue;
			}
			else {
				if (overlap < MIN_STRONG_OFFSETS || missingObserved != 0) continue;
			}

			result.add(m);
		}

		result.sort((a,b) -> {
			int c;
			c = Integer.compare(evidenceRank(b.signatureEvidence()), evidenceRank(a.signatureEvidence()));
			if (c != 0) return c;
			c = Integer.compare(b.arityMatches, a.arityMatches); if (c != 0) return c;
			c = Integer.compare(b.concreteArgExact, a.concreteArgExact); if (c != 0) return c;
			c = Integer.compare(b.thisMatches, a.thisMatches); if (c != 0) return c;
			c = Integer.compare(b.returnExact, a.returnExact); if (c != 0) return c;
			c = Integer.compare(b.concreteArgCompatible, a.concreteArgCompatible); if (c != 0) return c;
			c = Integer.compare(b.returnCompatible, a.returnCompatible); if (c != 0) return c;
			c = Integer.compare(a.concreteArgConflict, b.concreteArgConflict); if (c != 0) return c;
			c = Integer.compare(a.returnConflict, b.returnConflict); if (c != 0) return c;
			c = Integer.compare(a.arityConflicts, b.arityConflicts); if (c != 0) return c;
			c = Boolean.compare(b.exact, a.exact); if (c != 0) return c;
			c = Integer.compare(b.overlap, a.overlap); if (c != 0) return c;
			c = Double.compare(b.coverageModel, a.coverageModel); if (c != 0) return c;
			c = Integer.compare(a.extraModel, b.extraModel); if (c != 0) return c;
			return a.model.path.compareToIgnoreCase(b.model.path);
		});

		return result;
	}

	int evidenceRank(String s) {
		if ("STRONG".equals(s)) return 3;
		if ("SUPPORTED".equals(s)) return 2;
		return 1;
	}

	void writeReport(File report) throws IOException {
		try (PrintWriter o = new PrintWriter(
			new OutputStreamWriter(new FileOutputStream(report), "UTF-8"))) {

			o.println("========================================================================");
			o.println(" Behemoth - Object Finder");
			o.println("========================================================================");
			o.println("Program: " + currentProgram.getName());
			o.println("Pointer size: " + programPointerSize);
			o.println("Source: " + srcName);
			o.println();

			o.println("[SUMMARY]");
			o.println("Data types=" + datatypeCount);
			o.println("Callable structures=" + callableStructCount);
			o.println("Callable fields=" + callableFieldCount);
			o.println("Functions visited=" + functionsVisited);
			o.println("Functions decompiled=" + functionsDecompiled);
			o.println("Indirect calls=" + indirectCalls);
			o.println("Modeled object calls=" + modeledCalls);
			o.println("Candidate objects=" + objects.size());
			o.println("Protocol provenance calls=" + provenance.size());
			o.println("GUID database=" + guidDbSource);
			o.println("GUID type mappings=" + guidTypes.size());
			o.println();

			o.println("========================================================================");
			o.println(" OBSERVED OBJECTS");
			o.println("========================================================================");
			o.println();

			List<ObjectObs> obs = new ArrayList<>(objects.values());
			obs.sort((a,b) -> {
				int c = Integer.compare(b.offsets.size(), a.offsets.size());
				if (c != 0) return c;
				return a.display.compareToIgnoreCase(b.display);
			});

			for (ObjectObs obj : obs) {
				o.println("[Object]");
				o.println("Identity: " + obj.display);
				o.println("Kind: " + (obj.global ? "Global" : "High variable"));
				if (obj.globalAddress != null)
					o.println("Address: " + obj.globalAddress);
				o.println("Observed offsets: " + fingerprint(obj.offsets));
				o.println("Observed calls: " + obj.calls.size());

				List<Match> mm = matches(obj);
				int identityStrong = 0, identityAmbiguous = 0, identitySupported = 0, identityWeak = 0;
				int signatureStrong = 0, signatureSupported = 0, signatureWeak = 0;
				for (Match m : mm) {
					String ie = m.identityEvidence(mm.size());
					if ("STRONG".equals(ie)) identityStrong++;
					else if ("AMBIGUOUS".equals(ie)) identityAmbiguous++;
					else if ("SUPPORTED".equals(ie)) identitySupported++;
					else identityWeak++;

					String se = m.signatureEvidence();
					if ("STRONG".equals(se)) signatureStrong++;
					else if ("SUPPORTED".equals(se)) signatureSupported++;
					else signatureWeak++;
				}
				o.println("Candidates: " + mm.size());
				o.println("Identity evidence: strong=" + identityStrong +
					" ambiguous=" + identityAmbiguous +
					" supported=" + identitySupported + " weak=" + identityWeak);
				o.println("Signature evidence: strong=" + signatureStrong +
					" supported=" + signatureSupported + " weak=" + signatureWeak);

				int limit = Math.min(mm.size(), 25);
				for (int i = 0; i < limit; i++) {
					Match m = mm.get(i);
					o.printf("  [%d] %s | %s%n",
						i + 1, m.model.path, m.rankText(mm.size()));

					for (int off : obj.offsets) {
						List<MethodModel> methods = m.model.methods.get(off);
						if (methods == null) continue;
						for (MethodModel method : methods) {
							o.printf("       +0x%X %s -> %s%n",
								off, method.field, method.proto());
						}
					}
				}

				if (mm.size() > limit)
					o.println("  ... " + (mm.size() - limit) + " more candidates");

				o.println();
				o.println("Calls:");

				obj.calls.sort(Comparator.comparing(x -> x.callAddress));
				for (CallObs c : obj.calls) {
					o.printf("  %s  %s @ %s  offset=+0x%X  args=%d%n",
						c.callAddress, c.functionName, c.functionAddress,
						c.offset, c.argCount);
				}

				o.println();
				o.println("------------------------------------------------------------------------");
				o.println();
			}

			o.println("========================================================================");
			o.println(" UEFI PROTOCOL PROVENANCE");
			o.println("========================================================================");
			o.println();
			for (ProvenanceObs p : provenance) {
				o.println("[Provenance]");
				o.println("Call: " + p.callAddress + "  " + p.functionName + " @ " + p.functionAddress);
				o.println("Service: " + p.service);
				o.println("GUID: " + (p.guid == null ? "unresolved" : p.guid));
				o.println("GUID name: " + (p.guidName == null ? "unresolved" : p.guidName));
				o.println("Expected type: " + (p.expectedType == null ? "unresolved" : p.expectedType));
				o.println("Interface destination: " + (p.interfaceDisplay == null ? "unresolved" : p.interfaceDisplay));
				o.println("Recovered storage: " + (p.recoveredStorage == null ? "unresolved" : p.recoveredStorage));
				o.println("Storage kind: " + (p.recoveredStorageKind == null ? "unresolved" : p.recoveredStorageKind));
				o.println("Recovered variable type: " + (p.recoveredStorageType == null ? "unresolved" : p.recoveredStorageType));
				o.println("Linked object: " + (p.linkedObjectDisplay == null ? "unresolved" : p.linkedObjectDisplay));
				o.println("Link method: " + (p.linkMethod == null ? "unresolved" : p.linkMethod));
				o.println("Interface trace: " + (p.interfaceTrace == null ? "none" : p.interfaceTrace));
				if (p.storageDiagnostic != null) {
					o.println("Storage diagnostic:");
					o.print(p.storageDiagnostic);
				}

				String provenanceMatch = "unresolved";
				if (p.expectedType != null && p.linkedObjectKey != null) {
					ObjectObs linked = objects.get(p.linkedObjectKey);
					if (linked != null) {
						provenanceMatch = "NO";
						String wanted = p.expectedType.replaceFirst("^_+", "");
						for (Match m : matches(linked)) {
							String have = m.model.name == null ? "" :
								m.model.name.replaceFirst("^_+", "");
							if (wanted.equalsIgnoreCase(have)) {
								provenanceMatch = "YES";
								break;
							}
						}
					}
				}
				o.println("Expected type among structural candidates: " + provenanceMatch);
				o.println();
			}

			o.println("========================================================================");
			o.println(" CALLABLE STRUCTURE FINGERPRINTS");
			o.println("========================================================================");
			o.println();

			List<StructModel> models = new ArrayList<>(structs.values());
			models.sort(Comparator
				.comparing((StructModel s) -> s.name, String.CASE_INSENSITIVE_ORDER)
				.thenComparing(s -> s.path, String.CASE_INSENSITIVE_ORDER));

			for (StructModel s : models) {
				o.printf("%s | size=0x%X | callable=%d | fingerprint=%s%n",
					s.path, s.length, s.callableCount(), s.fp());
			}
		}
	}

	String fingerprint(Collection<Integer> offsets) {
		StringJoiner j = new StringJoiner(",", "{", "}");
		for (int x : offsets) j.add(String.format("%X", x));
		return j.toString();
	}

	String fieldName(DataTypeComponent c) {
		String n = c.getFieldName();
		if (n == null || n.isBlank()) n = c.getDefaultFieldName();
		if (n == null || n.isBlank())
			n = "field_" + Integer.toHexString(c.getOffset()).toUpperCase(Locale.ROOT);
		return n;
	}

	int length(DataType d) {
		try { return d.getLength(); }
		catch (Throwable t) { return -1; }
	}

	String path(DataType d) {
		try {
			DataTypePath p = d.getDataTypePath();
			if (p != null) return p.getPath();
		}
		catch (Throwable t) {}
		return d.getName();
	}

	String display(DataType d) {
		if (d == null) return "<null>";
		try {
			String x = d.getDisplayName();
			if (x != null && !x.isBlank()) return x;
		}
		catch (Throwable t) {}
		return d.getName();
	}
}
