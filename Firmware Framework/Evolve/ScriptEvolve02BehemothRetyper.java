// Behemoth semantic UEFI retyping engine. Uses the Behemoth GDT as the primary type authority, dynamically derives service layouts, performs whole-program interprocedural UEFI type propagation, identifies globals/protocols/GUIDs, and annotates indirect service calls.
// @author TheMalwareGuardian
// @category UEFI
//
// USAGE:
//   1. Import the target UEFI binary into Ghidra and let auto-analysis finish
//   2. Load the Behemoth UEFI Data Type Archive (.gdt) into the project
//   3. Open Script Manager and run BehemothRetyper.java
//   4. Review the recovered types, labels, comments, console output, and TXT report
//
// STEPS:
//   [1] Resolve common UEFI data types from the loaded Behemoth .gdt archive
//   [2] Retype the binary entry point as UefiMain(EFI_HANDLE, EFI_SYSTEM_TABLE *)
//   [3] Identify and retype global pointers: gImageHandle, gST, gBS, gRT
//   [4] Scan the binary for known EFI GUIDs and apply EFI_GUID type + labels
//   [5] Identify protocol interfaces from HandleProtocol/LocateProtocol/OpenProtocol and apply the concrete protocol pointer types
//   [6] Annotate EFI Boot/Runtime Services call sites (direct and gST-chained) and detect unknown GUIDs from decompiler casts
//   [7] Evidence-driven semantic type graph with interprocedural propagation
//   [8] Save the complete console results to Behemoth_Retyper_<binary>.txt
//
// INTENDED USE:
//   Firmware security research, UEFI malware analysis, vulnerability research, and general reverse engineering of EFI applications and drivers.
// ============================================================================

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

public class ScriptEvolve02BehemothRetyper extends GhidraScript {


	// =====================================================================
	// Dynamic semantic sources
	// =====================================================================

	private final Map<String, String[]> guidDb = new LinkedHashMap<>();
	private File guidDbFile;

	// Populated only from EFI_BOOT_SERVICES / EFI_RUNTIME_SERVICES in the GDT.
	private final Map<Integer, String> bsMap = new LinkedHashMap<>();
	private final Map<Integer, String> rtMap = new LinkedHashMap<>();

	// =====================================================================
	// State
	// =====================================================================

	private DataType dtStatus, dtHandle, dtSystemTable;
	private DataType dtBootServices, dtRuntimeServices, dtGuid;

	private int ptrSize;
	private final Map<Integer, DataType> bsFieldTypes = new LinkedHashMap<>();
	private final Map<Integer, DataType> rtFieldTypes = new LinkedHashMap<>();
	private final Map<String, DataType> typeCache = new HashMap<>();
	private int cntDynamicServiceFields, cntSemanticPasses;

	private Address gImageHandle, gST, gBS, gRT;

	private final Map<Address, String[]> knownGuids   = new LinkedHashMap<>();
	private final Map<Address, String>   unknownGuids = new LinkedHashMap<>();

	private final Set<Address> retypedAddresses = new HashSet<>();

	private final Map<String, List<String[]>> callSiteDetails = new LinkedHashMap<>();

	// =====================================================================
	// GUIDs
	// =====================================================================

	private FileDataTypeManager behemothGdtDtm;
	private boolean behemothGdtTried;

	private boolean isHeadless() { return state == null || state.getTool() == null; }

	private java.io.File behemothScriptDir() {
		try { return getSourceFile().getParentFile().getFile(false); }
		catch (Exception e) { return new java.io.File(System.getProperty("user.dir")); }
	}

	private java.io.File findUp(String... rels) {
		java.io.File base = behemothScriptDir();
		for (int up = 0; up < 6 && base != null; up++, base = base.getParentFile())
			for (String rel : rels) {
				java.io.File f = new java.io.File(base, rel);
				if (f.isFile()) return f;
			}
		return null;
	}

	private java.io.File behemothGuidIni() {
		String env = System.getenv("BEHEMOTH_GUIDS");
		if (env != null && !env.isEmpty() && new java.io.File(env).isFile()) return new java.io.File(env);
		return findUp("Build/GDT/GUIDs/Behemoth_GUIDs.ini", "GDT/GUIDs/Behemoth_GUIDs.ini",
					"Base/GDT/GUIDs/Behemoth_GUIDs.ini", "GUIDs/Behemoth_GUIDs.ini",
					"GDT/Behemoth_GUIDs.ini", "Behemoth_GUIDs.ini");
	}

	private java.io.File behemothGdtFile() {
		String env = System.getenv("BEHEMOTH_GDT");
		if (env != null && !env.isEmpty() && new java.io.File(env).isFile()) return new java.io.File(env);
		String name = (ptrSize == 4) ? "Behemoth_IA32.gdt" : "Behemoth_X64.gdt";
		return findUp("Build/GDT/" + name, "GDT/" + name, "Base/GDT/" + name, name);
	}

	private DataType resolveFromBehemothGdt(String name) {
		try {
			if (!behemothGdtTried) {
				behemothGdtTried = true;
				java.io.File gdt = behemothGdtFile();
				if (gdt != null) {
					behemothGdtDtm = FileDataTypeManager.openFileArchive(gdt, false);
					println("      [GDT] opened archive: " + gdt.getAbsolutePath());
				} else {
					println("      [GDT] archive not found (set BEHEMOTH_GDT or place Behemoth_*.gdt under GDT)");
				}
			}
			if (behemothGdtDtm == null) return null;
			ArrayList<DataType> r = new ArrayList<>();
			behemothGdtDtm.findDataTypes(name, r);
			return r.isEmpty() ? null : r.get(0);
		} catch (Exception e) {
			println("      [GDT] open failed: " + e.getMessage());
			return null;
		}
	}

	// =====================================================================
	// Evidence system
	// =====================================================================

	private enum Confidence {
		PROPAGATED(1), SUPPORTED(2), STRONG(3), AUTHORITATIVE(4);
		final int rank;
		Confidence(int r) { rank = r; }
	}

	private static class TypeEvidence {
		Function function;
		HighSymbol symbol;
		DataType type;
		Confidence confidence;
		int depth;
		String source;
		String origin;
		Address site;
		TypeEvidence(Function f, HighSymbol s, DataType t, Confidence c, int d, String src, String orig, Address a) {
			function=f; symbol=s; type=t; confidence=c; depth=d; source=src; origin=orig!=null?orig:src; site=a;
		}

		boolean canMutateSignature() {
			return depth <= 1;
		}

		boolean canMutateLocal() {
			return depth <= 2;
		}
	}

	private final Map<String, TypeEvidence> semanticFacts = new LinkedHashMap<>();
	private final Map<String, TypeEvidence> canonicalRootParamSeeds = new LinkedHashMap<>();
	private int cntEvidenceAccepted, cntEvidenceRejected, cntEvidenceConflicts;
	private int cntNewMutations, cntDuplicateFacts;

	private final List<String[]> protocolDetails = new ArrayList<>();

	private DecompInterface decompiler;

	private int cntProtocolTypes, cntKnownGuids, cntUnknownGuids, cntProtocols, cntAnnotations;
	private int cntLocalChanges, cntParamChanges, cntReturnChanges;
	private final Set<Address> improvedFunctions = new LinkedHashSet<>();

	// Exact console transcript, saved at the end of the analysis.
	private final StringBuilder consoleTranscript = new StringBuilder();

	@Override
	public void println(String message) {
		super.println(message);
		consoleTranscript.append(message == null ? "null" : message).append(System.lineSeparator());
	}



	// =====================================================================
	// Main
	// =====================================================================

	@Override
	protected void run() throws Exception {

		ptrSize = currentProgram.getDefaultPointerSize();

		println("========================================================================");
		println(" Behemoth - UEFI Semantic Retyper");
		println(" Target : " + currentProgram.getName());
		println(" Arch   : " + (ptrSize == 8 ? "x64" : "IA-32") + " (" + ptrSize + "-byte pointers)");
		println("========================================================================");

		int tx = currentProgram.startTransaction("Behemoth UEFI Retype");
		decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);

		try {

			if (!stepResolveTypes())  return;
			loadGuidDatabase();
			buildDynamicServiceModels();
			Function entry = stepRetypeEntry();
			stepFindGlobals(entry);
			stepBackPropCanonicalRoots(entry);
			stepLabelGuids();
			stepRetypeProtocols();
			stepAnnotateCalls();
			stepSemanticTypeGraph(entry);
			printFunctionTypeSummary(entry);
			printSummary();
			saveConsoleReport();

		} finally {
			decompiler.dispose();
			currentProgram.endTransaction(tx, true);
		}
	}


	// =====================================================================
	// Step 1 - Resolve Types
	// =====================================================================

	private boolean stepResolveTypes() {

		println("");
		println("[1/8] Resolving types from Behemoth GDT");
		println("----------------------------------------------------------------------");

		dtStatus          = resolveType("EFI_STATUS",           true);
		dtHandle          = resolveType("EFI_HANDLE",           true);
		dtSystemTable     = resolveType("EFI_SYSTEM_TABLE",     true);
		dtBootServices    = resolveType("EFI_BOOT_SERVICES",    true);
		dtRuntimeServices = resolveType("EFI_RUNTIME_SERVICES", true);
		dtGuid            = resolveType("EFI_GUID",             true);

		println("      " + pad("Type authority", 30) + "Behemoth GDT");

		for (String name : new String[]{
			"EFI_TABLE_HEADER", "EFI_FILE_PROTOCOL", "EFI_FILE_INFO",
			"EFI_TIME", "EFI_MEMORY_DESCRIPTOR", "EFI_INPUT_KEY"
		}) {
			resolveType(name, false);
		}

		if (dtStatus == null || dtSystemTable == null || dtBootServices == null) {
			println("");
			println("[!] Critical types missing. Is the Behemoth .gdt loaded?");
			return false;
		}

		return true;
	}


	// =====================================================================
	// Dynamic GDT model
	// =====================================================================

	private void buildDynamicServiceModels() {
		println("");
		println("[GDT] Building dynamic service models");
		println("----------------------------------------------------------------------");
		bsMap.clear(); rtMap.clear();
		bsMap.putAll(deriveFieldMap(dtBootServices, bsFieldTypes));
		rtMap.putAll(deriveFieldMap(dtRuntimeServices, rtFieldTypes));
		cntDynamicServiceFields = bsMap.size() + rtMap.size();
		println("      EFI_BOOT_SERVICES fields    : " + bsMap.size());
		println("      EFI_RUNTIME_SERVICES fields : " + rtMap.size());
		println("      Source                      : Behemoth GDT");
	}

	private Map<Integer, String> deriveFieldMap(DataType dt, Map<Integer, DataType> typeMap) {
		Map<Integer, String> out = new LinkedHashMap<>();
		DataType cur = dt;
		while (cur instanceof TypeDef) cur = ((TypeDef)cur).getBaseDataType();
		if (!(cur instanceof Structure)) return out;
		Structure st = (Structure) cur;
		for (DataTypeComponent c : st.getDefinedComponents()) {
			String n = c.getFieldName();
			if (n == null || n.isEmpty()) continue;
			out.put(c.getOffset(), n);
			typeMap.put(c.getOffset(), c.getDataType());
		}
		return out;
	}


	// =====================================================================
	// Semantic Type Graph
	// =====================================================================

	private void stepSemanticTypeGraph(Function entry) {
		println("");
		println("[SEMANTIC GRAPH] Conservative evidence analysis");
		println("----------------------------------------------------------------------");

		semanticFacts.clear();
		cntEvidenceAccepted = cntEvidenceRejected = cntEvidenceConflicts = 0;

		// Seed authoritative roots
		seedGlobalFact(gST, ptr(dtSystemTable), "gST", Confidence.AUTHORITATIVE);
		seedGlobalFact(gBS, ptr(dtBootServices), "gBS", Confidence.AUTHORITATIVE);
		seedGlobalFact(gRT, ptr(dtRuntimeServices), "gRT", Confidence.AUTHORITATIVE);

		// Canonical-root inverse assignments discovered during Step 3 are also authoritative roots. Keeping them at depth 0 lets direct-call propagation fan out exactly one supported hop without fabricating a generic STORE-backprop rule.
		semanticFacts.putAll(canonicalRootParamSeeds);

		final int maxPasses = 10;
		for (int pass = 1; pass <= maxPasses && !monitor.isCancelled(); pass++) {
			Map<String, TypeEvidence> proposed = new LinkedHashMap<>();
			int discovered = 0;

			FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
			while (fi.hasNext() && !monitor.isCancelled()) {
				Function f = fi.next();
				if (f.isExternal()) continue;
				DecompileResults dr = decompiler.decompileFunction(f, 20, monitor);
				if (dr == null || dr.getHighFunction() == null) continue;
				HighFunction hf = dr.getHighFunction();

				Iterator<PcodeOpAST> ops = hf.getPcodeOps();
				while (ops.hasNext()) {
					PcodeOpAST op = ops.next();

					if (op.getOpcode() == PcodeOp.CALLIND) {
						ServiceHit hit = resolveServiceCall(op);
						if (hit != null) {
							FunctionDefinition fd = unwrapFunctionDefinition(hit.fieldType);
							if (fd != null) {
								discovered += collectCallEvidence(
									f, hf, op, fd, Confidence.AUTHORITATIVE,
									hit.owner + "->" + hit.name, proposed);
								discovered += collectProtocolEvidence(f, hf, op, hit, proposed);
							}
						}
						// Protocol method calls through typed pointers
						discovered += collectProtocolMethodEvidence(f, hf, op, proposed);
					}

					if (op.getOpcode() == PcodeOp.CALL) {
						Function callee = resolveDirectCallee(op);
						if (callee != null && !callee.isExternal())
							discovered += collectDirectCallEvidence(f, hf, op, callee, proposed);
					}

					// If a function returns a typed value, propose evidence on the function's return type
					if (op.getOpcode() == PcodeOp.RETURN && op.getNumInputs() >= 2) {
						discovered += collectReturnEvidence(f, hf, op, proposed);
					}

					discovered += collectCopyEvidence(f, op, proposed);
				}
			}

			int applied = applyEvidenceBatch(proposed);
			cntSemanticPasses = pass;
			println("      Pass " + pass +
				": discovered=" + discovered +
				" mutations=" + cntNewMutations +
				" duplicates=" + cntDuplicateFacts +
				" rejected=" + cntEvidenceRejected +
				" conflicts=" + cntEvidenceConflicts);

			if (cntNewMutations == 0) {
				println("      CONVERGED (no new database mutations)");
				break;
			}
		}
	}

	private void seedGlobalFact(Address a, DataType t, String source, Confidence c) {
		if (a == null || t == null) return;
		String key = "GLOBAL:" + a;
		semanticFacts.put(key, new TypeEvidence(null, null, t, c, 0, source, "ROOT:" + source, a));
	}

	// -------------------------------------------------------------------
	// Evidence collection: service call arguments
	// -------------------------------------------------------------------

	private int collectCallEvidence(
		Function f, HighFunction hf, PcodeOpAST call, FunctionDefinition fd,
		Confidence confidence, String source, Map<String, TypeEvidence> proposed) {

		int n = 0;
		String origin = "GDT:" + source;
		ParameterDefinition[] defs = fd.getArguments();
		int count = Math.min(defs.length, call.getNumInputs() - 1);

		for (int i = 0; i < count; i++) {
			DataType wanted = defs[i].getDataType();
			if (!isUsefulUefiType(wanted)) continue;
			n += proposeVarnodeEvidence(
				f, hf, call.getInput(i + 1), wanted, confidence,
				0, source + " arg[" + i + "]", origin,
				call.getSeqnum().getTarget(), proposed);
		}

		if (call.getOutput() != null && isUsefulUefiType(fd.getReturnType()))
			n += proposeVarnodeEvidence(
				f, hf, call.getOutput(), fd.getReturnType(), confidence,
				0, source + " return", origin,
				call.getSeqnum().getTarget(), proposed);
		return n;
	}

	// -------------------------------------------------------------------
	// Evidence collection: protocol acquisition (GUID + output recovery)
	// -------------------------------------------------------------------

	private int collectProtocolEvidence(
		Function f, HighFunction hf, PcodeOpAST call, ServiceHit hit,
		Map<String, TypeEvidence> proposed) {

		int gi = protocolGuidArgumentIndex(hit.name);
		int oi = protocolOutputArgumentIndex(hit.name);
		if (gi < 0 || oi < 0 || call.getNumInputs() <= gi + 1 || call.getNumInputs() <= oi + 1)
			return 0;

		// Recover GUID address from p-code expression
		Address ga = recoverReferencedAddress(call.getInput(gi + 1), 32, new HashSet<Varnode>());
		if (ga == null) return 0;

		// Try known GUIDs first, then read raw bytes and look up in DB
		String[] info = knownGuids.get(ga);
		if (info == null) {
			String canonical = readGuidAt(ga);
			if (canonical != null) info = guidDb.get(canonical);
		}
		if (info == null || info[1] == null) return 0;

		DataType protocol = resolveType(info[1], false);
		if (protocol == null) return 0;
		DataType wanted = ptr(protocol);

		return proposeOutputStorageEvidence(
			f, hf, call.getInput(oi + 1), wanted, Confidence.STRONG,
			hit.owner + "->" + hit.name + " / " + info[0],
			call.getSeqnum().getTarget(), proposed);
	}

	// -------------------------------------------------------------------
	// Evidence collection: protocol method calls
	// -------------------------------------------------------------------

	private int collectProtocolMethodEvidence(
		Function f, HighFunction hf, PcodeOpAST call,
		Map<String, TypeEvidence> proposed) {

		if (call.getNumInputs() < 1) return 0;
		Varnode target = call.getInput(0);

		// The call target is a LOAD from (protocolPtr + methodOffset).
		// If protocolPtr has a known protocol type, we can resolve the method.
		PcodeOp def = target.getDef();
		if (def == null || def.getOpcode() != PcodeOp.LOAD || def.getNumInputs() < 2) return 0;

		Varnode ptr = def.getInput(1);
		PcodeOp ptrDef = ptr.getDef();
		if (ptrDef == null) return 0;

		// Look for pattern: PTRSUB/INT_ADD(protocolBase, offset)
		int opc = ptrDef.getOpcode();
		if (opc != PcodeOp.PTRSUB && opc != PcodeOp.INT_ADD && opc != PcodeOp.PTRADD) return 0;

		Long methodOffset = expressionConstantContribution(ptrDef);
		if (methodOffset == null) return 0;

		// Find the base varnode and check its type
		for (int i = 0; i < ptrDef.getNumInputs(); i++) {
			Varnode base = ptrDef.getInput(i);
			if (base.isConstant()) continue;

			DataType baseType = trustedTypeOf(base);
			if (baseType == null) continue;

			// Unwrap to structure
			DataType unwrapped = baseType;
			while (unwrapped instanceof Pointer) unwrapped = ((Pointer)unwrapped).getDataType();
			while (unwrapped instanceof TypeDef) unwrapped = ((TypeDef)unwrapped).getBaseDataType();
			if (!(unwrapped instanceof Structure)) continue;

			// Check if this is a protocol/EFI structure
			String sName = unwrapped.getName();
			if (sName == null || (!sName.startsWith("EFI_") && !sName.startsWith("EDKII_"))) continue;

			Structure st = (Structure) unwrapped;
			DataTypeComponent comp = st.getComponentContaining(methodOffset.intValue());
			if (comp == null) continue;

			DataType fieldType = comp.getDataType();
			FunctionDefinition fd = unwrapFunctionDefinition(fieldType);
			if (fd == null) continue;

			String tag = sName + "->" + comp.getFieldName();
			int n = collectCallEvidence(f, hf, call, fd, Confidence.STRONG, tag, proposed);
			if (n > 0) return n;
		}

		return 0;
	}

	// -------------------------------------------------------------------
	// Evidence collection: direct call propagation
	// -------------------------------------------------------------------

	private int collectDirectCallEvidence(
		Function caller, HighFunction callerHf, PcodeOpAST call, Function callee,
		Map<String, TypeEvidence> proposed) {

		int n = 0;
		Parameter[] params = callee.getParameters();
		int count = Math.min(params.length, call.getNumInputs() - 1);

		// Forward propagation is allowed only from an explicit depth-0 semantic fact.
		for (int i = 0; i < count; i++) {
			String paramKey = "PARAM:" + callee.getEntryPoint() + ":" + i;
			TypeEvidence root = semanticFacts.get(paramKey);
			if (root == null) continue;
			if (root.confidence.rank < Confidence.STRONG.rank || root.depth != 0) continue;
			if (!isUsefulUefiType(root.type)) continue;

			n += proposeVarnodeEvidence(
				caller, callerHf, call.getInput(i + 1), root.type,
				Confidence.SUPPORTED, 1,
				"direct call " + callee.getName() + " param[" + i + "]",
				root.origin, call.getSeqnum().getTarget(), proposed);
		}

		// No caller->callee signature inference and no inferred return propagation.
		return n;
	}

	// -------------------------------------------------------------------
	// Evidence collection: copy/cast/phi propagation
	// -------------------------------------------------------------------

	private int collectCopyEvidence(
		Function f, PcodeOpAST op, Map<String, TypeEvidence> proposed) {

		// Only an exact COPY from a depth-0 STRONG semantic fact is considered.
		if (op.getOpcode() != PcodeOp.COPY || op.getOutput() == null ||
			op.getNumInputs() != 1) return 0;

		Varnode in = op.getInput(0);
		String inKey = evidenceKey(in);
		TypeEvidence src = inKey != null ? semanticFacts.get(inKey) : null;
		if (src == null || !isUsefulUefiType(src.type)) return 0;
		if (src.confidence.rank < Confidence.STRONG.rank || src.depth != 0) return 0;

		Varnode outVn = op.getOutput();
		HighFunction hf = outVn.getHigh() != null ? outVn.getHigh().getHighFunction() : null;
		if (hf != null && detectFunctionParameter(hf, outVn) >= 0) return 0;

		return proposeVarnodeEvidence(
			f, hf, outVn, src.type, Confidence.SUPPORTED,
			0, "exact COPY alias of " + src.source, src.origin,
			op.getSeqnum().getTarget(), proposed);
	}

	// -------------------------------------------------------------------
	// Evidence collection: function return type inference
	// -------------------------------------------------------------------

	private int collectReturnEvidence(
		Function f, HighFunction hf, PcodeOpAST ret,
		Map<String, TypeEvidence> proposed) {

		// A typed value reaching RETURN does not establish the ABI contract.
		return 0;
	}

	// -------------------------------------------------------------------
	// Evidence proposal: varnode -> evidence key
	// -------------------------------------------------------------------

	private int proposeVarnodeEvidence(
		Function f, HighFunction hf, Varnode vn, DataType wanted, Confidence c,
		int depth, String source, String origin, Address site,
		Map<String, TypeEvidence> proposed) {

		if (vn == null || wanted == null || !isUsefulUefiType(wanted)) return 0;

		// Check for global address first
		if (vn.isAddress() && currentProgram.getMemory().contains(vn.getAddress())) {
			String key = "GLOBAL:" + vn.getAddress();
			return mergeEvidence(key, new TypeEvidence(f, null, wanted, c, depth, source, origin, site), proposed);
		}

		HighVariable hv = vn.getHigh();
		if (hv == null) return 0;

		HighSymbol sym = hv.getSymbol();

		// If no symbol, try to detect if this is a function parameter
		if (sym == null && hf != null) {
			int paramIdx = detectFunctionParameter(hf, vn);
			if (paramIdx >= 0) {
				String key = "PARAM:" + hf.getFunction().getEntryPoint() + ":" + paramIdx;
				return mergeEvidence(key, new TypeEvidence(f, null, wanted, c, depth, source, origin, site), proposed);
			}
		}

		// Build a key - with or without symbol
		String key = evidenceKey(vn);
		if (key == null) return 0;
		return mergeEvidence(key, new TypeEvidence(f, sym, wanted, c, depth, source, origin, site), proposed);
	}

	private int proposeOutputStorageEvidence(
		Function f, HighFunction hf, Varnode outputPointer, DataType wanted, Confidence c,
		String source, Address site, Map<String, TypeEvidence> proposed) {

		String origin = "GUID:" + source;
		Address global = recoverReferencedAddress(outputPointer, 32, new HashSet<Varnode>());
		if (global != null && isPlausibleGlobalAddress(global)) {
			String key = "GLOBAL:" + global;
			return mergeEvidence(key, new TypeEvidence(f, null, wanted, c, 0, source, origin, site), proposed);
		}
		return proposeVarnodeEvidence(f, hf, outputPointer, wanted, c, 0, source, origin, site, proposed);
	}

	// -------------------------------------------------------------------
	// Function parameter detection from varnode
	// -------------------------------------------------------------------

	private int detectFunctionParameter(HighFunction hf, Varnode vn) {
		if (hf == null || vn == null) return -1;
		Function func = hf.getFunction();
		if (func == null) return -1;

		HighVariable hv = vn.getHigh();
		if (hv == null) return -1;

		// Check if any symbol in the local map that matches this HighVariable is a parameter
		Iterator<HighSymbol> syms = hf.getLocalSymbolMap().getSymbols();
		while (syms.hasNext()) {
			HighSymbol s = syms.next();
			if (s.getHighVariable() == hv && s.isParameter()) {
				Parameter[] params = func.getParameters();
				for (int i = 0; i < params.length; i++) {
					if (params[i].getName().equals(s.getName())) return i;
				}
				// Parameter name didn't match - try by index from symbol
				int idx = s.getCategoryIndex();
				if (idx >= 0 && idx < func.getParameterCount()) return idx;
			}
		}

		// Fallback: match representative varnode storage against parameter storage
		Varnode rep = hv.getRepresentative();
		if (rep != null) {
			Parameter[] params = func.getParameters();
			for (int i = 0; i < params.length; i++) {
				VariableStorage storage = params[i].getVariableStorage();
				if (storage == null || storage.isBadStorage()) continue;
				Varnode[] pvns = storage.getVarnodes();
				for (Varnode pvn : pvns) {
					if (pvn.getAddress() != null && rep.getAddress() != null &&
						pvn.getAddress().equals(rep.getAddress()) &&
						pvn.getSize() == rep.getSize()) {
						return i;
					}
				}
			}
		}

		return -1;
	}

	// -------------------------------------------------------------------
	// Evidence merge
	// -------------------------------------------------------------------

	private int mergeEvidence(String key, TypeEvidence ev, Map<String, TypeEvidence> proposed) {

		TypeEvidence known = semanticFacts.get(key);
		if (known != null) {
			if (known.type.isEquivalent(ev.type)) {
				if (ev.confidence.rank > known.confidence.rank) proposed.put(key, ev);
				return 0;
			}
			if (known.confidence.rank >= ev.confidence.rank) {
				cntEvidenceRejected++;
				return 0;
			}
		}

		TypeEvidence cur = proposed.get(key);
		if (cur == null) { proposed.put(key, ev); return 1; }
		if (cur.type.isEquivalent(ev.type)) {
			if (ev.confidence.rank > cur.confidence.rank) proposed.put(key, ev);
			return 0;
		}
		if (cur.confidence.rank == ev.confidence.rank) {
			proposed.remove(key);
			cntEvidenceConflicts++;
			return 0;
		}
		if (ev.confidence.rank > cur.confidence.rank) proposed.put(key, ev);
		return 0;
	}

	// -------------------------------------------------------------------
	// Evidence application (staged batch)
	// -------------------------------------------------------------------

	private int applyEvidenceBatch(Map<String, TypeEvidence> proposed) {
		int changed = 0;
		cntNewMutations = 0;
		cntDuplicateFacts = 0;

		for (Map.Entry<String, TypeEvidence> e : proposed.entrySet()) {
			String key = e.getKey();
			TypeEvidence ev = e.getValue();
			TypeEvidence old = semanticFacts.get(key);

			// Already known with same type and equal/better confidence - duplicate
			if (old != null && old.type.isEquivalent(ev.type) &&
				old.confidence.rank >= ev.confidence.rank) {
				cntDuplicateFacts++;
				continue;
			}

			// Depth enforcement: deep evidence cannot mutate signatures/globals
			boolean dbChanged = false;
			try {
				if (key.startsWith("GLOBAL:")) {
					if (!ev.canMutateSignature()) { cntEvidenceRejected++; semanticFacts.put(key, ev); continue; }
					dbChanged = applyGlobalEvidence(key, ev);

				} else if (key.startsWith("PARAM:")) {
					// Observation only. Graph inference never changes function ABI.
					semanticFacts.put(key, ev);
					continue;

				} else if (key.startsWith("RETURN:")) {
					semanticFacts.put(key, ev);
					continue;

				} else if (ev.symbol != null) {
					// Stack/local HighSymbols can represent reused storage.
					semanticFacts.put(key, ev);
					continue;
				}
			} catch (Exception ex) {
				cntEvidenceRejected++;
				continue;
			}

			semanticFacts.put(key, ev);
			cntEvidenceAccepted++;
			if (dbChanged) { changed++; cntNewMutations++; }
		}

		return changed;
	}

	private boolean applyGlobalEvidence(String key, TypeEvidence ev) {
		try {
			Address a = toAddr(Long.parseLong(key.substring(7), 16));
			if (!currentProgram.getMemory().contains(a)) return false;
			if (!isPlausibleGlobalAddress(a)) return false;

			if (ev.confidence.rank < Confidence.STRONG.rank) return false;

			Data d = currentProgram.getListing().getDataAt(a);
			DataType before = d != null ? d.getDataType() : null;
			if (before != null && !isWeakType(before) && before.isEquivalent(ev.type)) return false;
			if (before != null && !isWeakType(before)) return false;

			// Pointer-depth compatibility: don't change pointer to scalar or vice versa
			if (!pointerDepthCompatible(before, ev.type)) return false;

			clearListing(a, a.add(Math.max(0, ev.type.getLength() - 1)));
			createData(a, ev.type);
			println("      [EVIDENCE/GLOBAL] " + a + " : " +
				(before != null ? before.getDisplayName() : "<none>") + " -> " +
				ev.type.getDisplayName() + "  [" + ev.confidence + " d=" + ev.depth + "] " + ev.source);
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	private boolean applyParamEvidence(String key, TypeEvidence ev) {
		try {
			String[] parts = key.split(":");
			Address funcAddr = toAddr(Long.parseLong(parts[1], 16));
			int paramIdx = Integer.parseInt(parts[2]);
			Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);
			if (func == null || paramIdx >= func.getParameterCount()) return false;

			Parameter param = func.getParameter(paramIdx);
			DataType before = param.getDataType();
			if (!isWeakType(before)) return false;
			if (before.isEquivalent(ev.type)) return false;
			if (!pointerDepthCompatible(before, ev.type)) return false;

			param.setDataType(ev.type, SourceType.ANALYSIS);
			cntParamChanges++;
			improvedFunctions.add(funcAddr);
			println("      [EVIDENCE/PARAM] " + funcAddr + " " + func.getName() +
				"  " + param.getName() + "[" + paramIdx + "] : " +
				before.getDisplayName() + " -> " + ev.type.getDisplayName() +
				"  [" + ev.confidence + " d=" + ev.depth + "] " + ev.source);
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	private boolean applyReturnEvidence(String key, TypeEvidence ev) {
		try {
			Address funcAddr = toAddr(Long.parseLong(key.substring(7), 16));
			Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);
			if (func == null) return false;

			DataType before = func.getReturnType();
			if (!isWeakType(before)) return false;
			if (before.isEquivalent(ev.type)) return false;
			if (!pointerDepthCompatible(before, ev.type)) return false;

			func.setReturnType(ev.type, SourceType.ANALYSIS);
			cntReturnChanges++;
			improvedFunctions.add(funcAddr);
			println("      [EVIDENCE/RETURN] " + funcAddr + " " + func.getName() +
				" : " + before.getDisplayName() + " -> " + ev.type.getDisplayName() +
				"  [" + ev.confidence + " d=" + ev.depth + "] " + ev.source);
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	private boolean applySymbolEvidence(String key, TypeEvidence ev) {
		try {
			DataType before = ev.symbol.getDataType();
			if (before != null && !isWeakType(before)) return false;
			if (before != null && before.isEquivalent(ev.type)) return false;
			if (before != null && !pointerDepthCompatible(before, ev.type)) return false;

			HighFunctionDBUtil.updateDBVariable(
				ev.symbol, ev.symbol.getName(), ev.type, SourceType.ANALYSIS);
			cntLocalChanges++;
			if (ev.function != null) improvedFunctions.add(ev.function.getEntryPoint());

			println("      [EVIDENCE/LOCAL] " +
				(ev.function != null ? ev.function.getEntryPoint() + " " + ev.function.getName() + "  " : "") +
				ev.symbol.getName() + " : " +
				(before != null ? before.getDisplayName() : "<unknown>") + " -> " +
				ev.type.getDisplayName() + "  [" + ev.confidence + " d=" + ev.depth + "] " + ev.source);
			return true;
		} catch (Exception ex) {
			return false;
		}
	}

	// -------------------------------------------------------------------
	// Evidence helpers: type/confidence queries
	// -------------------------------------------------------------------

	private String evidenceKey(Varnode vn) {
		if (vn == null) return null;

		if (vn.isAddress() && currentProgram.getMemory().contains(vn.getAddress()))
			return "GLOBAL:" + vn.getAddress();

		HighVariable hv = vn.getHigh();
		if (hv == null) return null;
		HighFunction hf = hv.getHighFunction();
		if (hf == null) return null;

		HighSymbol sym = hv.getSymbol();
		if (sym != null)
			return "SYM:" + hf.getFunction().getEntryPoint() + ":" + sym.getName() + ":" + sym.getStorage();

		Varnode rep = hv.getRepresentative();
		if (rep != null)
			return "VAR:" + hf.getFunction().getEntryPoint() + ":" + rep.toString();

		return null;
	}

	private DataType trustedTypeOf(Varnode vn) {
		if (vn == null) return null;
		String key = evidenceKey(vn);
		TypeEvidence ev = key != null ? semanticFacts.get(key) : null;
		// Decompiler state is not independent semantic evidence.
		return ev != null ? ev.type : null;
	}

	private Confidence confidenceOf(Varnode vn) {
		if (vn == null) return Confidence.PROPAGATED;
		String key = evidenceKey(vn);
		TypeEvidence ev = key != null ? semanticFacts.get(key) : null;
		return ev != null ? ev.confidence : Confidence.PROPAGATED;
	}

	private int depthOf(Varnode vn) {
		if (vn == null) return 99;
		String key = evidenceKey(vn);
		TypeEvidence ev = key != null ? semanticFacts.get(key) : null;
		return ev != null ? ev.depth : 99;
	}

	private String originOf(Varnode vn) {
		if (vn == null) return "unknown";
		String key = evidenceKey(vn);
		TypeEvidence ev = key != null ? semanticFacts.get(key) : null;
		return ev != null ? ev.origin : "unknown";
	}

	private DataType highType(Varnode vn) {
		if (vn == null || vn.getHigh() == null) return null;
		return vn.getHigh().getDataType();
	}

	private boolean isWeakType(DataType dt) {
		if (dt == null) return true;
		String n = dt.getName();
		if (dt instanceof Undefined) return true;
		if (n == null) return true;
		String l = n.toLowerCase(Locale.ROOT);
		return l.equals("void") || l.equals("void *") || l.startsWith("undefined") ||
			l.startsWith("unk") || l.equals("long") || l.equals("ulong") ||
			l.equals("longlong") || l.equals("ulonglong") ||
			l.equals("pointer") || l.equals("addr");
	}

	private boolean pointerDepthCompatible(DataType oldDt, DataType newDt) {
		if (oldDt == null || newDt == null) return true;

		int oldDepth = pointerDepth(oldDt);
		int newDepth = pointerDepth(newDt);

		// Only treat as "unknown depth" if old type is scalar AND weak
		if (oldDepth == 0 && isWeakType(oldDt)) return true;

		// Both scalars or both pointers - compatible
		if (oldDepth == 0 && newDepth == 0) return true;
		if (oldDepth > 0 && newDepth > 0) return true;

		// Mismatch: pointer <-> scalar - reject
		return false;
	}

	private int pointerDepth(DataType dt) {
		int depth = 0;
		DataType cur = dt;
		while (cur instanceof Pointer) {
			depth++;
			cur = ((Pointer) cur).getDataType();
		}
		while (cur instanceof TypeDef) {
			cur = ((TypeDef) cur).getBaseDataType();
			if (cur instanceof Pointer) { depth++; cur = ((Pointer) cur).getDataType(); }
		}
		return depth;
	}

	private boolean isUsefulUefiType(DataType dt) {
		if (dt == null || dt instanceof Undefined) return false;
		DataType cur = dt;
		for (int i = 0; i < 6 && cur != null; i++) {
			String n = cur.getName();
			if (n != null && (n.startsWith("EFI_") || n.startsWith("EDKII_") ||
				n.startsWith("RETURN_") || n.equals("UINTN") || n.equals("INTN") ||
				n.equals("CHAR16") || n.equals("CHAR8") || n.equals("BOOLEAN"))) return true;
			if (cur instanceof TypeDef) { cur = ((TypeDef)cur).getBaseDataType(); continue; }
			if (cur instanceof Pointer) { cur = ((Pointer)cur).getDataType(); continue; }
			break;
		}
		return false;
	}

	private boolean isProtocolPointerType(DataType dt) {
		if (dt == null) return false;
		DataType cur = dt;
		for (int i = 0; i < 8 && cur != null; i++) {
			String n = cur.getName();
			if (n != null && (n.contains("_PROTOCOL") || n.contains("_PPI"))) return true;
			if (cur instanceof TypeDef) { cur = ((TypeDef)cur).getBaseDataType(); continue; }
			if (cur instanceof Pointer) { cur = ((Pointer)cur).getDataType(); continue; }
			break;
		}
		return false;
	}


	// =====================================================================
	// Service resolution (p-code provenance)
	// =====================================================================

	private static class ServiceHit {
		String owner, name; DataType fieldType; int offset;
		ServiceHit(String o, String n, DataType t, int off) {
			owner=o; name=n; fieldType=t; offset=off;
		}
	}

	private ServiceHit resolveServiceCall(PcodeOpAST call) {
		if (call == null || call.getNumInputs() < 1) return null;
		Varnode target = call.getInput(0);

		ServiceHit bs = resolveServiceFromRoot(target, gBS, "gBS", bsMap, bsFieldTypes);
		ServiceHit rt = resolveServiceFromRoot(target, gRT, "gRT", rtMap, rtFieldTypes);
		ServiceHit st = resolveServiceFromSystemTable(target);

		List<ServiceHit> hits = new ArrayList<>();
		if (bs != null) hits.add(bs);
		if (rt != null) hits.add(rt);
		if (st != null) hits.add(st);
		if (hits.isEmpty()) return null;

		ServiceHit first = hits.get(0);
		for (int i = 1; i < hits.size(); i++) {
			ServiceHit h = hits.get(i);
			if (!first.owner.equals(h.owner) || !first.name.equals(h.name) || first.offset != h.offset)
				return null;
		}
		return first;
	}

	private ServiceHit resolveServiceFromSystemTable(Varnode target) {
		int bsOff = structureFieldOffset(dtSystemTable, "BootServices");
		int rtOff = structureFieldOffset(dtSystemTable, "RuntimeServices");
		if (bsOff < 0 || rtOff < 0) return null;

		List<ServiceHit> hits = new ArrayList<>();

		if (gST != null) {
			ServiceHit h = resolveNestedServiceFromRoot(target, gST, bsOff, "gBS", bsMap, bsFieldTypes);
			if (h != null) hits.add(h);
			h = resolveNestedServiceFromRoot(target, gST, rtOff, "gRT", rtMap, rtFieldTypes);
			if (h != null) hits.add(h);
		}

		// Also check typed EFI_SYSTEM_TABLE* parameters/locals
		HighFunction hf = target.getHigh() != null ? target.getHigh().getHighFunction() : null;
		if (hf != null) {
			Iterator<HighSymbol> syms = hf.getLocalSymbolMap().getSymbols();
			while (syms.hasNext()) {
				HighSymbol sym = syms.next();
				if (!isPointerToNamedType(sym.getDataType(), "EFI_SYSTEM_TABLE")) continue;
				HighVariable hv = sym.getHighVariable();
				if (hv == null) continue;
				Varnode rep = hv.getRepresentative();
				if (rep == null) continue;

				ServiceHit h = resolveNestedServiceFromVarnode(
					target, rep, bsOff, "gBS", bsMap, bsFieldTypes);
				if (h != null) hits.add(h);
				h = resolveNestedServiceFromVarnode(
					target, rep, rtOff, "gRT", rtMap, rtFieldTypes);
				if (h != null) hits.add(h);
			}
		}

		if (hits.isEmpty()) return null;
		ServiceHit first = hits.get(0);
		for (int i = 1; i < hits.size(); i++) {
			ServiceHit h = hits.get(i);
			if (!first.owner.equals(h.owner) || !first.name.equals(h.name) || first.offset != h.offset)
				return null;
		}
		return first;
	}

	private ServiceHit resolveServiceFromRoot(
		Varnode target, Address root, String owner,
		Map<Integer,String> names, Map<Integer,DataType> types) {

		if (root == null || target == null) return null;
		Set<Integer> offsets = new LinkedHashSet<>();
		collectRootedOffsets(target, root, 24, new HashSet<Varnode>(), offsets);
		return uniqueServiceHit(owner, names, types, offsets);
	}

	private ServiceHit resolveNestedServiceFromRoot(
		Varnode target, Address stRoot, int serviceTableOffset, String owner,
		Map<Integer,String> names, Map<Integer,DataType> types) {

		if (stRoot == null) return null;
		Set<Integer> serviceOffsets = new LinkedHashSet<>();
		collectNestedOffsetsFromAddress(
			target, stRoot, serviceTableOffset, 28, new HashSet<Varnode>(), serviceOffsets);
		return uniqueServiceHit(owner, names, types, serviceOffsets);
	}

	private ServiceHit resolveNestedServiceFromVarnode(
		Varnode target, Varnode stRoot, int serviceTableOffset, String owner,
		Map<Integer,String> names, Map<Integer,DataType> types) {

		if (stRoot == null) return null;
		Set<Integer> serviceOffsets = new LinkedHashSet<>();
		collectNestedOffsetsFromVarnode(
			target, stRoot, serviceTableOffset, 28, new HashSet<Varnode>(), serviceOffsets);
		return uniqueServiceHit(owner, names, types, serviceOffsets);
	}

	private ServiceHit uniqueServiceHit(
		String owner, Map<Integer,String> names, Map<Integer,DataType> types,
		Set<Integer> offsets) {

		ServiceHit hit = null;
		for (Integer off : offsets) {
			if (!names.containsKey(off)) continue;
			ServiceHit cur = new ServiceHit(owner, names.get(off), types.get(off), off);
			if (hit != null && hit.offset != cur.offset) return null;
			hit = cur;
		}
		return hit;
	}

	private Function resolveDirectCallee(PcodeOpAST call) {
		if (call.getNumInputs() < 1) return null;
		Varnode dst = call.getInput(0);
		if (!dst.isAddress()) return null;
		return currentProgram.getFunctionManager().getFunctionAt(dst.getAddress());
	}

	private FunctionDefinition unwrapFunctionDefinition(DataType dt) {
		if (dt == null) return null;
		DataType cur = dt;
		for (int i = 0; i < 4 && cur != null; i++) {
			if (cur instanceof FunctionDefinition) return (FunctionDefinition) cur;
			if (cur instanceof TypeDef) { cur = ((TypeDef)cur).getBaseDataType(); continue; }
			if (cur instanceof Pointer) { cur = ((Pointer)cur).getDataType(); continue; }
			break;
		}
		return null;
	}


	// =====================================================================
	// P-code offset/address recovery
	// =====================================================================

	private Address recoverReferencedAddress(Varnode vn, int depth, Set<Varnode> seen) {
		if (vn == null || depth <= 0 || !seen.add(vn)) return null;

		// Direct address-space varnode
		if (vn.isAddress() && currentProgram.getMemory().contains(vn.getAddress()))
			return vn.getAddress();

		// Constant that represents a valid program address
		if (vn.isConstant() && vn.getOffset() >= 0x200) {
			try {
				Address a = currentProgram.getAddressFactory()
					.getDefaultAddressSpace().getAddress(vn.getOffset());
				if (currentProgram.getMemory().contains(a)) return a;
			} catch (Exception e) { /* not a valid address */ }
		}

		PcodeOp def = vn.getDef();
		if (def == null) return null;
		int opc = def.getOpcode();

		// Transparent: COPY, CAST, INDIRECT
		if (opc == PcodeOp.COPY || opc == PcodeOp.CAST || opc == PcodeOp.INDIRECT)
			return recoverReferencedAddress(def.getInput(0), depth - 1, seen);

		// Pointer arithmetic: PTRSUB, INT_ADD, PTRADD
		if (opc == PcodeOp.PTRSUB || opc == PcodeOp.INT_ADD || opc == PcodeOp.PTRADD) {
			// Try non-constant inputs as address sources
			for (int i = 0; i < def.getNumInputs(); i++) {
				Varnode in = def.getInput(i);
				if (in.isConstant()) continue;
				Address a = recoverReferencedAddress(in, depth - 1, seen);
				if (a != null) return a;
			}
			// Try constant inputs as direct addresses (skip low values - PE header)
			for (int i = 0; i < def.getNumInputs(); i++) {
				Varnode in = def.getInput(i);
				if (!in.isConstant() || in.getOffset() < 0x200) continue;
				try {
					Address a = currentProgram.getAddressFactory()
						.getDefaultAddressSpace().getAddress(in.getOffset());
					if (currentProgram.getMemory().contains(a)) return a;
				} catch (Exception e) { /* not valid */ }
			}
		}

		// MULTIEQUAL (phi node): all arms must agree
		if (opc == PcodeOp.MULTIEQUAL) {
			Address result = null;
			for (int i = 0; i < def.getNumInputs(); i++) {
				Address a = recoverReferencedAddress(def.getInput(i), depth - 1, seen);
				if (a == null) continue;
				if (result == null) result = a;
				else if (!result.equals(a)) return null; // ambiguous
			}
			return result;
		}

		// LOAD: the address being loaded from might be what we want
		if (opc == PcodeOp.LOAD && def.getNumInputs() > 1) {
			return recoverReferencedAddress(def.getInput(1), depth - 1, seen);
		}

		return null;
	}

	private void collectRootedOffsets(
		Varnode vn, Address root, int depth, Set<Varnode> seen, Set<Integer> out) {

		if (vn == null || root == null || depth <= 0 || !seen.add(vn)) return;
		PcodeOp def = vn.getDef();
		if (def == null) return;
		int opc = def.getOpcode();

		if (opc == PcodeOp.LOAD && def.getNumInputs() > 1) {
			Varnode ptr = def.getInput(1);
			Integer off = offsetFromRootExpression(ptr, root, depth - 1, new HashSet<Varnode>());
			if (off != null) out.add(off);
			collectRootedOffsets(ptr, root, depth - 1, seen, out);
			return;
		}

		if (opc == PcodeOp.COPY || opc == PcodeOp.CAST || opc == PcodeOp.INDIRECT) {
			collectRootedOffsets(def.getInput(0), root, depth - 1, seen, out);
			return;
		}

		if (opc == PcodeOp.PTRADD || opc == PcodeOp.PTRSUB || opc == PcodeOp.INT_ADD ||
			opc == PcodeOp.MULTIEQUAL) {
			for (int i = 0; i < def.getNumInputs(); i++)
				collectRootedOffsets(def.getInput(i), root, depth - 1, seen, out);
		}
	}

	private Integer offsetFromRootExpression(
		Varnode vn, Address root, int depth, Set<Varnode> seen) {

		if (vn == null || root == null || depth <= 0 || !seen.add(vn)) return null;
		if (vn.isAddress() && root.equals(vn.getAddress())) return 0;

		PcodeOp def = vn.getDef();
		if (def == null) return null;
		int opc = def.getOpcode();

		if (opc == PcodeOp.COPY || opc == PcodeOp.CAST || opc == PcodeOp.INDIRECT)
			return offsetFromRootExpression(def.getInput(0), root, depth - 1, seen);

		if (opc == PcodeOp.LOAD && def.getNumInputs() > 1) {
			if (expressionReferencesAddress(def.getInput(1), root, depth - 1, new HashSet<Varnode>()))
				return 0;
			return offsetFromRootExpression(def.getInput(1), root, depth - 1, seen);
		}

		if (opc == PcodeOp.PTRSUB || opc == PcodeOp.INT_ADD) {
			Integer base = null;
			Long add = 0L;
			boolean haveConst = false;
			for (int i = 0; i < def.getNumInputs(); i++) {
				Varnode in = def.getInput(i);
				if (in.isConstant()) { add += in.getOffset(); haveConst = true; }
				else {
					Integer b = offsetFromRootExpression(in, root, depth - 1, new HashSet<Varnode>(seen));
					if (b != null) base = b;
				}
			}
			if (base != null) return base + (haveConst ? add.intValue() : 0);
		}

		if (opc == PcodeOp.PTRADD && def.getNumInputs() >= 2) {
			Integer base = offsetFromRootExpression(def.getInput(0), root, depth - 1, new HashSet<Varnode>(seen));
			if (base == null) return null;
			long idx = def.getInput(1).isConstant() ? def.getInput(1).getOffset() : 0;
			long scale = (def.getNumInputs() > 2 && def.getInput(2).isConstant()) ?
				def.getInput(2).getOffset() : 1;
			return base + (int)(idx * scale);
		}

		return null;
	}

	private boolean expressionReferencesAddress(Varnode vn, Address addr, int depth, Set<Varnode> seen) {
		if (vn == null || addr == null || depth <= 0 || !seen.add(vn)) return false;
		if (vn.isAddress() && addr.equals(vn.getAddress())) return true;
		if (vn.isConstant()) {
			try {
				Address a = currentProgram.getAddressFactory()
					.getDefaultAddressSpace().getAddress(vn.getOffset());
				if (addr.equals(a)) return true;
			} catch (Exception e) { /* not valid */ }
		}
		PcodeOp def = vn.getDef();
		if (def == null) return false;
		for (int i = 0; i < def.getNumInputs(); i++)
			if (expressionReferencesAddress(def.getInput(i), addr, depth - 1, seen)) return true;
		return false;
	}

	// Nested offset recovery for gST chains (address root)
	private void collectNestedOffsetsFromAddress(
		Varnode vn, Address stRoot, int tableOffset, int depth,
		Set<Varnode> seen, Set<Integer> out) {

		if (vn == null || depth <= 0 || !seen.add(vn)) return;
		PcodeOp def = vn.getDef();
		if (def == null) return;

		if (def.getOpcode() == PcodeOp.LOAD && def.getNumInputs() > 1) {
			Integer member = nestedMemberOffsetFromAddress(
				def.getInput(1), stRoot, tableOffset, depth - 1, new HashSet<Varnode>());
			if (member != null) out.add(member);
		}

		for (int i = 0; i < def.getNumInputs(); i++)
			collectNestedOffsetsFromAddress(
				def.getInput(i), stRoot, tableOffset, depth - 1, seen, out);
	}

	private Integer nestedMemberOffsetFromAddress(
		Varnode vn, Address stRoot, int tableOffset, int depth, Set<Varnode> seen) {

		if (vn == null || depth <= 0 || !seen.add(vn)) return null;
		PcodeOp def = vn.getDef();
		if (def == null) return null;

		if (def.getOpcode() == PcodeOp.PTRSUB || def.getOpcode() == PcodeOp.INT_ADD ||
			def.getOpcode() == PcodeOp.PTRADD) {

			Long constant = expressionConstantContribution(def);
			for (int i = 0; i < def.getNumInputs(); i++) {
				Varnode in = def.getInput(i);
				if (in.isConstant()) continue;
				if (isLoadedSystemTableMemberFromAddress(
					in, stRoot, tableOffset, depth - 1, new HashSet<Varnode>()))
					return constant != null ? constant.intValue() : 0;
				Integer nested = nestedMemberOffsetFromAddress(
					in, stRoot, tableOffset, depth - 1, new HashSet<Varnode>(seen));
				if (nested != null) return nested + (constant != null ? constant.intValue() : 0);
			}
		}

		if (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST ||
			def.getOpcode() == PcodeOp.INDIRECT || def.getOpcode() == PcodeOp.LOAD) {
			for (int i = 0; i < def.getNumInputs(); i++) {
				Integer r = nestedMemberOffsetFromAddress(
					in(def,i), stRoot, tableOffset, depth - 1, new HashSet<Varnode>(seen));
				if (r != null) return r;
			}
		}
		return null;
	}

	private boolean isLoadedSystemTableMemberFromAddress(
		Varnode vn, Address stRoot, int tableOffset, int depth, Set<Varnode> seen) {

		if (vn == null || depth <= 0 || !seen.add(vn)) return false;
		PcodeOp def = vn.getDef();
		if (def == null) return false;
		if (def.getOpcode() == PcodeOp.LOAD && def.getNumInputs() > 1) {
			Integer off = offsetFromRootExpression(
				def.getInput(1), stRoot, depth - 1, new HashSet<Varnode>());
			return off != null && off == tableOffset;
		}
		if (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST ||
			def.getOpcode() == PcodeOp.INDIRECT)
			return isLoadedSystemTableMemberFromAddress(
				def.getInput(0), stRoot, tableOffset, depth - 1, seen);
		return false;
	}

	// Nested offset recovery for gST chains (varnode root)
	private void collectNestedOffsetsFromVarnode(
		Varnode vn, Varnode stRoot, int tableOffset, int depth,
		Set<Varnode> seen, Set<Integer> out) {

		if (vn == null || depth <= 0 || !seen.add(vn)) return;
		PcodeOp def = vn.getDef();
		if (def == null) return;

		if (def.getOpcode() == PcodeOp.LOAD && def.getNumInputs() > 1) {
			Integer member = nestedMemberOffsetFromVarnode(
				def.getInput(1), stRoot, tableOffset, depth - 1, new HashSet<Varnode>());
			if (member != null) out.add(member);
		}

		for (int i = 0; i < def.getNumInputs(); i++)
			collectNestedOffsetsFromVarnode(
				def.getInput(i), stRoot, tableOffset, depth - 1, seen, out);
	}

	private Integer nestedMemberOffsetFromVarnode(
		Varnode vn, Varnode stRoot, int tableOffset, int depth, Set<Varnode> seen) {

		if (vn == null || depth <= 0 || !seen.add(vn)) return null;
		PcodeOp def = vn.getDef();
		if (def == null) return null;

		if (def.getOpcode() == PcodeOp.PTRSUB || def.getOpcode() == PcodeOp.INT_ADD ||
			def.getOpcode() == PcodeOp.PTRADD) {
			Long constant = expressionConstantContribution(def);
			for (int i = 0; i < def.getNumInputs(); i++) {
				Varnode in = def.getInput(i);
				if (in.isConstant()) continue;
				if (isLoadedSystemTableMemberFromVarnode(
					in, stRoot, tableOffset, depth - 1, new HashSet<Varnode>()))
					return constant != null ? constant.intValue() : 0;
				Integer nested = nestedMemberOffsetFromVarnode(
					in, stRoot, tableOffset, depth - 1, new HashSet<Varnode>(seen));
				if (nested != null) return nested + (constant != null ? constant.intValue() : 0);
			}
		}

		if (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST ||
			def.getOpcode() == PcodeOp.INDIRECT || def.getOpcode() == PcodeOp.LOAD) {
			for (int i = 0; i < def.getNumInputs(); i++) {
				Integer r = nestedMemberOffsetFromVarnode(
					in(def,i), stRoot, tableOffset, depth - 1, new HashSet<Varnode>(seen));
				if (r != null) return r;
			}
		}
		return null;
	}

	private boolean isLoadedSystemTableMemberFromVarnode(
		Varnode vn, Varnode stRoot, int tableOffset, int depth, Set<Varnode> seen) {

		if (vn == null || depth <= 0 || !seen.add(vn)) return false;
		PcodeOp def = vn.getDef();
		if (def == null) return false;
		if (def.getOpcode() == PcodeOp.LOAD && def.getNumInputs() > 1) {
			Integer off = offsetFromVarnodeRootExpression(
				def.getInput(1), stRoot, depth - 1, new HashSet<Varnode>());
			return off != null && off == tableOffset;
		}
		if (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST ||
			def.getOpcode() == PcodeOp.INDIRECT)
			return isLoadedSystemTableMemberFromVarnode(
				def.getInput(0), stRoot, tableOffset, depth - 1, seen);
		return false;
	}

	private Integer offsetFromVarnodeRootExpression(
		Varnode vn, Varnode root, int depth, Set<Varnode> seen) {

		if (vn == null || root == null || depth <= 0 || !seen.add(vn)) return null;
		if (sameStorage(vn, root)) return 0;
		PcodeOp def = vn.getDef();
		if (def == null) return null;

		if (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST ||
			def.getOpcode() == PcodeOp.INDIRECT)
			return offsetFromVarnodeRootExpression(def.getInput(0), root, depth - 1, seen);

		if (def.getOpcode() == PcodeOp.PTRSUB || def.getOpcode() == PcodeOp.INT_ADD ||
			def.getOpcode() == PcodeOp.PTRADD) {
			Long c = expressionConstantContribution(def);
			for (int i = 0; i < def.getNumInputs(); i++) {
				Varnode in = def.getInput(i);
				if (in.isConstant()) continue;
				Integer base = offsetFromVarnodeRootExpression(
					in, root, depth - 1, new HashSet<Varnode>(seen));
				if (base != null) return base + (c != null ? c.intValue() : 0);
			}
		}
		return null;
	}

	private boolean sameStorage(Varnode a, Varnode b) {
		if (a == null || b == null) return false;
		if (a.equals(b)) return true;
		HighVariable ha = a.getHigh(), hb = b.getHigh();
		if (ha != null && hb != null && ha == hb) return true;
		return a.getAddress() != null && b.getAddress() != null &&
			a.getAddress().equals(b.getAddress()) && a.getSize() == b.getSize();
	}

	private Long expressionConstantContribution(PcodeOp op) {
		if (op == null) return null;
		if (op.getOpcode() == PcodeOp.PTRADD && op.getNumInputs() >= 2) {
			long idx = op.getInput(1).isConstant() ? op.getInput(1).getOffset() : 0;
			long scale = (op.getNumInputs() > 2 && op.getInput(2).isConstant()) ?
				op.getInput(2).getOffset() : 1;
			return idx * scale;
		}
		long total = 0; boolean any = false;
		for (int i = 0; i < op.getNumInputs(); i++) {
			Varnode in = op.getInput(i);
			if (in.isConstant()) { total += in.getOffset(); any = true; }
		}
		return any ? total : null;
	}

	private boolean isPointerToNamedType(DataType dt, String wanted) {
		if (dt == null) return false;
		DataType cur = dt;
		for (int i = 0; i < 8 && cur != null; i++) {
			String n = cur.getName();
			if (wanted.equals(n) || ("_" + wanted).equals(n)) return true;
			if (cur instanceof TypeDef) { cur = ((TypeDef)cur).getBaseDataType(); continue; }
			if (cur instanceof Pointer) { cur = ((Pointer)cur).getDataType(); continue; }
			break;
		}
		return false;
	}

	// Shorthand to avoid repeating def.getInput(i) in recursive calls.
	private static Varnode in(PcodeOp op, int i) { return op.getInput(i); }


	// =====================================================================
	// Protocol helpers
	// =====================================================================

	private int protocolGuidArgumentIndex(String service) {
		if ("HandleProtocol".equals(service)) return 1;
		if ("LocateProtocol".equals(service)) return 0;
		if ("OpenProtocol".equals(service)) return 1;
		return -1;
	}

	private int protocolOutputArgumentIndex(String service) {
		if ("HandleProtocol".equals(service)) return 2;
		if ("LocateProtocol".equals(service)) return 2;
		if ("OpenProtocol".equals(service)) return 2;
		return -1;
	}


	// =====================================================================
	// Step 2 - Retype Entry Point
	// =====================================================================

	private Function stepRetypeEntry() throws Exception {

		println("");
		println("[2/8] Retyping entry point");
		println("----------------------------------------------------------------------");

		Address ea = findEntryAddress();
		if (ea == null) { println("      Entry point not found"); return null; }

		Function func = getFunctionAt(ea);
		if (func == null) { println("      No function at " + ea); return null; }

		func.setReturnType(dtStatus, SourceType.USER_DEFINED);
		if (dtHandle != null) {
			func.replaceParameters(
				Arrays.asList(
					new ParameterImpl("ImageHandle", dtHandle, currentProgram),
					new ParameterImpl("SystemTable", ptr(dtSystemTable), currentProgram)
				),
				Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED
			);
		}
		func.setName("UefiMain", SourceType.USER_DEFINED);

		println("      UefiMain @ " + ea);
		println("      EFI_STATUS UefiMain(EFI_HANDLE, EFI_SYSTEM_TABLE *)");
		return func;
	}

	private Address findEntryAddress() {
		AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator();
		if (it.hasNext()) return it.next();
		for (Symbol s : currentProgram.getSymbolTable().getSymbols("entry")) return s.getAddress();
		return null;
	}


	// =====================================================================
	// Step 3 - Find Global Pointers
	// =====================================================================

	private void stepFindGlobals(Function entry) {

		println("");
		println("[3/8] Finding global pointers");
		println("----------------------------------------------------------------------");

		if (entry == null) {
			println("      No entry function, running broad scan");
			broadScanGlobals(500);
			printGlobalResults();
			return;
		}

		Set<Function> targets = collectCallTree(entry, 2);
		println("      Scanning " + targets.size() + " functions (entry + 2 levels)");

		for (Function f : targets) { if (allGlobalsFound()) break; scanFunctionForGlobals(f); }

		if (!allGlobalsFound()) {
			println("      Re-scanning after type propagation...");
			for (Function f : targets) { if (allGlobalsFound()) break; scanFunctionForGlobals(f); }
		}

		if (!allGlobalsFound()) {
			println("      Broadening search...");
			broadScanGlobals(500);
		}

		if (gBS == null) { gBS = instrHeuristic(bsMap, "gBS"); if (gBS != null) applyGlobal(gBS, "gBS", ptr(dtBootServices)); }
		if (gRT == null) { gRT = instrHeuristic(rtMap, "gRT"); if (gRT != null) applyGlobal(gRT, "gRT", ptr(dtRuntimeServices)); }

		printGlobalResults();
	}

	private boolean allGlobalsFound() {
		return gImageHandle != null && gST != null && gBS != null && gRT != null;
	}

	private Set<Function> collectCallTree(Function root, int depth) {
		Set<Function> result = new LinkedHashSet<>();
		Set<Function> current = new LinkedHashSet<>();
		current.add(root); result.add(root);
		for (int level = 0; level < depth; level++) {
			Set<Function> next = new LinkedHashSet<>();
			for (Function f : current) for (Function c : getCallees(f)) if (result.add(c)) next.add(c);
			current = next;
		}
		return result;
	}

	private Set<Function> getCallees(Function func) {
		Set<Function> out = new LinkedHashSet<>();
		InstructionIterator ii = currentProgram.getListing().getInstructions(func.getBody(), true);
		while (ii.hasNext()) {
			Instruction instr = ii.next();
			if (instr.getFlowType().isCall())
				for (Reference ref : instr.getReferencesFrom()) {
					Function t = getFunctionAt(ref.getToAddress());
					if (t != null && !t.isThunk() && !t.isExternal()) out.add(t);
				}
		}
		return out;
	}

	private void scanFunctionForGlobals(Function func) {
		DecompileResults res = decompiler.decompileFunction(func, 15, monitor);
		if (res == null || res.getDecompiledFunction() == null) return;
		String c = res.getDecompiledFunction().getC();

		// Discovery only.  Do NOT back-propagate parameter types here: the
		// canonical roots must be fully discovered and frozen first.
		if (gImageHandle == null) {
			Address a = matchAddr(c, "_?DAT_(\\p{XDigit}+)\\s*=\\s*(?:ImageHandle|param_1)\\s*;");
			if (a != null) { gImageHandle = a; applyGlobal(a, "gImageHandle", dtHandle); }
		}
		if (gST == null) {
			Address a = matchAddr(c, "_?DAT_(\\p{XDigit}+)\\s*=\\s*(?:SystemTable|param_2)\\s*;");
			if (a != null && !a.equals(gImageHandle)) { gST = a; applyGlobal(a, "gST", ptr(dtSystemTable)); }
		}
		if (gBS == null) {
			int off = structureFieldOffset(dtSystemTable, "BootServices");
			String hx = off >= 0 ? Integer.toHexString(off) : "";
			Address a = firstAddr(c, off >= 0 ? new String[]{
				"_?DAT_(\\p{XDigit}+)\\s*=.*->BootServices",
				"_?DAT_(\\p{XDigit}+)\\s*=.*\\*\\s*\\(.*\\+\\s*0x" + hx + "\\s*\\)"
			} : new String[]{ "_?DAT_(\\p{XDigit}+)\\s*=.*->BootServices" });
			if (a != null && !a.equals(gST) && !a.equals(gImageHandle)) { gBS = a; applyGlobal(a, "gBS", ptr(dtBootServices)); }
		}
		if (gRT == null) {
			int off = structureFieldOffset(dtSystemTable, "RuntimeServices");
			String hx = off >= 0 ? Integer.toHexString(off) : "";
			Address a = firstAddr(c, off >= 0 ? new String[]{
				"_?DAT_(\\p{XDigit}+)\\s*=.*->RuntimeServices",
				"_?DAT_(\\p{XDigit}+)\\s*=.*\\*\\s*\\(.*\\+\\s*0x" + hx + "\\s*\\)"
			} : new String[]{ "_?DAT_(\\p{XDigit}+)\\s*=.*->RuntimeServices" });
			if (a != null && !a.equals(gST) && !a.equals(gImageHandle) && !a.equals(gBS)) { gRT = a; applyGlobal(a, "gRT", ptr(dtRuntimeServices)); }
		}
	}

	private void stepBackPropCanonicalRoots(Function entry) {
		if (gImageHandle == null && gST == null && gBS == null && gRT == null) return;

		println("");
		println("[ROOT BACK-PROP] Canonical root parameters");
		println("----------------------------------------------------------------------");

		int changes = 0;
		FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
		while (fi.hasNext() && !monitor.isCancelled()) {
			Function f = fi.next();
			if (f.isThunk() || f.isExternal() || f.getParameterCount() == 0) continue;
			DecompileResults res = decompiler.decompileFunction(f, 15, monitor);
			if (res == null || res.getDecompiledFunction() == null) continue;
			String c = res.getDecompiledFunction().getC();

			changes += backPropKnownRootInFunction(f, c, gImageHandle, "gImageHandle", dtHandle);
			changes += backPropKnownRootInFunction(f, c, gST, "gST", ptr(dtSystemTable));
			changes += backPropKnownRootInFunction(f, c, gBS, "gBS", ptr(dtBootServices));
			changes += backPropKnownRootInFunction(f, c, gRT, "gRT", ptr(dtRuntimeServices));
		}
		println("      Canonical parameter roots applied: " + changes);
	}

	private int backPropKnownRootInFunction(Function func, String c, Address rootAddr,
		String rootName, DataType wanted) {
		if (rootAddr == null || func == null || c == null || wanted == null) return 0;

		String addr = rootAddr.toString().replaceFirst("^0+", "");
		if (addr.length() == 0) addr = "0";
		String lhs = "(?:" + Pattern.quote(rootName) + "|_?DAT_0*" + Pattern.quote(addr) + ")";

		Pattern pat = Pattern.compile(lhs +
			"\\s*=\\s*(?:\\([^;=]+?\\)\\s*)*(param_\\d+|ImageHandle|SystemTable)\\s*;");
		Matcher m = pat.matcher(c);
		while (m.find()) {
			int idx = resolveParameterIndex(func, m.group(1));
			if (idx < 0) continue;
			return applyCanonicalRootParameter(func, idx, wanted, rootName) ? 1 : 0;
		}
		return 0;
	}

	private int resolveParameterIndex(Function func, String token) {
		if (func == null || token == null) return -1;
		Parameter[] params = func.getParameters();
		for (int i = 0; i < params.length; i++)
			if (token.equals(params[i].getName())) return i;
		Matcher pm = Pattern.compile("param_(\\d+)").matcher(token);
		if (pm.matches()) {
			int idx = Integer.parseInt(pm.group(1)) - 1;
			if (idx >= 0 && idx < params.length) return idx;
		}
		if ("ImageHandle".equals(token) && params.length >= 1) return 0;
		if ("SystemTable".equals(token) && params.length >= 2) return 1;
		return -1;
	}

	private boolean applyCanonicalRootParameter(Function func, int paramIdx,
		DataType wanted, String rootName) {
		if (func == null || wanted == null || paramIdx < 0 || paramIdx >= func.getParameterCount()) return false;
		try {
			Parameter param = func.getParameter(paramIdx);
			DataType before = param.getDataType();
			if (!isWeakType(before) && !before.isEquivalent(wanted)) return false;
			if (!pointerDepthCompatible(before, wanted)) return false;

			String key = "PARAM:" + func.getEntryPoint() + ":" + paramIdx;
			TypeEvidence ev = new TypeEvidence(func, null, wanted,
				Confidence.AUTHORITATIVE, 0, "canonical root " + rootName,
				"ROOT:" + rootName, func.getEntryPoint());
			canonicalRootParamSeeds.put(key, ev);

			if (before.isEquivalent(wanted)) return false;
			param.setDataType(wanted, SourceType.ANALYSIS);
			cntParamChanges++;
			improvedFunctions.add(func.getEntryPoint());
			println("      [ROOT/PARAM] " + func.getEntryPoint() + " " + func.getName() +
				"  " + param.getName() + "[" + paramIdx + "] : " +
				before.getDisplayName() + " -> " + wanted.getDisplayName() +
				"  [AUTHORITATIVE d=0] canonical root " + rootName);
			return true;
		} catch (Exception e) {
			println("      [!] Canonical root parameter back-prop failed in " +
				func.getName() + ": " + e.getMessage());
			return false;
		}
	}

	private Address matchAddr(String c, String pat) { return firstAddr(c, new String[]{ pat }); }

	private Address firstAddr(String c, String[] pats) {
		for (String pat : pats) {
			Matcher m = Pattern.compile(pat).matcher(c);
			if (m.find()) {
				try {
					Address a = toAddr(Long.parseLong(m.group(1), 16));
					if (currentProgram.getMemory().contains(a)) return a;
				} catch (Exception e) { /* next */ }
			}
		}
		return null;
	}

	private void broadScanGlobals(int limit) {
		FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
		int n = 0;
		while (fi.hasNext() && n < limit && !allGlobalsFound() && !monitor.isCancelled()) {
			Function f = fi.next();
			if (f.getBody().getNumAddresses() < 5) continue;
			n++; scanFunctionForGlobals(f);
		}
		println("      Broad scan checked " + n + " functions");
	}

	private Address instrHeuristic(Map<Integer, String> offsets, String name) {
		Map<Address, Integer> hits = new HashMap<>();
		InstructionIterator ii = currentProgram.getListing().getInstructions(currentProgram.getMemory(), true);
		int n = 0;
		while (ii.hasNext() && n < 80_000) {
			Instruction instr = ii.next(); n++;
			String text = instr.toString().toLowerCase();
			boolean has = false;
			for (int off : offsets.keySet()) if (text.contains(String.format("0x%x", off))) { has = true; break; }
			if (!has) continue;
			for (int op = 0; op < instr.getNumOperands(); op++)
				for (Reference ref : instr.getOperandReferences(op))
					if (ref.getReferenceType().isData()) {
						Address t = ref.getToAddress();
						if (!isKnownGlobal(t)) hits.merge(t, 1, Integer::sum);
					}
		}
		Address best = null; int bestN = 0;
		for (Map.Entry<Address, Integer> e : hits.entrySet())
			if (e.getValue() > bestN && e.getValue() >= 3) { best = e.getKey(); bestN = e.getValue(); }
		if (best != null) println("      Heuristic: " + name + " candidate at " + best + " (" + bestN + " hits)");
		return best;
	}

	private boolean isKnownGlobal(Address a) {
		return a.equals(gImageHandle) || a.equals(gST) || a.equals(gBS) || a.equals(gRT);
	}

	private void printGlobalResults() {
		println("");
		gLine("gImageHandle", gImageHandle, "EFI_HANDLE");
		gLine("gST",          gST,          "EFI_SYSTEM_TABLE *");
		gLine("gBS",          gBS,          "EFI_BOOT_SERVICES *");
		gLine("gRT",          gRT,          "EFI_RUNTIME_SERVICES *");
	}

	private void gLine(String name, Address a, String type) {
		println("      " + pad(name, 16) + (a != null ? a + "  " + type : "NOT FOUND"));
	}


	// =====================================================================
	// Step 4 - Label Known GUIDs
	// =====================================================================

	private void stepLabelGuids() {
		println("");
		println("[4/8] Scanning EFI GUIDs from Behemoth database");
		println("----------------------------------------------------------------------");
		Memory mem = currentProgram.getMemory();

		for (Map.Entry<String, String[]> entry : guidDb.entrySet()) {
			String canonical = entry.getKey();
			String label = entry.getValue()[0];
			String proto = entry.getValue()[1];

			if ("00000000-0000-0000-0000-000000000000".equals(canonical)) continue;

			try {
				byte[] pattern = guidStringToMemoryBytes(canonical);
				Address search = mem.getMinAddress();
				while (search != null) {
					Address addr = mem.findBytes(search, pattern, null, true, monitor);
					if (addr == null) break;
					Address next = addr.add(1);

					if (!hasCodeReferenceTo(addr)) { search = next; continue; }

					setLabel(addr, label);
					applyGuidDataType(addr);
					knownGuids.put(addr, new String[]{label, proto});
					cntKnownGuids++;
					println("      " + pad(label, 42) + addr +
						(proto != null ? "  -> " + proto : ""));
					search = next;
				}
			} catch (Exception e) { }
		}
		println("");
		println("      Total: " + cntKnownGuids + " known GUIDs labeled");
	}


	// =====================================================================
	// Step 5 - Retype Protocol Interfaces
	// =====================================================================

	private void stepRetypeProtocols() {

		println("");
		println("[5/8] Retyping protocol interfaces");
		println("----------------------------------------------------------------------");

		if (knownGuids.isEmpty()) { println("      No GUID mappings, skipping"); return; }

		int pcodeRecovered = recoverProtocolInterfacesFromPcode();
		if (pcodeRecovered > 0)
			println("      P-code protocol acquisitions recovered: " + pcodeRecovered);

		// Also attempt regex-based recovery from decompiled C (backup)
		for (Map.Entry<Address, String[]> entry : knownGuids.entrySet()) {
			Address guidAddr  = entry.getKey();
			String  guidLabel = entry.getValue()[0];
			String  protoName = entry.getValue()[1];
			if (protoName == null) continue;

			DataType protoDt = resolveType(protoName, false);
			if (protoDt == null) continue;
			DataType protoPtrDt = ptr(protoDt);

			ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(guidAddr);
			Set<Function> processed = new HashSet<>();

			while (ri.hasNext()) {
				Reference ref = ri.next();
				Function func = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (func == null || !processed.add(func)) continue;

				DecompileResults res = decompiler.decompileFunction(func, 15, monitor);
				if (res == null || res.getDecompiledFunction() == null) continue;
				String code = res.getDecompiledFunction().getC();
				HighFunction hf = res.getHighFunction();

				String ql = Pattern.quote(guidLabel);
				String[] pats = {
					"HandleProtocol[^;]*" + ql + "[^,]*,[^,]*,\\s*(?:&|\\(\\s*void\\s*\\*\\*\\s*\\)\\s*&?)?\\s*([a-zA-Z_]\\w*)",
					"LocateProtocol[^;]*"  + ql + "[^;]*,[^,]*,\\s*(?:&|\\(\\s*void\\s*\\*\\*\\s*\\)\\s*&?)?\\s*([a-zA-Z_]\\w*)\\s*\\)",
					"OpenProtocol[^;]*"    + ql + "[^,]*,[^,]*,\\s*(?:&|\\(\\s*void\\s*\\*\\*\\s*\\)\\s*&?)?\\s*([a-zA-Z_]\\w*)"
				};

				for (String pat : pats) {
					Matcher m = Pattern.compile(pat).matcher(code);
					while (m.find()) {
						String varName = m.group(1);
						if (varName.equals("NULL") || varName.equals("void")) continue;

						boolean applied = false;
						if (varName.matches("_?DAT_[0-9a-fA-F]+")) {
							try {
								Address ga = toAddr(Long.parseLong(varName.replaceFirst("_?DAT_", ""), 16));
								if (currentProgram.getMemory().contains(ga))
									applied = applyGlobal(ga,
										"g" + protoName.replace("EFI_","").replace("_PROTOCOL",""),
										protoPtrDt);
							} catch (Exception ex) { }
						}

						annotateEOL(ref.getFromAddress(), varName + " -> " + protoName + " *");
						String status = applied ? "RETYPED_GLOBAL" : "OBSERVED_VALUE";
						println("      " + func.getName() + ": " + varName + " -> " + protoName + " *  (" + status + ")");
						protocolDetails.add(new String[]{ func.getName(), varName, protoName, guidLabel, status });
						cntProtocols++;
					}
				}
			}
		}

		println("");
		println("      Total: " + cntProtocols + " protocol interfaces processed");
	}

	private int recoverProtocolInterfacesFromPcode() {
		int recovered = 0;
		FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
		Set<String> seen = new HashSet<>();

		while (fi.hasNext() && !monitor.isCancelled()) {
			Function func = fi.next();
			if (func.isExternal()) continue;
			DecompileResults res = decompiler.decompileFunction(func, 20, monitor);
			if (res == null || res.getHighFunction() == null) continue;
			HighFunction hf = res.getHighFunction();

			Iterator<PcodeOpAST> ops = hf.getPcodeOps();
			while (ops.hasNext()) {
				PcodeOpAST op = ops.next();
				if (op.getOpcode() != PcodeOp.CALLIND) continue;
				ServiceHit hit = resolveServiceCall(op);
				if (hit == null) continue;

				int guidArg = protocolGuidArgumentIndex(hit.name);
				int outArg = protocolOutputArgumentIndex(hit.name);
				if (guidArg < 0 || outArg < 0 ||
					op.getNumInputs() <= guidArg + 1 || op.getNumInputs() <= outArg + 1) continue;

				Address ga = recoverReferencedAddress(op.getInput(guidArg + 1), 32, new HashSet<Varnode>());
				if (ga == null) continue;

				String[] info = knownGuids.get(ga);
				if (info == null) {
					String canonical = readGuidAt(ga);
					if (canonical != null) {
						info = guidDb.get(canonical);
						if (info != null) {
							try {
								setLabel(ga, info[0]);
								applyGuidDataType(ga);
								knownGuids.put(ga, info);
								cntKnownGuids++;
								println("      [GUID]     " + ga + "  " + info[0] +
									(info[1] != null ? " -> " + info[1] : ""));
							} catch (Exception ex) { }
						}
					}
				}
				if (info == null || info[1] == null) continue;

				DataType proto = resolveType(info[1], false);
				if (proto == null) continue;
				DataType wanted = ptr(proto);
				Varnode dest = op.getInput(outArg + 1);

				String ckey = func.getEntryPoint() + ":" + op.getSeqnum().getTarget() + ":" + info[0];
				if (!seen.add(ckey)) continue;

				boolean applied = applyProtocolDestination(func, hf, dest, wanted, info[1], hit.name, info[0]);
				if (applied) recovered++;
			}
		}
		return recovered;
	}

	private boolean applyProtocolDestination(
		Function func, HighFunction hf, Varnode dest, DataType wanted,
		String protoName, String service, String guidLabel) {

		Address global = recoverReferencedAddress(dest, 32, new HashSet<Varnode>());
		boolean applied = false;
		String storage = describeVarnode(dest);

		// Persistent global storage has a stable program-wide identity, so a GUID-proven protocol acquisition may safely type that global.
		if (global != null && isPlausibleGlobalAddress(global)) {
			String label = "g" + protoName.replaceFirst("^_?EFI_", "").replace("_PROTOCOL", "");
			applied = applyGlobal(global, label, wanted);
			storage = global.toString();
		}
		else {
			HighVariable hv = dest.getHigh();
			if (hv != null && hv.getSymbol() != null)
				storage = hv.getSymbol().getName();
		}

		String status = applied ? "RETYPED_GLOBAL" : "OBSERVED_VALUE";
		println("      [PROTOCOL] " + func.getEntryPoint() + " " + func.getName() +
			"  " + storage + " -> " + protoName + " *  [" + service + " / " + guidLabel + "] " + status);
		protocolDetails.add(new String[]{func.getName(), storage, protoName, guidLabel, status});
		cntProtocols++;
		return applied;
	}


	private boolean retypeLocal(HighFunction hf, String varName, DataType newType) {
		try {
			Iterator<HighSymbol> syms = hf.getLocalSymbolMap().getSymbols();
			while (syms.hasNext()) {
				HighSymbol sym = syms.next();
				if (sym.getName().equals(varName)) {
					HighFunctionDBUtil.updateDBVariable(sym, varName, newType, SourceType.USER_DEFINED);
					return true;
				}
			}
		} catch (Exception e) { }
		return false;
	}


	// =====================================================================
	// Step 6 - Annotate Service Calls + Detect Unknown GUIDs
	// =====================================================================

	private void stepAnnotateCalls() {

		println("");
		println("[6/8] Recovering Boot/Runtime Service calls");
		println("----------------------------------------------------------------------");

		Map<String, Set<Address>> tracker = new LinkedHashMap<>();
		FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
		int scanned = 0;

		while (fi.hasNext() && !monitor.isCancelled()) {
			Function func = fi.next();
			if (func.isExternal()) continue;

			DecompileResults res = decompiler.decompileFunction(func, 20, monitor);
			if (res == null || res.getHighFunction() == null) continue;
			scanned++;

			HighFunction hf = res.getHighFunction();
			Iterator<PcodeOpAST> ops = hf.getPcodeOps();
			while (ops.hasNext()) {
				PcodeOpAST op = ops.next();
				if (op.getOpcode() != PcodeOp.CALLIND || op.getNumInputs() < 1) continue;

				ServiceHit hit = resolveServiceCall(op);
				if (hit == null) continue;

				Address site = op.getSeqnum().getTarget();
				String tag = hit.owner + "->" + hit.name;
				Set<Address> sites = tracker.computeIfAbsent(tag, k -> new LinkedHashSet<>());
				if (!sites.add(site)) continue;

				annotateEOL(site, tag);
				callSiteDetails.computeIfAbsent(tag, k -> new ArrayList<>())
					.add(new String[]{ func.getName(), site.toString() });
				cntAnnotations++;

				println("      [SERVICE] " + site + "  " + func.getName() +
					"  " + tag + "  [GDT offset 0x" + Integer.toHexString(hit.offset) + "]");
			}

			detectUnknownGuids(func, res);
		}

		println("");
		println("      Functions scanned: " + scanned);
		for (Map.Entry<String, Set<Address>> e : tracker.entrySet())
			println("      " + pad(e.getKey(), 42) + e.getValue().size() +
				" call " + (e.getValue().size() == 1 ? "site" : "sites"));
		println("");
		println("      Service calls: " + cntAnnotations + " annotated");
		println("      Unknown GUIDs: " + cntUnknownGuids + " detected and typed");
	}

	private void detectUnknownGuids(Function func, DecompileResults res) {
		if (res == null || res.getDecompiledFunction() == null) return;
		String code = res.getDecompiledFunction().getC();
		Matcher gm = Pattern.compile(
			"\\(\\s*EFI_GUID\\s*\\*\\s*\\)\\s*&\\s*_?(?:DAT_)?(\\p{XDigit}{4,})").matcher(code);
		while (gm.find()) {
			try {
				Address guidAddr = toAddr(Long.parseLong(gm.group(1), 16));
				if (!currentProgram.getMemory().contains(guidAddr) ||
					knownGuids.containsKey(guidAddr) || unknownGuids.containsKey(guidAddr)) continue;
				byte[] raw = new byte[16];
				currentProgram.getMemory().getBytes(guidAddr, raw);
				if (!looksLikeGuid(raw)) continue;
				String guidStr = bytesToGuidString(raw);
				unknownGuids.put(guidAddr, guidStr);
				applyGuidDataType(guidAddr);
				try { setLabel(guidAddr, "UnknownGuid_" + guidStr.substring(0, 8)); } catch (Exception e) { }
				cntUnknownGuids++;
				println("      [GUID?]   " + guidAddr + " " + guidStr + "  in " + func.getName());
			} catch (Exception e) { }
		}
	}

	private boolean hasCodeReferenceTo(Address addr) {
		ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(addr);
		while (ri.hasNext()) {
			Function f = currentProgram.getFunctionManager().getFunctionContaining(ri.next().getFromAddress());
			if (f != null) return true;
		}
		return false;
	}

	private String readGuidAt(Address addr) {
		if (addr == null || !currentProgram.getMemory().contains(addr)) return null;
		try {
			byte[] b = new byte[16];
			currentProgram.getMemory().getBytes(addr, b);
			if (!looksLikeGuid(b)) return null;
			long d1 = ((long)b[0]&0xff) | (((long)b[1]&0xff)<<8) |
				(((long)b[2]&0xff)<<16) | (((long)b[3]&0xff)<<24);
			int d2 = (b[4]&0xff) | ((b[5]&0xff)<<8);
			int d3 = (b[6]&0xff) | ((b[7]&0xff)<<8);
			return String.format(Locale.ROOT,
				"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				d1,d2,d3,b[8]&0xff,b[9]&0xff,b[10]&0xff,b[11]&0xff,
				b[12]&0xff,b[13]&0xff,b[14]&0xff,b[15]&0xff);
		} catch (Exception e) { return null; }
	}

	private String describeVarnode(Varnode vn) {
		if (vn == null) return "<null>";
		if (vn.isAddress()) return vn.getAddress().toString();
		return vn.toString();
	}


	// =====================================================================
	// Function type summary
	// =====================================================================

	private void printFunctionTypeSummary(Function entry) {
		println("");
		println("[TYPE GRAPH] Final function prototypes");
		println("----------------------------------------------------------------------");
		if (entry != null)
			println("      [MAIN]    " + entry.getEntryPoint() + "  " + entry.getPrototypeString(true, true));
		List<Address> a = new ArrayList<>(improvedFunctions); Collections.sort(a);
		for (Address x : a) {
			Function f = currentProgram.getFunctionManager().getFunctionAt(x);
			if (f != null && (entry == null || !x.equals(entry.getEntryPoint())))
				println("      [FUNC]    " + x + "  " + f.getPrototypeString(true, true));
		}
		println("      Functions improved ...... " + improvedFunctions.size());
		println("      Locals retyped .......... " + cntLocalChanges);
		println("      Parameters retyped ...... " + cntParamChanges);
		println("      Returns retyped ......... " + cntReturnChanges);
	}


	// =====================================================================
	// Step 7 - Generate Report
	// =====================================================================

	private void saveConsoleReport() {

		String safeName = currentProgram.getName().replaceAll("[^a-zA-Z0-9._-]", "_");
		File reportFile = new File(
			System.getProperty("user.home"),
			"Behemoth_Retyper_" + safeName + ".txt"
		);

		try (PrintWriter pw = new PrintWriter(new FileWriter(reportFile))) {
			pw.print(consoleTranscript.toString());
			super.println("");
			super.println("[REPORT] " + reportFile.getAbsolutePath());
		} catch (Exception e) {
			super.println("");
			super.println("[!] Failed to write report: " + e.getMessage());
		}
	}

	private int countInternalFunctions() {
		int n = 0;
		FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
		while (fi.hasNext()) if (!fi.next().isExternal()) n++;
		return n;
	}

	private int countGlobals() {
		int n=0;
		if(gImageHandle!=null)n++; if(gST!=null)n++;
		if(gBS!=null)n++; if(gRT!=null)n++;
		return n;
	}

	private void reportGlobal(StringBuilder r, String name, Address addr, String type) {
		r.append(String.format("  %-16s %-12s %s\n", name,
			addr != null ? addr.toString() : "NOT FOUND",
			addr != null ? type : ""));
	}


	// =====================================================================
	// Summary
	// =====================================================================

	private void printSummary() {
		println("");
		println("========================================================================");
		println(" Results");
		println("========================================================================");
		println(String.format("      %-16s %-14s %-16s %s",
			"Globals", countGlobals() + " / 4", "Known GUIDs", String.valueOf(cntKnownGuids)));
		println(String.format("      %-16s %-14s %-16s %s",
			"Unknown GUIDs", String.valueOf(cntUnknownGuids), "Protocols", String.valueOf(cntProtocols)));
		println(String.format("      %-16s %-14s %-16s %s",
			"Annotations", String.valueOf(cntAnnotations), "GDT svc fields", String.valueOf(cntDynamicServiceFields)));
		println(String.format("      %-16s %-14s %-16s %s",
			"Locals", String.valueOf(cntLocalChanges), "Params", String.valueOf(cntParamChanges)));
		println(String.format("      %-16s %-14s %-16s %s",
			"Returns", String.valueOf(cntReturnChanges), "Graph passes", String.valueOf(cntSemanticPasses)));
		println("========================================================================");
	}


	// =====================================================================
	// Dynamic semantic-source helpers
	// =====================================================================

	private void loadGuidDatabase() throws Exception {
		println("");
		println("[GUID DB] Loading Behemoth GUID identities");
		println("----------------------------------------------------------------------");

		if (isHeadless()) {
			guidDbFile = behemothGuidIni();
			if (guidDbFile == null) {
				println("      [GUID DB] not found (set BEHEMOTH_GUIDS or place Behemoth_GUIDs.ini under GDT/GUIDs)");
				return;
			}
		}
		else {
			guidDbFile = askFile("Select Behemoth GUID Database", "Select Behemoth_GUIDs.ini");
		}

		Map<String,String> symbols = new LinkedHashMap<>();
		Map<String,String> types = new LinkedHashMap<>();
		String section = "";
		try (BufferedReader br = new BufferedReader(new FileReader(guidDbFile))) {
			String line;
			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith(";") || line.startsWith("#")) continue;
				if (line.startsWith("[") && line.endsWith("]")) {
					section = line.substring(1, line.length()-1).trim();
					continue;
				}
				int eq = line.indexOf('=');
				if (eq <= 0) continue;
				String key = line.substring(0,eq).trim();
				String val = line.substring(eq+1).trim();
				if ("EDK2".equalsIgnoreCase(section)) {
					String g = normalizeGuid(val);
					if (g != null) symbols.put(key,g);
				} else if ("Types".equalsIgnoreCase(section)) {
					types.put(key,val);
				}
			}
		}
		for (Map.Entry<String,String> e : symbols.entrySet()) {
			String type = types.get(e.getKey());
			if (type != null && resolveType(type,false) == null) type = null;
			guidDb.put(e.getValue(), new String[]{e.getKey(),type});
			if (type != null) cntProtocolTypes++;
		}
		println("      Database ................ " + guidDbFile.getAbsolutePath());
		println("      GUID identities ......... " + guidDb.size());
		println("      Valid type associations . " + cntProtocolTypes);
	}

	private String normalizeGuid(String v) {
		Matcher m = Pattern.compile("(?i)([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})").matcher(v);
		if (!m.find()) return null;
		return (m.group(1)+"-"+m.group(2)+"-"+m.group(3)+"-"+m.group(4)+"-"+m.group(5)).toLowerCase(Locale.ROOT);
	}

	private byte[] guidStringToMemoryBytes(String g) {
		String[] p=g.split("-");
		long d1=Long.parseLong(p[0],16); int d2=Integer.parseInt(p[1],16); int d3=Integer.parseInt(p[2],16);
		String tail=p[3]+p[4]; byte[] b=new byte[16];
		b[0]=(byte)d1; b[1]=(byte)(d1>>8); b[2]=(byte)(d1>>16); b[3]=(byte)(d1>>24);
		b[4]=(byte)d2; b[5]=(byte)(d2>>8); b[6]=(byte)d3; b[7]=(byte)(d3>>8);
		for(int i=0;i<8;i++) b[8+i]=(byte)Integer.parseInt(tail.substring(i*2,i*2+2),16);
		return b;
	}

	private int structureFieldOffset(DataType dt, String field) {
		DataType cur=dt;
		while(cur instanceof TypeDef) cur=((TypeDef)cur).getBaseDataType();
		if(!(cur instanceof Structure)) return -1;
		for(DataTypeComponent c:((Structure)cur).getDefinedComponents())
			if(field.equals(c.getFieldName())) return c.getOffset();
		return -1;
	}


	// =====================================================================
	// Utilities - Types
	// =====================================================================

	private DataType resolveType(String name, boolean log) {
		if (name == null) return null;
		DataType cached = typeCache.get(name);
		if (cached != null) { if (log) println("      " + pad(name, 30) + "OK (cached)"); return cached; }

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		ArrayList<DataType> results = new ArrayList<>();
		dtm.findDataTypes(name, results);
		if (!results.isEmpty()) {
			typeCache.put(name, results.get(0));
			if (log) println("      " + pad(name, 30) + "OK");
			return results.get(0);
		}

		if (state != null && state.getTool() != null) {
			DataTypeManagerService svc = state.getTool().getService(DataTypeManagerService.class);
			if (svc != null){
				for (DataTypeManager a : svc.getDataTypeManagers()) {
					results.clear(); a.findDataTypes(name, results);
					if (!results.isEmpty()) {
						DataType imp = dtm.addDataType(results.get(0), DataTypeConflictHandler.REPLACE_HANDLER);
						typeCache.put(name, imp);
						if (log) println("      " + pad(name, 30) + "OK");
						return imp;
					}
				}
			}
		}

		DataType fromGdt = resolveFromBehemothGdt(name);
		if (fromGdt != null) {
			DataType imp = dtm.addDataType(fromGdt, DataTypeConflictHandler.REPLACE_HANDLER);
			typeCache.put(name, imp);
			if (log) println("      " + pad(name, 30) + "OK (gdt)");
			return imp;
		}

		if (log) println("      " + pad(name, 30) + "NOT FOUND");
		return null;
	}

	private DataType ptr(DataType dt) { return dt != null ? new PointerDataType(dt) : null; }


	// =====================================================================
	// Utilities - Globals
	// =====================================================================

	private boolean isPlausibleGlobalAddress(Address addr) {
		if (addr == null || addr.getOffset() == 0) return false;
		MemoryBlock block = currentProgram.getMemory().getBlock(addr);
		if (block == null) return false;
		// Reject addresses in the PE header area (first block, low offset)
		if (block.getStart().getOffset() == 0 && addr.getOffset() < 0x200) return false;
		// Reject addresses that already have non-trivial structured types
		Data existing = currentProgram.getListing().getDataAt(addr);
		if (existing != null) {
			DataType eDt = existing.getDataType();
			if (eDt != null && !(eDt instanceof Undefined) &&
				!eDt.getName().startsWith("undefined") &&
				!eDt.getName().startsWith("pointer") &&
				!eDt.getName().equals("addr") &&
				eDt.getLength() > ptrSize) return false;
		}
		return true;
	}

	private boolean applyGlobal(Address addr, String name, DataType dt) {
		if (addr == null || dt == null || retypedAddresses.contains(addr)) return false;
		if (!currentProgram.getMemory().contains(addr)) return false;
		if (!isPlausibleGlobalAddress(addr)) return false;
		try {
			Listing l = currentProgram.getListing();
			try { l.clearCodeUnits(addr, addr.add(dt.getLength() - 1), false); } catch (Exception e) { }
			l.createData(addr, dt);
			setLabel(addr, name);
			retypedAddresses.add(addr);
			println("      [GLOBAL]  " + addr + "  " + name + " : " + dt.getDisplayName());
			return true;
		} catch (Exception e) {
			println("      [!] Failed: " + name + " @ " + addr + ": " + e.getMessage());
			return false;
		}
	}


	// =====================================================================
	// Utilities - Symbols & Comments
	// =====================================================================

	private void setLabel(Address addr, String name) throws Exception {
		SymbolTable st = currentProgram.getSymbolTable();
		for (Symbol s : st.getSymbols(addr))
			if (s.getName().startsWith("DAT_") || s.getName().startsWith("_DAT_") || s.getSource() == SourceType.DEFAULT)
				s.delete();
		st.createLabel(addr, name, SourceType.USER_DEFINED);
	}

	private void annotateEOL(Address addr, String tag) {
		try {
			CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr);
			if (cu == null) cu = currentProgram.getListing().getCodeUnitBefore(addr);
			if (cu != null) {
				String ex = cu.getComment(CodeUnit.EOL_COMMENT);
				if (ex == null || !ex.contains(tag))
					cu.setComment(CodeUnit.EOL_COMMENT, ex != null ? ex + " | " + tag : tag);
			}
		} catch (Exception e) { }
	}


	// =====================================================================
	// Utilities - GUID
	// =====================================================================

	private void applyGuidDataType(Address addr) {
		if (dtGuid == null) return;
		try {
			currentProgram.getListing().clearCodeUnits(addr, addr.add(dtGuid.getLength() - 1), false);
			currentProgram.getListing().createData(addr, dtGuid);
		} catch (Exception e) { }
	}

	private static boolean looksLikeGuid(byte[] b) {
		if (b.length != 16) return false;
		int zeros = 0, ffs = 0;
		for (byte x : b) {
			if (x == 0) zeros++;
			if (x == (byte) 0xFF) ffs++;
		}
		return zeros < 12 && ffs < 12;
	}

	private static String bytesToGuidString(byte[] b) {
		return String.format("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			b[3]&0xFF, b[2]&0xFF, b[1]&0xFF, b[0]&0xFF,
			b[5]&0xFF, b[4]&0xFF,
			b[7]&0xFF, b[6]&0xFF,
			b[8]&0xFF, b[9]&0xFF,
			b[10]&0xFF, b[11]&0xFF, b[12]&0xFF, b[13]&0xFF, b[14]&0xFF, b[15]&0xFF);
	}


	// =====================================================================
	// Utilities - Formatting
	// =====================================================================

	private static String pad(String text, int width) {
		if (text.length() >= width) return text + " ";
		StringBuilder sb = new StringBuilder(text);
		sb.append(' ');
		while (sb.length() < width) sb.append('.');
		sb.append(' ');
		return sb.toString();
	}

}
