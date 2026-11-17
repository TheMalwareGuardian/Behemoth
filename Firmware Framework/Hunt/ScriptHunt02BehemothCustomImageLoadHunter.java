// Discovers custom UEFI image loaders, execution paths, verification controls, and embedded EFI targets.
// @author TheMalwareGuardian
// @category UEFI

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.*;
import java.util.regex.*;

public class ScriptHunt02BehemothCustomImageLoadHunter extends GhidraScript {

	private static final int DECOMPILE_TIMEOUT = 30;
	private static final int MAX_STRING_CHARS = 200;

	enum Severity { CRITICAL, HIGH, MEDIUM, REVIEW }

	enum EvidenceType {
		LOAD_IMAGE,
		START_IMAGE,
		UNLOAD_IMAGE,
		LOAD_START_CHAIN,
		DEVICE_PATH_CONSTRUCTION,
		BOOT_POLICY_TRUE,
		BOOT_POLICY_FALSE,
		MEMORY_SOURCE,
		SOURCE_SIZE_NONZERO,
		PE_DOS_MAGIC,
		PE_SIGNATURE,
		TE_SIGNATURE,
		PE32_MAGIC,
		PE32PLUS_MAGIC,
		SECTION_PROCESSING,
		ENTRYPOINT_DERIVATION,
		EXECUTABLE_ALLOCATION,
		HEADER_COPY,
		SECTION_MAPPING,
		RELOCATION_PROCESSING,
		ENTRYPOINT_EXPORT,
		ENTRYPOINT_EXECUTION,
		INDIRECT_CALL,
		SECURITY_ARCH,
		SECURITY2_ARCH,
		SECURITY_STATE_WRITE,
		IMAGE_PATH
	}

	static class Evidence {
		EvidenceType type;
		Function function;
		String line;
		String note;

		Evidence(EvidenceType type, Function function, String line, String note) {
			this.type = type;
			this.function = function;
			this.line = line;
			this.note = note;
		}
	}

	static class FunctionProfile {
		Function function;
		EnumSet<EvidenceType> types = EnumSet.noneOf(EvidenceType.class);
		List<Evidence> evidence = new ArrayList<>();

		void add(EvidenceType type, String line, String note) {
			types.add(type);
			evidence.add(new Evidence(type, function, line, note));
		}

		boolean has(EvidenceType t) { return types.contains(t); }
		boolean hasAny(EvidenceType... ts) {
			for (EvidenceType t : ts) if (types.contains(t)) return true;
			return false;
		}
	}

	static class Finding {
		Severity sev;
		String title;
		Function function;
		String classification;
		String detail;
		List<String> evidence = new ArrayList<>();

		String key() {
			return sev + "|" + safe(title) + "|" +
				(function == null ? "?" : function.getEntryPoint().toString()) + "|" +
				safe(classification);
		}
	}

	private final Map<String, String> decompiled = new LinkedHashMap<>();
	private final Map<String, Function> functionByKey = new HashMap<>();
	private final Map<String, FunctionProfile> profiles = new LinkedHashMap<>();
	private final Map<String, Finding> findings = new LinkedHashMap<>();
	private DecompInterface decompiler;

	private int functionsVisited;
	private int functionsDecompiled;

	@Override
	public void run() throws Exception {
		printHeader();

		decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		if (!decompiler.openProgram(currentProgram)) {
			printerr("[X] Could not initialize the decompiler.");
			return;
		}

		try {
			decompileProgram();
			buildProfiles();
			correlateProfiles();
			printReport();
		} finally {
			decompiler.dispose();
		}
	}

	private void printHeader() {
		println("========================================================================");
		println(" BEHEMOTH - UEFI CUSTOM IMAGE LOAD HUNTER");
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
			String key = f.getEntryPoint().toString();
			decompiled.put(key, dr.getDecompiledFunction().getC());
			functionByKey.put(key, f);
		}
	}

	private void buildProfiles() {
		for (Map.Entry<String, String> e : decompiled.entrySet()) {
			if (monitor.isCancelled()) break;
			Function f = functionByKey.get(e.getKey());
			FunctionProfile p = new FunctionProfile();
			p.function = f;
			profiles.put(e.getKey(), p);

			String[] lines = e.getValue().split("\\R");
			scanLoadExecutionEvidence(p, lines);
			scanImageFormatEvidence(p, lines);
			scanSecurityEvidence(p, lines);
			scanImagePathEvidence(p, lines);
		}
	}

	private void scanLoadExecutionEvidence(FunctionProfile p, String[] lines) {
		List<String> loadHandles = new ArrayList<>();

		for (int i = 0; i < lines.length; i++) {
			String shown = lines[i].trim();
			String code = stripStringLiterals(shown);

			if (isActualNamedCall(code, "LoadImage")) {
				String call = collectCallWindow(lines, i, "LoadImage", 8);
				String callCode = stripStringLiterals(call);
				if (callCode.isEmpty()) {
					call = shown;
					callCode = code;
				}

				p.add(EvidenceType.LOAD_IMAGE, oneLine(call), "UEFI LoadImage call");

				List<String> args = recoverCallArgs(callCode, "LoadImage");
				if (args.size() >= 6) {
					String bootPolicy = stripCasts(args.get(0)).trim();
					String source = stripCasts(args.get(3)).trim();
					String sourceSize = stripCasts(args.get(4)).trim();
					String outHandle = recoverAddressedVariable(args.get(5));

					if (isFalseLike(bootPolicy))
						p.add(EvidenceType.BOOT_POLICY_FALSE, oneLine(call),
							"LoadImage BootPolicy is FALSE");
					else if (isTrueLike(bootPolicy))
						p.add(EvidenceType.BOOT_POLICY_TRUE, oneLine(call),
							"LoadImage BootPolicy is TRUE");

					if (!isNullLike(source))
						p.add(EvidenceType.MEMORY_SOURCE, oneLine(call),
							"LoadImage SourceBuffer is non-null");

					if (!isZeroLike(sourceSize))
						p.add(EvidenceType.SOURCE_SIZE_NONZERO, oneLine(call),
							"LoadImage SourceSize is non-zero");

					if (outHandle != null)
						loadHandles.add(outHandle);
				}
			}

			if (isActualNamedCall(code, "StartImage")) {
				String call = collectCallWindow(lines, i, "StartImage", 6);
				if (call.isEmpty()) call = shown;
				p.add(EvidenceType.START_IMAGE, oneLine(call), "UEFI StartImage call");

				List<String> args = recoverCallArgs(stripStringLiterals(call), "StartImage");
				if (!args.isEmpty()) {
					String started = stripCasts(args.get(0)).trim();
					for (String h : loadHandles) {
						if (sameSimpleExpression(started, h)) {
							p.add(EvidenceType.LOAD_START_CHAIN, oneLine(call),
								"StartImage consumes ImageHandle returned by LoadImage: " + h);
							break;
						}
					}
				}
			}

			if (isActualNamedCall(code, "UnloadImage")) {
				String call = collectCallWindow(lines, i, "UnloadImage", 6);
				p.add(EvidenceType.UNLOAD_IMAGE,
					oneLine(call.isEmpty() ? shown : call),
					"UEFI UnloadImage call");
			}

			if (isDevicePathConstructionCall(code)) {
				String api = firstDevicePathApi(code);
				String call = collectCallWindow(lines, i, api, 8);
				p.add(EvidenceType.DEVICE_PATH_CONSTRUCTION,
					oneLine(call.isEmpty() ? shown : call),
					"Device-path construction/conversion API: " + api);
			}

			if (looksLikeIndirectCall(code))
				p.add(EvidenceType.INDIRECT_CALL, shown,
					"computed function-pointer invocation");
		}
	}

	private void scanImageFormatEvidence(FunctionProfile p, String[] lines) {
		int sectionish = 0;
		int copyOps = 0;
		boolean sawRelocLiteral = false;
		boolean sawRelocArithmetic = false;

		for (String raw : lines) {
			String shown = raw.trim();
			String s = stripStringLiterals(shown);
			String low = s.toLowerCase(Locale.ROOT);

			if (containsHex(s, "5a4d"))
				p.add(EvidenceType.PE_DOS_MAGIC, shown, "DOS MZ signature");
			if (containsHex(s, "4550"))
				p.add(EvidenceType.PE_SIGNATURE, shown, "PE signature");
			if (containsHex(s, "5a56"))
				p.add(EvidenceType.TE_SIGNATURE, shown, "TE VZ signature");
			if (containsHex(s, "10b"))
				p.add(EvidenceType.PE32_MAGIC, shown, "PE32 optional-header magic");
			if (containsHex(s, "20b"))
				p.add(EvidenceType.PE32PLUS_MAGIC, shown, "PE32+ optional-header magic");

			if (low.contains("addressofentrypoint") ||
				low.contains("entrypoint") || low.contains("entry_point"))
				p.add(EvidenceType.ENTRYPOINT_DERIVATION, shown,
					"entry-point-related expression");

			if (isActualNamedCall(s, "AllocatePages") &&
				(low.contains("efiloadercode") || low.contains("efiruntimeservicescode") ||
				low.contains("efibootservicescode")))
				p.add(EvidenceType.EXECUTABLE_ALLOCATION, shown,
					"executable EFI page allocation");

			if (Pattern.compile("(?:\\+|=)\\s*0x28\\b", Pattern.CASE_INSENSITIVE).matcher(s).find() ||
				Pattern.compile("\\b0x28\\s*\\*", Pattern.CASE_INSENSITIVE).matcher(s).find() ||
				Pattern.compile("\\+\\s*10\\s*;", Pattern.CASE_INSENSITIVE).matcher(s).find()) {
				sectionish++;
				if (sectionish == 2)
					p.add(EvidenceType.SECTION_PROCESSING, shown,
						"repeated image-section record processing");
			}

			if ((low.contains("param_1 +") || low.contains("param_1+")) &&
				Pattern.compile("\\+\\s*(?:\\(ulonglong\\))?[A-Za-z_][A-Za-z0-9_]*").matcher(s).find())
				p.add(EvidenceType.SECTION_MAPPING, shown,
					"source image offset participates in mapped-image operation");

			for (String lit : extractStringLiterals(shown))
				if (lit.equalsIgnoreCase(".reloc")) sawRelocLiteral = true;

			if ((s.contains(">> 0xc") || s.contains("& 0xfff")) &&
				(s.contains("+ (short)") || s.contains("+ (int)") ||
				s.contains("+ (longlong)") || s.contains("+ (ulonglong)") ||
				s.contains("+ (long)")))
				sawRelocArithmetic = true;

			if (sawRelocLiteral && sawRelocArithmetic)
				p.add(EvidenceType.RELOCATION_PROCESSING, shown,
					"relocation table/fixup arithmetic");

			if (Pattern.compile("\\b(?:DAT_|PTR_)[A-Za-z0-9_]*\\s*=\\s*\\([^;]*\\)\\s*\\([^;]*\\+[^;]*\\)")
					.matcher(s).find() ||
				Pattern.compile("\\b(?:DAT_|PTR_)[A-Za-z0-9_]*\\s*=.*\\+.*;").matcher(s).find()) {
				if (p.hasAny(EvidenceType.PE_SIGNATURE, EvidenceType.TE_SIGNATURE) &&
					p.has(EvidenceType.EXECUTABLE_ALLOCATION))
					p.add(EvidenceType.ENTRYPOINT_EXPORT, shown,
						"candidate mapped-image entry point exported");
			}
		}
	}

	private void scanSecurityEvidence(FunctionProfile p, String[] lines) {
		Map<String, String> addressAliases = new HashMap<>();

		Pattern aliasPattern = Pattern.compile(
			"\\b([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*" +
			"(?:\\([^;=]*?\\)\\s*)*" +
			"&\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*;");

		for (String raw : lines) {
			String code = stripStringLiterals(raw.trim());
			Matcher am = aliasPattern.matcher(code);
			if (am.find())
				addressAliases.put(am.group(1), am.group(2));
		}

		for (int i = 0; i < lines.length; i++) {
			String raw = lines[i].trim();
			String code = stripStringLiterals(raw);

			if (!containsSecurityGuidCode(code))
				continue;

			String call = collectNearbyCall(lines, i, "LocateProtocol", 4, 8);
			String callCode = stripStringLiterals(call);

			boolean inLocate = isActualNamedCall(callCode, "LocateProtocol");
			boolean sec1 = containsSecurity1GuidCode(inLocate ? callCode : code);
			boolean sec2 = containsSecurity2GuidCode(inLocate ? callCode : code);
			boolean auth = containsIdentifierCode(inLocate ? callCode : code,
												"FileAuthentication");

			if (sec1 || auth)
				p.add(EvidenceType.SECURITY_ARCH,
					oneLine(inLocate ? call : raw),
					auth ? "FileAuthentication/Security code reference"
						: "Security Architecture code reference");
			if (sec2)
				p.add(EvidenceType.SECURITY2_ARCH,
					oneLine(inLocate ? call : raw),
					"Security2 Architecture code reference");

			if (!inLocate)
				continue;

			String outVar = null;
			List<String> lpArgs = recoverCallArgs(callCode, "LocateProtocol");
			if (lpArgs.size() >= 3)
				outVar = recoverPointerOutputVariable(lpArgs.get(2));
			if (outVar == null)
				outVar = recoverLocateProtocolOutput(callCode);
			if (outVar == null)
				continue;

			String target = resolveAlias(addressAliases, outVar);

			String write = findProtocolWrite(lines, i + 1,
				Math.min(lines.length, i + 48), target);

			if (write != null)
				p.add(EvidenceType.SECURITY_STATE_WRITE, write,
					(sec2 ? "Security2" : "Security") +
					" protocol state/callback write through LocateProtocol result");
		}
	}

	private void scanImagePathEvidence(FunctionProfile p, String[] lines) {
		for (String raw : lines) {
			String s = raw.trim();
			for (String lit : extractStringLiterals(s)) {
				String cls = classifyImagePath(lit);
				if (cls != null)
					p.add(EvidenceType.IMAGE_PATH, s,
						cls + ": \"" + trim(lit, 80) + "\"");
			}
		}
	}

	private void correlateProfiles() {
		for (FunctionProfile p : profiles.values()) {
			if (monitor.isCancelled()) break;

			boolean peParser =
				p.has(EvidenceType.PE_SIGNATURE) &&
				p.hasAny(EvidenceType.PE_DOS_MAGIC, EvidenceType.PE32_MAGIC,
						EvidenceType.PE32PLUS_MAGIC);

			boolean teParser = p.has(EvidenceType.TE_SIGNATURE);

			boolean structuredParser =
				(peParser || teParser) &&
				p.hasAny(EvidenceType.SECTION_PROCESSING,
						EvidenceType.PE32_MAGIC, EvidenceType.PE32PLUS_MAGIC);

			boolean execCorrelated =
				p.has(EvidenceType.INDIRECT_CALL) &&
				(structuredParser || p.has(EvidenceType.ENTRYPOINT_DERIVATION));

			boolean standardLoad =
				p.has(EvidenceType.LOAD_IMAGE) || p.has(EvidenceType.START_IMAGE);

			boolean verificationPath =
				p.hasAny(EvidenceType.SECURITY_ARCH, EvidenceType.SECURITY2_ARCH);

			boolean verificationWrite =
				p.has(EvidenceType.SECURITY_STATE_WRITE);

			boolean semanticMapper =
				structuredParser &&
				p.has(EvidenceType.EXECUTABLE_ALLOCATION) &&
				p.hasAny(EvidenceType.SECTION_PROCESSING, EvidenceType.SECTION_MAPPING) &&
				p.has(EvidenceType.ENTRYPOINT_EXPORT);

			if (semanticMapper) {
				addProfileFinding(Severity.HIGH,
					"Resolved custom executable-image mapper", p,
					"CUSTOM_IMAGE_MAPPER_RESOLVED",
					"The function parses PE/TE metadata, allocates executable EFI pages, " +
					"maps image content, processes relocations and exports a derived entry " +
					"point. Transfer of control is evaluated separately.",
					EvidenceType.PE_DOS_MAGIC, EvidenceType.PE_SIGNATURE,
					EvidenceType.PE32_MAGIC, EvidenceType.PE32PLUS_MAGIC,
					EvidenceType.EXECUTABLE_ALLOCATION, EvidenceType.HEADER_COPY,
					EvidenceType.SECTION_PROCESSING, EvidenceType.SECTION_MAPPING,
					EvidenceType.RELOCATION_PROCESSING, EvidenceType.ENTRYPOINT_EXPORT);
			}

			if (structuredParser && execCorrelated) {
				addProfileFinding(Severity.HIGH,
					"Custom executable-image loader candidate", p,
					"CUSTOM_LOADER_CANDIDATE",
					"Image-format parsing is correlated with computed transfer of control. " +
					"Confirm allocation, relocation and entry-point provenance before promoting " +
					"this to a resolved custom loader.",
					EvidenceType.PE_DOS_MAGIC, EvidenceType.PE_SIGNATURE,
					EvidenceType.TE_SIGNATURE, EvidenceType.PE32_MAGIC,
					EvidenceType.PE32PLUS_MAGIC, EvidenceType.SECTION_PROCESSING,
					EvidenceType.ENTRYPOINT_DERIVATION, EvidenceType.INDIRECT_CALL);
			} else if (structuredParser) {
				addProfileFinding(Severity.MEDIUM,
					"Structured PE/TE parser", p,
					"IMAGE_PARSER_RESOLVED",
					"The function contains coherent PE/TE format parsing, but image execution " +
					"or entry-point transfer is not proven in this function.",
					EvidenceType.PE_DOS_MAGIC, EvidenceType.PE_SIGNATURE,
					EvidenceType.TE_SIGNATURE, EvidenceType.PE32_MAGIC,
					EvidenceType.PE32PLUS_MAGIC, EvidenceType.SECTION_PROCESSING);
			}

			if (standardLoad && verificationPath) {
				addProfileFinding(verificationWrite ? Severity.HIGH : Severity.MEDIUM,
					verificationWrite ? "Verification-control modification candidate" :
										"Image-load path intersects Security Architecture", p,
					verificationWrite ? "VERIFICATION_CONTROL_CANDIDATE" :
										"VERIFICATION_PATH_REFERENCE",
					verificationWrite
						? "Load/start-image behavior and Security/Security2 state modification " +
						"appear in the same function. Inspect callback provenance and whether " +
						"authentication behavior is restored, replaced or bypassed."
						: "Load/start-image behavior and Security/Security2 references occur in " +
						"the same function. This establishes a verification-sensitive path, " +
						"not a bypass.",
					EvidenceType.LOAD_IMAGE, EvidenceType.START_IMAGE,
					EvidenceType.SECURITY_ARCH, EvidenceType.SECURITY2_ARCH,
					EvidenceType.SECURITY_STATE_WRITE);
			} else if (verificationWrite) {
				addProfileFinding(Severity.MEDIUM,
					"Security Architecture state modification candidate", p,
					"SECURITY_STATE_WRITE_CANDIDATE",
					"A Security/Security2-related assignment was recovered. Confirm the target " +
					"field and callback semantics.",
					EvidenceType.SECURITY_ARCH, EvidenceType.SECURITY2_ARCH,
					EvidenceType.SECURITY_STATE_WRITE);
			}

			if (p.has(EvidenceType.BOOT_POLICY_FALSE) &&
				p.has(EvidenceType.MEMORY_SOURCE)) {
				addProfileFinding(Severity.HIGH,
					"Memory-backed custom LoadImage path", p,
					"MEMORY_BACKED_CUSTOM_LOAD",
					"LoadImage uses BootPolicy=FALSE with a non-null SourceBuffer. " +
					"This is a strong custom image-load path, but does not by itself " +
					"prove authentication or signature-verification bypass.",
					EvidenceType.LOAD_IMAGE, EvidenceType.BOOT_POLICY_FALSE,
					EvidenceType.MEMORY_SOURCE, EvidenceType.SOURCE_SIZE_NONZERO);
			} else if (p.has(EvidenceType.BOOT_POLICY_FALSE)) {
				addProfileFinding(Severity.MEDIUM,
					"Custom LoadImage policy", p,
					"CUSTOM_LOAD_PATH",
					"LoadImage is invoked with BootPolicy=FALSE. The caller controls " +
					"the load policy; this is not by itself a hand-rolled loader or " +
					"verification bypass.",
					EvidenceType.LOAD_IMAGE, EvidenceType.BOOT_POLICY_FALSE);
			} else if (p.has(EvidenceType.MEMORY_SOURCE)) {
				addProfileFinding(Severity.MEDIUM,
					"Memory-backed LoadImage path", p,
					"MEMORY_BACKED_LOAD",
					"LoadImage receives a non-null SourceBuffer. This is a custom image " +
					"source, but does not by itself establish verification bypass.",
					EvidenceType.LOAD_IMAGE, EvidenceType.BOOT_POLICY_TRUE,
					EvidenceType.MEMORY_SOURCE, EvidenceType.SOURCE_SIZE_NONZERO);
			}

			if (p.has(EvidenceType.IMAGE_PATH) && standardLoad) {
				addProfileFinding(Severity.REVIEW,
					"Embedded EFI target in image-load path", p,
					"IMAGE_TARGET_REFERENCE",
					"An embedded EFI image reference occurs in the same function as LoadImage " +
					"or StartImage.",
					EvidenceType.IMAGE_PATH, EvidenceType.LOAD_IMAGE,
					EvidenceType.START_IMAGE);
			}
		}

		correlateDirectCallers();
	}

	private static final int CROSS_FUNCTION_DEPTH = 3;

	private void correlateDirectCallers() {
		Map<String, Set<String>> graph = buildDirectCallGraph();

		for (FunctionProfile mapper : profiles.values()) {
			boolean mapperNode =
				mapper.hasAny(EvidenceType.PE_SIGNATURE, EvidenceType.TE_SIGNATURE) &&
				mapper.has(EvidenceType.EXECUTABLE_ALLOCATION) &&
				mapper.hasAny(EvidenceType.SECTION_PROCESSING, EvidenceType.SECTION_MAPPING) &&
				mapper.has(EvidenceType.ENTRYPOINT_EXPORT);
			if (!mapperNode) continue;

			String storage = recoverExportedEntryStorage(mapper);
			if (storage == null) continue;

			List<FunctionProfile> consumers = new ArrayList<>();
			List<String> executionLines = new ArrayList<>();

			for (FunctionProfile consumer : profiles.values()) {
				String code = decompiled.get(consumer.function.getEntryPoint().toString());
				if (code == null) continue;

				Pattern invoke = Pattern.compile(
					"\\(\\*\\s*" + Pattern.quote(storage) + "\\s*\\)\\s*\\(");
				if (!invoke.matcher(stripStringLiterals(code)).find()) continue;

				consumers.add(consumer);
				executionLines.add(firstMatchingInvocation(code, storage));
			}

			if (!consumers.isEmpty()) {
				Finding fd = new Finding();
				fd.sev = Severity.CRITICAL;
				fd.title = "Resolved custom executable-image loader";
				fd.function = mapper.function;
				fd.classification = "CUSTOM_LOADER_RESOLVED";
				fd.detail = "Resolved evidence graph: structured PE/TE parsing -> executable " +
							"destination -> image mapping -> derived/exported entry point -> " +
							"transfer of control. Relocation processing, when present, is " +
							"reported as supporting evidence rather than a mandatory condition.";
				fd.evidence.add("Mapper       " + displayFunction(mapper.function));
				fd.evidence.add("Format       " +
					(mapper.has(EvidenceType.TE_SIGNATURE) ? "PE/TE" : "PE"));
				fd.evidence.add("Allocation   " +
					firstEvidenceLine(mapper, EvidenceType.EXECUTABLE_ALLOCATION));
				fd.evidence.add("Mapping      " +
					firstEvidenceLine(mapper, EvidenceType.SECTION_MAPPING,
									EvidenceType.SECTION_PROCESSING));
				if (mapper.has(EvidenceType.RELOCATION_PROCESSING))
					fd.evidence.add("Relocations " +
						firstEvidenceLine(mapper, EvidenceType.RELOCATION_PROCESSING));
				fd.evidence.add("EntryPoint   " + storage);
				for (int i = 0; i < consumers.size(); i++) {
					fd.evidence.add("Consumer     " +
						displayFunction(consumers.get(i).function));
					fd.evidence.add("Execution    " + executionLines.get(i));
				}
				findings.putIfAbsent(fd.key(), fd);
			}
		}

		for (FunctionProfile src : profiles.values()) {
			if (monitor.isCancelled()) break;

			boolean srcParser =
				src.has(EvidenceType.PE_SIGNATURE) || src.has(EvidenceType.TE_SIGNATURE);
			if (!srcParser) continue;

			for (FunctionProfile dst : profiles.values()) {
				if (src == dst) continue;
				int depth = graphDistance(graph, src.function, dst.function,
										CROSS_FUNCTION_DEPTH);
				if (depth < 1) {
					depth = graphDistance(graph, dst.function, src.function,
										CROSS_FUNCTION_DEPTH);
				}
				if (depth < 1) continue;

				boolean dstExec =
					dst.has(EvidenceType.INDIRECT_CALL) ||
					dst.has(EvidenceType.START_IMAGE);
				if (!dstExec) continue;

				String resolvedStorage = recoverExportedEntryStorage(src);
				if (resolvedStorage != null) {
					String dstCode = decompiled.get(dst.function.getEntryPoint().toString());
					if (dstCode != null &&
						Pattern.compile("\\(\\*\\s*" + Pattern.quote(resolvedStorage) +
										"\\s*\\)\\s*\\(")
							.matcher(stripStringLiterals(dstCode)).find())
						continue;
				}

				Finding fd = new Finding();
				fd.sev = Severity.REVIEW;
				fd.title = "Cross-function custom-loader chain candidate";
				fd.function = dst.function;
				fd.classification = "CROSS_FUNCTION_LOADER_CHAIN";
				fd.detail = "Image-format parsing and an execution primitive are connected " +
							"within the bounded direct call graph (depth " + depth + "). " +
							"Validate data-flow before treating this as a custom loader.";
				fd.evidence.add("Parser      " + displayFunction(src.function));
				fd.evidence.add("Execution   " + firstEvidenceLine(dst,
					EvidenceType.START_IMAGE, EvidenceType.INDIRECT_CALL));
				fd.evidence.add("Call depth  " + depth);
				findings.putIfAbsent(fd.key(), fd);
			}
		}

		for (FunctionProfile sec : profiles.values()) {
			if (!sec.hasAny(EvidenceType.SECURITY_ARCH, EvidenceType.SECURITY2_ARCH))
				continue;

			for (FunctionProfile load : profiles.values()) {
				if (sec == load) continue;
				if (!load.hasAny(EvidenceType.LOAD_IMAGE, EvidenceType.START_IMAGE))
					continue;

				int depth = graphDistanceEitherWay(graph, sec.function, load.function,
												CROSS_FUNCTION_DEPTH);
				if (depth < 1) continue;

				Finding fd = new Finding();
				fd.sev = Severity.REVIEW;
				fd.title = "Cross-function verification/load relationship";
				fd.function = sec.function;
				fd.classification = "CROSS_FUNCTION_VERIFICATION_PATH";
				fd.detail = "Security/Security2 handling and image loading are connected " +
							"within the bounded direct call graph. This is structural " +
							"correlation only; authentication data-flow is not proven.";
				fd.evidence.add("Verification " + displayFunction(sec.function));
				fd.evidence.add("Load path    " + displayFunction(load.function));
				fd.evidence.add("Call depth   " + depth);
				findings.putIfAbsent(fd.key(), fd);
			}
		}

		for (FunctionProfile target : profiles.values()) {
			if (!target.has(EvidenceType.IMAGE_PATH)) continue;

			for (FunctionProfile load : profiles.values()) {
				if (target == load) continue;
				if (!load.hasAny(EvidenceType.LOAD_IMAGE, EvidenceType.START_IMAGE))
					continue;

				int depth = graphDistanceEitherWay(graph, target.function, load.function,
												CROSS_FUNCTION_DEPTH);
				if (depth < 1) continue;

				Finding fd = new Finding();
				fd.sev = Severity.REVIEW;
				fd.title = "Cross-function EFI target/load relationship";
				fd.function = target.function;
				fd.classification = "CROSS_FUNCTION_IMAGE_TARGET";
				fd.detail = "An embedded EFI target and image-loading behavior are connected " +
							"within the bounded direct call graph. DevicePath/data provenance " +
							"must be confirmed before associating the target with that load.";
				fd.evidence.add("Image path   " +
					firstEvidenceLine(target, EvidenceType.IMAGE_PATH));
				fd.evidence.add("Load path    " + displayFunction(load.function));
				fd.evidence.add("Call depth   " + depth);
				findings.putIfAbsent(fd.key(), fd);
			}
		}
	}

	private String recoverExportedEntryStorage(FunctionProfile p) {
		for (Evidence e : p.evidence) {
			if (e.type != EvidenceType.ENTRYPOINT_EXPORT) continue;
			Matcher m = Pattern.compile("\\b((?:DAT_|PTR_)[A-Za-z0-9_]*)\\s*=")
							.matcher(stripStringLiterals(e.line));
			if (m.find()) return m.group(1);
		}
		return null;
	}

	private String firstMatchingInvocation(String code, String storage) {
		for (String raw : code.split("\\R")) {
			String x = stripStringLiterals(raw.trim());
			if (Pattern.compile("\\(\\*\\s*" + Pattern.quote(storage) + "\\s*\\)\\s*\\(")
					.matcher(x).find())
				return oneLine(raw.trim());
		}
		return "?";
	}

	private Map<String, Set<String>> buildDirectCallGraph() {
		Map<String, Set<String>> graph = new LinkedHashMap<>();
		Map<String, String> nameToKey = new HashMap<>();

		for (FunctionProfile p : profiles.values()) {
			String key = p.function.getEntryPoint().toString();
			graph.put(key, new LinkedHashSet<String>());
			String name = p.function.getName();
			if (name != null && !name.isEmpty())
				nameToKey.put(name, key);
		}

		for (FunctionProfile p : profiles.values()) {
			String from = p.function.getEntryPoint().toString();
			String code = decompiled.get(from);
			if (code == null) continue;

			String noStrings = stripStringLiterals(code);
			for (Map.Entry<String, String> e : nameToKey.entrySet()) {
				String name = e.getKey();
				String to = e.getValue();
				if (from.equals(to)) continue;

				Pattern call = Pattern.compile(
					"\\b" + Pattern.quote(name) + "\\s*\\(");
				if (call.matcher(noStrings).find())
					graph.get(from).add(to);
			}
		}
		return graph;
	}

	private int graphDistanceEitherWay(Map<String, Set<String>> graph,
									Function a, Function b, int maxDepth) {
		int d = graphDistance(graph, a, b, maxDepth);
		if (d >= 1) return d;
		return graphDistance(graph, b, a, maxDepth);
	}

	private int graphDistance(Map<String, Set<String>> graph,
							Function from, Function to, int maxDepth) {
		if (from == null || to == null) return -1;
		String src = from.getEntryPoint().toString();
		String dst = to.getEntryPoint().toString();
		if (src.equals(dst)) return 0;

		Set<String> seen = new HashSet<>();
		LinkedHashSet<String> frontier = new LinkedHashSet<>();
		frontier.add(src);
		seen.add(src);

		for (int depth = 1; depth <= maxDepth; depth++) {
			LinkedHashSet<String> next = new LinkedHashSet<>();
			for (String cur : frontier) {
				Set<String> edges = graph.get(cur);
				if (edges == null) continue;
				for (String n : edges) {
					if (n.equals(dst)) return depth;
					if (seen.add(n)) next.add(n);
				}
			}
			if (next.isEmpty()) break;
			frontier = next;
		}
		return -1;
	}

	private void addProfileFinding(Severity sev, String title, FunctionProfile p,
								String classification, String detail,
								EvidenceType... wanted) {
		Finding fd = new Finding();
		fd.sev = sev;
		fd.title = title;
		fd.function = p.function;
		fd.classification = classification;
		fd.detail = detail;

		Set<EvidenceType> emitted = EnumSet.noneOf(EvidenceType.class);
		for (Evidence e : p.evidence) {
			boolean want = false;
			for (EvidenceType t : wanted) if (e.type == t) { want = true; break; }
			if (!want || emitted.contains(e.type)) continue;
			emitted.add(e.type);
			fd.evidence.add(String.format("%-18s %s",
				evidenceLabel(e.type), oneLine(e.line)));
		}
		findings.putIfAbsent(fd.key(), fd);
	}

	private String firstEvidenceLine(FunctionProfile p, EvidenceType... types) {
		for (Evidence e : p.evidence)
			for (EvidenceType t : types)
				if (e.type == t) return oneLine(e.line);
		return "?";
	}

	private static String evidenceLabel(EvidenceType t) {
		switch (t) {
			case LOAD_IMAGE: return "LoadImage";
			case START_IMAGE: return "StartImage";
			case UNLOAD_IMAGE: return "UnloadImage";
			case LOAD_START_CHAIN: return "Load->Start";
			case DEVICE_PATH_CONSTRUCTION: return "DevicePath";
			case BOOT_POLICY_TRUE: return "BootPolicy TRUE";
			case BOOT_POLICY_FALSE: return "BootPolicy FALSE";
			case MEMORY_SOURCE: return "SourceBuffer";
			case SOURCE_SIZE_NONZERO: return "SourceSize";
			case PE_DOS_MAGIC: return "MZ";
			case PE_SIGNATURE: return "PE";
			case TE_SIGNATURE: return "TE";
			case PE32_MAGIC: return "PE32";
			case PE32PLUS_MAGIC: return "PE32+";
			case SECTION_PROCESSING: return "Sections";
			case ENTRYPOINT_DERIVATION: return "EntryPoint";
			case EXECUTABLE_ALLOCATION: return "Exec allocation";
			case HEADER_COPY: return "Header copy";
			case SECTION_MAPPING: return "Section mapping";
			case RELOCATION_PROCESSING: return "Relocations";
			case ENTRYPOINT_EXPORT: return "EntryPoint export";
			case ENTRYPOINT_EXECUTION: return "EntryPoint exec";
			case INDIRECT_CALL: return "Indirect call";
			case SECURITY_ARCH: return "Security";
			case SECURITY2_ARCH: return "Security2";
			case SECURITY_STATE_WRITE: return "Security write";
			case IMAGE_PATH: return "Image path";
			default: return t.name();
		}
	}

	private static boolean containsHex(String s, String hex) {
		return Pattern.compile("\\b0x0*" + Pattern.quote(hex) + "\\b",
			Pattern.CASE_INSENSITIVE).matcher(s).find();
	}

	private List<String> recoverCallArgs(String s, String name) {
		if (s == null) return Collections.emptyList();

		Matcher m = Pattern.compile("\\b" + Pattern.quote(name) + "\\b",
			Pattern.CASE_INSENSITIVE).matcher(s);
		if (!m.find()) return Collections.emptyList();

		int pos = m.end();
		while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;

		if (pos < s.length() && s.charAt(pos) == '(') {
			int close = findMatchingParen(s, pos);
			if (close < 0) return Collections.emptyList();
			return splitArgs(s.substring(pos + 1, close));
		}

		while (pos < s.length()) {
			char c = s.charAt(pos);
			if (Character.isWhitespace(c) || c == ')') {
				pos++;
				continue;
			}
			break;
		}

		if (pos >= s.length() || s.charAt(pos) != '(')
			return Collections.emptyList();

		int close = findMatchingParen(s, pos);
		if (close < 0) return Collections.emptyList();
		return splitArgs(s.substring(pos + 1, close));
	}

	private boolean looksLikeIndirectCall(String s) {
		Matcher deref = Pattern.compile("\\(\\*\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\)\\s*\\(").matcher(s);
		if (deref.find()) {
			String callee = deref.group(1);
			if (!callee.equals("gBS") && !callee.equals("gRT") && !callee.equals("gST"))
				return true;
		}
		return Pattern.compile("\\(\\*\\s*(?:DAT_|PTR_|local_|param_)[A-Za-z0-9_]*\\s*\\)\\s*\\(")
					.matcher(s).find();
	}

	private String classifyImagePath(String lit) {
		String x = lit.toLowerCase(Locale.ROOT);
		if (x.matches(".*\\\\efi\\\\boot\\\\.*") || x.contains("/efi/boot/"))
			return "ESP default boot path";
		if (x.matches(".*\\b(bootx64|bootia32|bootaa64|bootarm)\\.efi\\b"))
			return "removable-media boot loader";
		if (x.matches(".*\\b(grubx64|shimx64|mmx64|fbx64|grub)\\b.*"))
			return "known third-party boot loader";
		if (x.matches(".*\\.efi\\b"))
			return "*.efi image reference";
		return null;
	}

	private void printInventory() {
		List<FunctionProfile> loads = profilesWith(EvidenceType.LOAD_IMAGE);
		List<FunctionProfile> starts = profilesWith(EvidenceType.START_IMAGE);
		List<FunctionProfile> unloads = profilesWith(EvidenceType.UNLOAD_IMAGE);
		List<FunctionProfile> loadStart = profilesWith(EvidenceType.LOAD_START_CHAIN);
		List<FunctionProfile> devPaths = profilesWith(EvidenceType.DEVICE_PATH_CONSTRUCTION);
		List<FunctionProfile> pe = new ArrayList<>();
		List<FunctionProfile> te = profilesWith(EvidenceType.TE_SIGNATURE);
		List<FunctionProfile> sec = profilesWith(EvidenceType.SECURITY_ARCH);
		List<FunctionProfile> sec2 = profilesWith(EvidenceType.SECURITY2_ARCH);
		List<FunctionProfile> secWrites = profilesWith(EvidenceType.SECURITY_STATE_WRITE);

		int bootTrue = 0, bootFalse = 0, memoryLoad = 0, memoryCustom = 0, indirect = 0;

		class TargetInfo {
			LinkedHashSet<String> paths = new LinkedHashSet<>();
			LinkedHashSet<String> functions = new LinkedHashSet<>();
		}
		Map<String, TargetInfo> targets = new LinkedHashMap<>();

		for (FunctionProfile p : profiles.values()) {
			if (p.has(EvidenceType.BOOT_POLICY_TRUE)) bootTrue++;
			if (p.has(EvidenceType.BOOT_POLICY_FALSE)) bootFalse++;
			if (p.has(EvidenceType.MEMORY_SOURCE)) memoryLoad++;
			if (p.has(EvidenceType.BOOT_POLICY_FALSE) && p.has(EvidenceType.MEMORY_SOURCE))
				memoryCustom++;
			if (p.has(EvidenceType.INDIRECT_CALL)) indirect++;

			if (p.has(EvidenceType.PE_SIGNATURE) &&
				p.hasAny(EvidenceType.PE_DOS_MAGIC, EvidenceType.PE32_MAGIC,
						EvidenceType.PE32PLUS_MAGIC))
				pe.add(p);

			for (Evidence e : p.evidence) {
				if (e.type != EvidenceType.IMAGE_PATH) continue;
				for (String lit : extractStringLiterals(e.line)) {
					if (classifyImagePath(lit) == null) continue;
					String base = imageBaseName(lit);
					String key = base.toLowerCase(Locale.ROOT);
					TargetInfo ti = targets.get(key);
					if (ti == null) {
						ti = new TargetInfo();
						targets.put(key, ti);
					}
					ti.paths.add(lit);
					ti.functions.add(canonicalFunctionDisplay(p.function));
				}
			}
		}

		println("");
		println("========================================================================");
		println(" IMAGE LOAD SURFACE");
		println("========================================================================");

		println("");
		println(" Execution");
		println("   LoadImage functions ......... " + loads.size());
		printFunctionDetails(loads, EvidenceType.LOAD_IMAGE, true);
		println("   BootPolicy TRUE ............. " + bootTrue);
		println("   BootPolicy FALSE ............ " + bootFalse);
		println("");

		println("   StartImage functions ........ " + starts.size());
		printFunctionDetails(starts, EvidenceType.START_IMAGE, false);
		println("   UnloadImage functions ....... " + unloads.size());
		printFunctionDetails(unloads, EvidenceType.UNLOAD_IMAGE, false);
		println("   Load->Start resolved ........ " + loadStart.size());
		printFunctionDetails(loadStart, EvidenceType.LOAD_START_CHAIN, false);
		println("   Memory-backed LoadImage ..... " + memoryLoad);
		println("   Memory + BootPolicy FALSE ... " + memoryCustom);
		println("   Indirect-call functions ..... " + indirect);

		println("");
		println(" Image path");
		println("   DevicePath functions ........ " + devPaths.size());
		printFunctionNames(devPaths);

		println("");
		println(" Image format");
		println("   PE parser functions ......... " + pe.size());
		printFunctionNames(pe);
		println("   TE parser functions ......... " + te.size());
		printFunctionNames(te);

		println("");
		println(" Verification");
		println("   Security references ......... " + sec.size());
		printFunctionNames(sec);
		println("   Security2 references ........ " + sec2.size());
		printFunctionNames(sec2);
		println("   Protocol-pointer writes ..... " + secWrites.size());
		printFunctionNames(secWrites);

		println("");
		println(" Targets");
		println("   Unique EFI images ........... " + targets.size());

		if (!targets.isEmpty()) {
			println("");
			println(" IMAGE TARGETS");
			println("------------------------------------------------------------------------");
			int n = 0;
			for (Map.Entry<String, TargetInfo> e : targets.entrySet()) {
				TargetInfo ti = e.getValue();
				String base = imageBaseName(ti.paths.iterator().next());

				println("");
				println(String.format(" [%02d] %s", ++n, trim(base, 110)));

				boolean hasFullPath = false;
				for (String path : ti.paths) {
					if (!path.equalsIgnoreCase(base)) {
						if (!hasFullPath) {
							println("      Paths");
							hasFullPath = true;
						}
						println("         " + trim(path, 110));
					}
				}

				println("      References   " + ti.functions.size() + " function(s)");
				for (String fn : ti.functions)
					println("      Function     " + fn);
			}
		}

		if (!loadStart.isEmpty()) {
			println("");
			println(" RESOLVED CHAINS");
			println("------------------------------------------------------------------------");
			int n = 0;
			for (FunctionProfile fp : loadStart) {
				println("");
				println(String.format(" [%02d] LOAD_START_CHAIN_RESOLVED", ++n));
				println("      Function     " + canonicalFunctionDisplay(fp.function));
				Evidence ev = firstEvidence(fp, EvidenceType.LOAD_START_CHAIN);
				if (ev != null) println("      Provenance   " + trim(ev.note, 100));
			}
		}
	}

	private List<FunctionProfile> profilesWith(EvidenceType type) {
		List<FunctionProfile> out = new ArrayList<>();
		for (FunctionProfile p : profiles.values())
			if (p.has(type)) out.add(p);
		return out;
	}

	private static Evidence firstEvidence(FunctionProfile p, EvidenceType type) {
		for (Evidence e : p.evidence)
			if (e.type == type) return e;
		return null;
	}

	private void printFunctionNames(List<FunctionProfile> list) {
		for (FunctionProfile p : list)
			println("      -> " + canonicalFunctionDisplay(p.function));
	}

	private void printFunctionDetails(List<FunctionProfile> list,
									EvidenceType primary, boolean loadDetails) {
		int n = 0;
		for (FunctionProfile p : list) {
			println(String.format("      [%02d] %s", ++n,
				canonicalFunctionDisplay(p.function)));

			if (loadDetails) {
				Evidence li = firstEvidence(p, EvidenceType.LOAD_IMAGE);
				if (li != null) {
					List<String> args = recoverCallArgs(
						stripStringLiterals(li.line), "LoadImage");
					if (args.size() >= 6) {
						String bp = stripCasts(args.get(0)).trim();
						String dp = args.get(2).trim();
						String sb = stripCasts(args.get(3)).trim();
						String ss = stripCasts(args.get(4)).trim();
						println("           BootPolicy     " +
							(isFalseLike(bp) ? "FALSE" :
							isTrueLike(bp) ? "TRUE" : trim(bp, 60)));
						println("           DevicePath     " + trim(dp, 70));
						println("           SourceBuffer   " +
							(isNullLike(sb) ? "NULL" : trim(sb, 70)));
						println("           SourceSize     " +
							(isZeroLike(ss) ? "0" : trim(ss, 70)));
					}
					println("           Call           " + trim(li.line, 100));
				}
			} else {
				Evidence ev = firstEvidence(p, primary);
				if (ev != null)
					println("           Call           " + trim(ev.line, 100));
			}
		}
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
		ordered.sort(Comparator.comparingInt(a -> a.sev.ordinal()));

		int crit = 0, high = 0, med = 0, review = 0;
		for (Finding f : ordered) {
			switch (f.sev) {
				case CRITICAL: crit++; break;
				case HIGH: high++; break;
				case MEDIUM: med++; break;
				case REVIEW: review++; break;
			}
		}

		printInventory();

		if (ordered.isEmpty()) {
			println("");
			println(" No correlated custom image-load findings were produced.");
		} else {
			Severity current = null;
			for (Finding f : ordered) {
				if (f.sev != current) {
					current = f.sev;
					println("");
					println(" " + current + " FINDINGS");
					println("------------------------------------------------------------------------");
				}
				println("");
				println(" [" + f.sev + "] " + f.title);
				println("   Function       " + displayFunction(f.function));
				println("   Classification " + safe(f.classification));
				println("   Detail         " + safe(f.detail));
				if (!f.evidence.isEmpty()) {
					println("   Evidence");
					for (String ev : f.evidence)
						println("      " + ev);
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
		println("   Profiles ........... " + profiles.size());
		println("");
		println(" Findings");
		println("   Total .............. " + ordered.size());
		println("   CRITICAL ........... " + crit);
		println("   HIGH ............... " + high);
		println("   MEDIUM ............. " + med);
		println("   REVIEW ............. " + review);
		println("");

		String verdict;
		boolean resolvedCustomLoader = false;
		for (Finding f : ordered) {
			if ("CUSTOM_LOADER_RESOLVED".equals(f.classification)) {
				resolvedCustomLoader = true;
				break;
			}
		}

		if (resolvedCustomLoader)
			verdict = "RESOLVED - custom executable-image loader detected";
		else if (crit > 0)
			verdict = "REVIEW - critical image-load / verification evidence requires manual confirmation";
		else if (high > 0)
			verdict = "REVIEW - strong correlated custom image-load candidates found";
		else if (med > 0)
			verdict = "REVIEW - structured image-load / verification evidence found";
		else if (review > 0)
			verdict = "REVIEW - image-loading relationships require validation";
		else
			verdict = "PASS - no correlated custom image-load indicators detected";

		println(" VERDICT");
		println("   " + verdict);
		println("");
		println(" Validation");
		println("   Inventory is descriptive; findings require correlated behavioral evidence.");
		println("   Diagnostic strings never count as API/GUID/section behavioral evidence.");
		println("   Confirm data-flow, callback provenance, reachability and transfer of control.");

		java.util.List<String> fj = new java.util.ArrayList<>();
		for (Finding f : ordered) {
			String sev = f.sev == Severity.REVIEW ? "review" : f.sev.toString().toLowerCase(Locale.ROOT);
			String desc = safe(f.classification) + " - " + safe(f.detail);
			String loc = f.function == null ? null : displayFunction(f.function);
			fj.add(finding(sev, f.title, desc, loc));
		}
		String sum = String.format("{\"critical\": %d, \"high\": %d, \"medium\": %d, \"review\": %d, \"total\": %d}",
			crit, high, med, review, ordered.size());
		writeJsonReport(".behemoth-imageload.json", "behemoth-imageload", sum, fj);
	}

	private static String stripStringLiterals(String s) {
		if (s == null || s.isEmpty()) return "";

		StringBuilder out = new StringBuilder(s.length());

		int i = 0;
		while (i < s.length()) {

			boolean wide =
				s.charAt(i) == 'L' &&
				i + 1 < s.length() &&
				s.charAt(i + 1) == '"';

			if (s.charAt(i) == '"' || wide) {

				if (wide) {
					i++;
				}

				i++;

				boolean escaped = false;

				while (i < s.length()) {
					char c = s.charAt(i++);

					if (escaped) {
						escaped = false;
						continue;
					}

					if (c == '\\') {
						escaped = true;
						continue;
					}

					if (c == '"') {
						break;
					}
				}

				out.append("\"\"");
				continue;
			}

			out.append(s.charAt(i));
			i++;
		}

		return out.toString();
	}

	private static boolean isActualNamedCall(String code, String name) {
		if (code == null) return false;
		return Pattern.compile("(?:->|\\.)?\\b" + Pattern.quote(name) +
				"\\s*\\)?\\s*\\(",
				Pattern.CASE_INSENSITIVE).matcher(code).find();
	}

	private static boolean containsIdentifierCode(String code, String name) {
		if (code == null) return false;
		return Pattern.compile("\\b" + Pattern.quote(name) + "\\b",
				Pattern.CASE_INSENSITIVE).matcher(code).find();
	}

	private static boolean containsSecurity1GuidCode(String code) {
		if (code == null) return false;
		String x = code.toLowerCase(Locale.ROOT);
		return x.contains("gefisecurityarchprotocolguid") ||
			x.contains("efi_security_arch_protocol") ||
			(x.contains("securityarchprotocol") && !x.contains("security2archprotocol"));
	}

	private static boolean containsSecurity2GuidCode(String code) {
		if (code == null) return false;
		String x = code.toLowerCase(Locale.ROOT);
		return x.contains("gefisecurity2archprotocolguid") ||
			x.contains("efi_security2_arch_protocol") ||
			x.contains("security2archprotocol");
	}

	private static boolean containsSecurityGuidCode(String code) {
		return containsSecurity1GuidCode(code) || containsSecurity2GuidCode(code) ||
			containsIdentifierCode(code, "FileAuthentication");
	}

	private static String collectCallWindow(String[] lines, int around, String callName, int radius) {
		int start = Math.max(0, around - 2);
		int end = Math.min(lines.length, around + radius);
		StringBuilder sb = new StringBuilder();
		boolean seen = false;
		int depth = 0;

		for (int i = start; i < end; i++) {
			String code = stripStringLiterals(lines[i].trim());
			if (!seen) {
				if (!isActualNamedCall(code, callName)) continue;
				seen = true;
			}

			if (sb.length() > 0) sb.append(' ');
			sb.append(lines[i].trim());

			String noStrings = stripStringLiterals(lines[i]);
			for (int j = 0; j < noStrings.length(); j++) {
				char c = noStrings.charAt(j);
				if (c == '(') depth++;
				else if (c == ')') depth--;
			}
			if (seen && depth <= 0 && noStrings.contains(";")) break;
		}
		return sb.toString();
	}

	private static String collectNearbyCall(String[] lines, int around,
													String callName,
													int backward, int forward) {
		int start = Math.max(0, around - backward);
		int end = Math.min(lines.length - 1, around + forward);

		for (int i = start; i <= around; i++) {
			String code = stripStringLiterals(lines[i].trim());
			if (!isActualNamedCall(code, callName))
				continue;

			String call = collectCallWindow(lines, i, callName,
				Math.max(4, end - i + 1));
			if (!call.isEmpty())
				return call;
		}

		for (int i = around + 1; i <= end; i++) {
			String code = stripStringLiterals(lines[i].trim());
			if (!isActualNamedCall(code, callName))
				continue;
			String call = collectCallWindow(lines, i, callName,
				Math.max(4, end - i + 1));
			if (!call.isEmpty())
				return call;
		}
		return "";
	}

	private static String resolveAlias(Map<String, String> aliases, String var) {
		String cur = var;
		Set<String> seen = new HashSet<>();
		for (int i = 0; i < 8 && cur != null && seen.add(cur); i++) {
			String next = aliases.get(cur);
			if (next == null) break;
			cur = next;
		}
		return cur;
	}

	private static String findProtocolWrite(String[] lines, int start, int end,
											String var) {
		if (var == null || var.isEmpty()) return null;

		Pattern bare = Pattern.compile(
			"^\\s*\\*\\s*" + Pattern.quote(var) +
			"\\s*=\\s*(?!=).+;\\s*$");

		Pattern arrow = Pattern.compile(
			"\\b" + Pattern.quote(var) +
			"\\s*->\\s*[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*(?!=).+;");

		Pattern derefField = Pattern.compile(
			"\\(\\s*\\*\\s*" + Pattern.quote(var) +
			"\\s*\\)\\s*\\.\\s*[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*(?!=).+;");

		for (int i = start; i < end; i++) {
			String raw = lines[i].trim();
			String code = stripStringLiterals(raw);
			if (bare.matcher(code).find() ||
				arrow.matcher(code).find() ||
				derefField.matcher(code).find())
				return raw;
		}
		return null;
	}

	private static String recoverPointerOutputVariable(String expr) {
		if (expr == null) return null;
		String x = expr.trim();

		Matcher direct = Pattern.compile(
			"(?:\\([^)]*\\)\\s*)*&\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*$")
			.matcher(x);
		if (direct.find()) return direct.group(1);

		String y = stripCasts(x).trim();
		Matcher plain = Pattern.compile("^([A-Za-z_][A-Za-z0-9_]*)$").matcher(y);
		return plain.find() ? plain.group(1) : null;
	}

	private static String recoverLocateProtocolOutput(String callCode) {
		if (callCode == null || callCode.isEmpty()) return null;

		Matcher direct = Pattern.compile(
			"\\(void\\s*\\*\\*\\)\\s*&\\s*([A-Za-z_][A-Za-z0-9_]*)",
			Pattern.CASE_INSENSITIVE).matcher(callCode);
		if (direct.find()) return direct.group(1);

		Matcher casted = Pattern.compile(
			"\\(void\\s*\\*\\*\\)\\s*([A-Za-z_][A-Za-z0-9_]*)",
			Pattern.CASE_INSENSITIVE).matcher(callCode);
		String last = null;
		while (casted.find()) last = casted.group(1);
		return last;
	}

	private static String findDereferenceWrite(String[] lines, int start, int end, String var) {
		if (var == null || var.isEmpty()) return null;
		Pattern p = Pattern.compile(
			"^\\s*\\*\\s*" + Pattern.quote(var) +
			"\\s*=\\s*(?!=).+;\\s*$");
		for (int i = start; i < end; i++) {
			String raw = lines[i].trim();
			String code = stripStringLiterals(raw);
			if (p.matcher(code).find()) return raw;
		}
		return null;
	}

	private static String recoverAddressedVariable(String expr) {
		if (expr == null) return null;
		String x = expr.trim();
		Matcher m = Pattern.compile(
			"(?:\\([^)]*\\)\\s*)*&\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*$")
			.matcher(x);
		if (m.find()) return m.group(1);
		return null;
	}

	private static boolean sameSimpleExpression(String a, String b) {
		if (a == null || b == null) return false;
		String x = stripCasts(a).replaceAll("\\s+", "");
		String y = stripCasts(b).replaceAll("\\s+", "");
		return x.equals(y);
	}

	private static final String[] DEVICE_PATH_APIS = {
		"FileDevicePath",
		"DevicePathFromHandle",
		"ConvertTextToDevicePath",
		"AppendDevicePath",
		"AppendDevicePathNode"
	};

	private static boolean isDevicePathConstructionCall(String code) {
		return firstDevicePathApi(code) != null;
	}

	private static String firstDevicePathApi(String code) {
		if (code == null) return null;
		for (String api : DEVICE_PATH_APIS)
			if (isActualNamedCall(code, api)) return api;
		return null;
	}

	private static boolean isFalseLike(String s) {
		if (s == null) return false;
		String x = stripCasts(s).replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
		return x.equals("0") || x.equals("0x0") || x.equals("false") ||
			x.equals("'\\0'") || x.equals("'\\x00'") ||
			x.equals("(boolean)0") || x.equals("(bool)0");
	}

	private static boolean isTrueLike(String s) {
		if (s == null) return false;
		String x = stripCasts(s).replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
		return x.equals("1") || x.equals("0x1") || x.equals("true") ||
			x.equals("'\\1'") || x.equals("'\\x01'");
	}

	private static boolean isZeroLike(String s) {
		return isNullLike(s);
	}

	private static boolean isNullLike(String s) {
		if (s == null) return true;
		String x = stripCasts(s).replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
		return x.equals("0") || x.equals("0x0") || x.equals("null") ||
			x.equals("(void*)0") || x.matches("\\([^)]*\\*\\)0x?0?");
	}

	private static boolean topLevelAssign(String s) {
		int par = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '(') par++;
			else if (c == ')') par--;
			else if (c == '=' && par == 0) {
				char prev = i > 0 ? s.charAt(i - 1) : '\0';
				char next = i + 1 < s.length() ? s.charAt(i + 1) : '\0';
				if (prev != '=' && prev != '!' && prev != '<' && prev != '>' && next != '=')
					return true;
			}
		}
		return false;
	}

	private static List<String> extractStringLiterals(String s) {
		List<String> out = new ArrayList<>();
		Matcher m = Pattern.compile("L?\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(s);
		while (m.find()) out.add(m.group(1));
		return out;
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

	private static String imageBaseName(String path) {
		if (path == null || path.isEmpty()) return "?";
		String x = path.replace('/', '\\');
		int i = x.lastIndexOf('\\');
		return i >= 0 && i + 1 < x.length() ? x.substring(i + 1) : x;
	}

	private String canonicalFunctionDisplay(Function f) {
		if (f == null) return "?";
		Function cur = f;
		Set<Address> seen = new HashSet<>();

		try {
			while (cur != null && cur.isThunk() &&
				seen.add(cur.getEntryPoint())) {
				Function next = cur.getThunkedFunction(true);
				if (next == null || next == cur) break;
				cur = next;
			}
		} catch (Exception ex) {
			cur = f;
		}

		return displayFunction(cur != null ? cur : f);
	}

	private String displayFunction(Function f) {
		if (f == null) return "?";
		String name = f.getName();
		String addr = f.getEntryPoint().toString();
		if (name != null && name.matches("(?i)FUN_0*" + Pattern.quote(addr))) return name;
		return name + " @ " + addr;
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
		} catch (MemoryAccessException ex) {  }
		return sb.toString();
	}

	private static String trim(String s, int max) {
		if (s == null) return "?";
		return s.length() <= max ? s : s.substring(0, max) + "...";
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

	private static String oneLine(String s) {
		if (s == null) return "?";
		return s.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
	}

	private static String safe(String s) { return s == null ? "?" : s; }
}
