package mapterbridge;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.google.gson.JsonObject;

import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.UnableToSwingException;
import mapterbridge.NavigationBackend.Reply;
import mapterbridge.ProgramNameMatcher.Match;

/**
 * Ghidra side of the bridge. Every public method may be called from any thread; the actual
 * Program/GUI work runs on the Swing thread and the caller waits for its real result.
 */
final class GhidraNavigator implements NavigationBackend {

	private static final int SWING_TIMEOUT_SECONDS = 15;

	private final PluginTool tool;
	private final String owner;

	/** Program holding our last highlight, so it can be cleared. Swing thread only. */
	private Program highlightedProgram;

	/** Latest cursor snapshot: written on the Swing thread, read by HTTP threads. */
	private volatile CursorSnapshot cursor = CursorSnapshot.NONE;

	/** Outcome of resolving a binary_name: exactly one of the two fields is set. */
	private record Resolved(Program program, String error) {
	}

	/**
	 * Where the CodeBrowser cursor is. Addresses use the dataset's {@code offset} format
	 * ({@code 0x} + lowercase unpadded hex); fields are null when unknown.
	 */
	private record CursorSnapshot(String program, String programSha256, String functionName,
			String entryAddress, String address) {
		static final CursorSnapshot NONE = new CursorSnapshot(null, null, null, null, null);
	}

	GhidraNavigator(PluginTool tool, String owner) {
		this.tool = tool;
		this.owner = owner;
	}

	// ---------------------------------------------------------------------------------------
	// NavigationBackend
	// ---------------------------------------------------------------------------------------

	@Override
	public Reply status() {
		JsonObject body = new JsonObject();
		body.addProperty("status", "running");
		body.addProperty("message", "Ghidra navigation server is active");
		body.addProperty("ghidra_available", true);
		try {
			JsonObject programs = onSwing(this::programSummary);
			programs.entrySet().forEach(e -> body.add(e.getKey(), e.getValue()));
		}
		catch (Exception e) {
			// Like the Python server: still "running", program info unknown.
			Msg.warn(this, "MapterBridge: /status could not query programs: " + e.getMessage());
			body.add("current_program", null);
			body.addProperty("program_count", 0);
		}
		return Reply.ok(body);
	}

	@Override
	public Reply current() {
		CursorSnapshot snap = cursor;
		JsonObject body = new JsonObject();
		body.addProperty("success", true);
		body.addProperty("program", snap.program());
		body.addProperty("program_sha256", snap.programSha256());
		body.addProperty("function_name", snap.functionName());
		body.addProperty("entry_address", snap.entryAddress());
		body.addProperty("address", snap.address());
		return Reply.ok(body);
	}

	/**
	 * Records the cursor location (called from the plugin's {@code locationChanged}, on the Swing
	 * thread). A null location means "program known, position not yet".
	 *
	 * <p>Addresses are only published for the program's default address space, the one MAPTER
	 * offsets live in: stack/register/external locations have no function, and an overlay offset
	 * could collide with an unrelated default-space function.
	 */
	void locationChanged(Program program, ProgramLocation location) {
		Program p = location != null && location.getProgram() != null
				? location.getProgram()
				: program;
		// Ghidra replays the last location event to newly added plugins; its program may be gone.
		if (p == null || p.isClosed()) {
			cursor = CursorSnapshot.NONE;
			return;
		}
		Address addr = location == null ? null : location.getAddress();
		String sha = normalizedSha(p);
		if (addr == null || !addr.isMemoryAddress()) {
			cursor = new CursorSnapshot(p.getName(), sha, null, null, null);
			return;
		}
		Function function = p.getFunctionManager().getFunctionContaining(addr);
		String functionName = function == null ? null : function.getName();
		if (!addr.getAddressSpace().equals(p.getAddressFactory().getDefaultAddressSpace())) {
			cursor = new CursorSnapshot(p.getName(), sha, functionName, null, null);
			return;
		}
		cursor = new CursorSnapshot(p.getName(), sha, functionName,
			function == null ? null : toHex(function.getEntryPoint()), toHex(addr));
	}

	/** The program's original-file SHA-256 (lowercase hex), or null if it records none. */
	private static String normalizedSha(Program program) {
		String sha = program.getExecutableSHA256();
		return sha == null || sha.isBlank() ? null : sha.strip().toLowerCase(Locale.ROOT);
	}

	/** The project file's recorded SHA-256 from its metadata, without opening it; or null. */
	private static String fileSha(DomainFile file) {
		try {
			Map<String, String> metadata = file.getMetadata();
			String sha = metadata == null ? null : metadata.get(BinaryMaterializer.METADATA_SHA256);
			return sha == null || sha.isBlank() ? null : sha.strip().toLowerCase(Locale.ROOT);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	@Override
	public Reply navigate(String address, String name, String binaryName) {
		try {
			return onSwing(() -> doNavigate(address, name, binaryName));
		}
		catch (Exception e) {
			Msg.error(this, "MapterBridge: navigation failed", e);
			return Reply.failure(500, "Navigation raised: " + e);
		}
	}

	// ---------------------------------------------------------------------------------------
	// Swing-thread work
	// ---------------------------------------------------------------------------------------

	/**
	 * Runs {@code work} on the Swing thread and returns its result. Fails if the Swing thread does
	 * not pick the task up within {@link #SWING_TIMEOUT_SECONDS} (the task is then dropped, not run
	 * late), and rethrows anything the task threw.
	 */
	private static <T> T onSwing(Supplier<T> work) throws Exception {
		AtomicReference<T> result = new AtomicReference<>();
		AtomicReference<Throwable> failure = new AtomicReference<>();
		try {
			Swing.runNow(() -> {
				try {
					result.set(work.get());
				}
				catch (Throwable t) {
					failure.set(t);
				}
			}, SWING_TIMEOUT_SECONDS, TimeUnit.SECONDS);
		}
		catch (UnableToSwingException e) {
			throw new Exception("Ghidra UI busy: task not started within " +
				SWING_TIMEOUT_SECONDS + "s", e);
		}
		if (failure.get() instanceof Exception e) {
			throw e;
		}
		if (failure.get() != null) {
			throw new Exception(failure.get());
		}
		if (result.get() == null) {
			throw new InterruptedException("Swing task interrupted");
		}
		return result.get();
	}

	private JsonObject programSummary() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		Program current = pm == null ? null : pm.getCurrentProgram();
		JsonObject o = new JsonObject();
		o.addProperty("current_program", current == null ? null : current.getName());
		o.addProperty("program_count", pm == null ? 0 : pm.getAllOpenPrograms().length);
		o.addProperty("project_program_count", projectProgramFiles().size());
		return o;
	}

	private Reply doNavigate(String addressText, String name, String binaryName) {
		ProgramManager pm = tool.getService(ProgramManager.class);
		GoToService goTo = tool.getService(GoToService.class);
		if (pm == null || goTo == null) {
			return Reply.failure(404, "ProgramManager/GoToService unavailable in this tool");
		}

		// 1. Which program: open programs first, then the project (opened on demand).
		Resolved resolved = resolveProgram(pm, binaryName);
		if (resolved.error() != null) {
			return notFound(resolved.error(), binaryName, addressText);
		}
		Program program = resolved.program();

		// 2. Which address/function: address first, then the name fallback.
		FunctionManager fm = program.getFunctionManager();
		Address target = null;
		Function function = null;
		if (addressText != null) {
			target = parseAddress(program, addressText);
			if (target == null) {
				return notFound("Could not parse address '" + addressText + "'", binaryName,
					addressText);
			}
			function = fm.getFunctionAt(target);
			if (function == null) {
				function = fm.getFunctionContaining(target);
			}
		}
		if (function == null && name != null) {
			Function byName = findFunctionByName(fm, name);
			if (byName != null) {
				function = byName;
				target = byName.getEntryPoint();
			}
		}
		if (target == null) {
			return notFound("Function not found by address or name", binaryName, addressText);
		}

		// 3. Switch (clearing our old highlight while its program is still current), go, highlight.
		clearHighlight();
		if (pm.getCurrentProgram() != program) {
			pm.setCurrentProgram(program);
		}
		if (!goTo.goTo(target, program)) {
			return notFound("Could not navigate to " + target + " in " + program.getName(),
				binaryName, addressText);
		}
		if (function != null) {
			tool.firePluginEvent(new ProgramHighlightPluginEvent(owner,
				new ProgramSelection(function.getBody()), program));
			highlightedProgram = program;
		}

		JsonObject body = new JsonObject();
		body.addProperty("success", true);
		body.addProperty("message", "Navigated");
		body.addProperty("function_name", function != null ? function.getName() : name);
		body.addProperty("address", target.toString());
		body.addProperty("binary", program.getName());
		return Reply.ok(body);
	}

	private Resolved resolveProgram(ProgramManager pm, String binaryName) {
		Match<Program> open =
			ProgramNameMatcher.match(List.of(pm.getAllOpenPrograms()), Program::getName,
				GhidraNavigator::normalizedSha, binaryName);
		if (open.found() != null) {
			return new Resolved(open.found(), null);
		}
		if (open.isAmbiguous()) {
			return new Resolved(null, ambiguous(binaryName, "open programs",
				open.candidates().stream().map(Program::getName)));
		}

		Match<DomainFile> file =
			ProgramNameMatcher.match(projectProgramFiles(), DomainFile::getName,
				GhidraNavigator::fileSha, binaryName);
		if (file.isAmbiguous()) {
			return new Resolved(null, ambiguous(binaryName, "project programs",
				file.candidates().stream().map(DomainFile::getPathname)));
		}
		if (file.found() == null) {
			return new Resolved(null,
				"No program in the project matches binary_name '" + binaryName + "'");
		}

		DomainFile df = file.found();
		Msg.info(this, "MapterBridge: opening " + df.getPathname() + " for '" + binaryName + "'");
		Program opened = pm.openProgram(df);
		if (opened == null) {
			return new Resolved(null, "Could not open program " + df.getPathname());
		}
		return new Resolved(opened, null);
	}

	/** All Program files in the active project (link files have another content type). */
	private List<DomainFile> projectProgramFiles() {
		return BinaryMaterializer.programFiles(tool.getProject());
	}

	private void clearHighlight() {
		Program previous = highlightedProgram;
		highlightedProgram = null;
		if (previous != null && !previous.isClosed()) {
			tool.firePluginEvent(
				new ProgramHighlightPluginEvent(owner, new ProgramSelection(), previous));
		}
	}

	/**
	 * Parses a hex string ({@code 0x401000}, {@code 401000}) as an offset in the program's default
	 * address space. The value is the loaded VA from MAPTER's {@code offset} column, used as-is.
	 */
	static Address parseAddress(Program program, String text) {
		String s = text.strip().toLowerCase(Locale.ROOT);
		if (s.startsWith("0x")) {
			s = s.substring(2);
		}
		try {
			long value = Long.parseUnsignedLong(s, 16);
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
		}
		catch (NumberFormatException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/** Inverse of {@link #parseAddress}: {@code 0x} + lowercase unpadded hex (unsigned). */
	static String toHex(Address address) {
		return "0x" + Long.toHexString(address.getOffset());
	}

	private static Function findFunctionByName(FunctionManager fm, String name) {
		for (Function f : fm.getFunctions(true)) {
			if (f.getName().equals(name) || f.getName(true).equals(name)) {
				return f;
			}
		}
		return null;
	}

	private static String ambiguous(String binaryName, String where,
			java.util.stream.Stream<String> names) {
		String list = names.sorted().collect(Collectors.joining(", "));
		Msg.warn(GhidraNavigator.class, "MapterBridge: ambiguous binary_name '" + binaryName +
			"' among " + where + ": " + list);
		return "Ambiguous binary_name '" + binaryName + "' matches " + where + ": " + list;
	}

	private static Reply notFound(String error, String binaryName, String address) {
		Reply reply = Reply.failure(404, error);
		reply.body().addProperty("binary_name", binaryName);
		reply.body().addProperty("address", address);
		return reply;
	}
}
