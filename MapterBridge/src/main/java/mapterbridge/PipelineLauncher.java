package mapterbridge;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.framework.Application;
import ghidra.framework.options.ToolOptions;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Runs the MAPTER generation pipeline ({@code mapter_pipeline.py}) as a DETACHED process, and
 * inspects/cancels it later.
 *
 * <p>The pipeline is a command line tool (see MAPTER_backend); it writes {@code status.json},
 * {@code pipeline.log} and {@code pipeline.lock} in its work folder. This class never owns the
 * process: it is not stopped when the plugin or Ghidra goes away (the CLI calls {@code setsid}),
 * and a run is found again after a restart from its work folder and pid.
 */
final class PipelineLauncher {

	private static final String MODULE_NAME = "MapterBridge";
	private static final String BUNDLED_BACKEND_DIR = "mapter_backend";
	static final String SCRIPT = "mapter_pipeline.py";
	static final String STDOUT_LOG = "pipeline.stdout.log";
	private static final int START_GRACE_SECONDS = 2;
	private static final boolean WINDOWS =
		System.getProperty("os.name", "").toLowerCase().startsWith("windows");

	/**
	 * Everything needed to run the CLI, resolved from the Tool Options.
	 *
	 * @param python interpreter of the pipeline environment
	 * @param backendDir folder holding {@code mapter_pipeline.py}
	 * @param modelDir folder with SAFEtorch.pt and word2id.json
	 * @param r2 radare2 path option (blank = auto)
	 * @param capa capa path option (blank = auto)
	 * @param appDir folder of the Dash app (for recommend_delta), or null
	 */
	record Settings(String python, File backendDir, File modelDir, String r2, String capa,
			File appDir) {

		static Settings fromOptions(ToolOptions options) throws IOException {
			File backend = PipelineLauncher.backendDir(options.getString(MapterBridgePlugin.OPTION_BACKEND_DIR, ""));
			File model = PipelineLauncher.modelDir(options.getString(MapterBridgePlugin.OPTION_MODEL_DIR, ""),
				backend);
			String python = PythonEnvironments.resolve(
				options.getString(MapterBridgePlugin.OPTION_PIPELINE_PYTHON, ""), backend,
				PythonEnvironments.PIPELINE);
			File app;
			try {
				app = DashLauncher.appDir(options.getString(MapterBridgePlugin.OPTION_APP_DIR, ""));
			}
			catch (IOException e) {
				app = null; // only used for the recommended default threshold
			}
			return new Settings(python, backend, model,
				options.getString(MapterBridgePlugin.OPTION_R2, "").strip(),
				options.getString(MapterBridgePlugin.OPTION_CAPA, "").strip(), app);
		}

		File script() {
			return new File(backendDir, SCRIPT);
		}
	}

	/** Pipeline phase as seen from outside (status.json plus whether the process is alive). */
	enum Phase {
		NONE, STARTING, RUNNING, DONE, FAILED, CANCELLED,
		/** status.json says running but the process is gone (killed, crashed, machine restart). */
		INTERRUPTED;

		boolean isActive() {
			return this == STARTING || this == RUNNING;
		}

		boolean isFinished() {
			return this == DONE || this == FAILED || this == CANCELLED || this == INTERRUPTED;
		}
	}

	/** The fields of {@code status.json} this plugin shows. Missing numbers are 0. */
	record RunStatus(String state, String stage, int stageIndex, int nStages, long done,
			long total, String current, String message, long pid, String out, String error,
			int failures, String startedKey) {
	}

	record Run(Phase phase, RunStatus status) {

		static final Run NONE = new Run(Phase.NONE, null);
	}

	/** Outcome of {@code install_tools.py}: its final JSON line. */
	record InstallResult(boolean ok, String path, String version, String message) {
	}

	private PipelineLauncher() {
	}

	// ---------------------------------------------------------------------------------------
	// Locations
	// ---------------------------------------------------------------------------------------

	/**
	 * The folder holding {@code mapter_pipeline.py}: {@code configured} if set, else the bundled
	 * copy.
	 *
	 * @throws IOException if the folder does not exist or has no mapter_pipeline.py
	 */
	static File backendDir(String configured) throws IOException {
		File dir = configured == null || configured.isBlank()
				? Application.getModuleDataSubDirectory(MODULE_NAME, BUNDLED_BACKEND_DIR)
						.getFile(false)
				: new File(configured.strip());
		if (!new File(dir, SCRIPT).isFile()) {
			throw new IOException("No " + SCRIPT + " in " + dir);
		}
		return dir;
	}

	/** SAFE model folder: {@code configured} if set, else {@code <backend>/model}. */
	static File modelDir(String configured, File backendDir) {
		return configured == null || configured.isBlank() ? new File(backendDir, "model")
				: new File(configured.strip());
	}

	/**
	 * Where tools/install_tools.py puts downloaded tools (capa); passed as MAPTER_TOOLS_DIR.
	 * Same default as the pipeline run by hand ({@code $MAPTER_TOOLS_DIR} or
	 * {@code ~/.mapter/tools}), and independent of the Ghidra version.
	 */
	static File toolsDir() {
		String env = System.getenv("MAPTER_TOOLS_DIR");
		return env != null && !env.isBlank() ? new File(env)
				: new File(new File(System.getProperty("user.home"), ".mapter"), "tools");
	}

	/** Default work folder of a project: {@code <user settings>/mapter-runs/<project>}. */
	static File defaultWorkDir(String projectName) {
		String safe = projectName == null ? "" : projectName.replaceAll("[^A-Za-z0-9._-]+", "_");
		return new File(new File(Application.getUserSettingsDirectory(), "mapter-runs"),
			safe.isBlank() ? "project" : safe);
	}

	// ---------------------------------------------------------------------------------------
	// Starting (slow-ish: call from a task, not the Swing thread)
	// ---------------------------------------------------------------------------------------

	/**
	 * Starts the pipeline detached and returns its pid. Binaries come from the manifest already
	 * in {@code work} (exported from Ghidra) or, when {@code binariesFolder} is given, are hashed
	 * and linked from that folder by the CLI.
	 *
	 * @param vtKey VirusTotal API key for {@code --vt-fetch}, or blank; only handed over in the
	 *            child's environment, never stored
	 * @throws IOException if the process cannot start or dies within the first seconds
	 */
	static long start(Settings s, File work, File binariesFolder, String name, String method,
			File vtReports, boolean vtFetch, String vtKey) throws IOException {
		if (activePid(work) > 0) {
			throw new IOException("A MAPTER pipeline run is already active in " + work);
		}
		if (!work.isDirectory() && !work.mkdirs()) {
			throw new IOException("Cannot create the work folder " + work);
		}
		Files.deleteIfExists(new File(work, "status.json").toPath()); // no stale result

		List<String> cmd = new ArrayList<>(List.of(s.python(), s.script().getPath(), "--work",
			work.getPath()));
		if (binariesFolder != null) {
			cmd.addAll(List.of("--binaries", binariesFolder.getPath()));
		}
		else {
			cmd.addAll(List.of("--manifest", new File(work, "manifest.json").getPath()));
		}
		cmd.addAll(List.of("--out", new File(work, "data_folder").getPath(), "--name", name,
			"--model-dir", s.modelDir().getPath(), "--method", method));
		if (!s.r2().isBlank()) {
			cmd.addAll(List.of("--r2", s.r2()));
		}
		if (!s.capa().isBlank()) {
			cmd.addAll(List.of("--capa", s.capa()));
		}
		if (vtFetch) {
			cmd.add("--vt-fetch");
		}
		if (vtReports != null) {
			cmd.addAll(List.of("--vt-reports", vtReports.getPath()));
		}
		if (s.appDir() != null) {
			cmd.addAll(List.of("--app-dir", s.appDir().getPath()));
		}

		File stdout = new File(work, STDOUT_LOG);
		ProcessBuilder pb = new ProcessBuilder(cmd).directory(work)
				.redirectErrorStream(true)
				.redirectOutput(Redirect.appendTo(stdout));
		configureEnvironment(pb.environment(), vtFetch ? vtKey : null);
		Msg.info(PipelineLauncher.class, "MapterBridge: starting pipeline: " +
			String.join(" ", cmd));
		Process p = pb.start();
		try {
			p.getOutputStream().close(); // nothing to read; do not hold a pipe to Ghidra
		}
		catch (IOException ignored) {
			// the child may already be gone; handled below
		}
		try {
			if (p.waitFor(START_GRACE_SECONDS, TimeUnit.SECONDS)) {
				throw new IOException("The pipeline exited at once with code " + p.exitValue() +
					".\n\nLast lines of " + stdout + ":\n" + DashLauncher.tail(stdout, 15));
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		return p.pid();
	}

	/** Environment contract of the CLI: tools dir, unbuffered output, Homebrew on PATH. */
	static void configureEnvironment(Map<String, String> env, String vtKey) {
		env.put("MAPTER_TOOLS_DIR", toolsDir().getPath());
		env.put("PYTHONUNBUFFERED", "1");
		if (vtKey != null && !vtKey.isBlank()) {
			env.put("VT_API_KEY", vtKey.strip());
		}
		if (!WINDOWS) {
			// Ghidra started from Finder/Dock has a minimal PATH on macOS.
			String path = env.getOrDefault("PATH", "");
			List<String> parts = new ArrayList<>(
				path.isEmpty() ? List.of() : Arrays.asList(path.split(File.pathSeparator)));
			for (String extra : List.of("/opt/homebrew/bin", "/usr/local/bin")) {
				if (!parts.contains(extra)) {
					parts.add(extra);
				}
			}
			env.put("PATH", String.join(File.pathSeparator, parts));
		}
	}

	// ---------------------------------------------------------------------------------------
	// Inspecting and cancelling
	// ---------------------------------------------------------------------------------------

	/** Parsed {@code <work>/status.json}, or null if absent/unreadable. */
	static RunStatus readStatus(File work) {
		File file = new File(work, "status.json");
		try {
			JsonElement root = JsonParser.parseString(
				Files.readString(file.toPath(), StandardCharsets.UTF_8));
			if (!root.isJsonObject()) {
				return null;
			}
			JsonObject o = root.getAsJsonObject();
			int failures = 0;
			if (o.has("failures") && o.get("failures").isJsonObject()) {
				for (var stage : o.getAsJsonObject("failures").entrySet()) {
					if (stage.getValue().isJsonObject()) {
						failures += stage.getValue().getAsJsonObject().size();
					}
				}
			}
			return new RunStatus(str(o, "state"), str(o, "stage"), (int) num(o, "stage_index"),
				(int) num(o, "n_stages"), num(o, "done"), num(o, "total"), str(o, "current"),
				str(o, "message"), num(o, "pid"), str(o, "out"), str(o, "error"), failures,
				str(o, "started"));
		}
		catch (IOException | RuntimeException e) {
			return null; // missing, or caught mid-write on a platform without atomic replace
		}
	}

	private static String str(JsonObject o, String key) {
		JsonElement e = o.get(key);
		return e == null || e.isJsonNull() ? "" : e.getAsString();
	}

	private static long num(JsonObject o, String key) {
		JsonElement e = o.get(key);
		try {
			return e == null || e.isJsonNull() ? 0 : (long) e.getAsDouble();
		}
		catch (RuntimeException ex) {
			return 0;
		}
	}

	/**
	 * Phase of the run in {@code work}.
	 *
	 * @param savedPid pid remembered by the project, used until status.json names the pid
	 */
	static Run inspect(File work, long savedPid) {
		RunStatus st = readStatus(work);
		long pid = st != null && st.pid() > 0 ? st.pid() : savedPid;
		boolean alive = isPipelineProcess(pid);
		if (st == null) {
			return alive ? new Run(Phase.STARTING, null) : Run.NONE;
		}
		Phase phase = switch (st.state()) {
			case "done" -> Phase.DONE;
			case "failed" -> Phase.FAILED;
			case "cancelled" -> Phase.CANCELLED;
			default -> alive ? Phase.RUNNING : Phase.INTERRUPTED;
		};
		return new Run(phase, st);
	}

	/** Pid of a live pipeline process holding the work folder's lock or status, else 0. */
	static long activePid(File work) {
		RunStatus st = readStatus(work);
		if (st != null && "running".equals(st.state()) && isPipelineProcess(st.pid())) {
			return st.pid();
		}
		try {
			String text = Files.readString(new File(work, "pipeline.lock").toPath()).strip();
			long pid = Long.parseLong(text.split("\\s+")[0]);
			return isPipelineProcess(pid) ? pid : 0;
		}
		catch (IOException | RuntimeException e) {
			return 0;
		}
	}

	/** True if {@code pid} is alive and, when its command line is visible, is our pipeline. */
	static boolean isPipelineProcess(long pid) {
		if (pid <= 0) {
			return false;
		}
		Optional<ProcessHandle> handle = ProcessHandle.of(pid);
		if (handle.isEmpty() || !handle.get().isAlive()) {
			return false;
		}
		ProcessHandle.Info info = handle.get().info();
		String command = info.commandLine().orElse(null);
		if (command == null) {
			command = info.arguments().map(a -> String.join(" ", a)).orElse(null);
		}
		return command == null || command.contains("mapter_pipeline"); // unknown: assume ours
	}

	/**
	 * Asks the pipeline to stop (SIGTERM): it finishes the binary in progress, then writes state
	 * 'cancelled'. Returns false if no such process.
	 */
	static boolean cancel(long pid) {
		if (!isPipelineProcess(pid)) {
			return false;
		}
		return ProcessHandle.of(pid).map(ProcessHandle::destroy).orElse(false);
	}

	/** Kills the pipeline and its children at once (no clean 'cancelled' state is written). */
	static void kill(long pid) {
		ProcessHandle.of(pid).ifPresent(h -> {
			h.descendants().forEach(ProcessHandle::destroyForcibly);
			h.destroyForcibly();
		});
	}

	// ---------------------------------------------------------------------------------------
	// Prerequisites and tool installation (slow: call from a task)
	// ---------------------------------------------------------------------------------------

	/**
	 * Runs {@code mapter_pipeline.py --check} and returns its JSON report ({@code ok, python,
	 * packages, radare2, capa, model, problems}). The exit code (1 = something required is
	 * missing) is not an error here; the report says what.
	 */
	static JsonObject runCheck(Settings s, TaskMonitor monitor)
			throws IOException, CancelledException {
		List<String> cmd = new ArrayList<>(List.of(s.python(), s.script().getPath(), "--check",
			"--model-dir", s.modelDir().getPath()));
		if (!s.r2().isBlank()) {
			cmd.addAll(List.of("--r2", s.r2()));
		}
		if (!s.capa().isBlank()) {
			cmd.addAll(List.of("--capa", s.capa()));
		}
		String out = runCaptured(cmd, 180, monitor);
		JsonObject json = parseJsonObject(out);
		if (json == null) {
			throw new IOException("--check printed no JSON report. Output:\n" + tailOf(out, 15));
		}
		return json;
	}

	/**
	 * Runs {@code tools/install_tools.py <tool>} ("capa" or "radare2") and returns its final JSON
	 * line. radare2 exits 3 with instructions when it cannot be installed automatically; that is
	 * reported as {@code ok == false} with the instructions as message.
	 */
	static InstallResult installTool(Settings s, String tool, TaskMonitor monitor)
			throws IOException, CancelledException {
		File script = new File(new File(s.backendDir(), "tools"), "install_tools.py");
		if (!script.isFile()) {
			throw new IOException("Missing " + script);
		}
		File py = new File(s.python()).canExecute() ? new File(s.python())
				: new File(PythonEnvironments.systemPython()); // stdlib-only script
		List<String> cmd = new ArrayList<>(List.of(py.getPath(), script.getPath(), tool));
		if (tool.equals("capa")) {
			cmd.addAll(List.of("--dest", toolsDir().getPath()));
		}
		String out = runCaptured(cmd, tool.equals("capa") ? 900 : 1800, monitor);
		JsonObject json = null;
		for (String line : out.lines().toList().reversed()) {
			if (line.strip().startsWith("{")) {
				json = parseJsonObject(line);
				if (json != null) {
					break;
				}
			}
		}
		if (json == null) {
			return new InstallResult(false, "", "",
				"install_tools.py printed no result. Output:\n" + tailOf(out, 15));
		}
		return new InstallResult(json.has("ok") && json.get("ok").getAsBoolean(),
			str(json, "path"), str(json, "version"), str(json, "message"));
	}

	/**
	 * Runs a command with the pipeline environment, waits (honouring the monitor), and returns its
	 * combined output. Output goes through a temp file so a chatty child can never block.
	 */
	private static String runCaptured(List<String> cmd, int timeoutSeconds, TaskMonitor monitor)
			throws IOException, CancelledException {
		File out = File.createTempFile("mapter-bridge-", ".out");
		try {
			ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true)
					.redirectOutput(Redirect.to(out));
			configureEnvironment(pb.environment(), null);
			Process p = pb.start();
			long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
			while (true) {
				if (monitor.isCancelled()) {
					p.destroyForcibly();
					throw new CancelledException();
				}
				if (System.nanoTime() > deadline) {
					p.destroyForcibly();
					throw new IOException("'" + cmd.get(1) + "' did not finish within " +
						timeoutSeconds + "s");
				}
				try {
					if (p.waitFor(250, TimeUnit.MILLISECONDS)) {
						break;
					}
				}
				catch (InterruptedException e) {
					p.destroyForcibly();
					throw new CancelledException();
				}
			}
			return Files.readString(out.toPath(), StandardCharsets.UTF_8);
		}
		finally {
			out.delete();
		}
	}

	/** A JSON object from tool output: the whole text, else its last JSON-looking line. */
	static JsonObject parseJsonObject(String text) {
		String stripped = text.strip();
		List<String> candidates = new ArrayList<>();
		candidates.add(stripped);
		int first = stripped.indexOf('{');
		int last = stripped.lastIndexOf('}');
		if (first >= 0 && last > first) {
			candidates.add(stripped.substring(first, last + 1));
		}
		for (String line : stripped.lines().toList().reversed()) {
			if (line.strip().startsWith("{")) {
				candidates.add(line.strip());
				break;
			}
		}
		for (String candidate : candidates) {
			try {
				JsonElement e = JsonParser.parseString(candidate);
				if (e.isJsonObject()) {
					return e.getAsJsonObject();
				}
			}
			catch (RuntimeException ignored) {
				// try the next candidate
			}
		}
		return null;
	}

	private static String tailOf(String text, int lines) {
		List<String> all = text.lines().toList();
		return String.join("\n", all.subList(Math.max(0, all.size() - lines), all.size()));
	}
}
