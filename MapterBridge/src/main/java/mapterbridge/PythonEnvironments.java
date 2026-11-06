package mapterbridge;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds, checks and creates Python environments for MAPTER: the one that runs the Dash app and
 * the one that runs the generation pipeline (see {@link Profile}).
 *
 * <p>An environment is valid for a profile when its interpreter has every package of the
 * profile's requirements file at the required version. Environments are configured either as an
 * environment folder (venv, conda env) or as a {@code python} executable.
 */
final class PythonEnvironments {

	/**
	 * What an environment is for: where its requirements file lives and how it is named in the
	 * options and on disk.
	 *
	 * @param title dialog title / noun shown to the user
	 * @param requirementsFile requirements file name, looked up in the profile's folder
	 *            (the app folder for the app, the backend folder for the pipeline)
	 * @param optionName Tool Option holding the environment folder or interpreter
	 * @param venvName default venv folder name inside Ghidra's user settings directory
	 * @param minPython minimum Python version as "major.minor"
	 * @param setupLog log file name (in the user settings directory) for create/install output
	 * @param projectFile file whose folder is "the project" (shown in the candidate origin)
	 */
	record Profile(String title, String requirementsFile, String optionName, String venvName,
			String minPython, String setupLog, String projectFile) {
	}

	/** Environment that runs the Dash app (requirements-app.txt in the app folder). */
	static final Profile APP = new Profile("MAPTER Python Environment", "requirements-app.txt",
		"Python Environment", "mapter-venv", "3.9", "mapter-setup.log", "app.py");

	/** Environment that runs the generation pipeline (requirements-pipeline.txt in the backend). */
	static final Profile PIPELINE = new Profile("MAPTER Pipeline Python Environment",
		"requirements-pipeline.txt", "Pipeline Python Environment", "mapter-pipeline-venv",
		"3.9", "mapter-pipeline-setup.log", "mapter_pipeline.py");

	private static final int CHECK_TIMEOUT_SECONDS = 20;
	private static final boolean WINDOWS =
		System.getProperty("os.name", "").toLowerCase().startsWith("windows");

	/**
	 * Reports, as JSON, the interpreter version, whether it runs inside a venv/conda env (prefix)
	 * and which requirement specs are missing or too old. argv[1] is the minimum Python
	 * ("3.9"), the rest are requirement lines ("name", "name>=x.y", "name[extra]==x ; marker").
	 * Lines whose environment marker is false here are skipped; markers are only evaluated when
	 * {@code packaging} is importable, otherwise such lines are skipped as optional.
	 */
	private static final String CHECK_SCRIPT = """
		import importlib.metadata as m, json, os, re, sys
		def ver(s): return tuple(int(x) for x in re.findall(r"\\d+", s)[:3])
		need = tuple(int(x) for x in sys.argv[1].split("."))
		missing = [] if sys.version_info[:2] >= need else ["Python >= " + sys.argv[1]]
		try:
		    from packaging.markers import Marker
		except Exception:
		    Marker = None
		for line in sys.argv[2:]:
		    spec, _, marker = line.partition(";")
		    if marker.strip():
		        try:
		            if Marker is None or not Marker(marker.strip()).evaluate():
		                continue
		        except Exception:
		            continue
		    mt = re.match(r"\\s*([A-Za-z0-9_.\\-]+)\\s*(?:\\[[^\\]]*\\])?\\s*(?:(>=|==|~=|>|<=|<|!=)\\s*([^,\\s]+))?", spec)
		    if not mt:
		        continue
		    name, op, low = mt.groups()
		    try:
		        have = m.version(name)
		    except m.PackageNotFoundError:
		        missing.append(name)
		        continue
		    if op in (">=", "==", "~=") and low and ver(have) < ver(low):
		        missing.append(f"{name} {have} < {low}")
		env = sys.prefix != sys.base_prefix or os.path.isdir(os.path.join(sys.prefix, "conda-meta"))
		print(json.dumps({"version": sys.version.split()[0], "env": env,
		                  "prefix": sys.prefix, "missing": missing}))
		""";

	/**
	 * A Python interpreter and how well it fits the MAPTER app.
	 *
	 * @param python the interpreter
	 * @param origin where it was found (shown to the user)
	 * @param version Python version, or null if it could not be run
	 * @param prefix environment root ({@code sys.prefix}) when {@code isEnvironment}
	 * @param isEnvironment true for a venv/conda env (safe to pip-install into)
	 * @param missing missing or too old requirements
	 * @param error why the interpreter could not be checked, or null
	 */
	record PythonEnv(File python, String origin, String version, File prefix,
			boolean isEnvironment, List<String> missing, String error) {

		boolean ready() {
			return error == null && missing.isEmpty();
		}

		String status() {
			if (error != null) {
				return error;
			}
			String kind = isEnvironment ? "Python " + version : "system Python " + version;
			return missing.isEmpty() ? kind + ", ready"
					: kind + ", missing: " + String.join(", ", missing);
		}

		/** What to store in the option: the environment folder, else the interpreter. */
		String setting() {
			return (isEnvironment && prefix != null ? prefix : python).getPath();
		}
	}

	private PythonEnvironments() {
	}

	// ---------------------------------------------------------------------------------------
	// Locations
	// ---------------------------------------------------------------------------------------

	/** Default folder for an environment created from Ghidra. */
	static File defaultVenv(Profile profile) {
		return new File(Application.getUserSettingsDirectory(), profile.venvName());
	}

	static File setupLog(Profile profile) {
		return new File(Application.getUserSettingsDirectory(), profile.setupLog());
	}

	/** The interpreter of an environment folder, or the file itself if it is one; else null. */
	static File interpreter(File pathOrFolder) {
		if (pathOrFolder.isFile()) {
			return pathOrFolder.canExecute() ? pathOrFolder : null;
		}
		List<String> names = WINDOWS ? List.of("Scripts/python.exe", "python.exe")
				: List.of("bin/python3", "bin/python");
		for (String name : names) {
			File f = new File(pathOrFolder, name);
			if (f.canExecute()) {
				return f;
			}
		}
		return null;
	}

	/**
	 * Interpreter to run the app (or pipeline) with: the configured environment/interpreter; when
	 * empty, the profile's default environment, then a {@code .venv} next to the app/backend
	 * folder's main script, then a system Python.
	 *
	 * @param projectDir the app folder (APP) or backend folder (PIPELINE)
	 */
	static String resolve(String configured, File projectDir, Profile profile) {
		if (configured != null && !configured.isBlank()) {
			File python = interpreter(new File(configured.strip()));
			return python != null ? python.getPath() : configured.strip();
		}
		for (File folder : List.of(defaultVenv(profile), new File(projectDir, ".venv"))) {
			File python = interpreter(folder);
			if (python != null) {
				return python.getPath();
			}
		}
		return systemPython();
	}

	/** A Python 3 on PATH (or a usual install location), for creating environments. */
	static String systemPython() {
		List<File> found = systemPythons();
		return found.isEmpty() ? (WINDOWS ? "python.exe" : "python3") : found.get(0).getPath();
	}

	private static List<File> systemPythons() {
		List<String> names = WINDOWS ? List.of("python.exe", "py.exe") : List.of("python3", "python");
		List<File> found = new ArrayList<>();
		String path = System.getenv("PATH");
		for (String dir : path == null ? new String[0] : path.split(File.pathSeparator)) {
			for (String name : names) {
				found.add(new File(dir, name));
			}
		}
		// Ghidra started from Finder/Dock gets a minimal PATH on macOS.
		for (String p : List.of("/opt/homebrew/bin/python3", "/usr/local/bin/python3",
			"/usr/bin/python3")) {
			found.add(new File(p));
		}
		found.removeIf(f -> !f.canExecute());
		return found;
	}

	/**
	 * Places worth checking, in display order, keyed by interpreter. Paths are not canonicalized:
	 * a venv's {@code bin/python} is a symlink to its base Python, and only the venv path runs
	 * with the venv's packages.
	 */
	static Map<File, String> candidates(String configured, File appDir, Profile profile) {
		Map<File, String> found = new LinkedHashMap<>();
		if (configured != null && !configured.isBlank()) {
			add(found, new File(configured.strip()), "configured");
		}
		add(found, defaultVenv(profile), "MAPTER environment");
		File[] ghidraVersions = Application.getUserSettingsDirectory().getParentFile().listFiles();
		for (File dir : ghidraVersions == null ? new File[0] : ghidraVersions) {
			add(found, new File(dir, profile.venvName()),
				"MAPTER environment (" + dir.getName() + ")");
		}
		if (appDir != null) {
			add(found, new File(appDir, ".venv"), "next to " + profile.projectFile());
			add(found, new File(appDir, "venv"), "next to " + profile.projectFile());
		}
		for (String var : List.of("VIRTUAL_ENV", "CONDA_PREFIX")) {
			String value = System.getenv(var);
			if (value != null) {
				add(found, new File(value), "active environment (" + var + ")");
			}
		}

		File home = new File(System.getProperty("user.home"));
		for (String parent : List.of(".virtualenvs", "venvs", ".venvs", "envs", ".pyenv/versions")) {
			addChildren(found, new File(home, parent), parent);
		}
		List<File> condaRoots = new ArrayList<>();
		for (String name : List.of("miniconda3", "anaconda3", "miniforge3", "mambaforge",
			"opt/miniconda3", "opt/anaconda3")) {
			condaRoots.add(new File(home, name));
		}
		for (String p : List.of("/opt/miniconda3", "/opt/anaconda3",
			"/opt/homebrew/Caskroom/miniconda/base", "/usr/local/Caskroom/miniconda/base")) {
			condaRoots.add(new File(p));
		}
		for (File root : condaRoots) {
			add(found, root, "conda base");
			addChildren(found, new File(root, "envs"), "conda");
		}
		for (File python : systemPythons()) {
			found.putIfAbsent(python.getAbsoluteFile(), "system");
		}
		return found;
	}

	private static void add(Map<File, String> found, File pathOrFolder, String origin) {
		File python = interpreter(pathOrFolder);
		if (python != null) {
			found.putIfAbsent(python.toPath().toAbsolutePath().normalize().toFile(), origin);
		}
	}

	private static void addChildren(Map<File, String> found, File parent, String origin) {
		File[] children = parent.listFiles(File::isDirectory);
		if (children != null) {
			Arrays.sort(children);
			for (File child : children) {
				add(found, child, origin);
			}
		}
	}

	// ---------------------------------------------------------------------------------------
	// Checking
	// ---------------------------------------------------------------------------------------

	/**
	 * Requirement lines ("dash>=3.0", "torch>=2.2 ; marker") from the profile's requirements
	 * file; comments and pip option lines ({@code -r}, {@code --index-url}) are dropped.
	 */
	static List<String> requirements(File dir, Profile profile) throws IOException {
		List<String> specs = new ArrayList<>();
		for (String line : Files.readAllLines(new File(dir, profile.requirementsFile()).toPath())) {
			String spec = line.replaceAll("#.*", "").strip();
			if (!spec.isEmpty() && !spec.startsWith("-")) {
				specs.add(spec);
			}
		}
		return specs;
	}

	/** Runs the interpreter to see whether it can run the app/pipeline. Never throws. */
	static PythonEnv check(File python, String origin, List<String> requirements,
			Profile profile) {
		List<String> command = new ArrayList<>(List.of(python.getPath(), "-c", CHECK_SCRIPT,
			profile.minPython()));
		command.addAll(requirements);
		try {
			Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
			if (!p.waitFor(CHECK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
				p.destroyForcibly();
				return failed(python, origin, "did not answer in " + CHECK_TIMEOUT_SECONDS + "s");
			}
			String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
			String last = out.strip().lines().reduce((a, b) -> b).orElse("");
			if (p.exitValue() != 0 || !last.startsWith("{")) {
				return failed(python, origin, "not a usable Python 3: " + last);
			}
			JsonObject o = JsonParser.parseString(last).getAsJsonObject();
			List<String> missing = new ArrayList<>();
			o.getAsJsonArray("missing").forEach(e -> missing.add(e.getAsString()));
			return new PythonEnv(python, origin, o.get("version").getAsString(),
				new File(o.get("prefix").getAsString()), o.get("env").getAsBoolean(), missing, null);
		}
		catch (IOException | RuntimeException e) {
			return failed(python, origin, "could not run: " + e.getMessage());
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return failed(python, origin, "check interrupted");
		}
	}

	private static PythonEnv failed(File python, String origin, String error) {
		return new PythonEnv(python, origin, null, null, false, List.of(), error);
	}

	// ---------------------------------------------------------------------------------------
	// Creating and installing (slow: call from a task)
	// ---------------------------------------------------------------------------------------

	/**
	 * Creates a venv in {@code folder} with {@code basePython} (unless one is already there) and
	 * installs the app's requirements into it.
	 *
	 * @return the new environment's interpreter
	 */
	static File create(String basePython, File folder, File appDir, Profile profile,
			TaskMonitor monitor) throws IOException, CancelledException {
		Files.writeString(setupLog(profile).toPath(), ""); // fresh log per setup
		if (interpreter(folder) == null) {
			run(profile, monitor, "Creating Python environment in " + folder,
				basePython, "-m", "venv", folder.getPath());
		}
		File python = interpreter(folder);
		if (python == null) {
			throw new IOException("No interpreter in " + folder + " after creating it");
		}
		install(python, appDir, profile, monitor);
		return python;
	}

	/** Installs (or upgrades to) the app's requirements into an environment's interpreter. */
	static void install(File python, File appDir, Profile profile, TaskMonitor monitor)
			throws IOException, CancelledException {
		File requirements = new File(appDir, profile.requirementsFile());
		if (!requirements.isFile()) {
			throw new IOException("Missing " + requirements);
		}
		run(profile, monitor, "Updating pip...",
			python.getPath(), "-m", "pip", "install", "--upgrade", "pip");
		run(profile, monitor, "Installing MAPTER requirements (this can take a few minutes)...",
			python.getPath(), "-m", "pip", "install", "-r", requirements.getPath());
	}

	private static void run(Profile profile, TaskMonitor monitor, String message,
			String... command) throws IOException, CancelledException {
		File log = setupLog(profile);
		monitor.setMessage(message);
		Msg.info(PythonEnvironments.class, "MapterBridge: " + String.join(" ", command));
		Process p = new ProcessBuilder(command).redirectErrorStream(true)
				.redirectOutput(Redirect.appendTo(log))
				.start();
		while (true) {
			if (monitor.isCancelled()) {
				p.destroyForcibly();
				throw new CancelledException();
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
		if (p.exitValue() != 0) {
			throw new IOException("'" + String.join(" ", command) + "' failed with code " +
				p.exitValue() + ".\n\nLast lines of " + log + ":\n" + DashLauncher.tail(log, 15));
		}
	}
}
