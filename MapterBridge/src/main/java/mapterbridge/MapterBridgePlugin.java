package mapterbridge;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

import javax.swing.Timer;

import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.Project;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.BrowserLoader;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import mapterbridge.PipelineLauncher.Phase;
import mapterbridge.PipelineLauncher.Run;
import mapterbridge.PipelineLauncher.RunStatus;
import mapterbridge.PythonEnvironments.PythonEnv;

/**
 * Bridge between Ghidra and the MAPTER Dash app.
 *
 * <p>Runs a localhost HTTP server ({@link NavigationServer}) that lets the Dash plots drive the
 * CodeBrowser: clicking a point navigates to that function, switching or opening the program in
 * the project as needed; {@code GET /current} lets the app follow the CodeBrowser cursor.
 *
 * <p>It also launches the Dash app itself ({@link DashLauncher}): Tools &rarr; MAPTER &rarr; Open
 * MAPTER runs the app bundled with this extension and opens it in the browser.
 *
 * <p>Tools &rarr; MAPTER &rarr; Run MAPTER Pipeline... generates MAPTER data from this project's
 * programs ({@link PipelineDialog}); the pipeline runs as a detached process ({@link
 * PipelineLauncher}) and its result becomes the project's MAPTER data folder.
 *
 * <p>Settings live under Edit &rarr; Tool Options &rarr; MAPTER Bridge.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "MAPTER bridge",
	description = "Links the MAPTER Dash visualization with the CodeBrowser: " +
		"navigate from plot points to functions and back."
)
//@formatter:on
public class MapterBridgePlugin extends ProgramPlugin implements OptionsChangeListener {

	static final String OPTIONS_CATEGORY = "MAPTER Bridge";
	static final String OPTION_HOST = "Server Host";
	static final String OPTION_PORT = "Server Port";
	static final String OPTION_AUTOSTART = "Start Server Automatically";
	static final String OPTION_DASH_PORT = "Dash Port";
	static final String OPTION_PYTHON = PythonEnvironments.APP.optionName();
	static final String OPTION_PIPELINE_PYTHON = PythonEnvironments.PIPELINE.optionName();
	static final String OPTION_BACKEND_DIR = "MAPTER Backend Folder";
	static final String OPTION_MODEL_DIR = "SAFE Model Folder";
	static final String OPTION_R2 = "radare2 Path";
	static final String OPTION_CAPA = "capa Path";
	private static final String OLD_OPTION_PYTHON = "Python Interpreter"; // before 2026-10
	static final String OPTION_APP_DIR = "MAPTER App Folder";
	static final String DEFAULT_HOST = "127.0.0.1";
	static final int DEFAULT_PORT = 9999;
	static final int DEFAULT_DASH_PORT = 15510;
	private static final String TITLE = "MAPTER Bridge";
	private static final int RUN_WATCH_MILLIS = 2500;

	private GhidraNavigator navigator;
	private ToggleDockingAction serverAction;
	private NavigationServer server; // Swing thread only
	private final DashLauncher launcher = new DashLauncher();
	private PipelineDialog pipelineDialog; // Swing thread only
	private Timer runWatch; // Swing thread: follows the project's pipeline run until it ends
	private String lastRunStage = ""; // last stage reported to the status bar
	private int reattachAttempts;

	public MapterBridgePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		navigator = new GhidraNavigator(tool, getName());
		ToolOptions options = registerOptions();
		createActions();
		if (options.getBoolean(OPTION_AUTOSTART, true)) {
			startServer(false);
		}
		Swing.runLater(this::reattachRun);
	}

	/**
	 * ProgramPlugin calls this for every cursor move in the current program, and with null on a
	 * program switch, so the reverse link ({@code GET /current}) follows the CodeBrowser.
	 */
	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (navigator != null) {
			navigator.locationChanged(currentProgram, loc);
		}
	}

	@Override
	protected void dispose() {
		stopServer();
		launcher.stop(); // only the app this plugin started
		if (runWatch != null) {
			runWatch.stop(); // the pipeline process itself is detached and keeps running
		}
		tool.getOptions(OPTIONS_CATEGORY).removeOptionsChangeListener(this);
		super.dispose();
	}

	// ---------------------------------------------------------------------------------------
	// Options and actions
	// ---------------------------------------------------------------------------------------

	private ToolOptions registerOptions() {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		options.registerOption(OPTION_HOST, DEFAULT_HOST, null,
			"Loopback address the navigation server binds to (localhost only).");
		options.registerOption(OPTION_PORT, DEFAULT_PORT, null,
			"Port of the navigation server; must match GHIDRA_PORT in the Dash app's config.py.");
		options.registerOption(OPTION_AUTOSTART, true, null,
			"Start the navigation server when this tool opens.");
		options.registerOption(OPTION_DASH_PORT, DEFAULT_DASH_PORT, null,
			"Port the MAPTER Dash app is served on (http://127.0.0.1:<port>).");
		options.registerOption(OPTION_PYTHON, "", null,
			"Python environment folder (venv/conda) or python executable that runs the MAPTER " +
				"app; easiest to pick with Tools > MAPTER > Python Environment. Empty: the " +
				"default mapter-venv, else a .venv next to app.py, else python3 on PATH.");
		String old = options.getString(OLD_OPTION_PYTHON, "");
		if (!old.isBlank() && options.getString(OPTION_PYTHON, "").isBlank()) {
			options.setString(OPTION_PYTHON, old);
		}
		options.removeOption(OLD_OPTION_PYTHON);
		options.registerOption(OPTION_APP_DIR, "", null,
			"Folder holding the MAPTER app.py (e.g. a repo checkout). Empty: the copy bundled " +
				"with this extension.");
		options.registerOption(OPTION_PIPELINE_PYTHON, "", null,
			"Python environment folder (venv/conda) or python executable that runs the MAPTER " +
				"generation pipeline (torch, r2pipe, scikit-learn...); easiest to pick in " +
				"Tools > MAPTER > Run MAPTER Pipeline. Empty: the default mapter-pipeline-venv, " +
				"else a .venv next to mapter_pipeline.py, else python3 on PATH.");
		options.registerOption(OPTION_BACKEND_DIR, "", null,
			"Folder holding mapter_pipeline.py (e.g. a repo checkout of MAPTER_backend). " +
				"Empty: the copy bundled with this extension.");
		options.registerOption(OPTION_MODEL_DIR, "", null,
			"Folder with the SAFE model (SAFEtorch.pt, word2id.json). Empty: model/ inside the " +
				"MAPTER Backend Folder (bundled with the extension).");
		options.registerOption(OPTION_R2, "", null,
			"Path of the radare2 executable (version 6 or newer). Empty: found automatically " +
				"(PATH, Homebrew locations).");
		options.registerOption(OPTION_CAPA, "", null,
			"Path of the capa executable. Empty: found automatically (PATH, the tool downloaded " +
				"with 'Install capa' in the pipeline dialog).");
		options.addOptionsChangeListener(this);
		return options;
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		if (OPTION_HOST.equals(optionName) && !isLoopback((String) newValue)) {
			throw new OptionsVetoException(
				OPTION_HOST + " must be a loopback address such as 127.0.0.1 or localhost");
		}
		if (OPTION_PORT.equals(optionName) || OPTION_DASH_PORT.equals(optionName)) {
			int port = (Integer) newValue;
			if (port < 1 || port > 65535) {
				throw new OptionsVetoException(optionName + " must be between 1 and 65535");
			}
		}
		boolean addressChanged = OPTION_HOST.equals(optionName) || OPTION_PORT.equals(optionName);
		if (addressChanged && server != null) {
			stopServer();
			startServer(true);
		}
	}

	private void createActions() {
		serverAction = new ToggleActionBuilder("MAPTER Navigation Server", getName())
				.menuPath("Tools", "MAPTER", "Navigation Server")
				.menuGroup("MAPTER", "3")
				.description("Start/stop the localhost server the MAPTER Dash app uses to " +
					"navigate this CodeBrowser")
				.onAction(context -> {
					if (serverAction.isSelected()) {
						startServer(true);
					}
					else {
						stopServer();
					}
				})
				.build();
		install(serverAction);

		install(new ActionBuilder("MAPTER Data Folder", getName())
				.menuPath("Tools", "MAPTER", "MAPTER Data Folder...")
				.menuGroup("MAPTER", "0")
				.description("Choose the MAPTER data (embeddings) for this Ghidra project")
				.onAction(context -> chooseDataFolder())
				.build());
		install(new ActionBuilder("Run MAPTER Pipeline", getName())
				.menuPath("Tools", "MAPTER", "Run MAPTER Pipeline...")
				.menuGroup("MAPTER", "05")
				.description("Generate MAPTER data (SAFE embeddings, CAPA, AVClass, 2D map) from " +
					"this project's programs or a folder of binaries")
				.onAction(context -> showPipelineDialog())
				.build());
		install(new ActionBuilder("Open MAPTER", getName())
				.menuPath("Tools", "MAPTER", "Open MAPTER")
				.menuGroup("MAPTER", "1")
				.description("Open the MAPTER Dash app in the browser, starting it if needed")
				.onAction(context -> openMapter())
				.build());
		install(new ActionBuilder("Stop MAPTER App", getName())
				.menuPath("Tools", "MAPTER", "Stop MAPTER App")
				.menuGroup("MAPTER", "2")
				.description("Stop the MAPTER Dash app (started here or by hand)")
				// Always enabled: Ghidra re-evaluates menu enablement only on context
				// changes, not when the app process starts or exits.
				.onAction(context -> stopApp())
				.build());
		install(new ActionBuilder("MAPTER Python Environment", getName())
				.menuPath("Tools", "MAPTER", "Python Environment...")
				.menuGroup("MAPTER", "4")
				.description("Find, choose or create the Python environment that runs MAPTER")
				.onAction(context -> showPythonEnvironmentDialog())
				.build());
	}

	private void install(DockingAction action) {
		action.markHelpUnnecessary();
		tool.addAction(action);
	}

	// ---------------------------------------------------------------------------------------
	// Server lifecycle (Swing thread)
	// ---------------------------------------------------------------------------------------

	/** @param interactive show an error dialog on failure (auto-start only logs it) */
	private void startServer(boolean interactive) {
		if (server != null) {
			return;
		}
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		String host = options.getString(OPTION_HOST, DEFAULT_HOST).strip();
		int port = options.getInt(OPTION_PORT, DEFAULT_PORT);
		try {
			if (!isLoopback(host)) {
				throw new IOException("'" + host + "' is not a loopback address");
			}
			server = NavigationServer.start(host, port, navigator,
				() -> Swing.runLater(this::stopServer));
			report("MAPTER navigation server listening on " + server.url(), false);
		}
		catch (IOException e) {
			String message = "MAPTER navigation server could not start on " + host + ":" + port +
				" (" + e.getMessage() + "). Is another CodeBrowser window or program using it?";
			if (interactive) {
				Msg.showError(this, tool.getToolFrame(), TITLE, message);
			}
			report(message, true);
		}
		updateAction();
	}

	private void stopServer() {
		if (server == null) {
			return;
		}
		server.stop();
		server = null;
		report("MAPTER navigation server stopped", false);
		updateAction();
	}

	// ---------------------------------------------------------------------------------------
	// MAPTER Dash app (Swing thread; the slow parts run in a modal task)
	// ---------------------------------------------------------------------------------------

	/** Opens the app in the browser, starting the bundled/configured app if nothing listens. */
	private void openMapter() {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		int dashPort = options.getInt(OPTION_DASH_PORT, DEFAULT_DASH_PORT);
		String url = "http://127.0.0.1:" + dashPort + "/";
		startServer(true); // plot clicks need it; no-op if running
		String data = projectDataFolder();
		if (launcher.isRunning() && !launcher.dataFolder().equals(data)) {
			launcher.stop(); // started for another project / folder: restart below
		}
		if (DashLauncher.isListening(dashPort)) {
			openBrowser(url); // already running (from here or started by hand)
			return;
		}
		launcher.stop(); // a previous start that never came up

		File appDir;
		try {
			appDir = DashLauncher.appDir(options.getString(OPTION_APP_DIR, ""));
		}
		catch (IOException e) {
			Msg.showError(this, tool.getToolFrame(), TITLE, "MAPTER app not found: " +
				e.getMessage() + "\nCheck Edit > Tool Options > " + OPTIONS_CATEGORY + " > " +
				OPTION_APP_DIR + ".");
			return;
		}
		String python = PythonEnvironments.resolve(options.getString(OPTION_PYTHON, ""), appDir,
			PythonEnvironments.APP);
		int ghidraPort = options.getInt(OPTION_PORT, DEFAULT_PORT);
		TaskLauncher.launchModal("Starting MAPTER", monitor -> {
			try {
				monitor.setMessage("Checking " + python + "...");
				PythonEnv env = PythonEnvironments.check(new File(python), "configured",
					PythonEnvironments.requirements(appDir, PythonEnvironments.APP),
					PythonEnvironments.APP);
				if (!env.ready()) {
					Swing.runLater(() -> offerPythonEnvironmentDialog(env));
					return;
				}
				launcher.start(python, appDir, data, dashPort, ghidraPort, monitor);
				Swing.runLater(() -> {
					report("MAPTER app running at " + url, false);
					openBrowser(url);
				});
			}
			catch (CancelledException e) {
				Swing.runLater(() -> report("MAPTER app start cancelled", false));
			}
			catch (IOException e) {
				Msg.showError(this, null, TITLE, "Could not start the MAPTER app with " + python +
					":\n" + e.getMessage() + "\n\nTo use another Python, see Tools > MAPTER > " +
					"Python Environment.");
			}
		});
	}

	// ---------------------------------------------------------------------------------------
	// MAPTER data folder (per Ghidra project)
	// ---------------------------------------------------------------------------------------

	/** The MAPTER data folder saved in the current project; blank = bundled sample data. */
	private String projectDataFolder() {
		return ProjectState.get(tool.getProject(), ProjectState.DATA_FOLDER);
	}

	/** Sets the data folder; the project's other saved keys (pipeline run) are kept. */
	private void setProjectDataFolder(Project project, String folder) {
		ProjectState.put(project, ProjectState.DATA_FOLDER, folder);
	}

	/**
	 * Lets the user pick this project's MAPTER data folder (or go back to the sample data). The
	 * folder layout is the contract in the app's dataset_registry.py / datasets/README.md, which
	 * the MAPTER generation pipeline is meant to write as well.
	 */
	private void chooseDataFolder() {
		Project project = tool.getProject();
		if (project == null) {
			Msg.showError(this, tool.getToolFrame(), TITLE, "Open a Ghidra project first.");
			return;
		}
		String current = projectDataFolder();
		int choice = OptionDialog.showOptionDialog(tool.getToolFrame(), "MAPTER Data Folder",
			"Project '" + project.getName() + "' uses:\n" +
				(current.isBlank() ? "the bundled sample data (APT 19)" : current) +
				"\n\nA MAPTER data folder holds reduced.pkl (required), and optionally " +
				"avclass.pkl,\na capa/ folder and dataset.json (see datasets/README.md).",
			"Choose Folder...", "Use Sample Data", OptionDialog.QUESTION_MESSAGE);
		String chosen;
		if (choice == OptionDialog.OPTION_ONE) {
			GhidraFileChooser chooser = new GhidraFileChooser(tool.getToolFrame());
			chooser.setTitle("MAPTER Data Folder for " + project.getName());
			chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			chooser.setApproveButtonText("Use Folder");
			if (!current.isBlank()) {
				chooser.setCurrentDirectory(new File(current));
			}
			File folder = chooser.getSelectedFile();
			chooser.dispose();
			if (folder == null) {
				return;
			}
			if (!new File(folder, "reduced.pkl").isFile()) {
				Msg.showError(this, tool.getToolFrame(), TITLE, folder +
					" has no reduced.pkl, so it is not a MAPTER data folder.");
				return;
			}
			chosen = folder.getPath();
		}
		else if (choice == OptionDialog.OPTION_TWO) {
			chosen = "";
		}
		else {
			return;
		}
		setProjectDataFolder(project, chosen);
		report("MAPTER data for project " + project.getName() + ": " +
			(chosen.isBlank() ? "sample data" : chosen), false);
		if (launcher.isRunning() && !launcher.dataFolder().equals(chosen) &&
			OptionDialog.showYesNoDialog(tool.getToolFrame(), TITLE,
				"Restart the MAPTER app with this data?") == OptionDialog.YES_OPTION) {
			openMapter(); // restarts because the folder changed
		}
	}

	/**
	 * Stops the app this tool started; otherwise asks a MAPTER app found on the Dash port (e.g.
	 * started by hand) to shut down.
	 */
	private void stopApp() {
		if (launcher.isRunning()) {
			launcher.stop();
			report("MAPTER app stopped", false);
			return;
		}
		int dashPort = tool.getOptions(OPTIONS_CATEGORY).getInt(OPTION_DASH_PORT, DEFAULT_DASH_PORT);
		if (!DashLauncher.isListening(dashPort)) {
			report("MAPTER app is not running", false);
			return;
		}
		if (DashLauncher.requestShutdown(dashPort)) {
			report("MAPTER app on port " + dashPort + " stopped", false);
		}
		else {
			Msg.showError(this, tool.getToolFrame(), TITLE, "Something listens on port " +
				dashPort + " but did not stop (not a MAPTER app, or an older version of it).\n" +
				"Stop it where it was started.");
		}
	}

	private void openBrowser(String url) {
		try {
			BrowserLoader.display(URI.create(url).toURL());
		}
		catch (IOException | IllegalArgumentException e) {
			Msg.showError(this, tool.getToolFrame(), TITLE, "Open " + url + " in your browser.");
		}
	}

	private void offerPythonEnvironmentDialog(PythonEnv env) {
		int answer = OptionDialog.showYesNoDialog(tool.getToolFrame(), TITLE,
			"MAPTER's Python is not ready:\n" + env.python() + "\n" + env.status() +
				"\n\nOpen the Python Environment dialog to choose or create one?");
		if (answer == OptionDialog.YES_OPTION) {
			showPythonEnvironmentDialog();
		}
	}

	/** Find, browse to, or create the Python environment; the choice updates the option. */
	private void showPythonEnvironmentDialog() {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		try {
			File appDir = DashLauncher.appDir(options.getString(OPTION_APP_DIR, ""));
			tool.showDialog(new PythonEnvironmentDialog(PythonEnvironments.APP, appDir,
				options.getString(OPTION_PYTHON, ""),
				value -> options.setString(OPTION_PYTHON, value)));
		}
		catch (IOException e) {
			Msg.showError(this, tool.getToolFrame(), TITLE, "MAPTER app not found: " +
				e.getMessage() + "\nCheck Edit > Tool Options > " + OPTIONS_CATEGORY + " > " +
				OPTION_APP_DIR + ".");
		}
	}

	// ---------------------------------------------------------------------------------------
	// MAPTER generation pipeline (Swing thread)
	// ---------------------------------------------------------------------------------------

	private void showPipelineDialog() {
		Project project = tool.getProject();
		if (project == null) {
			Msg.showError(this, tool.getToolFrame(), TITLE, "Open a Ghidra project first.");
			return;
		}
		if (pipelineDialog != null && pipelineDialog.isVisible()) {
			pipelineDialog.toFront();
			return;
		}
		pipelineDialog = new PipelineDialog(tool, new PipelineDialog.Host() {
			@Override
			public PipelineLauncher.Settings settings() throws IOException {
				return PipelineLauncher.Settings.fromOptions(tool.getOptions(OPTIONS_CATEGORY));
			}

			@Override
			public void editPythonEnvironment(Runnable onChanged) {
				showPipelinePythonEnvironmentDialog(onChanged);
			}

			@Override
			public void runStarted(File work, long pid) {
				pipelineRunStarted(work, pid);
			}

			@Override
			public File savedWork() {
				String work = ProjectState.get(tool.getProject(), ProjectState.PIPELINE_WORK);
				return work.isBlank() ? null : new File(work);
			}

			@Override
			public long savedPid() {
				return savedPipelinePid();
			}
		});
		tool.showDialog(pipelineDialog);
	}

	private void showPipelinePythonEnvironmentDialog(Runnable onChanged) {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		try {
			File backend = PipelineLauncher.backendDir(options.getString(OPTION_BACKEND_DIR, ""));
			tool.showDialog(new PythonEnvironmentDialog(PythonEnvironments.PIPELINE, backend,
				options.getString(OPTION_PIPELINE_PYTHON, ""), value -> {
					options.setString(OPTION_PIPELINE_PYTHON, value);
					onChanged.run();
				}));
		}
		catch (IOException e) {
			Msg.showError(this, tool.getToolFrame(), TITLE, "MAPTER backend not found: " +
				e.getMessage() + "\nCheck Edit > Tool Options > " + OPTIONS_CATEGORY + " > " +
				OPTION_BACKEND_DIR + ".");
		}
	}

	private long savedPipelinePid() {
		try {
			return Long.parseLong(ProjectState.get(tool.getProject(), ProjectState.PIPELINE_PID));
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	/** A run was started from the dialog: remember it in the project and follow it. */
	private void pipelineRunStarted(File work, long pid) {
		ProjectState.putAll(tool.getProject(), new String[][] {
			{ ProjectState.PIPELINE_WORK, work.getPath() },
			{ ProjectState.PIPELINE_PID, Long.toString(pid) } });
		lastRunStage = "";
		report("MAPTER pipeline started (work folder " + work + ")", false);
		watchRun();
	}

	/** After opening the tool: pick up a run started in an earlier session. */
	private void reattachRun() {
		Project project = tool.getProject();
		if (project == null) { // tool not yet attached to its project: try again shortly
			if (reattachAttempts++ < 5) {
				Timer retry = new Timer(1500, e -> reattachRun());
				retry.setRepeats(false);
				retry.start();
			}
			return;
		}
		String work = ProjectState.get(project, ProjectState.PIPELINE_WORK);
		if (work.isBlank()) {
			return;
		}
		Run run = PipelineLauncher.inspect(new File(work), savedPipelinePid());
		if (run.phase().isActive()) {
			report("MAPTER pipeline is running" + stageText(run.status()) +
				" (Tools > MAPTER > Run MAPTER Pipeline shows progress)", false);
			watchRun();
		}
		else if (run.phase().isFinished()) {
			finishRun(run, false);
		}
	}

	private void watchRun() {
		if (runWatch == null) {
			runWatch = new Timer(RUN_WATCH_MILLIS, e -> checkRun());
		}
		if (!runWatch.isRunning()) {
			runWatch.start();
		}
	}

	private void checkRun() {
		Project project = tool.getProject();
		String work = ProjectState.get(project, ProjectState.PIPELINE_WORK);
		if (work.isBlank()) {
			runWatch.stop();
			return;
		}
		Run run = PipelineLauncher.inspect(new File(work), savedPipelinePid());
		if (run.phase().isActive()) {
			String stage = stageText(run.status());
			if (!stage.equals(lastRunStage)) {
				lastRunStage = stage;
				tool.setStatusInfo("MAPTER pipeline running" + stage);
			}
			return;
		}
		runWatch.stop();
		if (run.phase().isFinished()) {
			finishRun(run, true);
		}
	}

	private static String stageText(RunStatus st) {
		return st == null || st.stage().isBlank() ? ""
				: " - stage " + st.stageIndex() + "/" + st.nStages() + " " + st.stage();
	}

	/**
	 * A pipeline run ended. Success makes its output the project's MAPTER data folder. Each
	 * run is applied once (its {@code started} stamp is remembered in the project).
	 *
	 * @param interactive the user is working in Ghidra: offer to open MAPTER, show errors
	 */
	private void finishRun(Run run, boolean interactive) {
		Project project = tool.getProject();
		RunStatus st = run.status();
		String key = st == null ? "" : st.startedKey();
		if (!key.isEmpty() && key.equals(ProjectState.get(project, ProjectState.PIPELINE_HANDLED))) {
			return;
		}
		ProjectState.put(project, ProjectState.PIPELINE_HANDLED, key);
		if (run.phase() == Phase.DONE && st != null && new File(st.out(), "reduced.pkl").isFile()) {
			setProjectDataFolder(project, st.out());
			report("MAPTER pipeline finished; data folder of project " + project.getName() +
				" set to " + st.out(), false);
			if (interactive) {
				offerOpenMapter(st.out());
			}
		}
		else if (run.phase() == Phase.DONE) {
			String message = "MAPTER pipeline finished but " + (st == null ? "?" : st.out()) +
				" has no reduced.pkl";
			report(message, true);
			if (interactive) {
				Msg.showError(this, tool.getToolFrame(), TITLE, message);
			}
		}
		else if (run.phase() == Phase.CANCELLED) {
			report("MAPTER pipeline cancelled (run it again to resume)", false);
		}
		else {
			String why = run.phase() == Phase.INTERRUPTED
					? "the process ended without finishing"
					: st == null || st.error().isBlank() ? "see pipeline.log" : st.error();
			report("MAPTER pipeline failed: " + why, true);
			if (interactive) {
				Msg.showError(this, tool.getToolFrame(), TITLE,
					"The MAPTER pipeline did not finish: " + why +
						"\nDetails: Tools > MAPTER > Run MAPTER Pipeline > Open Log.");
			}
		}
	}

	private void offerOpenMapter(String dataFolder) {
		boolean restart = launcher.isRunning() && !launcher.dataFolder().equals(dataFolder);
		int answer = OptionDialog.showYesNoDialog(tool.getToolFrame(), TITLE,
			"The MAPTER pipeline finished and its data is now this project's MAPTER data folder:\n" +
				dataFolder + "\n\n" + (restart ? "Restart the MAPTER app with the new data?"
						: "Open MAPTER now?"));
		if (answer == OptionDialog.YES_OPTION) {
			openMapter(); // restarts the app if its data folder differs
		}
	}

	private void updateAction() {
		if (serverAction != null) {
			serverAction.setSelected(server != null);
		}
	}

	private void report(String message, boolean isError) {
		if (isError) {
			Msg.warn(this, message);
		}
		else {
			Msg.info(this, message);
		}
		tool.setStatusInfo(message, isError);
	}

	private static boolean isLoopback(String host) {
		if (host == null || host.isBlank()) {
			return false;
		}
		try {
			return InetAddress.getByName(host.strip()).isLoopbackAddress();
		}
		catch (UnknownHostException e) {
			return false;
		}
	}
}
