package mapterbridge;

import java.awt.*;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import mapterbridge.PipelineLauncher.Phase;
import mapterbridge.PipelineLauncher.Run;
import mapterbridge.PipelineLauncher.RunStatus;
import mapterbridge.PipelineLauncher.Settings;
import mapterbridge.PythonEnvironments.PythonEnv;

/**
 * Tools &rarr; MAPTER &rarr; Run MAPTER Pipeline...: generates MAPTER data (SAFE embeddings, CAPA,
 * AVClass labels, 2D map) from this project's programs or from a folder of binaries.
 *
 * <p>The dialog only configures and monitors: the pipeline is a detached command line process
 * ({@link PipelineLauncher}) that keeps running if the dialog or Ghidra is closed. Progress is
 * read from the run's {@code status.json} every 2 seconds, so reopening the dialog (even after a
 * restart) shows a run in progress. Applying a finished run's result to the project is done by
 * the plugin, not here.
 */
final class PipelineDialog extends DialogComponentProvider {

	/** What the dialog needs from the plugin. */
	interface Host {

		/** Current options resolved for running the CLI. */
		Settings settings() throws IOException;

		/** Opens the pipeline Python environment dialog; {@code onChanged} runs after a choice. */
		void editPythonEnvironment(Runnable onChanged);

		/** A run was started in {@code work} (pid): persist it in the project and watch it. */
		void runStarted(File work, long pid);

		/** Work folder of the last run started from this project, or null. */
		File savedWork();

		long savedPid();
	}

	private enum Method {
		TSNE("t-SNE sweep (default)", "tsne"),
		UMAP("UMAP (needs umap-learn)", "umap"),
		PCA("PCA only (fast, rough map)", "pca"),
		FIXED("Fixed, legacy (PCA 40 + t-SNE perplexity 50)", "fixed");

		final String label;
		final String cli;

		Method(String label, String cli) {
			this.label = label;
			this.cli = cli;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private static final int POLL_MILLIS = 2000;

	private final PluginTool tool;
	private final Host host;
	private final String projectName;
	private final int programCount;

	private final JRadioButton projectRadio;
	private final JRadioButton folderRadio = new JRadioButton("A folder of binaries:");
	private final JTextField folderField = new JTextField();
	private final JButton folderBrowse = new JButton("Browse...");
	private final JTextField workField = new JTextField();
	private final JTextField nameField = new JTextField();
	private final JComboBox<Method> methodBox = new JComboBox<>(Method.values());
	private final JTextField vtReportsField = new JTextField();
	private final JCheckBox vtFetch = new JCheckBox("Fetch missing reports from VirusTotal");
	private final JPasswordField vtKey = new JPasswordField();

	private final JLabel pythonLabel = new JLabel(" ");
	private final JLabel checkLabel = new JLabel(" ");
	private final JButton pythonButton = new JButton("Python Environment...");
	private final JButton installCapaButton = new JButton("Install capa");
	private final JButton installR2Button = new JButton("Install radare2");
	private final JButton recheckButton = new JButton("Check again");

	private final JProgressBar bar = new JProgressBar(0, 100);
	private final JLabel stageLabel = new JLabel(" ");
	private final JLabel detailLabel = new JLabel(" ");

	private final JButton runButton = new JButton("Run");
	private final JButton cancelRunButton = new JButton("Cancel Run");
	private final JButton logButton = new JButton("Open Log");

	private final javax.swing.Timer poller = new javax.swing.Timer(POLL_MILLIS, e -> refreshRun());

	/** The run shown in the progress panel (null: none yet). Swing thread only. */
	private File trackedWork;
	private long trackedPid;
	private boolean cancelRequested;
	private int busy; // tasks scheduled or running
	private boolean prerequisitesOk;
	private boolean umapAvailable = true; // unknown until checked
	private Run lastRun = Run.NONE;

	PipelineDialog(PluginTool tool, Host host) {
		super("Run MAPTER Pipeline", false, true, true, true);
		this.tool = tool;
		this.host = host;
		Project project = tool.getProject();
		this.projectName = project == null ? "project" : project.getName();
		this.programCount = BinaryMaterializer.programFiles(project).size();
		this.projectRadio = new JRadioButton(
			"Programs of this Ghidra project (" + programCount + ")", programCount > 0);
		this.folderRadio.setSelected(programCount == 0);
		this.trackedWork = host.savedWork();
		this.trackedPid = host.savedPid();

		ButtonGroup group = new ButtonGroup();
		group.add(projectRadio);
		group.add(folderRadio);
		projectRadio.setEnabled(programCount > 0);
		projectRadio.addActionListener(e -> updateInputs());
		folderRadio.addActionListener(e -> updateInputs());

		File work = trackedWork != null ? trackedWork : PipelineLauncher.defaultWorkDir(projectName);
		workField.setText(work.getPath());
		nameField.setText(projectName);
		vtFetch.addActionListener(e -> updateInputs());

		addWorkPanel(buildPanel());
		runButton.addActionListener(e -> run());
		addButton(runButton);
		cancelRunButton.addActionListener(e -> cancelRun());
		addButton(cancelRunButton);
		logButton.addActionListener(e -> openLog());
		addButton(logButton);
		addCancelButton();
		setCancelButtonText("Close");
		setPreferredSize(860, 780);
		updateInputs();
		updateButtons();
	}

	// ---------------------------------------------------------------------------------------
	// Layout
	// ---------------------------------------------------------------------------------------

	private JComponent buildPanel() {
		JPanel root = new JPanel();
		root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
		root.setBorder(BorderFactory.createEmptyBorder(8, 10, 0, 10));

		// Input
		JPanel input = section("Input");
		JPanel folderRow = new JPanel(new BorderLayout(6, 0));
		folderRow.add(folderRadio, BorderLayout.WEST);
		folderRow.add(folderField, BorderLayout.CENTER);
		folderBrowse.addActionListener(e -> browseInto(folderField, "Folder of Binaries"));
		folderRow.add(folderBrowse, BorderLayout.EAST);
		input.add(left(projectRadio));
		input.add(folderRow);
		root.add(input);

		// Output
		JPanel output = section("Output");
		JPanel grid = new JPanel(new GridBagLayout());
		addRow(grid, 0, "Work folder:", workField, browseButton(workField, "Work Folder"));
		addRow(grid, 1, "Dataset name:", nameField, null);
		addRow(grid, 2, "Dimensionality reduction:", methodBox, null);
		output.add(grid);
		root.add(output);

		// VirusTotal
		JPanel vt = section("AVClass labels (optional, from VirusTotal reports)");
		JPanel vtGrid = new JPanel(new GridBagLayout());
		addRow(vtGrid, 0, "Reports folder:", vtReportsField,
			browseButton(vtReportsField, "Folder of VirusTotal Reports (<sha256>.json)"));
		addRow(vtGrid, 1, "API key:", vtKey, null);
		vtKey.setToolTipText("Used for this run only and never stored. " +
			"Only hashes are looked up; files are never uploaded.");
		vt.add(vtGrid);
		vt.add(left(vtFetch));
		root.add(vt);

		// Prerequisites
		JPanel pre = section("Prerequisites");
		JPanel pythonRow = new JPanel(new BorderLayout(6, 0));
		pythonRow.add(pythonLabel, BorderLayout.CENTER);
		pythonButton.addActionListener(e -> host.editPythonEnvironment(this::checkPrerequisites));
		pythonRow.add(pythonButton, BorderLayout.EAST);
		pre.add(pythonRow);
		checkLabel.setVerticalAlignment(SwingConstants.TOP);
		pre.add(Box.createVerticalStrut(4));
		pre.add(left(checkLabel));
		JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
		installCapaButton.addActionListener(e -> install("capa"));
		installR2Button.addActionListener(e -> install("radare2"));
		recheckButton.addActionListener(e -> checkPrerequisites());
		buttons.add(installCapaButton);
		buttons.add(installR2Button);
		buttons.add(recheckButton);
		pre.add(left(buttons));
		root.add(pre);

		// Progress
		JPanel progress = section("Run");
		bar.setStringPainted(true);
		progress.add(bar);
		progress.add(Box.createVerticalStrut(4));
		progress.add(left(stageLabel));
		progress.add(left(detailLabel));
		root.add(progress);
		root.add(Box.createVerticalGlue());
		return root;
	}

	private static JPanel section(String title) {
		JPanel p = new JPanel();
		p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
		p.setBorder(BorderFactory.createCompoundBorder(
			BorderFactory.createTitledBorder(title),
			BorderFactory.createEmptyBorder(2, 6, 4, 6)));
		p.setAlignmentX(Component.LEFT_ALIGNMENT);
		return p;
	}

	private static JComponent left(JComponent c) {
		JPanel p = new JPanel(new BorderLayout());
		p.add(c, BorderLayout.WEST);
		p.setAlignmentX(Component.LEFT_ALIGNMENT);
		return p;
	}

	private static void addRow(JPanel grid, int row, String label, JComponent field,
			JComponent extra) {
		GridBagConstraints c = new GridBagConstraints();
		c.gridy = row;
		c.insets = new Insets(2, 0, 2, 6);
		c.anchor = GridBagConstraints.WEST;
		grid.add(new JLabel(label), c);
		c.weightx = 1;
		c.fill = GridBagConstraints.HORIZONTAL;
		grid.add(field, c);
		c.weightx = 0;
		c.fill = GridBagConstraints.NONE;
		if (extra != null) {
			grid.add(extra, c);
		}
	}

	private JButton browseButton(JTextField target, String title) {
		JButton b = new JButton("Browse...");
		b.addActionListener(e -> browseInto(target, title));
		return b;
	}

	private void browseInto(JTextField target, String title) {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setTitle(title);
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		chooser.setApproveButtonText("Select");
		String current = target.getText().strip();
		if (!current.isEmpty() && new File(current).isDirectory()) {
			chooser.setCurrentDirectory(new File(current));
		}
		File chosen = chooser.getSelectedFile();
		chooser.dispose();
		if (chosen != null) {
			target.setText(chosen.getPath());
		}
	}

	// ---------------------------------------------------------------------------------------
	// Lifecycle
	// ---------------------------------------------------------------------------------------

	@Override
	protected void dialogShown() {
		poller.start();
		refreshRun();
		checkPrerequisites();
	}

	@Override
	protected void dialogClosed() {
		poller.stop(); // the pipeline itself keeps running
	}

	private void updateInputs() {
		boolean folder = folderRadio.isSelected();
		folderField.setEnabled(folder);
		folderBrowse.setEnabled(folder);
		vtKey.setEnabled(vtFetch.isSelected());
	}

	private void updateButtons() {
		boolean active = lastRun.phase().isActive();
		boolean idle = busy == 0;
		runButton.setEnabled(idle && !active && prerequisitesOk);
		cancelRunButton.setEnabled(active);
		cancelRunButton.setText(active && cancelRequested ? "Force Stop" : "Cancel Run");
		pythonButton.setEnabled(idle);
		installCapaButton.setEnabled(idle);
		installR2Button.setEnabled(idle);
		recheckButton.setEnabled(idle);
		logButton.setEnabled(logFile() != null);
	}

	// ---------------------------------------------------------------------------------------
	// Prerequisites
	// ---------------------------------------------------------------------------------------

	/** Checks the Python environment and runs {@code mapter_pipeline.py --check}. */
	private void checkPrerequisites() {
		prerequisitesOk = false;
		pythonLabel.setText("Checking...");
		checkLabel.setText(" ");
		runTask("Checking prerequisites", monitor -> {
			Settings s;
			try {
				s = host.settings();
			}
			catch (IOException e) {
				Swing.runLater(() -> showPrerequisites(null, null, null, e.getMessage()));
				return;
			}
			monitor.setMessage("Checking " + s.python() + "...");
			PythonEnv env;
			JsonObject report = null;
			String reportError = null;
			try {
				env = PythonEnvironments.check(new File(s.python()), "pipeline",
					PythonEnvironments.requirements(s.backendDir(), PythonEnvironments.PIPELINE),
					PythonEnvironments.PIPELINE);
			}
			catch (IOException e) {
				Swing.runLater(() -> showPrerequisites(s, null, null, e.getMessage()));
				return;
			}
			if (env.error() == null) {
				monitor.setMessage("Checking radare2, capa and the SAFE model...");
				try {
					report = PipelineLauncher.runCheck(s, monitor);
				}
				catch (IOException e) {
					reportError = e.getMessage();
				}
			}
			JsonObject finalReport = report;
			String finalError = reportError;
			Swing.runLater(() -> showPrerequisites(s, env, finalReport, finalError));
		});
	}

	/** Swing thread. Fills the prerequisites panel and decides whether Run is possible. */
	private void showPrerequisites(Settings s, PythonEnv env, JsonObject report, String error) {
		StringBuilder pyText = new StringBuilder("<html><body style='width: 560px'>");
		if (s == null) {
			pyText.append("<b>✗ Pipeline files not found:</b> ").append(esc(error));
			pythonLabel.setText(pyText.toString());
			checkLabel.setText(" ");
			prerequisitesOk = false;
			updateButtons();
			return;
		}
		pyText.append("<b>Pipeline Python:</b> ").append(esc(s.python())).append(" &nbsp;");
		if (env == null) {
			pyText.append("✗ ").append(esc(error));
		}
		else {
			pyText.append(env.ready() ? "✔ " : "✗ ").append(esc(env.status()));
		}
		pythonLabel.setText(pyText.toString());

		StringBuilder sb = new StringBuilder("<html><body style='width: 740px'>");
		boolean ok = false;
		if (report != null) {
			// Gate on the pipeline's own check (required tools/packages only); missing optional
			// packages from the requirements file (avclass, umap) must not block a run.
			ok = env != null && env.error() == null && bool(report, "ok");
			JsonObject packages = obj(report, "packages");
			sb.append(item(toolLabel("radare2", obj(report, "radare2")), true, "required"));
			sb.append(item(toolLabel("capa", obj(report, "capa")), false,
				"optional: without it the CAPA columns stay empty (Install capa)"));
			JsonObject model = obj(report, "model");
			boolean modelOk = model != null && bool(model, "ok");
			sb.append(item(new String[] { "SAFE model " + (model == null ? "" :
				"(" + str(model, "dir") + ")"), modelOk ? "ok" : null }, true,
				"SAFEtorch.pt and word2id.json must be in the model folder"));
			StringBuilder pk = new StringBuilder();
			for (String name : List.of("torch", "r2pipe", "pandas", "numpy", "sklearn")) {
				pk.append(present(packages, name) ? "✔ " : "✗ ").append(name).append("&nbsp; ");
			}
			pk.append("&nbsp;optional: ");
			for (String name : List.of("avclass", "umap")) {
				pk.append(present(packages, name) ? "✔ " : "– ").append(name).append("&nbsp; ");
			}
			sb.append("Packages: ").append(pk).append("<br>");
			umapAvailable = present(packages, "umap");
			if (env != null && env.error() == null && !env.ready()) {
				sb.append("<font color='#b00020'>Missing or outdated: ")
						.append(esc(String.join(", ", env.missing())))
						.append("</font> (Python Environment... &rarr; Install Packages)<br>");
			}
			if (report.has("problems") && report.get("problems").isJsonArray()) {
				for (JsonElement p : report.getAsJsonArray("problems")) {
					sb.append("<font color='#b00020'>! ").append(esc(p.getAsString()))
							.append("</font><br>");
				}
			}
		}
		else if (env != null && env.error() == null && !env.ready()) {
			sb.append("Missing packages in the pipeline environment: ")
					.append(esc(String.join(", ", env.missing())))
					.append("<br>Use <b>Python Environment...</b> &rarr; Install Packages.");
		}
		else if (error != null) {
			sb.append("<font color='#b00020'>").append(esc(error).replace("\n", "<br>"))
					.append("</font>");
		}
		checkLabel.setText(sb.toString());
		prerequisitesOk = ok;
		setStatusText(ok ? "Ready to run" : "Some prerequisites are missing",
			ok ? MessageType.INFO : MessageType.WARNING);
		updateButtons();
	}

	/** {name + version/path text, found-or-null} for a tool object {path, version} or null. */
	private static String[] toolLabel(String name, JsonObject o) {
		if (o == null) {
			return new String[] { name, null };
		}
		String version = str(o, "version");
		String path = str(o, "path");
		return new String[] { name + (version.isEmpty() ? "" : " " + version) +
			(path.isEmpty() ? "" : " (" + path + ")"), "ok" };
	}

	private static String item(String[] label, boolean required, String hint) {
		boolean found = label[1] != null;
		return (found ? "✔ " : required ? "✗ " : "– ") + esc(label[0]) +
			(found ? "" : " <i>not found - " + esc(hint) + "</i>") + "<br>";
	}

	private static JsonObject obj(JsonObject o, String key) {
		return o != null && o.has(key) && o.get(key).isJsonObject() ? o.getAsJsonObject(key)
				: null;
	}

	private static boolean bool(JsonObject o, String key) {
		JsonElement e = o.get(key);
		return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isBoolean() &&
			e.getAsBoolean();
	}

	private static String str(JsonObject o, String key) {
		JsonElement e = o.get(key);
		return e == null || e.isJsonNull() ? "" : e.getAsString();
	}

	/** A package entry counts as present unless it is absent, null, false or empty. */
	private static boolean present(JsonObject packages, String name) {
		JsonElement e = packages == null ? null : packages.get(name);
		if (e == null || e.isJsonNull()) {
			return false;
		}
		if (e.isJsonPrimitive() && e.getAsJsonPrimitive().isBoolean()) {
			return e.getAsBoolean();
		}
		return !(e.isJsonPrimitive() && e.getAsString().isBlank());
	}

	private static String esc(String text) {
		return text == null ? "" : text.replace("&", "&amp;").replace("<", "&lt;")
				.replace(">", "&gt;");
	}

	/** Downloads/installs capa or radare2 with tools/install_tools.py, then re-checks. */
	private void install(String toolName) {
		runTask("Installing " + toolName, monitor -> {
			Settings s;
			try {
				s = host.settings();
			}
			catch (IOException e) {
				Msg.showError(this, getComponent(), "Install " + toolName, e.getMessage());
				return;
			}
			monitor.setMessage("Running install_tools.py " + toolName + " (this can take a while)...");
			PipelineLauncher.InstallResult r = PipelineLauncher.installTool(s, toolName, monitor);
			Swing.runLater(() -> {
				String text = toolName + ": " + r.message() +
					(r.path().isEmpty() ? "" : "\n" + r.path());
				if (r.ok()) {
					setStatusText(toolName + " ready" +
						(r.version().isEmpty() ? "" : " (" + r.version() + ")"));
				}
				else {
					setStatusText(toolName + " not installed", MessageType.WARNING);
					Msg.showWarn(PipelineDialog.class, getComponent(), "Install " + toolName,
						text);
				}
				checkPrerequisites();
			});
		});
	}

	// ---------------------------------------------------------------------------------------
	// Running
	// ---------------------------------------------------------------------------------------

	private void run() {
		boolean folderMode = folderRadio.isSelected();
		File folder = folderMode ? new File(folderField.getText().strip()) : null;
		if (folderMode && !folder.isDirectory()) {
			error("Choose an existing folder of binaries.");
			return;
		}
		if (!folderMode && programCount == 0) {
			error("This project has no programs; choose a folder of binaries instead.");
			return;
		}
		String workText = workField.getText().strip();
		if (workText.isEmpty()) {
			error("Choose a work folder.");
			return;
		}
		File work = new File(workText);
		String name = nameField.getText().strip().isEmpty() ? projectName
				: nameField.getText().strip();
		Method method = (Method) methodBox.getSelectedItem();
		if (method == Method.UMAP && !umapAvailable) {
			error("UMAP needs the optional umap-learn package in the pipeline environment " +
				"(see requirements-pipeline.txt), or choose t-SNE.");
			return;
		}
		String reportsText = vtReportsField.getText().strip();
		File reports = reportsText.isEmpty() ? null : new File(reportsText);
		if (reports != null && !reports.isDirectory()) {
			error("The VirusTotal reports folder does not exist: " + reports);
			return;
		}
		boolean fetch = vtFetch.isSelected();
		char[] password = vtKey.getPassword();
		String key = new String(password);
		Arrays.fill(password, '\0');
		if (fetch && key.isBlank() && System.getenv("VT_API_KEY") == null) {
			error("Enter a VirusTotal API key, or untick 'Fetch missing reports'.");
			return;
		}
		Settings s;
		try {
			s = host.settings();
		}
		catch (IOException e) {
			error(e.getMessage());
			return;
		}
		if (PipelineLauncher.activePid(work) > 0) {
			error("A pipeline run is already active in " + work + ".");
			return;
		}
		Project project = tool.getProject();

		cancelRequested = false;
		runTask("MAPTER pipeline", monitor -> {
			BinaryMaterializer.Result exported = null;
			if (!folderMode) {
				monitor.setMessage("Exporting the project's original binaries...");
				exported = BinaryMaterializer.run(project, work, monitor, this);
				if (exported.ok() == 0) {
					throw new IOException("None of the " + exported.entries().size() +
						" programs could be exported:\n" +
						String.join("\n", exported.problems().stream().limit(10).toList()));
				}
			}
			monitor.setMessage("Starting the pipeline...");
			long pid = PipelineLauncher.start(s, work, folder, name, method.cli, reports, fetch,
				key);
			BinaryMaterializer.Result result = exported;
			Swing.runLater(() -> started(work, pid, result));
		});
	}

	/** Swing thread: the process is up; track it and tell the plugin. */
	private void started(File work, long pid, BinaryMaterializer.Result exported) {
		trackedWork = work;
		trackedPid = pid;
		lastRun = new Run(Phase.STARTING, null);
		host.runStarted(work, pid);
		setStatusText("MAPTER pipeline started. It keeps running if you close this window.");
		refreshRun();
		if (exported != null) {
			List<String> problems = exported.problems();
			if (!problems.isEmpty()) {
				Msg.showWarn(PipelineDialog.class, getComponent(), "Programs skipped",
					exported.ok() + " program(s) exported, " + problems.size() +
						" skipped:\n\n" + String.join("\n",
							problems.stream().limit(15).toList()) +
						(problems.size() > 15 ? "\n..." : ""));
			}
		}
	}

	private void cancelRun() {
		long pid = currentPid();
		if (!lastRun.phase().isActive() || pid <= 0) {
			return;
		}
		if (!cancelRequested) {
			cancelRequested = true;
			PipelineLauncher.cancel(pid);
			setStatusText("Cancel requested: the pipeline finishes the current binary, then stops");
		}
		else if (OptionDialog.showYesNoDialog(getComponent(), "Force Stop",
			"Kill the pipeline now? The current binary is lost; finished results are kept " +
				"and a new run resumes from them.") == OptionDialog.YES_OPTION) {
			PipelineLauncher.kill(pid);
			setStatusText("Pipeline killed", MessageType.WARNING);
		}
		refreshRun();
	}

	private long currentPid() {
		RunStatus st = lastRun.status();
		return st != null && st.pid() > 0 ? st.pid() : trackedPid;
	}

	/** Swing thread, every 2 s: reads status.json and updates the progress panel. */
	private void refreshRun() {
		if (trackedWork == null) {
			lastRun = Run.NONE;
			showIdle("No run yet. Pick the input and press Run.", "");
			updateButtons();
			return;
		}
		lastRun = PipelineLauncher.inspect(trackedWork, trackedPid);
		RunStatus st = lastRun.status();
		switch (lastRun.phase()) {
			case NONE -> showIdle("No run in " + trackedWork, "");
			case STARTING -> {
				bar.setIndeterminate(true);
				bar.setString("starting");
				stageLabel.setText("Starting...");
				detailLabel.setText(" ");
			}
			case RUNNING -> {
				boolean known = st.total() > 0;
				bar.setIndeterminate(!known);
				if (known) {
					bar.setValue((int) Math.min(100, st.done() * 100 / st.total()));
					bar.setString(st.done() + " / " + st.total());
				}
				else {
					bar.setString(" ");
				}
				stageLabel.setText((cancelRequested ? "Cancelling... " : "") + "Stage " +
					st.stageIndex() + "/" + st.nStages() + ": " + st.stage());
				detailLabel.setText(joinNonBlank(st.current(), st.message()));
			}
			case DONE -> {
				bar.setIndeterminate(false);
				bar.setValue(100);
				bar.setString("done");
				stageLabel.setText("Done. Data folder: " + st.out());
				detailLabel.setText((st.failures() > 0 ? st.failures() +
					" binary/stage problem(s), see the log. " : "") +
					"The project's MAPTER data folder is set to this output.");
			}
			case FAILED -> showIdle("Failed: " + st.error(), "See the log for details.");
			case CANCELLED -> showIdle("Cancelled. Press Run to resume.", "");
			case INTERRUPTED -> showIdle("The pipeline process ended without finishing.",
				"Press Run to resume; finished results are kept.");
		}
		if (!lastRun.phase().isActive()) {
			cancelRequested = false;
		}
		updateButtons();
	}

	private void showIdle(String stage, String detail) {
		bar.setIndeterminate(false);
		bar.setValue(0);
		bar.setString(" ");
		stageLabel.setText(stage);
		detailLabel.setText(detail.isEmpty() ? " " : detail);
	}

	private static String joinNonBlank(String a, String b) {
		return a == null || a.isBlank() ? (b == null || b.isBlank() ? " " : b)
				: b == null || b.isBlank() ? a : a + "  -  " + b;
	}

	private File logFile() {
		File work = trackedWork != null ? trackedWork : new File(workField.getText().strip());
		for (String name : List.of("pipeline.log", PipelineLauncher.STDOUT_LOG)) {
			File f = new File(work, name);
			if (f.isFile()) {
				return f;
			}
		}
		return null;
	}

	private void openLog() {
		File log = logFile();
		if (log == null) {
			return;
		}
		try {
			if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
				Desktop.getDesktop().open(log);
				return;
			}
		}
		catch (IOException | RuntimeException e) {
			Msg.warn(this, "MapterBridge: could not open " + log + ": " + e.getMessage());
		}
		Msg.showInfo(this, getComponent(), "Pipeline log (last lines of " + log + ")",
			DashLauncher.tail(log, 40));
	}

	private void error(String message) {
		setStatusText(message, MessageType.ERROR);
	}

	// ---------------------------------------------------------------------------------------
	// Tasks (progress shown inside the dialog)
	// ---------------------------------------------------------------------------------------

	private interface Work {
		void run(TaskMonitor monitor) throws Exception;
	}

	private void runTask(String title, Work work) {
		busy++;
		updateButtons();
		// Runs in the dialog's own progress bar, which only accepts non-modal tasks.
		executeProgressTask(new Task(title, true, true, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					work.run(monitor);
				}
				catch (CancelledException e) {
					Swing.runLater(() -> setStatusText(title + " cancelled"));
				}
				catch (Exception e) {
					Swing.runLater(() -> setStatusText(title + " failed", MessageType.ERROR));
					Msg.showError(PipelineDialog.class, getComponent(), title, e.getMessage(), e);
				}
				finally {
					Swing.runLater(() -> {
						busy--;
						updateButtons();
					});
				}
			}
		}, 300);
	}
}
