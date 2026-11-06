package mapterbridge;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import mapterbridge.PythonEnvironments.Profile;
import mapterbridge.PythonEnvironments.PythonEnv;

/**
 * Chooses a Python environment for MAPTER (the Dash app or the generation pipeline, see
 * {@link Profile}): lists the environments found on this machine (checked against the profile's
 * requirements), or browse to one, create a new one, or install the missing packages into the
 * selected one. The choice is stored through {@code onUse}.
 */
final class PythonEnvironmentDialog extends DialogComponentProvider {

	private final Profile profile;
	private final File appDir; // folder with the requirements file (app or backend folder)
	private final List<String> requirements;
	private final Consumer<String> onUse;
	private String setting;

	private final DefaultListModel<PythonEnv> model = new DefaultListModel<>();
	private final JList<PythonEnv> list = new JList<>(model);
	private final JLabel currentLabel = new JLabel();
	private final JButton useButton = new JButton("Use Selected");
	private final JButton installButton = new JButton("Install Packages");

	/**
	 * @param profile which environment this is (app or pipeline)
	 * @param appDir folder holding the profile's requirements file
	 * @param setting the current option value (empty = automatic)
	 * @param onUse stores a new option value (called on the Swing thread)
	 */
	PythonEnvironmentDialog(Profile profile, File appDir, String setting, Consumer<String> onUse)
			throws IOException {
		super(profile.title(), true, true, true, true);
		this.profile = profile;
		this.appDir = appDir;
		this.requirements = PythonEnvironments.requirements(appDir, profile);
		this.setting = setting;
		this.onUse = onUse;

		addWorkPanel(buildPanel());
		useButton.addActionListener(e -> use(list.getSelectedValue()));
		addButton(useButton);
		JButton browse = new JButton("Browse...");
		browse.addActionListener(e -> browse());
		addButton(browse);
		JButton create = new JButton("Create New...");
		create.addActionListener(e -> createNew());
		addButton(create);
		installButton.addActionListener(e -> install(list.getSelectedValue()));
		addButton(installButton);
		JButton rescan = new JButton("Rescan");
		rescan.addActionListener(e -> scan());
		addButton(rescan);
		addCancelButton();
		setCancelButtonText("Close");
		setPreferredSize(820, 440);
		updateButtons();
	}

	private JComponent buildPanel() {
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.setCellRenderer(new DefaultListCellRenderer() {
			@Override
			public Component getListCellRendererComponent(JList<?> l, Object value, int index,
					boolean selected, boolean focus) {
				PythonEnv env = (PythonEnv) value;
				String text = (env.ready() ? "✔  " : "✗  ") + env.python() + "   [" +
					env.origin() + "]   " + env.status();
				return super.getListCellRendererComponent(l, text, index, selected, focus);
			}
		});
		list.addListSelectionListener(e -> updateButtons());

		JPanel panel = new JPanel(new BorderLayout(0, 8));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
		panel.add(currentLabel, BorderLayout.NORTH);
		panel.add(new JScrollPane(list), BorderLayout.CENTER);
		panel.add(new JLabel("<html>✔ has every package of " +
			profile.requirementsFile() + ". Choose one and press <Use Selected>, " +
			"or Browse to a venv/conda folder or a python executable (Note: '.' starting folders will not appear unless the checkbox <Show Hidden Files> is checked in top right icon of the file chooser)."), BorderLayout.SOUTH);
		updateCurrentLabel();
		return panel;
	}

	@Override
	protected void dialogShown() {
		scan();
	}

	private void updateCurrentLabel() {
		String python = PythonEnvironments.resolve(setting, appDir, profile);
		currentLabel.setText("<html><b>" + (profile == PythonEnvironments.APP ? "MAPTER uses:" : "The pipeline uses:") +
			"</b> " + python +
			(setting == null || setting.isBlank() ? " &nbsp;(automatic)" : ""));
	}

	private void updateButtons() {
		PythonEnv env = list.getSelectedValue();
		useButton.setEnabled(env != null && env.error() == null);
		installButton.setEnabled(env != null && env.isEnvironment());
	}

	// ---------------------------------------------------------------------------------------
	// Actions
	// ---------------------------------------------------------------------------------------

	/** Finds and checks the environments on this machine (ready ones first). */
	private void scan() {
		model.clear();
		updateButtons();
		runTask("Looking for Python environments", monitor -> {
			Map<File, String> candidates = PythonEnvironments.candidates(setting, appDir, profile);
			monitor.initialize(candidates.size());
			List<PythonEnv> found = new ArrayList<>();
			for (Map.Entry<File, String> c : candidates.entrySet()) {
				monitor.checkCancelled();
				monitor.setMessage("Checking " + c.getKey());
				found.add(PythonEnvironments.check(c.getKey(), c.getValue(), requirements,
					profile));
				monitor.incrementProgress(1);
			}
			found.sort(Comparator.comparing((PythonEnv e) -> !e.ready())
					.thenComparing(e -> e.error() != null));
			Swing.runLater(() -> {
				found.forEach(model::addElement);
				long ready = found.stream().filter(PythonEnv::ready).count();
				setStatusText(found.size() + " Python interpreter(s) found, " + ready + " ready");
				selectCurrent();
			});
		});
	}

	private void selectCurrent() {
		String python = PythonEnvironments.resolve(setting, appDir, profile);
		for (int i = 0; i < model.size(); i++) {
			if (model.get(i).python().getPath().equals(python)) {
				list.setSelectedIndex(i);
				return;
			}
		}
		if (!model.isEmpty()) {
			list.setSelectedIndex(0);
		}
	}

	/** Makes {@code env} MAPTER's Python; offers to complete it if packages are missing. */
	private void use(PythonEnv env) {
		if (env == null || env.error() != null) {
			return;
		}
		setting = env.setting();
		onUse.accept(setting);
		updateCurrentLabel();
		list.repaint();
		if (env.ready()) {
			setStatusText("MAPTER will use " + env.python());
		}
		else if (env.isEnvironment()) {
			int answer = OptionDialog.showYesNoDialog(getComponent(), "Missing Packages",
				"This environment lacks: " + String.join(", ", env.missing()) +
					"\n\nInstall them now? (needs internet)");
			if (answer == OptionDialog.YES_OPTION) {
				install(env);
			}
		}
		else {
			setStatusText("This system Python lacks packages; pip should not modify it. " +
				"Use Create New... to make an environment.", MessageType.WARNING);
		}
	}

	private void browse() {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setTitle("Choose a Python Environment Folder or Interpreter");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
		chooser.setApproveButtonText("Select");
		File chosen = chooser.getSelectedFile();
		chooser.dispose();
		if (chosen == null) {
			return;
		}
		File python = PythonEnvironments.interpreter(chosen);
		if (python == null) {
			setStatusText("No Python interpreter in " + chosen, MessageType.ERROR);
			return;
		}
		checkThenUse(python, "chosen");
	}

	private void createNew() {
		String path = OptionDialog.showInputSingleLineDialog(getComponent(),
			"Create " + profile.title(), "Folder for the new environment:",
			PythonEnvironments.defaultVenv(profile).getPath());
		if (path == null || path.isBlank()) {
			return;
		}
		File folder = new File(path.strip());
		String[] contents = folder.list();
		if (contents != null && contents.length > 0 &&
			PythonEnvironments.interpreter(folder) == null) {
			setStatusText(folder + " exists and is not a Python environment", MessageType.ERROR);
			return;
		}
		String basePython = PythonEnvironments.systemPython();
		int answer = OptionDialog.showYesNoDialog(getComponent(), "Create " + profile.title(),
			"Create a Python environment in\n" + folder + "\nwith " + basePython +
				" and install " + profile.requirementsFile() +
				"?\n\nNeeds internet access and takes a few minutes.\nLog: " +
				PythonEnvironments.setupLog(profile));
		if (answer != OptionDialog.YES_OPTION) {
			return;
		}
		runTask("Creating Python environment", monitor -> {
			File python = PythonEnvironments.create(basePython, folder, appDir, profile, monitor);
			finishCheck(python, "created");
		});
	}

	private void install(PythonEnv env) {
		if (env == null || !env.isEnvironment()) {
			return;
		}
		runTask("Installing MAPTER packages", monitor -> {
			PythonEnvironments.install(env.python(), appDir, profile, monitor);
			finishCheck(env.python(), env.origin());
		});
	}

	private void checkThenUse(File python, String origin) {
		runTask("Checking " + python, monitor -> finishCheck(python, origin));
	}

	/** Re-checks an interpreter after a change, shows it in the list and uses it. */
	private void finishCheck(File python, String origin) {
		PythonEnv env = PythonEnvironments.check(python, origin, requirements, profile);
		Swing.runLater(() -> {
			for (int i = model.size() - 1; i >= 0; i--) {
				if (model.get(i).python().equals(python)) {
					model.remove(i);
				}
			}
			model.add(0, env);
			list.setSelectedIndex(0);
			if (env.error() == null) {
				use(env);
			}
			else {
				setStatusText(python + ": " + env.status(), MessageType.ERROR);
			}
		});
	}

	// ---------------------------------------------------------------------------------------
	// Tasks (progress shown inside the dialog)
	// ---------------------------------------------------------------------------------------

	private interface Work {
		void run(TaskMonitor monitor) throws Exception;
	}

	private void runTask(String title, Work work) {
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
					Msg.showError(PythonEnvironmentDialog.class, getComponent(),
						profile.title(), e.getMessage());
				}
			}
		}, 300);
	}
}
