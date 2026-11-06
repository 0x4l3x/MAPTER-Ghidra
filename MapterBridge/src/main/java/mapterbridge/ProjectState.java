package mapterbridge;

import ghidra.framework.model.Project;
import ghidra.framework.options.SaveState;

/**
 * Per-project storage of this extension (saved with the Ghidra project): the MAPTER data folder
 * and the generation pipeline run bookkeeping. All values are strings under one SaveState, and
 * writing one key keeps the others.
 */
final class ProjectState {

	private static final String STATE_KEY = "MapterBridge";
	static final String DATA_FOLDER = "dataFolder";
	/** Work folder of the last pipeline run started from this project. */
	static final String PIPELINE_WORK = "pipelineWork";
	/** Pid of that run's process (it outlives Ghidra, so it is re-attached by pid). */
	static final String PIPELINE_PID = "pipelinePid";
	/** {@code started} stamp of the last run whose result was already applied to the project. */
	static final String PIPELINE_HANDLED = "pipelineHandled";

	private ProjectState() {
	}

	static String get(Project project, String key) {
		SaveState state = project == null ? null : project.getSaveableData(STATE_KEY);
		return state == null ? "" : state.getString(key, "");
	}

	/** Sets {@code key}, keeping every other key of the project's state. */
	static void put(Project project, String key, String value) {
		putAll(project, new String[][] { { key, value } });
	}

	/** Sets several {@code {key, value}} pairs at once, keeping every other key. */
	static void putAll(Project project, String[][] pairs) {
		if (project == null) {
			return;
		}
		SaveState old = project.getSaveableData(STATE_KEY);
		SaveState state = new SaveState();
		if (old != null) {
			for (String name : old.getNames()) {
				state.putString(name, old.getString(name, ""));
			}
		}
		for (String[] pair : pairs) {
			state.putString(pair[0], pair[1]);
		}
		project.setSaveableData(STATE_KEY, state);
	}
}
