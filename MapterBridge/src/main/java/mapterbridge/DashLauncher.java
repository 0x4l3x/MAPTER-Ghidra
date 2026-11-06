package mapterbridge;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.TimeUnit;

import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Runs the MAPTER Dash app ({@code app.py}) as a child process.
 *
 * <p>The app is bundled in this extension's {@code data/mapter_app} folder (copied from the repo
 * at build time); a different folder (e.g. a repo checkout) can be configured instead. The app's
 * output goes to a log file in Ghidra's user settings directory. Python environments are handled
 * by {@link PythonEnvironments}.
 */
final class DashLauncher {

	private static final String MODULE_NAME = "MapterBridge";
	private static final String BUNDLED_APP_DIR = "mapter_app";
	static final String APP_LOG = "mapter-app.log";

	private static final int START_TIMEOUT_SECONDS = 120;

	/** The app process this launcher started, if any, and the data folder it was given. */
	private Process process;
	private String dataFolder;

	// ---------------------------------------------------------------------------------------
	// Locations
	// ---------------------------------------------------------------------------------------

	/**
	 * The folder holding {@code app.py}: {@code configured} if set, else the bundled copy.
	 *
	 * @throws IOException if the folder does not exist or has no app.py
	 */
	static File appDir(String configured) throws IOException {
		File dir = configured == null || configured.isBlank()
				? Application.getModuleDataSubDirectory(MODULE_NAME, BUNDLED_APP_DIR).getFile(false)
				: new File(configured.strip());
		if (!new File(dir, "app.py").isFile()) {
			throw new IOException("No app.py in " + dir);
		}
		return dir;
	}

	static File logFile(String name) {
		return new File(Application.getUserSettingsDirectory(), name);
	}

	// ---------------------------------------------------------------------------------------
	// App process
	// ---------------------------------------------------------------------------------------

	static boolean isListening(int port) {
		try (Socket socket = new Socket()) {
			socket.connect(new InetSocketAddress("127.0.0.1", port), 300);
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * Asks the MAPTER app on {@code port} to exit ({@code POST /_mapter/shutdown}) and waits up to
	 * 5 s for the port to close. Works for an app this launcher did not start.
	 *
	 * @return true if the app stopped
	 */
	static boolean requestShutdown(int port) {
		try {
			HttpURLConnection c = (HttpURLConnection) URI.create(
				"http://127.0.0.1:" + port + "/_mapter/shutdown").toURL().openConnection();
			c.setRequestMethod("POST");
			c.setRequestProperty("X-MAPTER", "shutdown");
			c.setConnectTimeout(2000);
			c.setReadTimeout(2000);
			int code = c.getResponseCode();
			c.disconnect();
			if (code != 200) {
				return false;
			}
		}
		catch (IOException e) {
			return false;
		}
		for (int i = 0; i < 20 && isListening(port); i++) {
			sleep(250);
		}
		return !isListening(port);
	}

	/** Data folder the running app was started with (blank: bundled sample data). */
	synchronized String dataFolder() {
		return dataFolder == null ? "" : dataFolder;
	}

	synchronized boolean isRunning() {
		return process != null && process.isAlive();
	}

	/**
	 * Starts {@code python app.py} and waits until it listens on {@code dashPort}.
	 *
	 * @throws IOException if the process cannot start, exits early or does not come up in time
	 * @throws CancelledException if the user cancels the wait (the process is stopped)
	 */
	void start(String python, File appDir, String data, int dashPort, int ghidraPort,
			TaskMonitor monitor) throws IOException, CancelledException {
		File log = logFile(APP_LOG);
		ProcessBuilder pb = new ProcessBuilder(python, "app.py").directory(appDir);
		pb.environment().put("MAPTER_MANAGED", "1"); // data chosen in Ghidra, not in the app
		if (data != null && !data.isBlank()) {
			pb.environment().put("MAPTER_DATA", data);
		}
		pb.environment().put("MAPTER_PORT", Integer.toString(dashPort));
		pb.environment().put("MAPTER_GHIDRA_PORT", Integer.toString(ghidraPort));
		pb.environment().put("MAPTER_DEBUG", "0"); // no Flask reloader child to orphan
		pb.environment().put("PYTHONUNBUFFERED", "1");
		pb.redirectErrorStream(true).redirectOutput(Redirect.to(log));
		Msg.info(this, "MapterBridge: starting " + python + " app.py in " + appDir);

		Process p = pb.start();
		synchronized (this) {
			process = p;
			dataFolder = data;
		}
		monitor.setMessage("Waiting for the MAPTER app on port " + dashPort + "...");
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(START_TIMEOUT_SECONDS);
		while (!isListening(dashPort)) {
			if (monitor.isCancelled()) {
				stop();
				throw new CancelledException();
			}
			if (!p.isAlive()) {
				throw new IOException("The MAPTER app exited with code " + p.exitValue() +
					".\n\nLast lines of " + log + ":\n" + tail(log, 15));
			}
			if (System.nanoTime() > deadline) {
				stop();
				throw new IOException("The MAPTER app did not start within " +
					START_TIMEOUT_SECONDS + "s. See " + log);
			}
			sleep(250);
		}
	}

	/** Stops the app this launcher started (and any child process it spawned). */
	synchronized void stop() {
		if (process == null) {
			return;
		}
		process.descendants().forEach(ProcessHandle::destroy);
		process.destroy();
		try {
			if (!process.waitFor(3, TimeUnit.SECONDS)) {
				process.destroyForcibly();
			}
		}
		catch (InterruptedException e) {
			process.destroyForcibly();
		}
		process = null;
		Msg.info(this, "MapterBridge: MAPTER app stopped");
	}

	/** Last {@code lines} lines of a log file, for error messages. */
	static String tail(File file, int lines) {
		try {
			List<String> all = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
			return String.join("\n", all.subList(Math.max(0, all.size() - lines), all.size()));
		}
		catch (IOException e) {
			return "(log unreadable: " + e.getMessage() + ")";
		}
	}

	private static void sleep(long millis) {
		try {
			Thread.sleep(millis);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
