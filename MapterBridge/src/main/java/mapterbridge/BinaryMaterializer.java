package mapterbridge;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Exports the ORIGINAL binaries of a Ghidra project's programs to {@code <work>/binaries/<sha256>}
 * and writes {@code <work>/manifest.json} (the input contract of the MAPTER pipeline).
 *
 * <p>The bytes come from the program's first {@link FileBytes} (the file as imported, not the
 * patched memory) and are verified against the program's {@code Executable SHA256}; if they do
 * not match, or the program has no FileBytes, the file at {@code Executable Location} is used
 * when it exists and its hash matches. Anything else is reported per program, never fatal.
 *
 * <p>Slow: call from a task, never from the Swing thread.
 */
final class BinaryMaterializer {

	static final String METADATA_SHA256 = "Executable SHA256";
	static final String METADATA_FORMAT = "Executable Format";
	private static final int CHUNK = 1 << 20;
	private static final int NAME_LENGTH = 6;

	/** One manifest entry. Field names are the manifest keys. */
	static final class Entry {
		String sha256;
		String path;
		String binary_name;
		String program_name;
		String domain_path;
		String format;
		String status;
		String reason;
	}

	/** Outcome of {@link #run}: the entries (also written to the manifest) and tallies. */
	record Result(List<Entry> entries, File manifest) {

		long count(String status) {
			return entries.stream().filter(e -> status.equals(e.status)).count();
		}

		/** Entries the pipeline can process. */
		long ok() {
			return count("ok");
		}

		/** Entries that could not be exported, with their reasons (for the user). */
		List<String> problems() {
			return entries.stream().filter(e -> !"ok".equals(e.status))
					.map(e -> e.domain_path + ": " + e.reason).toList();
		}
	}

	private BinaryMaterializer() {
	}

	/** All Program files in the project (link files have another content type). */
	static List<DomainFile> programFiles(Project project) {
		if (project == null) {
			return List.of();
		}
		List<DomainFile> files = new ArrayList<>();
		Deque<DomainFolder> pending = new ArrayDeque<>();
		pending.push(project.getProjectData().getRootFolder());
		while (!pending.isEmpty()) {
			DomainFolder folder = pending.pop();
			for (DomainFile df : folder.getFiles()) {
				if (ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(df.getContentType())) {
					files.add(df);
				}
			}
			for (DomainFolder sub : folder.getFolders()) {
				pending.push(sub);
			}
		}
		return files;
	}

	/**
	 * Exports every program of the project and writes the manifest.
	 *
	 * @param consumer owner object for opening the programs (released afterwards)
	 * @throws IOException if the work folder cannot be written
	 * @throws CancelledException if the user cancels (partial files are removed, no manifest)
	 */
	static Result run(Project project, File work, TaskMonitor monitor, Object consumer)
			throws IOException, CancelledException {
		Path binaries = work.toPath().resolve("binaries");
		Files.createDirectories(binaries);
		List<DomainFile> files = programFiles(project);
		files.sort(Comparator.comparing(DomainFile::getPathname));
		monitor.initialize(files.size());

		List<Entry> entries = new ArrayList<>();
		Map<String, Entry> bySha = new HashMap<>();
		for (DomainFile df : files) {
			monitor.checkCancelled();
			monitor.setMessage("Exporting " + df.getPathname());
			Entry entry = new Entry();
			entry.program_name = df.getName();
			entry.domain_path = df.getPathname();
			entry.format = "";
			entry.reason = "";
			try {
				export(df, binaries, entry, monitor, consumer);
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (VersionException e) {
				fail(entry, "error", "program needs an upgrade or is from another Ghidra " +
					"version (open it once in Ghidra): " + e.getMessage());
			}
			catch (IOException | RuntimeException e) {
				fail(entry, "error", e.getClass().getSimpleName() + ": " + e.getMessage());
			}
			if ("ok".equals(entry.status)) {
				Entry first = bySha.putIfAbsent(entry.sha256, entry);
				if (first != null) { // same binary imported twice: process it once
					entry.status = "error";
					entry.reason = "duplicate of " + first.domain_path;
				}
			}
			if (!"ok".equals(entry.status)) {
				Msg.warn(BinaryMaterializer.class, "MapterBridge: " + entry.domain_path + " not " +
					"exported (" + entry.status + "): " + entry.reason);
			}
			entries.add(entry);
			monitor.incrementProgress(1);
		}
		assignNames(entries);

		Map<String, Object> manifest = new LinkedHashMap<>();
		manifest.put("source", "ghidra");
		manifest.put("project", project.getName());
		manifest.put("binaries", entries);
		File manifestFile = new File(work, "manifest.json");
		Path tmp = work.toPath().resolve("manifest.json.tmp");
		Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
		Files.writeString(tmp, gson.toJson(manifest));
		Files.move(tmp, manifestFile.toPath(), StandardCopyOption.REPLACE_EXISTING,
			StandardCopyOption.ATOMIC_MOVE);
		return new Result(entries, manifestFile);
	}

	private static void fail(Entry entry, String status, String reason) {
		entry.status = status;
		entry.reason = reason;
	}

	/** Sets {@code entry.sha256}/{@code path}/{@code status} for one program. */
	private static void export(DomainFile df, Path binaries, Entry entry, TaskMonitor monitor,
			Object consumer) throws IOException, CancelledException, VersionException {
		Map<String, String> metadata = df.getMetadata();
		String expected = normalize(metadata == null ? null : metadata.get(METADATA_SHA256));
		if (metadata != null && metadata.get(METADATA_FORMAT) != null) {
			entry.format = metadata.get(METADATA_FORMAT);
		}

		// Resume: the exported file of an earlier run, still matching the recorded hash.
		if (expected != null) {
			Path existing = binaries.resolve(expected);
			if (Files.isRegularFile(existing) && sha256(existing, monitor).equals(expected)) {
				done(entry, expected, existing, "reused an earlier export");
				return;
			}
		}

		DomainObject object = df.getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION,
			monitor);
		try {
			if (!(object instanceof Program program)) {
				fail(entry, "error", "not a program");
				return;
			}
			if (program.getExecutableFormat() != null) {
				entry.format = program.getExecutableFormat();
			}
			String recorded = normalize(program.getExecutableSHA256());
			if (recorded != null) {
				expected = recorded;
			}
			String why = fromFileBytes(program, binaries, expected, entry, monitor);
			if ("ok".equals(entry.status)) {
				return;
			}
			String why2 = fromExecutablePath(program.getExecutablePath(), binaries, expected,
				entry, monitor);
			if ("ok".equals(entry.status)) {
				return;
			}
			fail(entry, "missing", why + "; " + why2);
		}
		finally {
			object.release(consumer);
		}
	}

	/**
	 * Streams the original bytes of the first FileBytes into a temp file while hashing, checks
	 * the hash, renames. Returns why it did not work (entry.status stays null), or "" on success.
	 */
	private static String fromFileBytes(Program program, Path binaries, String expected,
			Entry entry, TaskMonitor monitor) throws IOException, CancelledException {
		List<FileBytes> all = program.getMemory().getAllFileBytes();
		if (all.isEmpty()) {
			return "the program keeps no original file bytes";
		}
		FileBytes bytes = all.get(0);
		long size = bytes.getSize();
		Path tmp = Files.createTempFile(binaries, "export-", ".tmp");
		try {
			MessageDigest digest = newDigest();
			byte[] buffer = new byte[CHUNK];
			try (var out = Files.newOutputStream(tmp)) {
				long offset = 0;
				while (offset < size) {
					monitor.checkCancelled();
					int want = (int) Math.min(buffer.length, size - offset);
					int got = bytes.getOriginalBytes(offset, buffer, 0, want);
					if (got <= 0) {
						throw new IOException("short read of the original bytes at " + offset);
					}
					digest.update(buffer, 0, got);
					out.write(buffer, 0, got);
					offset += got;
				}
			}
			String actual = hex(digest.digest());
			if (expected != null && !actual.equals(expected)) {
				return "stored original bytes hash to " + actual.substring(0, 12) +
					"... but the program records " + expected.substring(0, 12) + "...";
			}
			String note = expected == null
					? "program records no Executable SHA256; hash computed from the stored bytes"
					: "";
			moveIn(tmp, binaries.resolve(actual));
			done(entry, actual, binaries.resolve(actual), note);
			return "";
		}
		finally {
			Files.deleteIfExists(tmp);
		}
	}

	/** Fallback: the file the program was imported from, if still there and unchanged. */
	private static String fromExecutablePath(String executablePath, Path binaries,
			String expected, Entry entry, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (expected == null) {
			return "no recorded Executable SHA256 to verify the imported file against";
		}
		Path source = resolveExecutablePath(executablePath);
		if (source == null || !Files.isRegularFile(source)) {
			return "imported file not found (" + (executablePath == null ? "no path" :
				executablePath) + ")";
		}
		String actual = sha256(source, monitor);
		if (!actual.equals(expected)) {
			return "imported file " + source + " changed since the import (hash differs)";
		}
		Path tmp = Files.createTempFile(binaries, "export-", ".tmp");
		try {
			Files.copy(source, tmp, StandardCopyOption.REPLACE_EXISTING);
			moveIn(tmp, binaries.resolve(actual));
			done(entry, actual, binaries.resolve(actual), "copied from " + source);
			return "";
		}
		finally {
			Files.deleteIfExists(tmp);
		}
	}

	private static void done(Entry entry, String sha, Path path, String note) {
		entry.sha256 = sha;
		entry.path = path.toAbsolutePath().toString();
		entry.status = "ok";
		entry.reason = note;
	}

	private static void moveIn(Path tmp, Path target) throws IOException {
		try {
			Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING,
				StandardCopyOption.ATOMIC_MOVE);
		}
		catch (AtomicMoveNotSupportedException e) {
			Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
		}
	}

	/** The local file for an {@code Executable Location} value (plain path or file: URI). */
	private static Path resolveExecutablePath(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		try {
			if (value.startsWith("file:")) {
				return Paths.get(URI.create(value));
			}
			String v = value;
			if (v.matches("^/[A-Za-z]:[/\\\\].*")) { // "/C:/dir/x.exe" as Ghidra stores it
				v = v.substring(1);
			}
			return Paths.get(v);
		}
		catch (RuntimeException e) { // InvalidPathException, bad URI
			return null;
		}
	}

	/** First {@value #NAME_LENGTH} hex chars of the sha256; longer for every entry on a clash. */
	private static void assignNames(List<Entry> entries) {
		Set<String> shas = new TreeSet<>();
		for (Entry e : entries) {
			if (e.sha256 != null) {
				shas.add(e.sha256);
			}
		}
		int n = NAME_LENGTH;
		while (n < 64) {
			final int len = n;
			if (shas.stream().map(s -> s.substring(0, len)).distinct().count() == shas.size()) {
				break;
			}
			n++;
		}
		for (Entry e : entries) {
			if (e.sha256 != null) {
				e.binary_name = e.sha256.substring(0, n);
			}
		}
	}

	private static String normalize(String sha) {
		if (sha == null || !sha.strip().matches("(?i)[0-9a-f]{64}")) {
			return null;
		}
		return sha.strip().toLowerCase(Locale.ROOT);
	}

	private static MessageDigest newDigest() throws IOException {
		try {
			return MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

	private static String sha256(Path file, TaskMonitor monitor)
			throws IOException, CancelledException {
		MessageDigest digest = newDigest();
		byte[] buffer = new byte[CHUNK];
		try (InputStream in = Files.newInputStream(file)) {
			int n;
			while ((n = in.read(buffer)) > 0) {
				monitor.checkCancelled();
				digest.update(buffer, 0, n);
			}
		}
		return hex(digest.digest());
	}

	private static String hex(byte[] bytes) {
		return HexFormat.of().formatHex(bytes);
	}
}
