package mapterbridge;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;
import mapterbridge.NavigationBackend.Reply;

/**
 * Localhost JSON/HTTP server the MAPTER Dash app talks to:
 *
 * <ul>
 * <li>{@code GET  /status}   &rarr; {@code {status, message, ghidra_available, current_program,
 * program_count}}</li>
 * <li>{@code GET  /current}  &rarr; {@code {success, program, program_sha256, function_name,
 * entry_address, address}} (reverse link: Ghidra cursor &rarr; Dash highlight; the SHA-256 is the
 * program's {@code Executable SHA256}, lowercase hex, or null)</li>
 * <li>{@code POST /navigate} body {@code {"address", "binary_name", "name"?}}
 * &rarr; 200 / 400 / 404 / 500</li>
 * <li>{@code POST /shutdown} &rarr; stops this server (not Ghidra)</li>
 * </ul>
 *
 * <p>Requests are served by a small thread pool; all Ghidra work is delegated to the
 * {@link NavigationBackend}, which marshals it onto the Swing thread.
 */
final class NavigationServer {

	static final int MAX_REQUEST_SIZE = 4096; // bytes
	private static final int WORKER_THREADS = 4;
	private static final Gson GSON =
		new GsonBuilder().serializeNulls().disableHtmlEscaping().create();

	private final HttpServer http;
	private final ExecutorService pool;
	private final NavigationBackend backend;
	private final Runnable onShutdownRequested;

	/** Thrown while reading a request to answer 400 / 413 without touching Ghidra. */
	private static final class BadRequest extends Exception {
		final int status;

		BadRequest(int status, String message) {
			super(message);
			this.status = status;
		}
	}

	private NavigationServer(HttpServer http, ExecutorService pool, NavigationBackend backend,
			Runnable onShutdownRequested) {
		this.http = http;
		this.pool = pool;
		this.backend = backend;
		this.onShutdownRequested = onShutdownRequested;
	}

	/**
	 * Binds and starts serving.
	 *
	 * @param onShutdownRequested run (on an HTTP thread) after a {@code /shutdown} reply is sent;
	 *            the owner is expected to call {@link #stop()}
	 * @throws IOException if the address cannot be bound (e.g. port already in use)
	 */
	static NavigationServer start(String host, int port, NavigationBackend backend,
			Runnable onShutdownRequested) throws IOException {
		HttpServer http =
			HttpServer.create(new InetSocketAddress(InetAddress.getByName(host), port), 0);
		AtomicInteger n = new AtomicInteger();
		ExecutorService pool = Executors.newFixedThreadPool(WORKER_THREADS, r -> {
			Thread t = new Thread(r, "MapterBridge-http-" + n.incrementAndGet());
			t.setDaemon(true);
			return t;
		});
		NavigationServer server = new NavigationServer(http, pool, backend, onShutdownRequested);
		http.createContext("/", server::handle);
		http.setExecutor(pool);
		http.start();
		return server;
	}

	/** Stops listening and drops in-flight requests. Safe to call from the Swing thread. */
	void stop() {
		http.stop(0);
		pool.shutdownNow();
	}

	String url() {
		InetSocketAddress a = http.getAddress();
		return "http://" + a.getHostString() + ":" + a.getPort();
	}

	// ---------------------------------------------------------------------------------------
	// Request handling
	// ---------------------------------------------------------------------------------------

	private void handle(HttpExchange exchange) {
		boolean shutdown = false;
		try {
			String path = exchange.getRequestURI().getPath();
			switch (exchange.getRequestMethod()) {
				case "OPTIONS" -> sendEmpty(exchange, 204);
				case "GET" -> handleGet(exchange, path);
				case "POST" -> shutdown = handlePost(exchange, path);
				default -> send(exchange, 405, error("Method not allowed"));
			}
		}
		catch (Exception e) {
			Msg.error(this, "MapterBridge: error handling " + exchange.getRequestURI(), e);
			try {
				send(exchange, 500, Reply.failure(500, "Internal error: " + e).body());
			}
			catch (IOException | RuntimeException ignored) {
				// headers already sent or client gone
			}
		}
		finally {
			exchange.close();
		}
		if (shutdown) {
			onShutdownRequested.run();
		}
	}

	private void handleGet(HttpExchange exchange, String path) throws IOException {
		if (path.equals("/status")) {
			reply(exchange, backend.status());
		}
		else if (path.equals("/current")) {
			reply(exchange, backend.current());
		}
		else {
			send(exchange, 404, error("Unknown endpoint"));
		}
	}

	/** @return true if the caller should trigger a shutdown after the reply is closed */
	private boolean handlePost(HttpExchange exchange, String path) throws IOException {
		JsonObject data;
		try {
			data = readJsonBody(exchange);
		}
		catch (BadRequest e) {
			reply(exchange, Reply.failure(e.status, e.getMessage()));
			return false;
		}

		switch (path) {
			case "/navigate" -> handleNavigate(exchange, data);
			case "/shutdown" -> {
				JsonObject body = new JsonObject();
				body.addProperty("success", true);
				body.addProperty("message", "Server shutting down");
				send(exchange, 200, body);
				return true;
			}
			default -> reply(exchange, Reply.failure(404, "Unknown endpoint"));
		}
		return false;
	}

	private void handleNavigate(HttpExchange exchange, JsonObject data) throws IOException {
		String address, name, binaryName;
		try {
			address = stringField(data, "address");
			name = stringField(data, "name");
			binaryName = stringField(data, "binary_name");
		}
		catch (BadRequest e) {
			reply(exchange, Reply.failure(e.status, e.getMessage()));
			return;
		}
		if (address == null && name == null) {
			reply(exchange, Reply.failure(400, "Provide \"address\" or \"name\""));
			return;
		}
		if (binaryName == null) {
			reply(exchange, Reply.failure(400, "Provide \"binary_name\""));
			return;
		}
		reply(exchange, backend.navigate(address, name, binaryName));
	}

	private static JsonObject readJsonBody(HttpExchange exchange) throws IOException, BadRequest {
		// Read one byte past the limit instead of trusting Content-Length.
		byte[] raw = exchange.getRequestBody().readNBytes(MAX_REQUEST_SIZE + 1);
		if (raw.length > MAX_REQUEST_SIZE) {
			throw new BadRequest(413, "Request too large");
		}
		String text;
		try {
			text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(raw)).toString();
		}
		catch (CharacterCodingException e) {
			throw new BadRequest(400, "Bad request body: not valid UTF-8");
		}
		if (text.isBlank()) {
			return new JsonObject();
		}
		try {
			JsonElement element = JsonParser.parseString(text);
			if (!element.isJsonObject()) {
				throw new BadRequest(400, "Bad request body: expected a JSON object");
			}
			return element.getAsJsonObject();
		}
		catch (JsonParseException e) {
			throw new BadRequest(400, "Bad request body: " + e.getMessage());
		}
	}

	/** A string field, or null if absent, JSON null, blank or "None" (Python's str(None)). */
	private static String stringField(JsonObject data, String key) throws BadRequest {
		JsonElement value = data.get(key);
		if (value == null || value.isJsonNull()) {
			return null;
		}
		if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
			throw new BadRequest(400, "\"" + key + "\" must be a string");
		}
		String s = value.getAsString().strip();
		return s.isEmpty() || s.equals("None") ? null : s;
	}

	// ---------------------------------------------------------------------------------------
	// Responses (CORS headers on every reply, like the Python server)
	// ---------------------------------------------------------------------------------------

	private static JsonObject error(String message) {
		JsonObject body = new JsonObject();
		body.addProperty("error", message);
		return body;
	}

	private static void reply(HttpExchange exchange, Reply reply) throws IOException {
		send(exchange, reply.status(), reply.body());
	}

	private static void send(HttpExchange exchange, int status, JsonObject body)
			throws IOException {
		byte[] payload = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
		addCorsHeaders(exchange);
		exchange.getResponseHeaders().set("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, payload.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(payload);
		}
	}

	private static void sendEmpty(HttpExchange exchange, int status) throws IOException {
		addCorsHeaders(exchange);
		exchange.sendResponseHeaders(status, -1);
	}

	private static void addCorsHeaders(HttpExchange exchange) {
		var headers = exchange.getResponseHeaders();
		headers.set("Access-Control-Allow-Origin", "*");
		headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		headers.set("Access-Control-Allow-Headers", "Content-Type");
	}
}
