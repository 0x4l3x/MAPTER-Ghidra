package mapterbridge;

import com.google.gson.JsonObject;

/**
 * What the HTTP layer ({@link NavigationServer}) asks of Ghidra. Implementations do their own
 * thread handling; methods are called from HTTP worker threads.
 */
interface NavigationBackend {

	/** An HTTP status code plus the JSON body to send. */
	record Reply(int status, JsonObject body) {

		static Reply ok(JsonObject body) {
			return new Reply(200, body);
		}

		static Reply failure(int status, String error) {
			JsonObject body = new JsonObject();
			body.addProperty("success", false);
			body.addProperty("error", error);
			return new Reply(status, body);
		}
	}

	/** Body for {@code GET /status}. */
	Reply status();

	/** Body for {@code GET /current}: the function under the CodeBrowser cursor. */
	Reply current();

	/**
	 * Navigate to a function. At least one of {@code address} / {@code name} is non-null and
	 * {@code binaryName} is non-null.
	 *
	 * @param address loaded virtual address as a hex string (e.g. {@code 0x401000})
	 * @param name optional function name, used when the address does not resolve
	 * @param binaryName MAPTER binary hash identifying the program
	 */
	Reply navigate(String address, String name, String binaryName);
}
