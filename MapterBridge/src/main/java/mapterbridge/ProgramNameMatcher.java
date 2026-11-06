package mapterbridge;

import java.util.Collection;
import java.util.List;
import java.util.Comparator;
import java.util.Locale;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Matches a MAPTER {@code binary_name} (a possibly truncated hash, e.g. {@code e27fb1}) against
 * Ghidra program names (e.g. {@code e27fb1....exe}).
 *
 * <p>Rules, case-insensitive: first (when a hash accessor is given) a unique program whose
 * SHA-256 starts with the binary_name, which is how the MAPTER pipeline derives binary_name; then
 * a unique exact name match, then a unique prefix match, then a unique substring match. More than
 * one substring hit with no unique winner in an earlier tier is ambiguous and is rejected rather
 * than guessed.
 */
final class ProgramNameMatcher {

	/** Outcome: {@code found} is set on a unique match; otherwise {@code candidates} lists ties. */
	record Match<T>(T found, List<T> candidates) {

		boolean isAmbiguous() {
			return found == null && candidates.size() > 1;
		}
	}

	private ProgramNameMatcher() {
	}

	/** Fewer hex characters than this are too weak to identify a program by its hash. */
	private static final int MIN_HASH_PREFIX = 4;

	static <T> Match<T> match(Collection<T> items, Function<T, String> nameOf, String binaryName) {
		return match(items, nameOf, null, binaryName);
	}

	/**
	 * @param shaOf the program's SHA-256 (hex) or null/blank if unknown; may be null itself to
	 *            skip the hash tier
	 */
	static <T> Match<T> match(Collection<T> items, Function<T, String> nameOf,
			Function<T, String> shaOf, String binaryName) {
		String target = binaryName.strip().toLowerCase(Locale.ROOT);
		Function<T, String> key = t -> nameOf.apply(t).toLowerCase(Locale.ROOT);

		List<T> byHash = List.of();
		if (shaOf != null && target.length() >= MIN_HASH_PREFIX) {
			byHash = items.stream().filter(t -> {
				String sha = shaOf.apply(t);
				return sha != null && sha.strip().toLowerCase(Locale.ROOT).startsWith(target);
			}).toList();
			if (byHash.size() == 1) {
				return new Match<>(byHash.get(0), byHash);
			}
			if (byHash.size() > 1 && byHash.stream()
					.map(t -> shaOf.apply(t).strip().toLowerCase(Locale.ROOT))
					.distinct()
					.count() == 1) {
				// The same binary imported more than once: any copy is right; pick a stable one.
				T first = byHash.stream().min(Comparator.comparing(nameOf)).orElseThrow();
				return new Match<>(first, byHash);
			}
			// none, or several different binaries sharing the prefix: fall back to the names
		}

		List<Predicate<String>> tiers =
			List.of(n -> n.equals(target), n -> n.startsWith(target), n -> n.contains(target));
		List<T> hits = List.of();
		for (Predicate<String> tier : tiers) {
			hits = items.stream().filter(t -> tier.test(key.apply(t))).toList();
			if (hits.size() == 1) {
				return new Match<>(hits.get(0), hits);
			}
		}
		// hits now holds the substring tier, the widest one
		return new Match<>(null, hits.isEmpty() ? byHash : hits);
	}
}
