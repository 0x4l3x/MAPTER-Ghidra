"""
Simplify raw ``capa --json`` reports into the compact format MAPTER reads.

The simplified JSON (one file per binary, named ``<sha256>.json``) has the
top-level keys ``timestamp``, ``version``, ``extractor``, ``rules`` and
``analysis``; it is what the app's ``CapaLoader`` (and this backend's
``capa_data_loader.CapaLoader``) consume. Raw capa output is NOT understood by
those loaders.

Library use (no third-party dependencies)::

    from capa_simplifier import simplify_capa_report, simplify_capa_file
    simple = simplify_capa_report(json.load(open("raw.json")))
    simplify_capa_file("raw/<sha>.json", "capa/<sha>.json")

CLI::

    python capa_simplifier.py -d raw_dir -o out_dir [--rewrite]
    python capa_simplifier.py -f raw/<sha>.json -o out_dir
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:  # progress bar is a convenience only
    from tqdm import tqdm
except ImportError:  # pragma: no cover - depends on the environment
    tqdm = None

logger = logging.getLogger("mapter.capa_simplifier")

PathLike = Union[str, "os.PathLike[str]"]


def parse_attack_meta(rule_details):
    """
    Extract ATT&CK meta from rule details.

    Parameters:
    rule_details (dict): Rule details dictionary.

    Returns:
    dict: ATT&CK meta data (first entry only), or None.
    """
    attack_data = rule_details.get('meta', {}).get('attack', [])
    if not attack_data:
        return None
    attack_entry = attack_data[0]
    return {
        "tactic_attck": attack_entry.get('tactic', ''),
        "technique_attck": attack_entry.get('technique', ''),
        "subtechnique_attck": attack_entry.get('subtechnique', ''),
        "attck_id": attack_entry.get('id', '')
    }


def parse_mbc_meta(rule_details):
    """
    Extract MBC meta from rule details.

    Parameters:
    rule_details (dict): Rule details dictionary.

    Returns:
    dict: MBC meta data (first entry only), or None.
    """
    mbc_data = rule_details.get('meta', {}).get('mbc', [])
    if not mbc_data:
        return None
    mbc_entry = mbc_data[0]
    return {
        "objective_mbc": mbc_entry.get('objective', ''),
        "behavior_mbc": mbc_entry.get('behavior', ''),
        "method_mbc": mbc_entry.get('method', ''),
        "mbc_id": mbc_entry.get('id', '')
    }


def collect_location_values(children, rule_capability, rules_non_code_related):
    """
    Recursively search child elements to collect all location values.

    Args:
        children (list): List of child elements.
        rule_capability (str): Rule capability identifier.
        rules_non_code_related (list): Accumulates non-code-related rule data.

    Returns:
        list: List of location values.
    """
    results = []
    for child in children:
        if child.get("success"):
            for location in child.get("locations", []):
                loc_type = location.get("type")
                loc_value = location.get("value")
                if loc_type in ("absolute", "dn token"):
                    results.append(loc_value)
                else:
                    rules_non_code_related.append([rule_capability, loc_type, loc_value])

        # Recursively search deeper children
        deeper_children = child.get("children", [])
        results.extend(collect_location_values(deeper_children, rule_capability, rules_non_code_related))

    return results


def extract_primary_block_address(match_group, rule_capability, non_code_related_rules):
    """
    Extract the primary block address from a match group.

    Args:
        match_group (list): ``[address, match, ...]`` pair of a rule match.
        rule_capability (str): Rule capability identifier.
        non_code_related_rules (list): Accumulates non-code-related rule data.

    Returns:
        str or list: Block address or list of addresses.
    """
    if not match_group:
        return None

    block_address = match_group[0].get('value')

    if block_address:
        return block_address

    for nested_dict in match_group[1:]:
        if nested_dict.get("success"):
            locations = nested_dict.get("locations", [])

            if locations:
                loc_type = locations[0].get("type")
                loc_value = locations[0].get("value")

                if loc_type in ("absolute", "dn token"):
                    return loc_value
                else:
                    non_code_related_rules.append([rule_capability, loc_type, loc_value])
            else:
                return collect_location_values(nested_dict.get("children", []), rule_capability, non_code_related_rules)
        else:
            return collect_location_values(nested_dict.get("children", []), rule_capability, non_code_related_rules)

    return None


def match_functions_from_rules(rule_matches, rule_capability, file_functions, non_code_related_rules):
    """
    Identify and match functions from rule matches.

    Args:
        rule_matches (list): List of rule match groups.
        rule_capability (str): Rule capability identifier.
        file_functions (dict): Mapping of block/function addresses to function addresses.
        non_code_related_rules (list): Accumulates non-code-related rule data.

    Returns:
        tuple: (List of associated functions, List of associated addresses)
    """
    associated_functions = []
    associated_addresses = []

    for match_group in rule_matches:
        block_address = extract_primary_block_address(match_group, rule_capability, non_code_related_rules)

        if block_address:
            associated_addresses.append(block_address)

            # Handle list of addresses by selecting the first one
            if isinstance(block_address, list):
                block_address = block_address[0] if block_address else None

            function_name = file_functions.get(block_address) if isinstance(block_address, (int, str)) else None
            if function_name:
                associated_functions.append(function_name)

    return associated_functions, associated_addresses


def deduplicate_rule_matches(rules_non_code_related):
    """
    Deduplicate rule file matches (order is made deterministic).

    Args:
        rules_non_code_related (list): List of non-code-related rule data.

    Returns:
        list: Deduplicated list of non-code-related rule data.
    """
    normalized = []
    for lst in rules_non_code_related:
        converted = []
        for elem in lst:
            if isinstance(elem, list):
                converted.append(tuple(elem))
            else:
                converted.append(elem)
        normalized.append(tuple(converted))
    unique = sorted(set(normalized), key=repr)
    return [list(item) for item in unique]


def extract_rules(rules_data, file_functions):
    """
    Parse rule data and extract associated functions and addresses.

    Args:
        rules_data (dict): Rule data dictionary.
        file_functions (dict): Mapping of addresses to function addresses.

    Returns:
        dict: Parsed rule data keyed by rule name.
    """
    parsed_rules = {}

    for rule_name, rule_details in rules_data.items():
        meta_info = rule_details.get('meta', {})
        rule_capability = meta_info.get('name', 'Unknown')
        rule_namespace = meta_info.get('namespace', 'Unknown')

        rule_attack = parse_attack_meta(rule_details)
        rule_mbc = parse_mbc_meta(rule_details)
        rule_matches = rule_details.get('matches', [])

        # Per-rule accumulator (the original shared one list across all rules,
        # leaking one rule's file-level hits into the next rule's entry).
        rules_non_code_related: List[list] = []
        associated_funcs, associated_addresses = match_functions_from_rules(
            rule_matches, rule_capability, file_functions, rules_non_code_related
        )
        if rules_non_code_related:
            rules_non_code_related = deduplicate_rule_matches(rules_non_code_related)

        parsed_rules[rule_capability] = {
            "rule_name": rule_name,
            "rule_namespace": rule_namespace,
            "rule_attack": rule_attack,
            "rule_mbc": rule_mbc,
            "associated_funcs": associated_funcs,
            "associated_addresses": associated_addresses,
            "rules_non_code_related": rules_non_code_related
        }

    return parsed_rules


def parse_function_data(functions_data):
    """
    Create a map of addresses to function addresses for quick lookup.

    Args:
        functions_data (list): List of function data dictionaries.

    Returns:
        dict: Mapping of function/basic-block addresses to function addresses.
    """
    parsed_functions = {}
    for function_data in functions_data:
        fun_addr_val = function_data.get('address', {}).get('value', '0')
        parsed_functions[fun_addr_val] = fun_addr_val
        for basic_block in function_data.get('matched_basic_blocks', []):
            block_addr_val = basic_block.get('address', {}).get('value', '0')
            parsed_functions[block_addr_val] = fun_addr_val
    return parsed_functions


def extract_analysis(analysis_data):
    """
    Extract basic analysis, functions, and library function data.

    Args:
        analysis_data (dict): Analysis data dictionary.

    Returns:
        dict: Parsed analysis data.
    """
    base_address = analysis_data.get('base_address', '0')
    code_data = analysis_data.get('layout', {})
    file_functions = parse_function_data(code_data.get('functions', []))

    library_functions = {}
    for lib_func in analysis_data.get('library_functions', []):
        lib_func_address = lib_func.get('address', {}).get('value')
        library_functions[lib_func_address] = lib_func.get('name')

    return {
        "base_address": base_address,
        "file_functions": file_functions,
        "library_functions": library_functions
    }


def simplify_capa_report(capa_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simplify an already-loaded raw capa report (the dict from ``capa --json``).

    Returns:
        dict: ``{timestamp, version, extractor, rules, analysis}``.
    """
    meta = capa_data.get('meta', {})
    analysis_data = meta.get('analysis', {})
    parsed_analysis = extract_analysis(analysis_data)
    parsed_rules = extract_rules(capa_data.get('rules', {}), parsed_analysis["file_functions"])

    return {
        "timestamp": meta.get('timestamp', 'Unknown'),
        "version": meta.get('version', 'Unknown'),
        "extractor": analysis_data.get('extractor', 'Unknown'),
        "rules": parsed_rules,
        "analysis": parsed_analysis
    }


def parse_capa_output(json_path):
    """
    Parse capa output from a JSON file.

    Args:
        json_path (str): Path to the JSON file.

    Returns:
        dict: Parsed (simplified) capa output data.
    """
    with open(json_path, 'r', encoding='utf-8') as file:
        capa_data = json.load(file)
    return simplify_capa_report(capa_data)


def _read_umask() -> int:
    """Process umask (os.umask can only be read by setting it; done once at import)."""
    mask = os.umask(0)
    os.umask(mask)
    return mask


_UMASK = _read_umask()


def _write_json_atomic(path: Path, obj: Any) -> None:
    """Write JSON to `path` through a temp file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=4)
        os.chmod(tmp, 0o666 & ~_UMASK)  # mkstemp creates 0600
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def simplify_capa_file(input_file: PathLike, output_file: PathLike) -> Dict[str, Any]:
    """
    Simplify one raw capa JSON file into `output_file` (atomic write).

    Raises:
        FileNotFoundError / ValueError for missing, empty or non-JSON input,
        ValueError when the file is not a capa report (no ``rules``/``meta``).
    """
    input_file, output_file = Path(input_file), Path(output_file)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    if input_file.stat().st_size == 0:
        raise ValueError(f"Input file is empty: {input_file}")
    try:
        with open(input_file, 'r', encoding='utf-8') as fh:
            capa_data = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Not valid JSON: {input_file}: {exc}") from exc
    if not isinstance(capa_data, dict) or 'rules' not in capa_data or 'meta' not in capa_data:
        raise ValueError(f"Not a capa report (missing 'meta'/'rules'): {input_file}")
    simplified = simplify_capa_report(capa_data)
    _write_json_atomic(output_file, simplified)
    return simplified


def process_capa_directory(directory, output_directory, rewrite=False):
    """
    Parse all valid JSON files in a directory, process them and store the results in a new directory.

    Args:
        directory (str): Path to the directory containing JSON files.
        output_directory (str): Path to the output directory.
        rewrite (bool, optional): If True, reprocess files even if an output
            file already exists. Defaults to False.

    Returns:
        dict: ``{filename: parsed data}`` of the files processed in this call.
    """
    directory, output_directory = Path(directory), Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    result_dict = {}
    logger.info(f"Processing directory: {directory} to {output_directory}")
    names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    iterator = tqdm(names, desc="directory") if tqdm is not None else names
    for filename in iterator:
        file_path = directory / filename
        output_file = output_directory / filename

        # Skip already processed files unless rewrite is enabled
        if not rewrite and output_file.exists():
            continue

        if file_path.stat().st_size == 0:
            continue

        try:
            result_dict[filename] = simplify_capa_file(file_path, output_file)
        except Exception as e:
            logger.error(f"Error parsing file >{filename}<: {e}")

    return result_dict


def process_single_capa_json(input_file, output_directory):
    """
    Process a single capa JSON file and save the parsed result.

    Args:
        input_file (str | Path): Path to the input JSON file.
        output_directory (str | Path): Directory where output will be stored
            (same file name as the input).

    Returns:
        dict: Parsed data, or None if the file could not be parsed.
    """
    input_file = Path(input_file)
    output_directory = Path(output_directory)

    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    if input_file.suffix.lower() != ".json":
        raise ValueError(f"Input file is not a JSON file: {input_file}")
    if input_file.stat().st_size == 0:
        raise ValueError(f"Input file is empty: {input_file}")

    try:
        parsed = simplify_capa_file(input_file, output_directory / input_file.name)
        logger.info(f"Processed file: {input_file}")
        return parsed
    except Exception as e:
        logger.error(f"Error parsing file >{input_file.name}<: {e}")
        return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Process capa JSON files.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--directory", default=None,
                       help="Directory containing raw capa JSON files")
    group.add_argument("-f", "--file", default=None,
                       help="Single raw capa JSON file to process")
    parser.add_argument("-o", "--output", default="capa_simplified",
                        help="Output directory (default: capa_simplified)")
    parser.add_argument("--rewrite", action="store_true", default=False,
                        help="Rewrite existing output files")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    output_directory = Path(args.output)
    output_directory.mkdir(parents=True, exist_ok=True)

    if args.file:
        return 0 if process_single_capa_json(args.file, output_directory) is not None else 1
    process_capa_directory(args.directory, output_directory, args.rewrite)
    # nohup python capa_simplifier.py -d capa_jsons > capa_simplifier.log 2>&1 &
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
