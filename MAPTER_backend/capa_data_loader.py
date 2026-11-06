#!/usr/bin/env python
# coding: utf-8
"""
Load simplified CAPA reports (see ``capa_simplifier.py``) and merge them into a
MAPTER function table (columns ``binary_name`` and ``offset``).

Same data model as ``malware_data_loader.CapaLoader`` in the app, with fixes:

* address lookups use the JSON (string) keys of ``file_functions``;
* ``binary_name`` can come from an explicit ``{sha256: binary_name}`` mapping
  instead of ``sha256[:6]``;
* optionally, a CAPA address that is not the start of a known function is
  attributed to the function whose ``[offset, offset + size)`` interval
  contains it (``use_intervals=True``);
* no plotting / sklearn imports, ``analyze_capa_data`` works.

``legacy=True`` on ``CapaLoader`` / ``CapaUtils.extract_rule_functions``
reproduces the app's original (bug-compatible) behaviour.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Iterable, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger("mapter.capa_data_loader")

FUNCTION_COLUMNS = ['rule_name', 'tactic', 'technique', 'subtechnique', 'attack_id',
                    'objective', 'behavior', 'method', 'mbc_id']
CAPA_COLUMNS = FUNCTION_COLUMNS + ['library_name']


def _flatten(items: Iterable[Any]) -> List[Any]:
    """Flatten one level of nesting (CAPA sometimes stores a list of addresses)."""
    out: List[Any] = []
    for item in items:
        if isinstance(item, (list, tuple)):
            out.extend(item)
        else:
            out.append(item)
    return out


class CapaUtils:
    """Utility class for CAPA data processing."""

    @staticmethod
    def handle_rule_addresses(addresses: List[Any], function_map: Dict[Any, Any],
                              legacy: bool = False) -> List[Any]:
        """
        Handle rule addresses by mapping them to function addresses using the provided function map.
        If an address does not have a corresponding function, it is returned as is.

        The map comes from JSON, so its keys are strings; `legacy=True` looks up
        the raw (int) address like the app's original code, which never hits.
        """
        if legacy:
            return [function_map.get(address, address) for address in addresses]
        out = []
        for address in addresses:
            try:
                key = str(int(address))
            except (TypeError, ValueError):
                out.append(address)
                continue
            mapped = function_map.get(key)
            if mapped is None:
                mapped = function_map.get(address, address)
            out.append(mapped)
        return out

    @staticmethod
    def extract_mapping_info(rule_info: Dict[str, Any], mapping_type: str) -> Optional[Dict[str, Any]]:
        """
        Extract mapping information (MITRE ATT&CK or MBC) from rule info.

        Args:
            rule_info: Dictionary containing rule information
            mapping_type: 'attack' or 'mbc'

        Returns:
            Dictionary with mapping information or None if not available
        """
        mapping_key = f'rule_{mapping_type}'
        mapping_data = rule_info.get(mapping_key)

        if not mapping_data:
            return None

        if mapping_type == 'attack':
            return {
                'tactic': mapping_data.get('tactic_attck'),
                'technique': mapping_data.get('technique_attck'),
                'subtechnique': mapping_data.get('subtechnique_attck'),
                'attack_id': mapping_data.get('attck_id')
            }
        elif mapping_type == 'mbc':
            return {
                'objective': mapping_data.get('objective_mbc'),
                'behavior': mapping_data.get('behavior_mbc'),
                'method': mapping_data.get('method_mbc'),
                'mbc_id': mapping_data.get('mbc_id')
            }

        return None

    @staticmethod
    def create_function_info(rule_functions: List[Any], sha256: str, rule_name: str,
                             attack_info: Optional[Dict], mbc_info: Optional[Dict]) -> List[Dict[str, Any]]:
        """
        Create function information records for each function in a rule.
        """
        function_info = []
        for func in rule_functions:
            function_info.append({
                'func_addr': func,
                'sha256': sha256,
                'rule_name': rule_name,
                'tactic': attack_info.get('tactic') if attack_info else None,
                'technique': attack_info.get('technique') if attack_info else None,
                'subtechnique': attack_info.get('subtechnique') if attack_info else None,
                'attack_id': attack_info.get('attack_id') if attack_info else None,
                'objective': mbc_info.get('objective') if mbc_info else None,
                'behavior': mbc_info.get('behavior') if mbc_info else None,
                'method': mbc_info.get('method') if mbc_info else None,
                'mbc_id': mbc_info.get('mbc_id') if mbc_info else None
            })
        return function_info

    @staticmethod
    def safe_hex_conversion(addr: Any) -> Optional[str]:
        """Safely convert address to hex string (lowercase, unpadded ``0x...``)."""
        try:
            if pd.isna(addr):
                return None
            return hex(int(addr))
        except (ValueError, TypeError):
            return str(addr) if addr else None

    @staticmethod
    def extract_rule_functions(rule_info: Dict[str, Any], function_map: Dict[str, Any],
                               enable_debug_info: bool = False, legacy: bool = False) -> List[Any]:
        """
        Functions (start addresses) a rule matched in.

        `associated_funcs` holds the matches CAPA mapped to a function; when
        some matches could not be mapped, fall back to the raw match addresses,
        mapped through `function_map` where possible.
        """
        associated_funcs = rule_info.get('associated_funcs', [])
        associated_addresses = rule_info.get('associated_addresses', [])

        if len(associated_funcs) >= len(associated_addresses):
            return associated_funcs

        if legacy:
            # Original behaviour: only the first nested list is used, and int
            # addresses never hit the string-keyed map.
            addresses_to_process = associated_addresses
            if associated_addresses and isinstance(associated_addresses[0], list):
                if enable_debug_info:
                    logger.debug(f"Nested list detected in associated_addresses: {associated_addresses}")
                addresses_to_process = associated_addresses[0] if associated_addresses[0] else []
        else:
            addresses_to_process = _flatten(associated_addresses)

        try:
            return CapaUtils.handle_rule_addresses(addresses_to_process, function_map, legacy=legacy)
        except Exception as e:
            logger.warning(f"Error processing addresses {addresses_to_process}: {e}")
            return []

    @staticmethod
    def extract_library_info(data: Dict[str, Any], sha256: str) -> List[Dict[str, Any]]:
        """Extract library function information."""
        library_map = data.get('analysis', {}).get('library_functions', {})
        library_info = []

        for func_addr, lib_name in library_map.items():
            library_info.append({
                'func_addr': func_addr,
                'sha256': sha256,
                'library_name': lib_name if lib_name != "?" else "Unknown library",
            })

        return library_info

    @staticmethod
    def concatenate_unique_values(series: pd.Series) -> Optional[str]:
        """Concatenate unique non-null values from a pandas Series."""
        unique_vals = series.dropna().unique()
        if len(unique_vals) == 0:
            return None
        return '; '.join(sorted(str(val) for val in unique_vals))


# --------------------------------------------------------------------------- intervals
def _parse_offset(value: Any) -> Optional[int]:
    """int of an ``'0x...'`` offset string (None when not parseable)."""
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


class FunctionIntervals:
    """Per-binary sorted function intervals ``[offset, offset + size)`` of a
    MAPTER table, used to attribute CAPA addresses to the containing function."""

    def __init__(self, df: pd.DataFrame):
        self._by_binary: Dict[str, tuple] = {}
        if df.empty or not {'binary_name', 'offset'} <= set(df.columns):
            return
        sizes = pd.to_numeric(df['size'], errors='coerce') if 'size' in df.columns \
            else pd.Series(np.nan, index=df.index)
        starts = df['offset'].map(_parse_offset)
        work = pd.DataFrame({'b': df['binary_name'], 'o': df['offset'], 's': starts, 'z': sizes}).dropna(subset=['s'])
        for name, grp in work.groupby('b'):
            grp = grp.drop_duplicates('s').sort_values('s')
            st = grp['s'].astype('int64').to_numpy()
            # unknown / zero size: the function only covers its own start address
            ln = np.nan_to_num(grp['z'].to_numpy(dtype='float64'), nan=0.0).clip(min=1).astype('int64')
            self._by_binary[str(name)] = (st, st + ln, grp['o'].to_numpy(dtype=object))

    def attribute(self, binary_name: str, address: Any) -> Optional[str]:
        """Offset string of the function containing `address`, or None."""
        entry = self._by_binary.get(binary_name)
        if entry is None:
            return None
        try:
            addr = int(address)
        except (TypeError, ValueError):
            return None
        st, en, offs = entry
        i = int(np.searchsorted(st, addr, side='right')) - 1
        if i >= 0 and addr < en[i]:
            return str(offs[i])
        return None


class CapaLoader:
    """Class for loading and processing CAPA analysis data."""

    def __init__(self, capa_dir: str, legacy: bool = False):
        """Initialize CAPA loader with directory path (`legacy`: bug-compatible with the app's loader)."""
        self.capa_dir = capa_dir
        self.legacy = legacy

    def parse_capa_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a single simplified CAPA JSON file and extract relevant information."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to parse JSON file {file_path}: {e}")

        # Extract sha256 from filename
        sha256 = os.path.basename(file_path).split('.')[0]

        capabilities = []
        mitre_mappings = []
        mbc_mappings = []
        all_function_info = []

        function_map = data.get('analysis', {}).get('file_functions', {})
        rules = data.get('rules', {})

        # Process each rule
        for rule_name, rule_info in rules.items():
            capabilities.append(rule_name)

            rule_functions = CapaUtils.extract_rule_functions(
                rule_info, function_map, enable_debug_info=False, legacy=self.legacy)

            # Extract mapping information
            attack_info = CapaUtils.extract_mapping_info(rule_info, 'attack')
            mbc_info = CapaUtils.extract_mapping_info(rule_info, 'mbc')

            # Add to mappings lists if valid
            if attack_info:
                mitre_mappings.append(attack_info)
            if mbc_info:
                mbc_mappings.append(mbc_info)

            # Create function information
            function_info = CapaUtils.create_function_info(rule_functions, sha256, rule_name, attack_info, mbc_info)
            all_function_info.extend(function_info)

        # Process library functions
        library_info = CapaUtils.extract_library_info(data, sha256)

        return {
            'sha256': sha256,
            'capabilities': capabilities,
            'mitre_mappings': mitre_mappings,
            'mbc_mappings': mbc_mappings,
            'function_info': all_function_info,
            'library_info': library_info
        }

    def create_empty_mitre_df(self) -> pd.DataFrame:
        """Create empty MITRE dataframe."""
        return pd.DataFrame(columns=['sha256', 'tactic', 'technique', 'subtechnique', 'attack_id'])

    def create_empty_mbc_df(self) -> pd.DataFrame:
        """Create empty MBC dataframe."""
        return pd.DataFrame(columns=['sha256', 'objective', 'behavior', 'method', 'mbc_id'])

    def create_empty_dataframes(self) -> Dict[str, pd.DataFrame]:
        """Create empty dataframes with proper structure."""
        return {
            'capability': pd.DataFrame(columns=['sha256', 'capability']),
            'mitre': self.create_empty_mitre_df(),
            'mbc': self.create_empty_mbc_df(),
            'function_info': pd.DataFrame(columns=['func_addr', 'sha256', 'rule_name', 'tactic',
                                                   'technique', 'subtechnique', 'attack_id',
                                                   'objective', 'behavior', 'method', 'mbc_id']),
            'library_info': pd.DataFrame(columns=['func_addr', 'sha256', 'library_name'])
        }

    def create_dataframes(self, capa_data: List[Dict[str, Any]]) -> Dict[str, pd.DataFrame]:
        """Create DataFrames from processed CAPA data."""
        if not capa_data:
            return self.create_empty_dataframes()

        capability_records = []
        mitre_records = []
        mbc_records = []
        function_records = []
        library_records = []

        for sample in capa_data:
            sha256 = sample['sha256']

            capability_records.extend([{'sha256': sha256, 'capability': cap} for cap in sample['capabilities']])
            mitre_records.extend([{'sha256': sha256, **mapping} for mapping in sample['mitre_mappings']])
            mbc_records.extend([{'sha256': sha256, **mapping} for mapping in sample['mbc_mappings']])
            function_records.extend(sample['function_info'])
            library_records.extend(sample['library_info'])

        empty = self.create_empty_dataframes()
        return {
            'capability': pd.DataFrame(capability_records) if capability_records else empty['capability'],
            'mitre': pd.DataFrame(mitre_records) if mitre_records else empty['mitre'],
            'mbc': pd.DataFrame(mbc_records) if mbc_records else empty['mbc'],
            'function_info': pd.DataFrame(function_records) if function_records else empty['function_info'],
            'library_info': pd.DataFrame(library_records) if library_records else empty['library_info'],
        }

    def load_capa_data(self, sha256_array: Optional[List[str]] = None) -> Dict[str, pd.DataFrame]:
        """
        Load simplified CAPA data.

        Args:
            sha256_array: sha256 hashes to load (files ``<sha256>.json``);
                None loads every ``*.json`` of the directory.
        """
        if not os.path.isdir(self.capa_dir):
            logger.warning(f"CAPA directory {self.capa_dir} does not exist")
            return self.create_empty_dataframes()

        if sha256_array is None:
            filenames = sorted(f for f in os.listdir(self.capa_dir) if f.endswith('.json'))
        else:
            filenames = [f"{sha}.json" for sha in sha256_array]
        if not filenames:
            logger.warning(f"No JSON files found in {self.capa_dir}")
            return self.create_empty_dataframes()

        capa_data = []
        for filename in filenames:
            file_path = os.path.join(self.capa_dir, filename)
            if not os.path.isfile(file_path):
                continue
            try:
                capa_data.append(self.parse_capa_file(file_path))
            except Exception as e:
                logger.error(f"Error processing {filename}: {e}")

        return self.create_dataframes(capa_data)

    @staticmethod
    def _binary_names(sha256: pd.Series, binary_names: Optional[Dict[str, str]]) -> pd.Series:
        """binary_name per row: explicit mapping, or sha256[:6]; unmapped rows -> NaN."""
        if binary_names is None:
            return sha256.str[:6]
        return sha256.map(binary_names)

    def merge_function_info(self, df: pd.DataFrame, func_df: pd.DataFrame,
                            binary_names: Optional[Dict[str, str]] = None,
                            use_intervals: bool = False) -> pd.DataFrame:
        """Merge function information (rules) with main dataframe."""
        func_df = func_df.copy()

        func_df['binary_name'] = self._binary_names(func_df['sha256'], binary_names)
        func_df = func_df.dropna(subset=['binary_name'])
        func_df['offset'] = func_df['func_addr'].apply(CapaUtils.safe_hex_conversion)

        if use_intervals and not func_df.empty:
            func_df['offset'] = self._attribute_offsets(df, func_df)

        # Drop sha256 and func_addr columns
        func_df = func_df.drop(columns=['sha256', 'func_addr'])
        if func_df.empty:
            return df.copy()

        # Group by binary_name and offset, concatenate multiple values
        func_grouped = func_df.groupby(['binary_name', 'offset']).agg(
            {col: CapaUtils.concatenate_unique_values for col in FUNCTION_COLUMNS}).reset_index()

        return pd.merge(df, func_grouped, on=['binary_name', 'offset'], how='left')

    @staticmethod
    def _attribute_offsets(df: pd.DataFrame, func_df: pd.DataFrame) -> pd.Series:
        """Offsets of func_df rows, replacing an address that starts no known
        function by the offset of the function whose interval contains it."""
        intervals = FunctionIntervals(df)
        known = set(zip(df['binary_name'], df['offset'])) if not df.empty else set()
        result = []
        for b, off, addr in zip(func_df['binary_name'], func_df['offset'], func_df['func_addr']):
            if (b, off) not in known:
                containing = intervals.attribute(b, addr)
                if containing is not None:
                    off = containing
            result.append(off)
        return pd.Series(result, index=func_df.index)

    def merge_library_info(self, df: pd.DataFrame, lib_df: pd.DataFrame,
                           binary_names: Optional[Dict[str, str]] = None) -> pd.DataFrame:
        """Merge library information with main dataframe (exact function start only)."""
        lib_df = lib_df.copy()

        lib_df['binary_name'] = self._binary_names(lib_df['sha256'], binary_names)
        lib_df = lib_df.dropna(subset=['binary_name'])
        lib_df['offset'] = lib_df['func_addr'].apply(CapaUtils.safe_hex_conversion)

        lib_df = lib_df.drop(columns=['sha256', 'func_addr'])
        if lib_df.empty:
            return df.copy()

        lib_grouped = lib_df.groupby(['binary_name', 'offset']).agg({
            'library_name': CapaUtils.concatenate_unique_values
        }).reset_index()

        return pd.merge(df, lib_grouped, on=['binary_name', 'offset'], how='left')

    def merge_capa_with_df(self, df: pd.DataFrame, capa_dataframes: Dict[str, pd.DataFrame],
                           binary_names: Optional[Dict[str, str]] = None,
                           use_intervals: bool = False) -> pd.DataFrame:
        """
        Merge CAPA dataframes with the original dataframe.

        Parameters:
        df: Original dataframe with binary_name and offset columns
        capa_dataframes: Dictionary containing CAPA dataframes
        binary_names: {sha256: binary_name}; default binary_name = sha256[:6]
        use_intervals: attribute rule addresses that start no known function
            to the function whose [offset, offset+size) contains them

        Returns:
        DataFrame: Merged dataframe with CAPA information
        """
        df_merged = df.copy()

        if 'function_info' in capa_dataframes and not capa_dataframes['function_info'].empty:
            df_merged = self.merge_function_info(df_merged, capa_dataframes['function_info'],
                                                 binary_names, use_intervals)

        if 'library_info' in capa_dataframes and not capa_dataframes['library_info'].empty:
            df_merged = self.merge_library_info(df_merged, capa_dataframes['library_info'], binary_names)

        return df_merged

    def analyze_capa_data(self, sha256_array: Optional[List[str]] = None) -> Dict[str, pd.DataFrame]:
        """Main function to analyze CAPA data."""
        logger.info("Processing CAPA JSON files...")
        capa_dataframes = self.load_capa_data(sha256_array)

        logger.info(f"Extracted {len(capa_dataframes['capability'])} capability entries")
        logger.info(f"Extracted {len(capa_dataframes['mitre'])} MITRE ATT&CK mappings")
        logger.info(f"Extracted {len(capa_dataframes['mbc'])} MBC mappings")
        logger.info(f"Extracted {len(capa_dataframes['function_info'])} function information entries")
        logger.info(f"Extracted {len(capa_dataframes['library_info'])} library information entries")

        return capa_dataframes
