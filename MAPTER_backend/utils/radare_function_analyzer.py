# SAFE TEAM
# Copyright (C) 2019  Luca Massarelli, Giuseppe Antonio Di Luna, Fabio Petroni, Leonardo Querzoni, Roberto Baldoni
#
# Adapted for the MAPTER pipeline:
#   * radare2 >= 6 reports a function's address under 'addr', older versions
#     under 'offset': both are accepted (see ``function_address``).
#   * functions are keyed by address (r2 can name two functions identically).
#   * r2 is always closed (context manager / ``close``), aflj failures raise a
#     clear error instead of a TypeError, unsupported architectures raise
#     ``UnsupportedArchitecture`` instead of silently yielding nothing.
#   * the SAFE token format (``X_``/``A_`` + mnemonic + operands) is unchanged,
#     so model/word2id.json still matches.

import json
import logging
import os
import pickle
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger("mapter.safe.radare")

# r2 arch name -> SAFE token prefix (the vocabulary only knows x86 and arm)
ARCH_PREFIX = {"x86": "X_", "arm": "A_"}


class RadareError(RuntimeError):
    """radare2 could not open or analyse the binary."""


class UnsupportedArchitecture(RadareError):
    """The binary's architecture has no SAFE vocabulary (only x86/arm)."""


def function_address(fn: dict) -> Optional[int]:
    """Start address of an ``aflj`` entry: 'addr' (radare2 >= 6) or 'offset'."""
    addr = fn.get("addr", fn.get("offset"))
    return addr if isinstance(addr, int) else None


def function_size(fn: dict) -> Optional[int]:
    """Size of an ``aflj`` entry ('size', else 'realsz'), None when absent."""
    size = fn.get("size", fn.get("realsz"))
    return size if isinstance(size, int) else None


class RadareFunctionAnalyzer:
    """Extracts, per function, the SAFE token sequence of a binary with radare2.

    Use as a context manager (or call ``close``) so r2 is always terminated::

        with RadareFunctionAnalyzer(path, depth=0, r2_path=None) as a:
            functions = a.analyze()   # {address: {name, size, filtered_instructions, ...}}
    """

    def __init__(self, filename, depth=0, ghidra_offsets=None, r2_path: Optional[str] = None):
        import r2pipe  # imported lazily so the module loads without r2pipe

        self.filename = filename
        self.top_depth = depth
        self.ghidra_offsets = ghidra_offsets
        self.afl: Optional[List[dict]] = None
        self.number_functions = 0
        self.info: dict = {}
        self.r2 = None
        flags = ["-2"]
        kwargs = {}
        if r2_path:
            home = os.path.dirname(os.path.abspath(r2_path))
            if os.path.basename(r2_path).lower() in ("radare2", "radare2.exe"):
                kwargs["radare2home"] = home
        try:
            self.r2 = r2pipe.open(str(filename), flags=flags, **kwargs)
        except (OSError, FileNotFoundError, ValueError) as e:
            raise RadareError(f"cannot start radare2 ({e})") from e
        try:
            self.r2.cmd("e scr.color=0")
            self.info = self._read_info()
            self.arch = self.info.get("arch")
            self.bits = self.info.get("bits")
            self.r2.cmd("aaa")
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self) -> None:
        """Terminate r2 (never raises)."""
        r2, self.r2 = self.r2, None
        if r2 is None:
            return
        try:
            r2.quit()
        except Exception:
            pass
        proc = getattr(r2, "process", None)
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass

    # ------------------------------------------------------------------ SAFE tokens
    @staticmethod
    def filter_reg(op):
        return op["value"]

    @staticmethod
    def filter_imm(op):
        imm = int(op["value"])
        if -int(5000) <= imm <= int(5000):
            ret = str(hex(op["value"]))
        else:
            ret = str('HIMM')
        return ret

    @staticmethod
    def filter_mem(op):
        if "base" not in op:
            op["base"] = 0

        if op["base"] == 0:
            r = "[" + "MEM" + "]"
        else:
            reg_base = str(op["base"])
            disp = str(op["disp"])
            scale = str(op["scale"])
            r = '[' + reg_base + "*" + scale + "+" + disp + ']'
        return r

    @staticmethod
    def filter_memory_references(i):
        inst = "" + i["mnemonic"]

        for op in i["operands"]:
            if op["type"] == 'reg':
                inst += " " + RadareFunctionAnalyzer.filter_reg(op)
            elif op["type"] == 'imm':
                inst += " " + RadareFunctionAnalyzer.filter_imm(op)
            elif op["type"] == 'mem':
                inst += " " + RadareFunctionAnalyzer.filter_mem(op)
            if len(i["operands"]) > 1:
                inst = inst + ","

        if "," in inst:
            inst = inst[:-1]
        inst = inst.replace(" ", "_")

        return str(inst)

    @staticmethod
    def get_callref(my_function, depth):
        calls = {}
        if 'callrefs' in my_function and depth > 0:
            for cc in my_function['callrefs']:
                if cc["type"] == "C":
                    calls[cc['at']] = cc['addr']
        return calls

    def get_binary_functions(self):
        return self.number_functions

    def get_instruction(self, instruction):
        """First entry of an ``aoj`` result with its operands attached, or None."""
        if not isinstance(instruction, list) or len(instruction) == 0:
            return None
        instruction = instruction[0]
        if not isinstance(instruction, dict) or 'opex' not in instruction \
                or 'mnemonic' not in instruction:
            return None
        instruction['operands'] = list(instruction['opex'].get('operands', []))
        return instruction

    def _token(self, instruction: dict) -> str:
        prefix = ARCH_PREFIX.get(self.arch)
        if prefix is None:
            raise UnsupportedArchitecture(f"unsupported architecture: {self.arch!r}")
        return prefix + RadareFunctionAnalyzer.filter_memory_references(instruction)

    # ------------------------------------------------------------------ r2 helpers
    def _read_info(self) -> dict:
        """``ij`` -> bin info ({arch, bits, baddr, ...}); {} if r2 does not know the file."""
        try:
            info = json.loads(self.r2.cmd('ij'))
            return info.get('bin') or {}
        except (ValueError, AttributeError, TypeError):
            return {}

    def get_arch(self):
        return self.arch, self.bits

    def _instruction_addresses(self, address: int) -> List[int]:
        """Addresses of the instructions of the function at `address`
        (``pdf``, falling back to ``pdfj``)."""
        self.r2.cmd(f's {address}')
        addrs: List[int] = []
        for line in self.r2.cmd('pdf').split('\n'):
            parts = line.split()
            # instruction lines start with the address; indentation depends on the version
            if not parts or not parts[0].startswith('0x'):
                continue
            try:
                addrs.append(int(parts[0], 16))
            except ValueError:
                continue
        if not addrs:
            try:
                data = json.loads(self.r2.cmd('pdfj'))
                for op in data.get('ops', []):
                    a = op.get('addr', op.get('offset'))
                    if isinstance(a, int):
                        addrs.append(a)
            except (ValueError, AttributeError, TypeError):
                pass
        return addrs

    def function_to_inst(self, functions_dict, my_function, depth):
        """SAFE tokens (and hex bytes) of one function, recursing into callees for depth > 0."""
        instructions = []
        asm = ""
        start = function_address(my_function)
        calls = RadareFunctionAnalyzer.get_callref(my_function, depth)
        skipped = 0
        for s in self._instruction_addresses(start):
            try:
                instruction = self.get_instruction(json.loads(self.r2.cmd(f'aoj 1 @ {hex(s)}')))
            except ValueError:
                instruction = None
            if instruction is None:
                skipped += 1
                continue
            asm += instruction.get("bytes", "")
            instructions.append(self._token(instruction))

            # recurse into the called function (only for depth > 0)
            if s in calls and depth > 0 and calls[s] in functions_dict:
                ii, aa = self.function_to_inst(functions_dict, functions_dict[calls[s]], depth - 1)
                instructions.extend(ii)
                asm += aa
        if skipped:
            logger.debug("function %s: %d instruction(s) without opex skipped", hex(start), skipped)
        return instructions, asm

    def set_afl(self) -> None:
        """Load the function list (``aflj``); raises RadareError when it cannot be parsed."""
        try:
            afl = json.loads(self.r2.cmd('aflj'))
        except (ValueError, TypeError) as e:
            raise RadareError(f"radare2 could not list the functions (aflj): {e}") from e
        if afl is None:
            afl = []
        if not isinstance(afl, list):
            raise RadareError("radare2 returned an unexpected aflj payload")
        self.afl = afl
        self.number_functions = len(afl)

    def find_functions(self):
        if self.afl is None:
            self.set_afl()
        return self.afl or []

    def find_functions_by_symbols(self):
        self.r2.cmd('aa')
        try:
            symbols = json.loads(self.r2.cmd('isj'))
            return [s for s in symbols if s['type'] == 'FUNC']
        except (ValueError, TypeError, KeyError):
            return []

    # ------------------------------------------------------------------ analysis
    def analyze(self) -> Dict[int, dict]:
        """{address: {'name', 'size', 'filtered_instructions', 'asm', 'address'}} for every
        function radare2 found. Keyed by address (names are not unique)."""
        if self.arch not in ARCH_PREFIX:
            raise UnsupportedArchitecture(f"unsupported architecture: {self.arch!r}")
        self.set_afl()
        self.r2.cmd('e asm.lines=false')
        function_list = self.afl or []
        functions_dict: Dict[int, dict] = {}
        result: Dict[int, dict] = {}
        for my_function in function_list:
            address = function_address(my_function)
            if address is not None:
                functions_dict.setdefault(address, my_function)
        for address, my_function in functions_dict.items():
            try:
                instructions, asm = self.function_to_inst(functions_dict, my_function, self.top_depth)
            except UnsupportedArchitecture:
                raise
            except Exception as e:  # one bad function must not lose the binary
                logger.warning("error %s in function %s from %s", e, my_function.get('name'), self.filename)
                continue
            result[address] = {'name': my_function.get('name'), 'size': function_size(my_function),
                               'filtered_instructions': instructions, 'asm': asm, 'address': address}
        return result

    def analyze_address(self, search_address):
        """Same as ``analyze`` for the single function at `search_address` ('0x...')."""
        self.set_afl()
        self.r2.cmd('e asm.lines=false')
        function_list = self.find_functions()
        functions_dict = {}
        for my_function in function_list:
            a = function_address(my_function)
            if a is not None:
                functions_dict[a] = my_function
        result = {}
        for address, my_function in functions_dict.items():
            if hex(address) == search_address:
                instructions, asm = self.function_to_inst(functions_dict, my_function, self.top_depth)
                result[address] = {'name': my_function.get('name'), 'size': function_size(my_function),
                                   'filtered_instructions': instructions, 'asm': asm, 'address': address}
                break
        return result

    def get_ghidra_funcs(self):
        with open(self.ghidra_offsets, 'rb') as f:
            functions = pickle.load(f)
        return functions

    def analyze_ghidra(self):
        """Tokens for the function list exported from Ghidra (pickle given as ghidra_offsets)."""
        functions_dict = self.get_ghidra_funcs()
        result = defaultdict(list)
        if len(functions_dict) == 0:
            logger.warning("Empty data for %s", self.filename)
            return None
        for offset, func_info in functions_dict.items():
            instructions = []
            asm = ""
            self.r2.cmd(f's  {func_info["address"]}')
            for instruction_offset in func_info["instructions"]:
                instruction = json.loads(self.r2.cmd(f'aoj 1 @ {instruction_offset}'))
                instruction = self.get_instruction(instruction)
                if instruction is None:
                    continue
                asm += instruction.get("bytes", "")
                instructions.append(self._token(instruction))
            result.update({offset: {'name': func_info["name"], 'filtered_instructions': instructions,
                                    "asm": asm, "address": func_info["address"],
                                    "size": func_info["instruction_length"]}})
        return result

    def get_information(self):
        """[{offset: '0x..', name, size}] for every function (offset = lowercase unpadded hex)."""
        self.set_afl()
        info = []
        for function in self.afl:
            address = function_address(function)
            if address is None:
                continue
            info.append({"offset": hex(address), "name": function.get("name"),
                         "size": function_size(function)})
        if len(info) > 0:
            return info
        return [{"offset": None, "name": None, "size": None}]
