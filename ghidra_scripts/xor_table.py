# Extract xor data (e.g., C2, Scan Receiver, DoS parameter) from Mirai table.c
# @author Shun Morishita
# @category Analysis
# @runtime Jython

import collections
import copy
import hashlib
import jarray
import json
import re
import __main__ as ghidra_app
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.address import AddressSet, GenericAddress
from ghidra.program.model.block import IsolatedEntrySubModel
from ghidra.program.model.data import IntegerDataType, PointerDataType
from ghidra.program.model.listing import Function, ParameterImpl
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor

KEYWORDS = ["SHELL", "ENABLE", "SYSTEM", "LOGIN", "PASSWORD", "login",
            "password", "CNC", "PRIVMSG", "telnet", "MIRAI", "admin", "root", "REPORT", "scanner"]

KEY_SCRIPT_NAME = "script_name"
KEY_GHIDRA_CURRENT_PROGRAM = "ghidra_current_program"
KEY_NAME = "name"
KEY_PATH = "path"
KEY_SHA256 = "sha256"
KEY_LANGUAGE_ID = "language_id"
KEY_IMAGE_BASE = "image_base"
KEY_MIN_ADDR = "min_addr"
KEY_MAX_ADDR = "max_addr"
KEY_TABLE_LOCK_VAL_FUNC = "table_lock_val_func"
KEY_ENTRYPOINT = "entrypoint"
KEY_TABLE_KEY = "table_key"
KEY_TABLE_ORIGINAL_KEY = "table_original_key"
KEY_TABLE_INIT_FUNC = "table_init_func"
KEY_TABLES_SHA256 = "tables_sha256"
KEY_TABLES_COUNT = "tables_count"
KEY_TABLES_INT_COUNT = "tables_int_count"
KEY_TABLES_STR_COUNT = "tables_str_count"
KEY_TABLES = "tables"
KEY_ID = "id"
KEY_TYPE = "type"
KEY_STR_DATA = "str_data"
KEY_INT_DATA = "int_data"
KEY_TABLE_ADDR = "table_addr"
KEY_REFS = "refs"
KEY_FUNC = "func"
KEY_ADDR = "addr"

MNE_CALL = "CALL"
MNE_CALLIND = "CALLIND"
MNE_INT_XOR = "INT_XOR"

ARCH_ARM_BE = "ARM:BE:32:v8"
ARCH_ARM_LE = "ARM:LE:32:v8"
ARCH_M68K = "68000:BE:32:Coldfire"
ARCH_MIPS_BE = "MIPS:BE:32:default"
ARCH_MIPS_LE = "MIPS:LE:32:default"
ARCH_PPC = "PowerPC:BE:32:default"
ARCH_SH4 = "SuperH4:LE:32:default"
ARCH_SPC = "sparc:BE:32:default"
ARCH_X86 = "x86:LE:32:default"
ARCH_X86_64 = "x86:LE:64:default"

SCRIPT_NAME = "xor_table.py"
LANGS = [
    ARCH_ARM_BE, ARCH_ARM_LE, ARCH_M68K, ARCH_MIPS_BE,
    ARCH_MIPS_LE, ARCH_PPC, ARCH_SH4, ARCH_SPC,
    ARCH_X86, ARCH_X86_64
    ]


def defUndefinedFuncs(listing, monitor):
    # ref. https://github.com/EliasKotlyar/Med9GhidraScripts/blob/main/general/DefineUndefinedFunctions.py
    addr_set = AddressSet()
    instructs = listing.getInstructions(currentProgram.getMemory(), True)
    while instructs.hasNext() and not monitor.isCancelled():
        instruct = instructs.next()
        addr_set.addRange(instruct.getMinAddress(), instruct.getMaxAddress())
    funcs = listing.getFunctions(True)
    while funcs.hasNext() and not monitor.isCancelled():
        func = funcs.next()
        addr_set.delete(func.getBody())
    if addr_set.getNumAddressRanges() == 0:
        return None
    # go through address set and find actual start of flow into dead code
    submodel = IsolatedEntrySubModel(currentProgram)
    subIter = submodel.getCodeBlocksContaining(addr_set, monitor)
    codeStarts = AddressSet()
    # sometimes IsolatedEntrySubModel() doesnt work correctly, we set the maximum value to 1000
    i = 0
    while subIter.hasNext():
        if i >= 1000:
            return None
        block = subIter.next()
        deadStart = block.getFirstStartAddress()
        codeStarts.add(deadStart)
        i += 1
    for startAdr in codeStarts:
        phyAdr = startAdr.getMinAddress()
        createFunction(phyAdr, None)
    return None


def getStringBytes(addr, mem, bytes_cache):
    # bulk-read once per address (instead of up to 1024 individual getByte()
    # calls) and cache, since the same address is looked at again for every
    # candidate xor key and again later when decoding the actual table.
    addr_str = addr.toString()
    if addr_str in bytes_cache:
        return bytes_cache[addr_str]
    # cap the read to what's actually left in this block: requesting a fixed
    # 1024 would throw MemoryAccessException whenever addr sits near a block
    # end (a real, common case for the last string in a section), silently
    # losing an otherwise valid short string.
    block = mem.getBlock(addr)
    avail = min(1024, int(block.getEnd().subtract(addr)) + 1) if block else 0
    byte_list = []
    if avail > 0:
        buf = jarray.zeros(avail, "b")
        try:
            n = mem.getBytes(addr, buf)
        except MemoryAccessException:
            n = 0
        for i in range(n):
            b = buf[i] & 0xFF
            if b == 0:
                break
            byte_list.append(b)
    bytes_cache[addr_str] = byte_list
    return byte_list


def collectFuncStringRefs(listing, func_mgr):
    # one pass over every instruction of every function to find candidate
    # table-string references. Independent of table_key, so it only needs to
    # run once no matter how many xor-key candidates getTableInitFunc tries.
    func_addrs = []
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        addrs = []
        for instruct in listing.getInstructions(func.getBody(), True):
            refs = getReferencesFrom(instruct.getAddress())
            if len(refs) == 0:
                continue
            for ref in refs:
                data_addr = ref.getToAddress()
                data_symbol = getSymbolAt(data_addr)
                if data_symbol and data_symbol.toString().startswith(("DAT_", "s_")):
                    addrs.append(data_addr)
        if addrs:
            func_addrs.append((func, addrs))
    return func_addrs


def getTableKeys(listing, func_mgr):
    candidates = []
    language_id = currentProgram.getLanguageID().toString()
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        instruct_mnemonics_list = []
        first_varnodes_list = []
        second_varnodes_list = []
        instructs = list(listing.getInstructions(func.getBody(), True))
        for instruct in instructs:
            pcode = instruct.getPcode()
            for entry in pcode:
                if entry.getMnemonic() != MNE_INT_XOR:
                    continue
                varnodes = entry.getInputs()
                first_varnode = varnodes[0]
                second_varnode = varnodes[1]
                if first_varnode.toString() == second_varnode.toString():
                    continue
                first_type = parseVarnode(first_varnode)[0]
                second_type = parseVarnode(second_varnode)[0]
                if language_id == ARCH_M68K:
                    if first_type != "register" and second_type == "register":
                        continue
                else:
                    if first_type == "register" and second_type != "register":
                        continue
                instruct_mnemonics_list.append(instruct.getMnemonicString())
                first_varnodes_list.append(first_varnode)
                second_varnodes_list.append(second_varnode)
                break
        instruct_mnemonics_set = set(instruct_mnemonics_list)
        first_varnodes_set = set(first_varnodes_list)
        second_varnodes_set = set(second_varnodes_list)
        if (len(instruct_mnemonics_set) == 1
                and len(second_varnodes_list) == 4
                and len(second_varnodes_set) == 1):
            pass
        elif (len(instruct_mnemonics_set) == 1
                and len(second_varnodes_list) == 4
                and len(first_varnodes_set) == 1):
            pass
        elif (len(instruct_mnemonics_set) == 1
                and len(second_varnodes_list) == 4
                and len(second_varnodes_set) == 2):
            pass
        else:
            continue
        
        target_func_flag = False
        data_addrs = []
        func_table_key = None
        func_table_orig_key = None
        for instruct in instructs:
            try:
                refs = getReferencesFrom(instruct.getAddress())
                if len(refs) == 0:
                    continue
                for ref in refs:
                    data_addr = ref.getToAddress()
                    if not data_addr.isMemoryAddress():
                        continue
                    data_addrs.append(data_addr)
                    bytes = getDataAt(data_addr).getValue()
                    if not isinstance(bytes, Scalar):
                        continue
                    if bytes.bitLength() != 32:
                        continue
                    target_func_flag = True
                    func_table_orig_key = format(bytes.getUnsignedValue(), "#010x")
                    func_table_key = int(func_table_orig_key[2:4], 16) ^ \
                            int(func_table_orig_key[4:6], 16) ^ \
                            int(func_table_orig_key[6:8], 16) ^ \
                            int(func_table_orig_key[8:10], 16)
            except:
                continue
        if target_func_flag:
            table_base_addr = collections.Counter(data_addrs).most_common(1)[0][0]
            found = False
            for cand in candidates:
                if cand[1] == func_table_key and cand[2] == func_table_orig_key and cand[3] == table_base_addr:
                    cand[0].append(func)
                    found = True
                    break
            if not found:
                candidates.append(([func], func_table_key, func_table_orig_key, table_base_addr))
                
    KNOWN_KEYS = ["0xdeadbeef", "0xdf7ecadf", "0xdedefbaf", "0x1337c0d3"]
    # Sort: known keys first, then by number of functions that matched it, then by lowest address
    candidates.sort(key=lambda c: (
        1 if c[2] in KNOWN_KEYS else 0,
        len(c[0]),
        -c[3].getOffset() if c[3] else 0
    ), reverse=True)
    return candidates



def getTableInitFunc(ifc, monitor, func_addrs, bytes_cache, mem, table_key, xor_string_count_threshold=3):
    def _getCandUtilMemcpyFuncs(cand_caller_func):
        res = ifc.decompileFunction(cand_caller_func, 60, monitor)
        if not res:
            return None
        high_func = res.getHighFunction()
        pcodes = high_func.getPcodeOps()
        # get target_funcs: malloc() or util_memcpy()
        cand_util_memcpy_funcs = []
        for pcode in pcodes:
            if pcode.getMnemonic() not in (MNE_CALL, MNE_CALLIND):
                continue
            instruct_addr = pcode.getSeqnum().getTarget()
            ref = getReferencesFrom(instruct_addr)
            if len(ref) == 0:
                continue
            ref_func = getFunctionAt(ref[0].getToAddress())
            if ref_func:
                cand_util_memcpy_funcs.append(ref_func)
        return cand_util_memcpy_funcs
    table_init_func = util_memcpy_func = add_entry_func = None

    for func, addrs in func_addrs:
        cand_table_init_func = cand_add_entry_func = None
        # check func has xor strings (default threshold is 3)
        xor_string_count = 0
        for data_addr in addrs:
            byte_list = getStringBytes(data_addr, mem, bytes_cache)
            if len(byte_list) < 2:
                continue
            decoded_chars = [chr(b ^ table_key) if 32 <= (b ^ table_key) <= 126 else "." for b in byte_list]
            decoded = "".join(decoded_chars)

            if any(kw in decoded for kw in KEYWORDS):
                xor_string_count += 3  # Strong keyword match
            elif len([c for c in decoded_chars if c != "."]) >= len(byte_list) * 0.8:
                xor_string_count += 1  # High printable ratio

            if xor_string_count >= xor_string_count_threshold:
                cand_table_init_func = func
                break
        if cand_table_init_func:
            cand_util_memcpy_funcs = _getCandUtilMemcpyFuncs(cand_table_init_func)
            if len(set(cand_util_memcpy_funcs)) == 2:
                pass
            elif len(set(cand_util_memcpy_funcs)) == 1:
                # maybe this is add_entry_func (this malware is not using optimization level -O3)
                cand_add_entry_func = cand_util_memcpy_funcs[0]
                cand_util_memcpy_funcs = _getCandUtilMemcpyFuncs(cand_add_entry_func)
                if len(set(cand_util_memcpy_funcs)) == 2:
                    pass
                else:
                    continue
            else:
                continue
            # get mode function
            cand_util_memcpy_func1 = collections.Counter(cand_util_memcpy_funcs).most_common(2)[0][0]
            cand_func1_instructs = list(listing.getInstructions(cand_util_memcpy_func1.getBody(), True))
            # get second mode function
            cand_util_memcpy_func2 = collections.Counter(cand_util_memcpy_funcs).most_common(2)[1][0]
            cand_func2_instructs = list(listing.getInstructions(cand_util_memcpy_func2.getBody(), True))
            # minimum function is util_memcpy()
            if len(cand_func1_instructs) > len(cand_func2_instructs):
                util_memcpy_func = cand_util_memcpy_func2
            else:
                util_memcpy_func = cand_util_memcpy_func1
            table_init_func = cand_table_init_func
            add_entry_func = cand_add_entry_func
            break
    return table_init_func, util_memcpy_func, add_entry_func


def updateUtilMemcpyFunc(util_memcpy_func):
    # set util_memcpy arguments
    args = []
    args.append(ParameterImpl("dst", PointerDataType(), currentProgram))
    args.append(ParameterImpl("src", PointerDataType(), currentProgram))
    args.append(ParameterImpl("len", IntegerDataType(), currentProgram))
    util_memcpy_func.updateFunction(
            currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
            util_memcpy_func.getReturn(), args,
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
            SourceType.USER_DEFINED
            )
    return None


def getTables(listing, ifc, monitor, table_init_func, util_memcpy_func, add_entry_func, table_key, table_base_addr, mem, bytes_cache):
    tables = []
    language_id = currentProgram.getLanguageID().toString()
    bits = int(language_id.split(":")[2])
    ccode = getDecompileCCode(table_init_func, ifc, monitor)
    if not ccode:
        return None
    if not add_entry_func:
        # get enc data from util_memcpy_func second argument (optimization level is -O3)
        call_func_strs = re.findall(
                util_memcpy_func.getName() + r"\(.+?,.+?,[0-9a-fA-F|x]+\);",
                ccode.toString()
                )
        for call_func_str in call_func_strs:
            args = re.match(
                    util_memcpy_func.getName() + r"\((.+?),(.+?),([0-9a-fA-F|x]+)\);",
                    call_func_str
                    )
            if len(args.groups()) != 3:
                continue
            data = getDecodeData(args.group(2), table_key, mem, bytes_cache)
            table = collections.OrderedDict()
            table[KEY_ID] = None
            table[KEY_TYPE] = str(type(data)).split("'")[1]
            if isinstance(data, int):
                table[KEY_INT_DATA] = data
            elif isinstance(data, str):
                table[KEY_STR_DATA] = data
            tables.append(table)
        # get table_addr from table_mnemonic_strs instruct (after each util_memcpy_func)
        table_mnemonic_strs, table_reg_str = getTableMnemonicString()
        instructs = list(listing.getInstructions(table_init_func.getBody(), True))
        index = table_count = 0
        while index < len(instructs):
            instruct = instructs[index]
            index += 1
            refs = getReferencesFrom(instruct.getAddress())
            if len(refs) == 0:
                continue
            ref_addr = refs[0].getToAddress()
            if ref_addr != util_memcpy_func.getEntryPoint():
                continue
            while index < len(instructs):
                inner_instruct = instructs[index]
                index += 1
                if inner_instruct.getMnemonicString() not in table_mnemonic_strs:
                    continue
                # check second operand is table_reg_str
                if table_reg_str:
                    try:
                        if table_reg_str != inner_instruct.getOpObjects(1)[0].toString():
                            continue
                    except:
                        continue
                inner_refs = getReferencesFrom(inner_instruct.getAddress())
                if len(inner_refs) == 0:
                    continue
                table_addr = inner_refs[0].getToAddress()
                # get id = (table_addr - table_base_addr) / size(m68k:6, 32bit:8, 64bit:16)
                id = None
                if table_addr.isMemoryAddress():
                    if language_id == ARCH_M68K:
                        id = int(table_addr.subtract(table_base_addr) / 6)
                    elif bits == 32:
                        id = int(table_addr.subtract(table_base_addr) / 8)
                    elif bits == 64:
                        id = int(table_addr.subtract(table_base_addr) / 16)
                    if id < 0:
                        id = None
                if table_count < len(tables):
                    tables[table_count][KEY_ID] = id
                    tables[table_count][KEY_TABLE_ADDR] = getAddrString(table_addr)
                    tables[table_count][KEY_REFS] = []
                    table_count += 1
                break
    else:
        # get enc data from add_entry_func second argument (optimization level is not -O3)
        call_func_strs = re.findall(
                add_entry_func.getName() + r"\([0-9a-fA-F|x]+,.+?,[0-9a-fA-F|x]+\);",
                ccode.toString()
                )
        for call_func_str in call_func_strs:
            args = re.match(
                    add_entry_func.getName() + r"\(([0-9a-fA-F|x]+),(.+?),([0-9a-fA-F|x]+)\);",
                    call_func_str
                    )
            if len(args.groups()) != 3:
                continue
            id = int(args.group(1), 0)
            data = getDecodeData(args.group(2), table_key, mem, bytes_cache)
            table_addr = None
            if language_id == ARCH_M68K:
                table_addr = table_base_addr.add(id * 6)
            elif bits == 32:
                table_addr = table_base_addr.add(id * 8)
            elif bits == 64:
                table_addr = table_base_addr.add(id * 16)
            table = collections.OrderedDict()
            table[KEY_ID] = id
            table[KEY_TYPE] = str(type(data)).split("'")[1]
            if isinstance(data, int):
                table[KEY_INT_DATA] = data
            elif isinstance(data, str):
                table[KEY_STR_DATA] = data
            table[KEY_TABLE_ADDR] = getAddrString(table_addr)
            table[KEY_REFS] = []
            tables.append(table)
    return tables


def getTableRetrieveValFunc(table_lock_val_funcs, table_base_addr):
    table_retrieve_val_func = None
    refs = getReferencesTo(table_base_addr)
    for ref in refs:
        cand_table_retrieve_val_func = getFunctionContaining(ref.getFromAddress())
        # exclude None from cand_table_retrieve_val_func
        if cand_table_retrieve_val_func and cand_table_retrieve_val_func not in table_lock_val_funcs:
            table_retrieve_val_func = cand_table_retrieve_val_func
            break
    return table_retrieve_val_func


def updateTableRetrieveValFunc(table_retrieve_val_func):
    # set table_retrieve_val args
    args = []
    args.append(ParameterImpl("id", IntegerDataType(), currentProgram))
    args.append(ParameterImpl("len", PointerDataType(), currentProgram))
    table_retrieve_val_func.updateFunction(
            currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
            table_retrieve_val_func.getReturn(), args,
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
            SourceType.USER_DEFINED
            )
    return None


def connectRefs(ifc, monitor, table_retrieve_val_func, table_base_addr, tables):
    language_id = currentProgram.getLanguageID().toString()
    bits = int(language_id.split(":")[2])
    # get reference functions to table_retrieve_val_func
    ref_funcs = set()
    refs = getReferencesTo(table_retrieve_val_func.getEntryPoint())
    for ref in refs:
        ref_func = getFunctionContaining(ref.getFromAddress())
        if ref_func:
            ref_funcs.add(ref_func)
    for ref_func in ref_funcs:
        res = ifc.decompileFunction(ref_func, 60, monitor)
        if not res:
            continue
        high_func = res.getHighFunction()
        if not high_func:
            continue
        pcodes = high_func.getPcodeOps()
        for pcode in pcodes:
            if pcode.getMnemonic() not in (MNE_CALL, MNE_CALLIND):
                continue
            inputs = pcode.getInputs()
            # addr = inputs[0].getAddress()
            args = inputs[1:]
            instruct_addr = pcode.getSeqnum().getTarget()
            ref = getReferencesFrom(instruct_addr)
            if len(ref) == 0:
                continue
            if table_retrieve_val_func != getFunctionAt(ref[0].getToAddress()):
                continue
            first_arg = int(parseVarnode(args[0])[1], 0)
            # calc id * size(m68k:6, 32bit:8, 64bit:16) to map to table addr
            target_table_addr = None
            if language_id == ARCH_M68K:
                target_table_addr = table_base_addr.add(first_arg * 6)
            elif bits == 32:
                target_table_addr = table_base_addr.add(first_arg * 8)
            elif bits == 64:
                target_table_addr = table_base_addr.add(first_arg * 16)
            else:
                break
            new_tables = []
            for index, table in enumerate(tables):
                if table[KEY_TABLE_ADDR] == getAddrString(target_table_addr):
                    if not table[KEY_ID]:
                        table[KEY_ID] = first_arg
                    ref_dict = collections.OrderedDict()
                    ref_dict[KEY_FUNC] = ref_func.getName()
                    ref_dict[KEY_ADDR] = getAddrString(instruct_addr)
                    table[KEY_REFS].append(ref_dict)
                new_tables.append(table)
            # update tables
            tables = copy.copy(new_tables)
    return tables


def getTablesSHA256(tables):
    message = ""
    for table in tables:
        message += str(table[KEY_TYPE])
        if table[KEY_TYPE] == "int":
            message += str(table[KEY_INT_DATA])
        elif table[KEY_TYPE] == "str":
            message += str(table[KEY_STR_DATA])
    tables_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return tables_hash


def getTablesCount(tables):
    tables_count = len(tables)
    tables_int_count = tables_str_count = 0
    for table in tables:
        if table[KEY_TYPE] == "int":
            tables_int_count += 1
        elif table[KEY_TYPE] == "str":
            tables_str_count += 1
    return tables_count, tables_int_count, tables_str_count


def getDecodeData(var, table_key, mem, bytes_cache):
    if not isinstance(var, unicode):
        return None
    bytes = bytearray()
    if var.startswith('"') and var.endswith('"'):
        # e.g. u'"CFOKL"' / u'"\\rRPMA\\r\\""'
        enc_string = var[1:-1]
        enc_size = len(enc_string)
        index = 0
        while index < enc_size:
            if enc_string[index] == "\\":
                if enc_string[index + 1] == "a":
                    bytes.append(7)
                    index += 1
                elif enc_string[index + 1] == "b":
                    bytes.append(8)
                    index += 1
                elif enc_string[index + 1] == "t":
                    bytes.append(9)
                    index += 1
                elif enc_string[index + 1] == "n":
                    bytes.append(10)
                    index += 1
                elif enc_string[index + 1] == "v":
                    bytes.append(11)
                    index += 1
                elif enc_string[index + 1] == "f":
                    bytes.append(12)
                    index += 1
                elif enc_string[index + 1] == "r":
                    bytes.append(13)
                    index += 1
            else:
                bytes.append(ord(enc_string[index]))
            index += 1
    elif var.startswith("&"):
        # e.g. u'&DAT_00412084'
        addr = toAddr(var.split("_")[1])
        bytes = bytearray(getStringBytes(addr, mem, bytes_cache))
    data = None
    data_size = len(bytes)
    # if data is port number, data must be 2 bytes and last byte is not table_key
    if data_size == 2 and bytes[1] != table_key:
        first_byte = bytes[0] ^ table_key
        second_byte = bytes[1] ^ table_key
        number = first_byte * 256 + second_byte
        data = number
    else:
        string = ""
        for byte in bytes:
            code = byte ^ table_key
            if code == 0:
                pass
            # convert ascii printable characters
            elif 32 <= code <= 126:
                string += chr(code)
            else:
                string += "\\x{:02x}".format(code)
        data = string
    return data


def getDecompileCCode(func, ifc, monitor):
    res = ifc.decompileFunction(func, 60, monitor)
    if not res:
        return None
    ccode = res.getCCodeMarkup()
    if not ccode:
        return None
    return ccode


def getAddrString(addr):
    addr_str = None
    if isinstance(addr, str):
        if addr.startswith("0x"):
            addr_str = toAddr(addr).toString()
        else:
            addr_str = addr
    elif isinstance(addr, unicode):
        addr = str(addr)
        if addr.startswith("0x"):
            addr_str = toAddr(addr).toString()
        else:
            addr_str = addr
    elif isinstance(addr, GenericAddress):
        addr_str = addr.toString()
    elif isinstance(addr, Scalar):
        addr_str = toAddr(addr.toString()).toString()
    else:
        pass
    return addr_str


def parseVarnode(varnode):
    return varnode.toString().strip("()").split(", ")


def getTableMnemonicString():
    table_mnemonic_strs = table_reg_str = None
    language_id = currentProgram.getLanguageID().toString()
    if language_id in [ARCH_ARM_BE, ARCH_ARM_LE]:
        table_mnemonic_strs = ["str"]
    elif language_id in [ARCH_M68K]:
        table_mnemonic_strs = ["move.l"]
    elif language_id in [ARCH_MIPS_BE, ARCH_MIPS_LE]:
        table_mnemonic_strs = ["sw"]
    elif language_id in [ARCH_PPC]:
        table_mnemonic_strs = ["stw"]
    elif language_id in [ARCH_SH4]:
        table_mnemonic_strs = ["mov.l"]
    elif language_id in [ARCH_SPC]:
        table_mnemonic_strs = ["stw", "_stw"]
    elif language_id in [ARCH_X86]:
        table_mnemonic_strs = ["MOV"]
        table_reg_str = "EBX"
    elif language_id in [ARCH_X86_64]:
        table_mnemonic_strs = ["MOV"]
        table_reg_str = "RBX"
    return table_mnemonic_strs, table_reg_str


if __name__ == "__main__":
    language_id = currentProgram.getLanguageID().toString()
    if language_id not in LANGS:
        print("error: this script only target for " + str(LANGS))
    listing = currentProgram.getListing()
    func_mgr = currentProgram.getFunctionManager()
    ifc = DecompInterface()
    _ = ifc.setOptions(DecompileOptions())
    _ = ifc.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    defUndefinedFuncs(listing, monitor)
    table_lock_val_funcs = table_init_func = util_memcpy_func = None
    add_entry_func = table_retrieve_val_func = table_key = None
    table_original_key_str = table_base_addr = tables = None
    candidates = getTableKeys(
            listing, func_mgr
            )
    mem = currentProgram.getMemory()
    bytes_cache = {}
    # collected once: independent of table_key, so all candidate keys below
    # reuse it instead of re-scanning every instruction of every function
    func_addrs = collectFuncStringRefs(listing, func_mgr)

    for cand in candidates[:3]:
        table_lock_val_funcs, table_key, table_original_key_str, table_base_addr = cand
        if table_lock_val_funcs and table_key and table_original_key_str and table_base_addr:
            table_init_func, util_memcpy_func, add_entry_func = getTableInitFunc(
                    ifc, monitor, func_addrs, bytes_cache, mem, table_key
                    )
            if table_init_func and util_memcpy_func:
                updateUtilMemcpyFunc(util_memcpy_func)
                tables = getTables(
                        listing, ifc, monitor, table_init_func, util_memcpy_func,
                        add_entry_func, table_key, table_base_addr, mem, bytes_cache
                        )
                # reference connector is optional feature
                try:
                    if tables:
                        table_retrieve_val_func = getTableRetrieveValFunc(
                                table_lock_val_funcs, table_base_addr
                                )
                        if table_retrieve_val_func:
                            updateTableRetrieveValFunc(table_retrieve_val_func)
                            tables = connectRefs(
                                    ifc, monitor, table_retrieve_val_func,
                                    table_base_addr, tables
                                    )
                except:
                    pass
                break
    # make results data
    output_dict = collections.OrderedDict()
    output_dict[KEY_SCRIPT_NAME] = SCRIPT_NAME
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM] = collections.OrderedDict()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_NAME] = currentProgram.getName()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_PATH] = currentProgram.getExecutablePath()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_SHA256] = currentProgram.getExecutableSHA256()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_LANGUAGE_ID] = language_id
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_IMAGE_BASE] = currentProgram.getImageBase().toString()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_MIN_ADDR] = currentProgram.getMinAddress().toString()
    output_dict[KEY_GHIDRA_CURRENT_PROGRAM][KEY_MAX_ADDR] = currentProgram.getMaxAddress().toString()
    if table_lock_val_funcs and table_key and table_original_key_str:
        output_dict[KEY_TABLE_LOCK_VAL_FUNC] = collections.OrderedDict()
        output_dict[KEY_TABLE_LOCK_VAL_FUNC][KEY_NAME] = table_lock_val_funcs[0].getName()
        output_dict[KEY_TABLE_LOCK_VAL_FUNC][KEY_ENTRYPOINT] = table_lock_val_funcs[0].getEntryPoint().toString()
        output_dict[KEY_TABLE_LOCK_VAL_FUNC][KEY_TABLE_KEY] = "0x{:02x}".format(table_key)
        output_dict[KEY_TABLE_LOCK_VAL_FUNC][KEY_TABLE_ORIGINAL_KEY] = table_original_key_str
    if table_init_func:
        output_dict[KEY_TABLE_INIT_FUNC] = collections.OrderedDict()
        output_dict[KEY_TABLE_INIT_FUNC][KEY_NAME] = table_init_func.getName()
        output_dict[KEY_TABLE_INIT_FUNC][KEY_ENTRYPOINT] = table_init_func.getEntryPoint().toString()
    if tables:
        output_dict[KEY_TABLE_INIT_FUNC][KEY_TABLES_SHA256] = getTablesSHA256(tables)
        tables_count, tables_int_count, tables_str_count = getTablesCount(tables)
        output_dict[KEY_TABLE_INIT_FUNC][KEY_TABLES_COUNT] = tables_count
        output_dict[KEY_TABLE_INIT_FUNC][KEY_TABLES_INT_COUNT] = tables_int_count
        output_dict[KEY_TABLE_INIT_FUNC][KEY_TABLES_STR_COUNT] = tables_str_count
        output_dict[KEY_TABLE_INIT_FUNC][KEY_TABLES] = []
        for table in tables:
            output_dict[KEY_TABLE_INIT_FUNC][KEY_TABLES].append(table)
    # output results to stdout/jsonfile
    args = ghidra_app.getScriptArgs()
    if len(args) < 1:
        print("")
        print("")
        print(json.dumps(output_dict, ensure_ascii=False, indent=2))
        print("")
        print("")
    else:
        output_file = args[0]
        with open(output_file, "w") as f:
            json.dump(output_dict, f, ensure_ascii=False, indent=2)
