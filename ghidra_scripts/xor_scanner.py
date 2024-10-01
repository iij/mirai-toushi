#Extract xor data (password list) from Mirai scanner.c
#@author Shun Morishita
#@category Analysis

import collections
import hashlib
import json
import re
import __main__ as ghidra_app
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.program.model.block import IsolatedEntrySubModel
from ghidra.program.model.data import PointerDataType, UnsignedIntegerDataType
from ghidra.program.model.lang import Register
from ghidra.program.model.listing import Function, ParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor


KEY_SCRIPT_NAME = "script_name"
KEY_GHIDRA_CURRENT_PROGRAM = "ghidra_current_program"
KEY_NAME = "name"
KEY_PATH = "path"
KEY_SHA256 = "sha256"
KEY_LANGUAGE_ID = "language_id"
KEY_IMAGE_BASE = "image_base"
KEY_MIN_ADDR = "min_addr"
KEY_MAX_ADDR = "max_addr"
KEY_ADD_AUTH_ENTRY_FUNC = "add_auth_entry_func"
KEY_ENTRYPOINT = "entrypoint"
KEY_SCANNER_KEY = "scanner_key"
KEY_SCANNER_INIT_FUNC = "scanner_init_func"
KEY_AUTH_TABLES_SHA256 = "auth_tables_sha256"
KEY_AUTH_TABLES_COUNT = "auth_tables_count"
KEY_AUTH_TABLES = "auth_tables"
KEY_USER = "user"
KEY_PASS = "pass"
KEY_WEIGHT = "weight"

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

SCRIPT_NAME = "xor_scanner.py"
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
    while subIter.hasNext():
        block = subIter.next()
        deadStart = block.getFirstStartAddress()
        codeStarts.add(deadStart)
    for startAdr in codeStarts:
        phyAdr = startAdr.getMinAddress()
        createFunction(phyAdr, None)
    return None


def getScannerKey(func_mgr, ifc, monitor):
    add_auth_entry_func = deobf_func = scanner_key = None
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        res = ifc.decompileFunction(func, 60, monitor)
        if not res:
            continue
        ccode = res.getCCodeMarkup()
        if not ccode:
            continue
        roop_strs = re.findall(r"do \{.+?\} while", ccode.toString())
        if len(roop_strs) == 0:
            # sparc uses while(true) statement
            roop_strs = re.findall(r"while\( true \) \{.+?\}", ccode.toString())
        # add_auth_entry_func has two while statements
        if len(roop_strs) == 2:
            keys = []
            for roop_str in roop_strs:
                # ; *(byte *)(iVar4 + (int)pvVar3) = *(byte *)(iVar4 + (int)pvVar3) ^ 0xb4;
                match = re.search(r".+? = .+? \^ ([0-9a-fA-F|x]+);", roop_str)
                if match:
                    key = int(match.group(1), 0)
                    # check 1 byte key
                    if key >= 0 and key <= 255:
                        keys.append(key)
            if len(keys) == 2:
                if None not in keys and keys[0] == keys[1]:
                    add_auth_entry_func = func
                    scanner_key = keys[0]
                    break
        else:
            # maybe this is deobf_func (this malware is not using optimization level -O3)
            # ; while ((int)lVar2 < *param_2) {
            roop_strs = re.findall(r"while \(.+? \< .+?\) \{.+?\}", ccode.toString())
            if len(roop_strs) == 0:
                # get for statement
                # ; for (iVar1 = 0; iVar1 < *param_2; iVar1 = iVar1 + 1) {
                roop_strs = re.findall(r"for \(.+?; .+?; .+?\) \{.+?\}", ccode.toString())
            if len(roop_strs) == 1:
                # handle more than one xor statement
                # ; *(byte *)(lVar3 + lVar2) = *(byte *)(lVar3 + lVar2) ^ 3;
                xor_strs = re.findall(r".+? = .+? \^ [0-9a-fA-F|x]+;", roop_strs[0])
                if len(xor_strs) >= 1:
                    for xor_str in xor_strs:
                        match = re.search(r".+? = .+? \^ ([0-9a-fA-F|x]+);", xor_str)
                        if match:
                            key = int(match.group(1), 0)
                            # check 1 byte key
                            if key >= 0 and key <= 255:
                                if not scanner_key:
                                    scanner_key = key
                                else:
                                    scanner_key ^= key
                    if scanner_key:
                        deobf_func = func
                        add_auth_entry_func = getModeCallerFunc(deobf_func)
    return add_auth_entry_func, scanner_key


def getModeCallerFunc(callee_func):
    caller_func = None
    language_id = currentProgram.getLanguageID().toString()
    entry_point = callee_func.getEntryPoint()
    refs = getReferencesTo(entry_point)
    cand_caller_funcs = []
    for ref in refs:
        cand_caller_func = None
        # in some cases (sh4), getFunctionContaining cannot identify function correctly
        if language_id == ARCH_SH4:
            cand_caller_func = getFunctionBefore(ref.getFromAddress())
        else:
            cand_caller_func = getFunctionContaining(ref.getFromAddress())
        cand_caller_funcs.append(cand_caller_func)
    # use mode function for caller_func
    if len(cand_caller_funcs) >= 1:
        caller_func = collections.Counter(cand_caller_funcs).most_common(1)[0][0]
    return caller_func


def updateAddAuthEntryFunc(add_auth_entry_func, scanner_init_func):
    reg1 = reg2 = reg3 = None
    reg1_str, reg2_str, reg3_str = getRegisterString()
    # get 1st~3rd register variables
    if reg1_str and reg2_str and reg3_str:
        for instruct in listing.getInstructions(scanner_init_func.getBody(), True):
            try:
                for i in range(3):
                    operand = instruct.getOpObjects(i)[0]
                    if not isinstance(operand, Register):
                        continue
                    if operand.toString() == reg1_str:
                        reg1 = operand
                    elif operand.toString() == reg2_str:
                        reg2 = operand
                    elif operand.toString() == reg3_str:
                        reg3 = operand
            except:
                pass
            if None not in (reg1, reg2, reg3):
                break
    # set add_auth_entry args
    if reg1 and reg2 and reg3:
        args = []
        args.append(ParameterImpl("enc_user", PointerDataType(), reg1, currentProgram))
        args.append(ParameterImpl("enc_pass", PointerDataType(), reg2, currentProgram))
        args.append(ParameterImpl("weight", UnsignedIntegerDataType(), reg3, currentProgram))
        add_auth_entry_func.updateFunction(
                currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                add_auth_entry_func.getReturn(), args,
                Function.FunctionUpdateType.CUSTOM_STORAGE, True,
                SourceType.USER_DEFINED
                )
    else:
        args = []
        args.append(ParameterImpl("enc_user", PointerDataType(), currentProgram))
        args.append(ParameterImpl("enc_pass", PointerDataType(), currentProgram))
        args.append(ParameterImpl("weight", UnsignedIntegerDataType(), currentProgram))
        add_auth_entry_func.updateFunction(
                currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                add_auth_entry_func.getReturn(), args,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                SourceType.USER_DEFINED
                )
    return None


def getAuthTables(ifc, monitor, add_auth_entry_func, scanner_init_func, scanner_key):
    language_id = currentProgram.getLanguageID().toString()
    auth_tables = []
    timeout = 60
    if language_id == ARCH_SH4:
        timeout = 360
    res = ifc.decompileFunction(scanner_init_func, timeout, monitor)
    if not res:
        return auth_tables
    ccode = res.getCCodeMarkup()
    if not ccode:
        return auth_tables
    call_func_strs = re.findall(
            add_auth_entry_func.getName() + r"\(.*?,.*?,[0-9a-fA-F|x]+\);",
            ccode.toString()
            )
    for call_func_str in call_func_strs:
        args = re.match(
                add_auth_entry_func.getName() + r"\((.*?),(.*?),([0-9a-fA-F|x]+)\);",
                call_func_str
                )
        if len(args.groups()) == 3:
            try:
                auth_table = collections.OrderedDict()
                user = getDecodeString(args.group(1), scanner_key)
                _pass = getDecodeString(args.group(2), scanner_key)
                auth_table[KEY_USER] = user
                auth_table[KEY_PASS] = _pass
                auth_table[KEY_WEIGHT] = int(args.group(3), 0)
                auth_tables.append(auth_table)
            except:
                continue
    return auth_tables


def getAuthTablesSHA256(tables):
    message = ""
    for table in tables:
        message += str(table[KEY_USER])
        message += str(table[KEY_PASS])
        message += str(table[KEY_WEIGHT])
    tables_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return tables_hash


def getAuthTablesCount(tables):
    tables_count = len(tables)
    return tables_count


def getDecodeString(var, scanner_key):
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
        # max size (1024) of bytes
        for count in range(1024):
            byte = getUByte(addr.add(count))
            # null
            if byte == 0:
                break
            else:
                bytes.append(byte)
    string = ""
    for byte in bytes:
        code = byte ^ scanner_key
        if code == 0:
            pass
        # convert ascii printable characters
        elif code >= 32 and code <= 126:
            string += chr(code)
        else:
            string += "\\x{:02x}".format(code)
    return string


def getUByte(addr):
    return getByte(addr) & 0xFF


def parseVarnode(varnode):
    return varnode.toString().strip("()").split(", ")


def getRegisterString():
    reg1_str = reg2_str = reg3_str = None
    language_id = currentProgram.getLanguageID().toString()
    if language_id in [ARCH_ARM_BE, ARCH_ARM_LE]:
        reg1_str, reg2_str, reg3_str = "r0", "r1", "r2"
    elif language_id in [ARCH_M68K]:
        pass
    elif language_id in [ARCH_MIPS_BE, ARCH_MIPS_LE]:
        reg1_str, reg2_str, reg3_str = "a0", "a1", "a2"
    elif language_id in [ARCH_PPC]:
        reg1_str, reg2_str, reg3_str = "r3", "r4", "r5"
    elif language_id in [ARCH_SH4]:
        reg1_str, reg2_str, reg3_str = "r4", "r5", "r6"
    elif language_id in [ARCH_SPC]:
        reg1_str, reg2_str, reg3_str = "o0", "o1", "o2"
    elif language_id in [ARCH_X86]:
        reg1_str, reg2_str, reg3_str = "EAX", "EDX", "ECX"
    elif language_id in [ARCH_X86_64]:
        reg1_str, reg2_str, reg3_str = "RDI", "RSI", "RDX"
    return reg1_str, reg2_str, reg3_str


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
    add_auth_entry_func = scanner_init_func = scanner_key = auth_tables = None
    add_auth_entry_func, scanner_key = getScannerKey(func_mgr, ifc, monitor)
    if add_auth_entry_func and scanner_key:
        scanner_init_func = getModeCallerFunc(add_auth_entry_func)
        if scanner_init_func:
            updateAddAuthEntryFunc(add_auth_entry_func, scanner_init_func)
            auth_tables = getAuthTables(
                    ifc, monitor, add_auth_entry_func,
                    scanner_init_func, scanner_key
                    )
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
    if add_auth_entry_func and scanner_key:
        output_dict[KEY_ADD_AUTH_ENTRY_FUNC] = collections.OrderedDict()
        output_dict[KEY_ADD_AUTH_ENTRY_FUNC][KEY_NAME] = add_auth_entry_func.getName()
        output_dict[KEY_ADD_AUTH_ENTRY_FUNC][KEY_ENTRYPOINT] = add_auth_entry_func.getEntryPoint().toString()
        output_dict[KEY_ADD_AUTH_ENTRY_FUNC][KEY_SCANNER_KEY] = "0x{:02x}".format(scanner_key)
    if scanner_init_func:
        output_dict[KEY_SCANNER_INIT_FUNC] = collections.OrderedDict()
        output_dict[KEY_SCANNER_INIT_FUNC][KEY_NAME] = scanner_init_func.getName()
        output_dict[KEY_SCANNER_INIT_FUNC][KEY_ENTRYPOINT] = scanner_init_func.getEntryPoint().toString()
    if auth_tables:
        output_dict[KEY_SCANNER_INIT_FUNC][KEY_AUTH_TABLES_SHA256] = getAuthTablesSHA256(auth_tables)
        output_dict[KEY_SCANNER_INIT_FUNC][KEY_AUTH_TABLES_COUNT] = getAuthTablesCount(auth_tables)
        output_dict[KEY_SCANNER_INIT_FUNC][KEY_AUTH_TABLES] = []
        for auth_table in auth_tables:
            output_dict[KEY_SCANNER_INIT_FUNC][KEY_AUTH_TABLES].append(auth_table)
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
