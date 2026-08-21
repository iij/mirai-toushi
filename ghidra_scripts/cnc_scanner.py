# Extract C2 endpoints that are hardcoded as numeric immediates (sockaddr_in setup)
# @author mirai-toushi
# @category Analysis
# @runtime Jython

# Many Mirai forks never store the C2 as a string: they write the address and
# port straight into a sockaddr_in as 32/16 bit literals, e.g.
#
#   _DAT_00512640 = 2;            // sin_family = AF_INET
#   _DAT_00512642 = 0x1700;       // sin_port   = 23
#   _DAT_00512644 = 0x5f3447a7;   // sin_addr   = 167.71.52.95
#
#   *DAT_000107ac = 2;
#   *(sa + 2) = htons(0x46d1);    // 18129
#   *(sa + 4) = htonl(0xb5d663b4);// 181.214.99.180
#
# table.c and the strings fallback are both blind to that. This script anchors
# on the socket setup shape instead: a write of AF_INET (2), then constant
# writes 2 and 4 bytes further into the same struct.

import collections
import json
import re

try:
    import __main__ as ghidra_app
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.block import IsolatedEntrySubModel
    from ghidra.util.task import ConsoleTaskMonitor
    HAS_GHIDRA = True
except ImportError:
    # allows running the pure-python helpers under CPython for the self-test
    HAS_GHIDRA = False

KEY_SCRIPT_NAME = "script_name"
KEY_GHIDRA_CURRENT_PROGRAM = "ghidra_current_program"
KEY_NAME = "name"
KEY_PATH = "path"
KEY_SHA256 = "sha256"
KEY_LANGUAGE_ID = "language_id"
KEY_IMAGE_BASE = "image_base"
KEY_MIN_ADDR = "min_addr"
KEY_MAX_ADDR = "max_addr"
KEY_MAIN_FUNC = "main_func"
KEY_ENTRYPOINT = "entrypoint"
KEY_HOW = "how"
KEY_CNC_CANDIDATES = "cnc_candidates"
KEY_IP = "ip"
KEY_PORT = "port"
KEY_ROLE = "role"
KEY_SCORE = "score"
KEY_BEST = "best"
KEY_FUNC = "func"
KEY_ADDR = "addr"
KEY_RAW_CONST = "raw_const"
KEY_BYTE_ORDER = "byte_order"
KEY_SOCKADDR_ADDR = "sockaddr_addr"
KEY_HAS_CONNECT = "has_connect"

ROLE_CNC = "cnc"
ROLE_RESOLVER = "resolver"
ROLE_BIND = "bind"

ORDER_WRAPPER = "wrapper"
ORDER_MEMORY = "memory"

MNE_CALL = "CALL"
MNE_CALLIND = "CALLIND"
MNE_COPY = "COPY"
MNE_STORE = "STORE"
MNE_LOAD = "LOAD"
MNE_CAST = "CAST"
MNE_INT_ADD = "INT_ADD"
MNE_INT_SUB = "INT_SUB"
MNE_INT_OR = "INT_OR"
MNE_INT_LEFT = "INT_LEFT"
MNE_INT_ZEXT = "INT_ZEXT"
MNE_INT_SEXT = "INT_SEXT"
MNE_SUBPIECE = "SUBPIECE"
MNE_PTRSUB = "PTRSUB"
MNE_PTRADD = "PTRADD"
MNE_MULTIEQUAL = "MULTIEQUAL"
MNE_INDIRECT = "INDIRECT"

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

SCRIPT_NAME = "cnc_scanner.py"
LANGS = [
    ARCH_ARM_BE, ARCH_ARM_LE, ARCH_M68K, ARCH_MIPS_BE,
    ARCH_MIPS_LE, ARCH_PPC, ARCH_SH4, ARCH_SPC,
    ARCH_X86, ARCH_X86_64
    ]

AF_INET = 2
# sin_port lives at +2, sin_addr at +4 in every sockaddr_in we care about
OFF_PORT = 2
OFF_ADDR = 4
# Mirai binds this port to enforce a single instance
PORT_SINGLE_INSTANCE = 48101
PORT_DNS = 53
PUBLIC_RESOLVERS = ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "4.2.2.1", "4.2.2.2")
# cap the work when main cannot be identified
MAX_FALLBACK_FUNCS = 60
MIN_FALLBACK_BODY = 200


# --------------------------------------------------------------------------
# pure helpers (no Ghidra API, covered by selfTest())
# --------------------------------------------------------------------------

def intToBytes(value, size):
    """big-endian byte list of a `size`-byte word"""
    out = []
    for i in range(size):
        out.append((value >> (8 * (size - 1 - i))) & 0xFF)
    return out


def toNetworkBytes(value, size, byte_order, language_id):
    """Return the bytes as they hit the wire.

    A value that went through htons()/htonl() is a host-order number, so its
    big-endian rendering is already the network order. A value written straight
    into memory is read back in program byte order, so on little endian the
    memory image is the reverse of the big-endian rendering. ARM:BE:32:v8 is
    treated as LE here, matching parse_main.getCnc().
    """
    byte_list = intToBytes(value, size)
    if byte_order == ORDER_WRAPPER:
        return byte_list
    endian = language_id.split(":")[1] if ":" in language_id else "BE"
    if endian == "LE" or language_id == ARCH_ARM_BE:
        byte_list.reverse()
    return byte_list


def bytesToIp(byte_list):
    return ".".join([str(b) for b in byte_list])


def isGlobalUnicast(byte_list):
    """reject anything that cannot be a routable C2"""
    if len(byte_list) != 4:
        return False
    a, b = byte_list[0], byte_list[1]
    if a == 0 or a == 127 or a >= 224:
        return False
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if byte_list == [255, 255, 255, 255]:
        return False
    # a C2 with two zero octets is a constant that merely looks like an IP
    # (0x9 -> 9.0.0.0), and no reachable host has a zero last octet
    if byte_list[3] == 0:
        return False
    if len([x for x in byte_list if x == 0]) >= 2:
        return False
    return True


def looksLikeAddress(value, image_range):
    """a constant that lands inside the program image is a pointer, not an IP"""
    if not image_range:
        return False
    low, high = image_range
    return low <= value <= high


def classify(ip, port, in_main, has_connect):
    """role + score for one candidate"""
    role = ROLE_CNC
    score = 0
    if in_main:
        score += 2
    if has_connect:
        score += 2
    if ip in PUBLIC_RESOLVERS and port == PORT_DNS:
        role = ROLE_RESOLVER
        score -= 5
    elif port == PORT_SINGLE_INSTANCE:
        role = ROLE_BIND
        score -= 5
    if port is None:
        score -= 1
    return role, score


def rankCandidates(candidates):
    """dedupe on (ip, port) keeping the best score, sort, flag the winner"""
    best_by_key = collections.OrderedDict()
    for cand in candidates:
        key = (cand[KEY_IP], cand[KEY_PORT])
        if key not in best_by_key or cand[KEY_SCORE] > best_by_key[key][KEY_SCORE]:
            best_by_key[key] = cand
    ranked = list(best_by_key.values())
    ranked.sort(key=lambda c: (-c[KEY_SCORE], c[KEY_IP]))
    for cand in ranked:
        cand[KEY_BEST] = False
    for cand in ranked:
        # a bare address with neither a port nor a connect call next to it is
        # not enough to name something the C2
        if cand[KEY_ROLE] != ROLE_CNC:
            continue
        if cand[KEY_PORT] is None and not cand[KEY_HAS_CONNECT]:
            continue
        cand[KEY_BEST] = True
        break
    return ranked


def makeCandidate(ip, port, role, score, func_name, addr_str, raw_const,
                  byte_order, sockaddr_addr, has_connect=False):
    cand = collections.OrderedDict()
    cand[KEY_IP] = ip
    cand[KEY_PORT] = port
    cand[KEY_ROLE] = role
    cand[KEY_SCORE] = score
    cand[KEY_BEST] = False
    cand[KEY_FUNC] = func_name
    cand[KEY_ADDR] = addr_str
    cand[KEY_RAW_CONST] = raw_const
    cand[KEY_BYTE_ORDER] = byte_order
    cand[KEY_SOCKADDR_ADDR] = sockaddr_addr
    cand[KEY_HAS_CONNECT] = has_connect
    return cand


# --------------------------------------------------------------------------
# Ghidra side
# --------------------------------------------------------------------------

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
    submodel = IsolatedEntrySubModel(currentProgram)
    subIter = submodel.getCodeBlocksContaining(addr_set, monitor)
    codeStarts = AddressSet()
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


def getDecompileCCode(func, ifc, monitor):
    res = ifc.decompileFunction(func, 60, monitor)
    if not res:
        return None
    ccode = res.getCCodeMarkup()
    if not ccode:
        return None
    return ccode


def getHighFunc(func, ifc, monitor):
    res = ifc.decompileFunction(func, 60, monitor)
    if not res:
        return None
    return res.getHighFunction()


def getMainFuncByHeuristic(func_mgr, ifc, monitor):
    """same shape test parse_main.py uses: daemonize close(0/1/2) + C2 retry loop"""
    for func in func_mgr.getFunctions(True):
        if func.getBody().getNumAddresses() < 1000:
            continue
        ccode = getDecompileCCode(func, ifc, monitor)
        if not ccode:
            continue
        close_strs = re.findall(r".+?\(0\);.+?\(1\);.+?\(2\);", ccode.toString())
        if len(close_strs) != 1:
            continue
        c2conn_strs = re.findall(
                r"(do|while\( true \)) \{.+?if \(.+? != .+?(0xffffffff|\-1)\) \{.+?\}.+?if \(.+? == .+?(0xffffffff|\-1)\)",
                ccode.toString()
                )
        if 1 <= len(c2conn_strs) <= 2:
            return func
    return None


def readPointer(addr, bits):
    try:
        if bits == 64:
            return getLong(addr) & 0xFFFFFFFFFFFFFFFF
        return getInt(addr) & 0xFFFFFFFF
    except:
        return None


def getMainFuncByLibcStart(func_mgr, ifc, monitor):
    """__libc_start_main(main, argc, argv, ...) - main is the first argument.

    Covers the forks whose main does not match the heuristic above: the entry
    thunk passes a pointer (ARM/x86 pass a DAT_ pointer, MIPS an indirect
    PTR_FUN_ call), and that pointer's *value* is main.
    """
    language_id = currentProgram.getLanguageID().toString()
    bits = int(language_id.split(":")[2])
    entry_points = []
    for addr in currentProgram.getSymbolTable().getExternalEntryPointIterator():
        entry_points.append(addr)
    for entry_addr in entry_points:
        func = getFunctionContaining(entry_addr)
        if not func:
            continue
        for depth_func in _entryChain(func, ifc, monitor):
            high_func = getHighFunc(depth_func, ifc, monitor)
            if not high_func:
                continue
            for pcode in high_func.getPcodeOps():
                if pcode.getMnemonic() not in (MNE_CALL, MNE_CALLIND):
                    continue
                args = pcode.getInputs()[1:]
                if not args:
                    continue
                cand = _mainFromArg(args[0], bits, func_mgr)
                if cand:
                    return cand
    return None


def _entryChain(func, ifc, monitor):
    """entry itself plus the single function it tails into (x86/ARM stubs)"""
    chain = [func]
    ccode = getDecompileCCode(func, ifc, monitor)
    if not ccode:
        return chain
    for match in re.finditer(r"(FUN_[0-9a-fA-F]+)\(", ccode.toString()):
        callees = getGlobalFunctions(match.group(1))
        if callees and callees[0] not in chain:
            chain.append(callees[0])
    return chain[:3]


def _mainFromArg(varnode, bits, func_mgr):
    """turn a __libc_start_main first argument into a Function"""
    cands = []
    const = resolveConst(varnode, bits, depth=0)
    if const is not None:
        cands.append(const[0])
    addr_val = _varnodeAddress(varnode)
    if addr_val is not None:
        cands.append(addr_val)
        ptr = readPointer(toAddr(addr_val), bits)
        if ptr:
            cands.append(ptr)
    for cand in cands:
        if not cand:
            continue
        try:
            addr = toAddr(cand)
        except:
            continue
        if addr is None:
            continue
        func = getFunctionAt(addr)
        if func:
            return func
        # main may still be undefined code (MIPS/SH), create it
        if getInstructionAt(addr):
            func = createFunction(addr, None)
            if func:
                return func
    return None


def _varnodeAddress(varnode):
    try:
        addr = varnode.getAddress()
    except:
        return None
    if addr is None:
        return None
    try:
        if addr.getAddressSpace().isMemorySpace() or varnode.isConstant():
            return addr.getOffset()
    except:
        return None
    return None


def resolveConst(varnode, bits, depth=0, wrapper=False):
    """Evaluate a varnode to (value, wrapper_flag) when it is compile-time known.

    One evaluator covers both roles a varnode plays here - the value being
    stored, and the pointer expression saying where it goes - because a
    pointer's value *is* the address. Handles literal pools (a LOAD from, or a
    plain read of, a fixed address: how ARM/MIPS materialise a 32-bit
    constant), htons()/htonl() wrappers, and the lui/ori split immediate when
    the decompiler leaves it unfolded.
    """
    if varnode is None or depth > 12:
        return None
    if varnode.isConstant():
        return (varnode.getOffset(), wrapper)
    op = varnode.getDef()
    if op is None:
        # a global variable read: its value is the memory content
        addr_val = _varnodeAddress(varnode)
        if addr_val is None or varnode.isRegister():
            return None
        value = _readWord(addr_val, varnode.getSize())
        if value is None:
            return None
        return (value, wrapper)
    mnemonic = op.getMnemonic()
    inputs = op.getInputs()
    if mnemonic in (MNE_COPY, MNE_CAST, MNE_INT_ZEXT, MNE_INT_SEXT, MNE_SUBPIECE, MNE_INDIRECT):
        return resolveConst(inputs[0], bits, depth + 1, wrapper)
    if mnemonic == MNE_MULTIEQUAL:
        for inp in inputs:
            res = resolveConst(inp, bits, depth + 1, wrapper)
            if res is not None:
                return res
        return None
    if mnemonic == MNE_LOAD:
        # inputs[0] is the address space id, inputs[1] the pointer expression
        ptr = resolveConst(inputs[1], bits, depth + 1, wrapper)
        if ptr is None:
            return None
        value = _readWord(ptr[0], varnode.getSize())
        if value is None:
            return None
        return (value, ptr[1])
    if mnemonic in (MNE_CALL, MNE_CALLIND):
        # htons()/htonl() wrapper. Ghidra guesses the parameter list, so a
        # one-argument wrapper can show up with extra junk arguments; take the
        # first argument that is compile-time known.
        for arg in inputs[1:]:
            res = resolveConst(arg, bits, depth + 1, True)
            if res is not None:
                return res
        return None
    if mnemonic in (MNE_INT_OR, MNE_INT_ADD, MNE_INT_SUB, MNE_INT_LEFT, MNE_PTRSUB, MNE_PTRADD):
        left = resolveConst(inputs[0], bits, depth + 1, wrapper)
        right = resolveConst(inputs[1], bits, depth + 1, wrapper) if len(inputs) > 1 else None
        if left is None or right is None:
            return None
        if mnemonic == MNE_INT_OR:
            value = left[0] | right[0]
        elif mnemonic == MNE_INT_SUB:
            value = left[0] - right[0]
        elif mnemonic == MNE_INT_LEFT:
            value = (left[0] << right[0]) & 0xFFFFFFFF
        elif mnemonic == MNE_PTRADD and len(inputs) > 2 and inputs[2].isConstant():
            value = left[0] + right[0] * inputs[2].getOffset()
        else:
            value = left[0] + right[0]
        return (value, left[1] or right[1])
    return None


def resolveAddr(varnode, bits, depth=0):
    """address a pointer expression points at (the pointer's value)"""
    res = resolveConst(varnode, bits, depth)
    if res is None:
        return None
    return res[0]


def _readWord(addr_val, size):
    try:
        addr = toAddr(addr_val)
        if addr is None:
            return None
        if size >= 8:
            return getLong(addr) & 0xFFFFFFFFFFFFFFFF
        if size >= 4:
            return getInt(addr) & 0xFFFFFFFF
        if size == 2:
            return getShort(addr) & 0xFFFF
        return getByte(addr) & 0xFF
    except:
        return None


GROUP_ABS = "abs"


def storeTarget(varnode, bits):
    """Where a store lands, as (group, offset).

    Absolute addresses share the single "abs" group, so a global sockaddr is
    matched on real addresses. When the base cannot be resolved - MIPS reaches
    its globals through $gp, and stack structs through the frame pointer - fall
    back to a symbolic group keyed on the base varnode, with the constant part
    peeled off as the offset. Relative offsets are all the sockaddr match needs.
    """
    absolute = resolveConst(varnode, bits)
    if absolute is not None:
        return (GROUP_ABS, absolute[0])
    node = varnode
    offset = 0
    for _ in range(12):
        op = node.getDef()
        if op is None:
            break
        mnemonic = op.getMnemonic()
        inputs = op.getInputs()
        if mnemonic in (MNE_COPY, MNE_CAST, MNE_INT_ZEXT, MNE_INT_SEXT, MNE_INDIRECT):
            node = inputs[0]
            continue
        if mnemonic in (MNE_INT_ADD, MNE_PTRSUB) and len(inputs) > 1 and inputs[1].isConstant():
            offset += inputs[1].getOffset()
            node = inputs[0]
            continue
        if mnemonic == MNE_PTRADD and len(inputs) > 2 and inputs[1].isConstant() and inputs[2].isConstant():
            offset += inputs[1].getOffset() * inputs[2].getOffset()
            node = inputs[0]
            continue
        if mnemonic == MNE_INT_SUB and len(inputs) > 1 and inputs[1].isConstant():
            offset -= inputs[1].getOffset()
            node = inputs[0]
            continue
        break
    return (_varnodeKey(node), offset)


def _varnodeKey(varnode):
    """stable identity for one SSA value, so writes through it group together"""
    op = varnode.getDef()
    seq = "-"
    if op is not None:
        try:
            seq = op.getSeqnum().toString()
        except:
            seq = str(op.getSeqnum())
    return varnode.toString() + "@" + seq


def collectWrites(high_func, bits):
    """Constant writes, grouped by target: {(group, offset): [(value, size, order, op_addr)]}"""
    writes = {}
    for pcode in high_func.getPcodeOps():
        mnemonic = pcode.getMnemonic()
        target = None
        value_vn = None
        size = None
        if mnemonic == MNE_STORE:
            inputs = pcode.getInputs()
            if len(inputs) < 3:
                continue
            target = storeTarget(inputs[1], bits)
            value_vn = inputs[2]
            size = inputs[2].getSize()
        elif mnemonic == MNE_COPY:
            out = pcode.getOutput()
            if out is None:
                continue
            addr_val = _globalOutputAddress(out)
            if addr_val is None:
                continue
            target = (GROUP_ABS, addr_val)
            value_vn = pcode.getInputs()[0]
            size = out.getSize()
        if target is None or value_vn is None:
            continue
        const = resolveConst(value_vn, bits)
        if const is None:
            continue
        op_addr = pcode.getSeqnum().getTarget()
        writes.setdefault(target, []).append(
                (const[0], size, ORDER_WRAPPER if const[1] else ORDER_MEMORY, op_addr))
    return writes


def _globalOutputAddress(varnode):
    if varnode.isRegister() or varnode.isConstant() or varnode.isUnique():
        return None
    try:
        addr = varnode.getAddress()
        if addr is None or not addr.getAddressSpace().isMemorySpace():
            return None
        return addr.getOffset()
    except:
        return None


def hasConnectShape(high_func):
    """crude: does this function call something with a (fd, ptr, 0x10) argument list"""
    for pcode in high_func.getPcodeOps():
        if pcode.getMnemonic() not in (MNE_CALL, MNE_CALLIND):
            continue
        args = pcode.getInputs()[1:]
        if len(args) < 3:
            continue
        last = args[2]
        if last.isConstant() and last.getOffset() == 0x10:
            return True
    return False


def scanFunc(func, high_func, language_id, bits, in_main, image_range=None):
    """find sockaddr_in setups whose address (and ideally port) are literals"""
    candidates = []
    writes = collectWrites(high_func, bits)
    connect_shape = hasConnectShape(high_func)
    for (group, offset), entries in writes.items():
        if not [e for e in entries if e[0] == AF_INET and e[1] <= 4]:
            continue
        addr_entry = _pickWrite(writes, (group, offset + OFF_ADDR), 4)
        if addr_entry is None:
            continue
        if looksLikeAddress(addr_entry[0], image_range):
            continue
        ip_bytes = toNetworkBytes(addr_entry[0], 4, addr_entry[2], language_id)
        if not isGlobalUnicast(ip_bytes):
            continue
        ip = bytesToIp(ip_bytes)
        port = _portFromWrites(writes, group, offset, language_id)
        role, score = classify(ip, port, in_main, connect_shape)
        if group == GROUP_ABS:
            sockaddr = hex(offset).rstrip("L")
        else:
            sockaddr = group
        candidates.append(makeCandidate(
            ip, port, role, score, func.getName(),
            addr_entry[3].toString() if addr_entry[3] else None,
            hex(addr_entry[0]).rstrip("L"),
            addr_entry[2],
            sockaddr,
            connect_shape))
    return candidates


def _portFromWrites(writes, group, offset, language_id):
    """sin_port, written either as one 16-bit word or as two single bytes"""
    entry = _pickWrite(writes, (group, offset + OFF_PORT), 2)
    if entry is not None and entry[1] == 2:
        port_bytes = toNetworkBytes(entry[0] & 0xFFFF, 2, entry[2], language_id)
        port = (port_bytes[0] << 8) | port_bytes[1]
        return port if 1 <= port <= 65535 else None
    high = _pickWrite(writes, (group, offset + OFF_PORT), 1)
    low = _pickWrite(writes, (group, offset + OFF_PORT + 1), 1)
    if high is None or low is None or high[1] != 1 or low[1] != 1:
        return None
    # single bytes are already in memory (= network) order
    port = ((high[0] & 0xFF) << 8) | (low[0] & 0xFF)
    return port if 1 <= port <= 65535 else None


def _pickWrite(writes, key, want_size):
    """the write at `key`, preferring the expected size; None if absent"""
    entries = writes.get(key)
    if not entries:
        return None
    sized = [e for e in entries if e[1] == want_size]
    if sized:
        return sized[-1]
    return entries[-1]


def targetFuncs(main_func, func_mgr, ifc, monitor):
    """main plus its direct callees; fall back to the biggest functions"""
    funcs = []
    if main_func:
        funcs.append((main_func, True))
        for callee in main_func.getCalledFunctions(monitor):
            if callee != main_func:
                funcs.append((callee, False))
        return funcs
    cands = []
    for func in func_mgr.getFunctions(True):
        size = func.getBody().getNumAddresses()
        if size >= MIN_FALLBACK_BODY:
            cands.append((size, func))
    cands.sort(key=lambda pair: -pair[0])
    for _, func in cands[:MAX_FALLBACK_FUNCS]:
        funcs.append((func, False))
    return funcs


def selfTest():
    language_le = ARCH_X86_64
    language_be = ARCH_MIPS_BE
    # IZ1H9: _DAT_00512644 = 0x5f3447a7 written straight to memory on x86-64
    assert bytesToIp(toNetworkBytes(0x5f3447a7, 4, ORDER_MEMORY, language_le)) == "167.71.52.95"
    # boatnet: htonl(0xb5d663b4) on ARM LE
    assert bytesToIp(toNetworkBytes(0xb5d663b4, 4, ORDER_WRAPPER, ARCH_ARM_LE)) == "181.214.99.180"
    # big endian program, straight memory write
    assert bytesToIp(toNetworkBytes(0xb5d663b4, 4, ORDER_MEMORY, language_be)) == "181.214.99.180"
    # ARM:BE:32:v8 behaves like LE here, matching parse_main.getCnc()
    assert bytesToIp(toNetworkBytes(0x5f3447a7, 4, ORDER_MEMORY, ARCH_ARM_BE)) == "167.71.52.95"
    # ports
    port_bytes = toNetworkBytes(0x1700, 2, ORDER_MEMORY, language_le)
    assert (port_bytes[0] << 8) | port_bytes[1] == 23
    port_bytes = toNetworkBytes(0x46d1, 2, ORDER_WRAPPER, ARCH_ARM_LE)
    assert (port_bytes[0] << 8) | port_bytes[1] == 18129
    # IZ1H9 on ARM splits sin_port into two byte stores: 0x00 then 0x17
    byte_writes = {("abs", 0x23bd2): [(0x00, 1, ORDER_MEMORY, None)],
                   ("abs", 0x23bd3): [(0x17, 1, ORDER_MEMORY, None)]}
    assert _portFromWrites(byte_writes, "abs", 0x23bd0, ARCH_ARM_LE) == 23
    assert _portFromWrites({}, "abs", 0x23bd0, ARCH_ARM_LE) is None
    # validation
    assert not isGlobalUnicast(toNetworkBytes(0x0100007f, 4, ORDER_MEMORY, language_le))  # 127.0.0.1
    assert not isGlobalUnicast([0, 0, 0, 0])
    assert not isGlobalUnicast([192, 168, 1, 1])
    assert not isGlobalUnicast([239, 1, 1, 1])
    assert isGlobalUnicast([167, 71, 52, 95])
    assert not isGlobalUnicast([9, 0, 0, 0])
    assert not isGlobalUnicast([1, 2, 3, 0])
    # 0x805a341 is a pointer into a 32-bit x86 image, not 8.5.163.65
    assert looksLikeAddress(0x805a341, (0x8048000, 0x805f000))
    assert not looksLikeAddress(0x5f3447a7, (0x400000, 0x520000))
    # roles
    assert classify("8.8.8.8", 53, True, False)[0] == ROLE_RESOLVER
    assert classify("1.2.3.4", PORT_SINGLE_INSTANCE, True, False)[0] == ROLE_BIND
    assert classify("1.2.3.4", 23, True, True) == (ROLE_CNC, 4)
    # ranking: resolver never wins, duplicates collapse
    resolver_role, resolver_score = classify("8.8.8.8", 53, True, False)
    cnc_role, cnc_score = classify("167.71.52.95", 23, True, False)
    ranked = rankCandidates([
        makeCandidate("8.8.8.8", 53, resolver_role, resolver_score, "f", "0", "0x0", ORDER_MEMORY, "0x0"),
        makeCandidate("167.71.52.95", 23, cnc_role, cnc_score, "f", "0", "0x0", ORDER_MEMORY, "0x0"),
        makeCandidate("167.71.52.95", 23, cnc_role, cnc_score - 2, "g", "0", "0x0", ORDER_MEMORY, "0x0"),
        ])
    assert len(ranked) == 2
    assert ranked[0][KEY_IP] == "167.71.52.95" and ranked[0][KEY_BEST]
    assert ranked[1][KEY_BEST] is False
    # a bare address with no port and no connect call is never promoted
    weak = rankCandidates([makeCandidate("8.5.163.65", None, ROLE_CNC, 1, "f", "0", "0x0", ORDER_WRAPPER, "0x0")])
    assert weak[0][KEY_BEST] is False
    strong = rankCandidates([makeCandidate("8.5.163.65", None, ROLE_CNC, 1, "f", "0", "0x0", ORDER_WRAPPER, "0x0", True)])
    assert strong[0][KEY_BEST] is True
    print("selfTest: ok")


if __name__ == "__main__":
    if not HAS_GHIDRA:
        selfTest()
    else:
        language_id = currentProgram.getLanguageID().toString()
        if language_id not in LANGS:
            print("error: this script only target for " + str(LANGS))
        bits = int(language_id.split(":")[2])
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        ifc = DecompInterface()
        _ = ifc.setOptions(DecompileOptions())
        _ = ifc.openProgram(currentProgram)
        monitor = ConsoleTaskMonitor()
        defUndefinedFuncs(listing, monitor)
        main_func = getMainFuncByHeuristic(func_mgr, ifc, monitor)
        main_how = "heuristic"
        if not main_func:
            main_func = getMainFuncByLibcStart(func_mgr, ifc, monitor)
            main_how = "libc_start_main"
        if not main_func:
            main_how = None
        image_range = (currentProgram.getMinAddress().getOffset(),
                       currentProgram.getMaxAddress().getOffset())
        candidates = []
        for func, in_main in targetFuncs(main_func, func_mgr, ifc, monitor):
            high_func = getHighFunc(func, ifc, monitor)
            if not high_func:
                continue
            try:
                candidates.extend(scanFunc(func, high_func, language_id, bits, in_main, image_range))
            except:
                continue
        candidates = rankCandidates(candidates)
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
        if main_func:
            output_dict[KEY_MAIN_FUNC] = collections.OrderedDict()
            output_dict[KEY_MAIN_FUNC][KEY_NAME] = main_func.getName()
            output_dict[KEY_MAIN_FUNC][KEY_ENTRYPOINT] = main_func.getEntryPoint().toString()
            output_dict[KEY_MAIN_FUNC][KEY_HOW] = main_how
        if candidates:
            output_dict[KEY_CNC_CANDIDATES] = candidates
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
