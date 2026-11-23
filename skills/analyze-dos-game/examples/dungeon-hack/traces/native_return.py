"""Shared checks for phase-one native calls, returns and their DOSBox captures."""
import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path

HASHES = {
    "AESOP.EXE": "d3676cb71fd9a869004ee08d3f75e96861e19aeb003d89d3c4ef93436796d450",
    "HACK.RES": "207eaf4081eee453c718fc8f761a707ab5c36bf974255185e2bc90ebe84cac66",
    "HACK.TBL": "5ad8586f21908e791ef27a357a35f11e64022af054c3ae15cc4d803b5db59e7f",
}
# Each probe label maps to a symbol, its class import offset and its global vector offset.
IMPORTS = {
    "sound": ("init_sound", 56, 484),
    "graphics": ("init_graphics", 60, 280),
    "interface": ("init_interface", 64, 228),
    "wipe_window": ("wipe_window", 48, 336),
    "create_program": ("create_program", 0, 520),
    "set_palette": ("set_palette", 12, 328),
    "envval": ("envval", 24, 136),
}
LITERAL_WIDTH = {0x1d: 1, 0x1e: 2}  # SHTC and INTC


def check(condition, detail):
    if not condition:
        raise ValueError(detail)


def word(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def dword(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def dictionary(data):
    entries = {}
    for pos in struct.unpack_from(f"<{word(data, 0)}I", data, 2):
        while pos and word(data, pos):
            pair = []
            for _ in range(2):
                end = pos + 2 + word(data, pos)
                pair.append(data[pos+2:end].rstrip(b"\0").decode("cp437"))
                pos = end
            entries[pair[0]] = pair[1]
    return entries


def far(text):
    segment, offset = text.split(":")
    return int(segment, 16), int(offset, 16)


def argument_words(arguments):
    words = [len(arguments)]
    for arg in arguments:
        words.extend((arg & 0xffff, (arg >> 16) & 0xffff))
    return words


def sample(row, *fields):
    return tuple(int(row[field], 16) for field in fields)


def check_instruction(exe, row, raw, displacement=0):
    seg, ip = far(row["image_cs_ip"])
    offset = 16 * word(exe, 8) + 16*seg + ip + displacement
    check(exe.startswith(bytes.fromhex(raw), offset), f"Native instructions at {row['point']}")


def call_fetch_offsets(code, resume_pc, incoming_count, import_offset, arguments):
    check(code[resume_pc-2:resume_pc] == bytes((0x21, incoming_count)), "Returning CALL and argument count")
    return import_call_offsets(code, resume_pc, import_offset, arguments)


def import_call_offsets(code, import_pc, import_offset, arguments):
    check(code[import_pc:import_pc+3] == struct.pack("<BH", 0x20, import_offset), "RCRS import operand")
    offsets = [import_pc]
    pc = import_pc + 3
    for argument in arguments:
        literal_pc = pc+1
        width = LITERAL_WIDTH.get(code[pc+1])
        check(code[pc] == 0x04 and width is not None, f"Expected PUSH and a literal at +0x{pc:04X}")
        operand = code[pc+2:pc+2+width]
        check(len(operand) == width, f"Truncated literal at +0x{literal_pc:04X}")
        value = int.from_bytes(operand, "little")
        offsets.extend((pc, literal_pc))
        pc += 2 + width
        if code[pc:pc+1] == b"\x08":  # NEG operates on the 32-bit VM slot.
            offsets.append(pc)
            value = -value
            pc += 1
        check(value == argument, f"Argument from literal at +0x{literal_pc:04X}")
    check(code[pc:pc+2] == bytes((0x21, len(arguments))), "Next CALL and argument count")
    return [*offsets, pc]


def read_capture(trace, profile, literal_count=0, *, expected_order=None):
    with trace.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    check(rows and all(None not in row and None not in row.values() for row in rows), "Incomplete CSV record")
    points = [line.partition("#")[0].split()[1:] for line in profile.read_text(encoding="ascii").splitlines()
              if line.startswith(("start ", "watch ", "stop "))]
    registered = {(address, name): condition for address, name, *condition in points}
    order = list(expected_order) if expected_order is not None else list(dict.fromkeys(point[1] for point in points))
    if literal_count and expected_order is None:
        pair = ["fetch_constant", "fetch_after_constant"]
        first = order.index(pair[0])
        check(order[first:first+2] == pair, "Literal probe order")
        order[first:first+2] = pair * literal_count
    check([r["point"] for r in rows] == order, f"Checkpoint order in {trace.name}")
    base = (far(rows[0]["guest_cs_ip"])[0] - far(rows[0]["image_cs_ip"])[0]) & 0xffff
    for i, row in enumerate(rows, 1):
        rel, ip = far(row["image_cs_ip"])
        key = (row["image_cs_ip"], row["point"])
        check(key in registered and int(row["event"]) == i and
              far(row["guest_cs_ip"]) == ((base+rel) & 0xffff, ip), f"{trace.name} event {i} address or sequence")
        for condition in registered[key]:
            field, value = condition.split("=")
            if field in row:
                check(int(row[field], 16) == int(value, 16), f"{trace.name} event {i} stack condition")
    return rows


def load_game(game):
    paths = {p.name.upper(): p for p in game.iterdir() if p.is_file()}
    files = {}
    for name, digest in HASHES.items():
        check(name in paths, f"Missing {name}")
        files[name] = paths[name].read_bytes()
        check(hashlib.sha256(files[name]).hexdigest() == digest, f"Different revision of {name}")
    exe, archive, index = (files[name] for name in ("AESOP.EXE", "HACK.RES", "HACK.TBL"))

    def resource(number):
        head = dword(index, 4 * int(number))
        return archive[head+12:head+12+dword(archive, head+8)]

    return exe, index, resource


def check_native_import(exe, imports, functions, routine, row):
    name, local, vector = IMPORTS[routine]
    check((int(imports[f"C:{name}"]), int(functions[name])) == (local, vector), f"{name} import")
    ptr = 0x1c8f8 + vector
    seg, ip = far(row["image_cs_ip"])
    check(struct.unpack_from("<HH", exe, ptr) == (ip, seg), f"{name} pointer")
    mz = 16 * word(exe, 8)
    table = word(exe, 0x18)
    relocations = struct.iter_unpack("<HH", exe[table:table + 4*word(exe, 6)])
    check(any(mz + 16*s + o == ptr+2 for o, s in relocations), f"{name} pointer relocation")


def check_call_frame(call_site, entry, arguments, next_pc, vm_stack, return_to):
    stack, vm_sp = vm_stack
    return_cs, return_ip = return_to
    words = argument_words(arguments)
    call_sp = (vm_sp-2*len(words)) & 0xffff
    fields = [f"stack{i}" for i in range(len(words))]
    check(sample(call_site, "si", "ss", "sp", *fields) == (next_pc, stack, call_sp, *words),
          "Native call site and arguments")
    fields = [f"stack{i}" for i in range(2+len(words))]
    check(sample(entry, "ss", "sp", *fields) == (stack, (call_sp-4) & 0xffff, return_ip, return_cs, *words),
          "Next native entry, return address and arguments")


def verify_transition(game, trace, profile, *, returned, next_call, resume_pc, arguments, check_tail,
                      next_arguments=(), program_class=None, prefix=None, check_archive=None, expected_order=None):
    exe, index, resource = load_game(game)
    names = dictionary(resource(0))
    check(names["phase-one"] == "2932" and names["phase-one.IMPT"] == "2930", "phase-one resource IDs")
    start = dword(index, 4*2932) + 12
    code = resource(2932)
    imports = dictionary(resource(names["phase-one.IMPT"]))
    functions = dictionary(resource(3))
    next_name, import_offset, _ = IMPORTS[next_call]
    check(start == 0x687718, "phase-one code payload location")
    fetch_offsets = call_fetch_offsets(code, resume_pc, len(arguments), import_offset, next_arguments)
    call_pc = fetch_offsets[-1]
    if program_class is not None:
        check(next_name == "create_program" and len(next_arguments) == 2 and
              int(names[program_class]) == next_arguments[1], "Program class resource ID")
        exports = dictionary(resource(names[f"{program_class}.EXPT"]))
        check(exports["N:OBJECT"] == program_class, "Program class export name")

    rows = read_capture(trace, profile, len(next_arguments), expected_order=expected_order)
    target = rows[-1]["point"]
    if prefix is not None:
        earlier = read_capture(*prefix)
        # Independent profiles number events from one. Every other field at the shared instruction must match.
        check({**earlier[-1], "event": rows[0]["event"]} == rows[0], "Captures disagree at their shared instruction")
        rows = earlier[:-1] + rows
    literal_points = ("fetch_constant", "fetch_after_constant")
    records = {r["point"]: r for r in rows if r["point"] not in literal_points}

    def values(point, *fields):
        return sample(records[point], *fields)

    if check_archive is not None:
        check_archive(resource, names, values)

    entry, retf = f"{returned}_entry", f"{returned}_retf"
    for routine, point in ((returned, entry), (next_call, target)):
        check_native_import(exe, imports, functions, routine, records[point])

    def instruction(point, raw, displacement=0):
        check_instruction(exe, records[point], raw, displacement)

    for point, raw in ((retf, "CB"), ("vm_resume", "8B 4E F6"), ("store_low", "26 89 05 26 89 55 02"),
                       ("replace_low", "26 89 1D 26 8C 5D 02"), ("far_call", "26 FF 1D")):
        instruction(point, raw)

    vm_cs, vm_ip = far(records["vm_resume"]["guest_cs_ip"])
    frame = [vm_ip, vm_cs, *argument_words(arguments)]
    fields = [f"stack{i}" for i in range(len(frame))]
    for point in (entry, retf):
        check(values(point, *fields) == tuple(frame), f"{point} saved return and arguments")
    stack, sp = values(entry, "ss", "sp")
    check(values(retf, "ss", "sp") == (stack, sp) and
          values("vm_resume", "ss", "sp", "si") == (stack, (sp+4) & 0xffff, resume_pc),
          "RETF stack transition and resumed bytecode position")
    dx, ax = values(retf, "dx", "ax")
    result = (dx << 16) | ax
    check_tail(values, instruction, (dx, ax))
    for point in ("vm_resume", "store_low", "store_high", "result_stored"):
        check(values(point, "dx", "ax") == (dx, ax), f"DX:AX at {point}")
    slot = values("result_stored", "es", "di")

    def check_slot(row, depth, value):
        expected = (slot[0], (slot[1] - 4*depth) & 0xffff, value)
        check(sample(row, "es", "di", "es_di_dword") == expected, f"VM slot at event {row['event']}")

    original_cs, original_ip = far(records[entry]["guest_cs_ip"])
    check_slot(records["store_low"], 0, original_cs << 16 | original_ip)
    check_slot(records["store_high"], 0, original_cs << 16 | ax)
    for point in ("result_stored", "fetch_import", "import_operand", "replace_low"):
        check_slot(records[point], 0, result)

    code_seg, = values("fetch_import", "ds")

    def check_bytecode(row, pc):
        check(sample(row, "ds", "si", "ds_si_dword") == (code_seg, pc, dword(code, pc)),
              f"Live bytecode differs from HACK.RES at +0x{pc:04X}")

    fetches = [row for row in rows if row["point"].startswith("fetch_")]
    check(len(fetches) == len(fetch_offsets), "All bytecodes through CALL")
    for row, pc in zip(fetches, fetch_offsets):
        check_bytecode(row, pc)
    check_bytecode(records["import_operand"], resume_pc+1)
    check_bytecode(records["call_argc"], call_pc+1)
    target_cs, target_ip = far(records[target]["guest_cs_ip"])
    pointer = target_cs << 16 | target_ip
    check(values("replace_low", "ds", "bx") == (target_cs, target_ip), f"Resolved {next_call} import")
    after_import = "fetch_after_import" if next_arguments else "fetch_call"
    for point in ("import_stored", after_import, "far_call", target):
        check_slot(records[point], 0, pointer)

    # Observe the completed write at the following opcode fetch, including an in-place NEG.
    depth = value = 0
    for pc, following in zip(fetch_offsets[1:-1], fetches[2:]):
        opcode = code[pc]
        if opcode == 0x04:
            depth += 1
            value = 0
        elif opcode == 0x08:
            value = (-value) & 0xffffffff
        else:
            width = LITERAL_WIDTH[opcode]
            value = int.from_bytes(code[pc+1:pc+1+width], "little")
        check_slot(following, depth, value)
    unsigned_arguments = tuple(arg & 0xffffffff for arg in next_arguments)
    count = len(next_arguments)
    check_slot(records["call_argc"], count, unsigned_arguments[-1] if count else pointer)
    vm_sp, = values("call_argc", "sp")
    transfers = [r for r in rows if r["point"].startswith("marshal_")]
    check(len(transfers) == count, "Native argument transfer count")
    for i, row in enumerate(transfers):
        remaining = count-i
        instruction(row["point"], "26 FF 75 02 26 FF 35 83 C7 04")
        check_slot(row, remaining, unsigned_arguments[remaining-1])
        check(sample(row, "ss", "sp", "cx") == (stack, (vm_sp-4*i) & 0xffff, remaining),
              f"Native argument transfer {i+1}")

    check_call_frame(records["far_call"], records[target], next_arguments, call_pc+2, (stack, vm_sp), (vm_cs, vm_ip))
    args = ", ".join(map(str, arguments))
    next_args = ", ".join(map(str, next_arguments))
    print(f"Verified {IMPORTS[returned][0]}({args}), DX:AX = {result:08X}, slot {slot[0]:04X}:{slot[1]:04X}, "
          f"then {next_name}({next_args}) at {target_cs:04X}:{target_ip:04X}.")


def run_cli(verify, directory, description, *, parser=None):
    if parser is None:
        parser = argparse.ArgumentParser(description=description)
    parser.add_argument("game", type=Path, help="Folder containing AESOP.EXE, HACK.RES and HACK.TBL")
    parser.add_argument("--trace", type=Path, default=directory/"trace.csv", help="Captured observer CSV")
    options = vars(parser.parse_args())
    game = options.pop("game")
    trace = options.pop("trace")
    try:
        verify(game, trace, **options)
    except (OSError, ValueError, KeyError, IndexError, struct.error) as error:
        sys.exit(f"Verification failed: {error}")
