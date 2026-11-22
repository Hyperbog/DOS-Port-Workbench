"""Verify a phase-one native return and the next call, including inline byte arguments."""
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
}


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


def verify_transition(game, trace, profile, *, returned, next_call, resume_pc, arguments, check_tail,
                      next_arguments=()):
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

    names = dictionary(resource(0))
    check(names["phase-one"] == "2932" and names["phase-one.IMPT"] == "2930", "phase-one resource IDs")
    start = dword(index, 4*2932) + 12
    code = resource(2932)
    imports = dictionary(resource(names["phase-one.IMPT"]))
    functions = dictionary(resource(3))
    next_name, import_offset, _ = IMPORTS[next_call]
    load_import = struct.pack("<BH", 0x20, import_offset)
    literals = b"".join(bytes((0x04, 0x1d, value)) for value in next_arguments)
    call_pc = resume_pc + len(load_import) + len(literals)
    expected_code = bytes((0x21, len(arguments))) + load_import + literals + bytes((0x21, len(next_arguments)))
    check(start == 0x687718 and code[resume_pc-2:call_pc+2] == expected_code,
          "phase-one call, import and call bytes")

    with trace.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    check(rows and all(None not in row and None not in row.values() for row in rows), "Incomplete CSV record")
    points = [line.split()[1:] for line in profile.read_text(encoding="ascii").splitlines()
              if line.startswith(("start ", "watch ", "stop "))]
    literal_points = ("fetch_constant", "fetch_after_constant")
    if next_arguments:
        names = [name for address, name in points]
        first = names.index(literal_points[0])
        check(tuple(names[first:first+2]) == literal_points, "Literal probe order")
        points[first:first+2] = points[first:first+2] * len(next_arguments)
    check([(r["image_cs_ip"], r["point"]) for r in rows] == [tuple(p) for p in points], "Checkpoint order")
    records = {r["point"]: r for r in rows if r["point"] not in literal_points}
    base = (far(rows[0]["guest_cs_ip"])[0] - far(rows[0]["image_cs_ip"])[0]) & 0xffff
    for i, r in enumerate(rows, 1):
        rel, ip = far(r["image_cs_ip"])
        check(int(r["event"]) == i and far(r["guest_cs_ip"]) == ((base+rel) & 0xffff, ip),
              f"Record {i} relocation or sequence")

    def values(point, *fields):
        return sample(records[point], *fields)

    mz = 16 * word(exe, 8)
    relocations = {mz + seg*16 + ip for ip, seg in struct.iter_unpack("<HH", exe[
        word(exe, 0x18):word(exe, 0x18) + 4*word(exe, 6)])}
    for routine in (returned, next_call):
        name, local, vector_offset = IMPORTS[routine]
        point = f"{routine}_entry"
        check((int(imports[f"C:{name}"]), int(functions[name])) == (local, vector_offset), f"{name} import")
        ptr = 0x1c8f8 + vector_offset
        seg, ip = far(records[point]["image_cs_ip"])
        check(struct.unpack_from("<HH", exe, ptr) == (ip, seg) and ptr+2 in relocations, f"{name} pointer")

    def instruction(point, raw):
        seg, ip = far(records[point]["image_cs_ip"])
        offset = mz + 16*seg + ip
        check(exe.startswith(bytes.fromhex(raw), offset), f"Native instructions at {point}")

    entry, retf, target = f"{returned}_entry", f"{returned}_retf", f"{next_call}_entry"
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

    pc = resume_pc
    sizes = {0x20: 3, 0x04: 1, 0x1d: 2, 0x21: 2}
    for row in rows:
        if row["point"].startswith("fetch_"):
            check_bytecode(row, pc)
            pc += sizes[code[pc]]
    check(pc == call_pc+2, "All bytecodes through CALL")
    check_bytecode(records["import_operand"], resume_pc+1)
    check_bytecode(records["call_argc"], call_pc+1)
    target_cs, target_ip = far(records[target]["guest_cs_ip"])
    pointer = target_cs << 16 | target_ip
    check(values("replace_low", "ds", "bx") == (target_cs, target_ip), f"Resolved {next_call} import")
    after_import = "fetch_after_import" if next_arguments else "fetch_call"
    for point in ("import_stored", after_import, "far_call", target):
        check_slot(records[point], 0, pointer)

    literal_rows = [r for r in rows if r["point"] in literal_points]
    for i, arg in enumerate(next_arguments):
        check_slot(literal_rows[2*i], i+1, 0)
        check_slot(literal_rows[2*i+1], i+1, arg)
    count = len(next_arguments)
    check_slot(records["call_argc"], count, next_arguments[-1] if count else pointer)
    vm_sp, = values("call_argc", "sp")
    transfers = [r for r in rows if r["point"].startswith("marshal_")]
    check(len(transfers) == count, "Native argument transfer count")
    for i, row in enumerate(transfers):
        remaining = count-i
        instruction(row["point"], "26 FF 75 02 26 FF 35 83 C7 04")
        check_slot(row, remaining, next_arguments[remaining-1])
        check(sample(row, "ss", "sp", "cx") == (stack, (vm_sp-4*i) & 0xffff, remaining),
              f"Native argument transfer {i+1}")

    words = argument_words(next_arguments)
    call_sp = (vm_sp-2*len(words)) & 0xffff
    call_fields = [f"stack{i}" for i in range(len(words))]
    check(values("far_call", "si", "ss", "sp", *call_fields) == (call_pc+2, stack, call_sp, *words),
          "Native call site and arguments")
    entry_fields = [f"stack{i}" for i in range(2+len(words))]
    check(values(target, "ss", "sp", *entry_fields) == (stack, (call_sp-4) & 0xffff, vm_ip, vm_cs, *words),
          "Next native entry, return address and arguments")
    args = ", ".join(map(str, arguments))
    next_args = ", ".join(map(str, next_arguments))
    print(f"Verified {IMPORTS[returned][0]}({args}), DX:AX = {result:08X}, slot {slot[0]:04X}:{slot[1]:04X}, "
          f"then {next_name}({next_args}) at {target_cs:04X}:{target_ip:04X}.")


def run_cli(verify, directory, description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("game", type=Path, help="Folder containing AESOP.EXE, HACK.RES and HACK.TBL")
    parser.add_argument("--trace", type=Path, default=directory/"trace.csv", help="Captured observer CSV")
    args = parser.parse_args()
    try:
        verify(args.game, args.trace)
    except (OSError, ValueError, KeyError, IndexError, struct.error) as error:
        sys.exit(f"Verification failed: {error}")
