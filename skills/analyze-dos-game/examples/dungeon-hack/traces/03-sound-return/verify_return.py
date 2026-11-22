"""Verify the phase-one sound return and graphics call using the original game files."""
import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HASHES = {
    "AESOP.EXE": "d3676cb71fd9a869004ee08d3f75e96861e19aeb003d89d3c4ef93436796d450",
    "HACK.RES": "207eaf4081eee453c718fc8f761a707ab5c36bf974255185e2bc90ebe84cac66",
    "HACK.TBL": "5ad8586f21908e791ef27a357a35f11e64022af054c3ae15cc4d803b5db59e7f",
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


def verify(game, trace):
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
    check(start == 0x687718 and code[0x37b:0x382] == bytes.fromhex("21 01 20 3C 00 21 00"),
          "phase-one call, import and call bytes")

    with trace.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    profile = (HERE / "phase-one.profile").read_text(encoding="ascii").splitlines()
    points = [line.split()[1:] for line in profile if line.startswith(("start ", "watch ", "stop "))]
    check([(r["image_cs_ip"], r["point"]) for r in rows] == [tuple(p) for p in points], "Checkpoint order")
    records = {r["point"]: r for r in rows}
    base = (far(rows[0]["guest_cs_ip"])[0] - far(rows[0]["image_cs_ip"])[0]) & 0xffff
    for i, r in enumerate(rows, 1):
        rel, ip = far(r["image_cs_ip"])
        check(int(r["event"]) == i and far(r["guest_cs_ip"]) == ((base+rel) & 0xffff, ip),
              f"Record {i} relocation or sequence")

    def values(point, *fields):
        return tuple(int(records[point][field], 16) for field in fields)

    mz = 16 * word(exe, 8)
    relocations = {mz + seg*16 + ip for ip, seg in struct.iter_unpack("<HH", exe[
        word(exe, 0x18):word(exe, 0x18) + 4*word(exe, 6)])}
    for name, point, local, vector_offset in (("init_sound", "sound_entry", 56, 484),
                                               ("init_graphics", "graphics_entry", 60, 280)):
        check((int(imports[f"C:{name}"]), int(functions[name])) == (local, vector_offset), f"{name} import")
        ptr = 0x1c8f8 + vector_offset
        seg, ip = far(records[point]["image_cs_ip"])
        check(struct.unpack_from("<HH", exe, ptr) == (ip, seg) and ptr+2 in relocations, f"{name} pointer")
    for point, raw in (("sound_retf", "CB"), ("vm_resume", "8B 4E F6"), ("store_low", "26 89 05 26 89 55 02"),
                       ("replace_low", "26 89 1D 26 8C 5D 02"), ("far_call", "26 FF 1D")):
        seg, ip = far(records[point]["image_cs_ip"])
        offset = mz + 16*seg + ip
        check(exe.startswith(bytes.fromhex(raw), offset), f"Native instructions at {point}")

    vm_cs, vm_ip = far(records["vm_resume"]["guest_cs_ip"])
    sound_frame = (vm_ip, vm_cs, 1, 0, 0)
    for point in ("sound_entry", "sound_retf"):
        check(values(point, "stack0", "stack1", "stack2", "stack3", "stack4") == sound_frame,
              f"{point} saved return and argument")
    stack, sp = values("sound_entry", "ss", "sp")
    check(values("sound_retf", "ss", "sp") == (stack, sp) and
          values("vm_resume", "ss", "sp") == (stack, (sp+4) & 0xffff), "Sound RETF stack transition")
    dx, ax = values("sound_retf", "dx", "ax")
    result = (dx << 16) | ax
    for point in ("sound_epilogue", "vm_resume", "store_low", "store_high", "result_stored"):
        check(values(point, "dx", "ax") == (dx, ax), f"DX:AX at {point}")
    slot = values("result_stored", "es", "di")
    for r in rows[4:]:
        check(values(r["point"], "es", "di") == slot, f"VM slot at {r['point']}")
    before, = values("store_low", "es_di_dword")
    sound_cs, sound_ip = far(records["sound_entry"]["guest_cs_ip"])
    check(before == (sound_cs << 16 | sound_ip), "Original sound pointer in slot")
    check(values("store_high", "es_di_dword") == ((before & 0xffff0000) | ax,), "Low-word store")
    for point in ("result_stored", "fetch_import", "import_operand", "replace_low"):
        check(values(point, "es_di_dword") == (result,), f"Sound result at {point}")

    code_seg, = values("fetch_import", "ds")
    for point, pc in (("fetch_import", 0x37d), ("import_operand", 0x37e), ("fetch_call", 0x380), ("call_argc", 0x381)):
        check(values(point, "ds", "si", "ds_si_dword") == (code_seg, pc, dword(code, pc)),
              f"Live bytecode differs from HACK.RES at +0x{pc:04X}")
    target_cs, target_ip = far(records["graphics_entry"]["guest_cs_ip"])
    check(values("replace_low", "ds", "bx") == (target_cs, target_ip), "Resolved graphics import")
    for point in ("import_stored", "fetch_call", "call_argc", "far_call", "graphics_entry"):
        check(values(point, "es_di_dword") == (target_cs << 16 | target_ip,), f"Graphics pointer at {point}")
    call_sp, count = values("far_call", "sp", "stack0")
    check(count == 0 and values("far_call", "si", "ss") == (0x382, stack), "Graphics CALL 0")
    check(values("graphics_entry", "ss", "sp", "stack0", "stack1", "stack2") ==
          (stack, (call_sp-4) & 0xffff, vm_ip, vm_cs, 0), "Graphics entry and argument count")
    print(f"Verified init_sound(0), DX:AX = {result:08X}, slot {slot[0]:04X}:{slot[1]:04X}, "
          f"then init_graphics() at {target_cs:04X}:{target_ip:04X}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("game", type=Path, help="Folder containing AESOP.EXE, HACK.RES and HACK.TBL")
    parser.add_argument("--trace", type=Path, default=HERE/"trace.csv", help="Captured observer CSV")
    args = parser.parse_args()
    try:
        verify(args.game, args.trace)
    except (OSError, ValueError, KeyError, IndexError, struct.error) as error:
        sys.exit(f"Verification failed: {error}")
