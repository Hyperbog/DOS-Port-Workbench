"""Verify the Dungeon Hack phase-one dispatch capture against your game files."""
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
OPCODES = {0x1d: ("SHTC", 2), 0x3c: ("SSB", 3), 0x20: ("RCRS", 3),
           0x04: ("PUSH", 1), 0x21: ("CALL", 2)}


def check(ok, message):
    if not ok:
        raise ValueError(message)


def word(data, off):
    return struct.unpack_from("<H", data, off)[0]


def dword(data, off):
    return struct.unpack_from("<I", data, off)[0]


def far(text):
    seg, off = text.split(":")
    return int(seg, 16), int(off, 16)


def table(blob):
    result = {}
    for cursor in struct.unpack_from(f"<{word(blob, 0)}I", blob, 2):
        while cursor and word(blob, cursor):
            pair = []
            for _ in range(2):
                n = word(blob, cursor)
                raw = blob[cursor+2:cursor+2+n]
                pair.append(raw.rstrip(b"\0").decode("cp437"))
                cursor += 2 + n
            result[pair[0]] = pair[1]
    return result


def csv_rows(path):
    with path.open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader(source))


def verify(game, trace, image):
    paths = {p.name.upper(): p for p in game.iterdir() if p.is_file()}
    inputs = {}
    for name, sha in HASHES.items():
        check(name in paths, f"Missing {name}")
        inputs[name] = paths[name].read_bytes()
        check(hashlib.sha256(inputs[name]).hexdigest() == sha, f"Different build of {name}")
    exe, res, tbl = (inputs[n] for n in ("AESOP.EXE", "HACK.RES", "HACK.TBL"))

    def resource(rid):
        header = dword(tbl, 4*rid)
        start = header + 12
        return start, res[start:start+dword(res, header+8)]

    names = table(resource(0)[1])
    messages = table(resource(4)[1])
    rid = int(names["phase-one"])
    start, code = resource(rid)
    exports = table(resource(int(names["phase-one.EXPT"]))[1])
    imports = table(resource(int(names["phase-one.IMPT"]))[1])
    msg = int(messages["create"])
    entry = int(exports[f"M:{msg}"])
    check((rid, msg, start, len(code), entry) == (2932, 0, 0x687718, 1121, 0x369), "Resource mapping")
    check(exports["N:OBJECT"] == "phase-one" and word(code, entry) == 2, "Handler frame")
    check(int(imports["C:init_sound"]) == 56, "Sound import")
    check(int(table(resource(3)[1])["init_sound"]) == 484, "Runtime function dictionary")
    if image:
        check(image.read_bytes() == code, "Live code image differs from the archive")

    rows = csv_rows(trace)
    reference = csv_rows(HERE / "dispatch.csv")
    check(len(rows) == len(reference) == 22, "Incomplete dispatch log")
    details = [dict(item.split("=", 1) for item in row["detail"].split()) for row in rows]
    base = int(details[0]["image"], 16)
    for i, (row, expected) in enumerate(zip(rows, reference), 1):
        check((row["event"], row["kind"], row["ghidra_cs_ip"]) ==
              (str(i), expected["kind"], expected["ghidra_cs_ip"]), f"Trace record {i}")
        cs, ip = far(row["guest_cs_ip"])
        check(far(row["ghidra_cs_ip"]) == (cs-base+0x1000, ip), f"Relocation at record {i}")
    check(details[1]["name"] == "phase-one" and details[2] == {"slot": "2000", "class": str(rid)}, "Creation")
    for detail in details[3:5]:
        check((detail["receiver"], detail["message"], detail["selector"]) == ("2000", str(msg), "FFFF"), "Send")
    check(details[4]["ordinal"] == "1" and details[5] == {"message": "0", "header": "0369"}, "First dispatch")
    code_seg, frame = far(details[6]["bytecode"])
    check(frame == entry and details[6]["auto_bytes"] == "2", "Runtime handler entry")

    pc = frame + 2
    mz = 16*word(exe, 8)
    vm_base = mz + 16*0x10f5
    decoded = csv_rows(HERE / "bytecode.csv")
    observed = [(r, d) for r, d in zip(rows, details) if r["kind"] == "opcode_fetch"]
    check(len(observed) == len(decoded) == 8, "Opcode count")
    for (row, detail), item in zip(observed, decoded):
        op = code[pc]
        name, length = OPCODES[op]
        raw = code[pc:pc+length]
        native_ip = word(exe, vm_base+0x641+2*op)
        operand = str(int.from_bytes(raw[1:], "little")) if length > 1 else ""
        check(far(detail["bytecode"]) == (code_seg, pc) and int(detail["op"], 16) == op, "Opcode fetch")
        check(int(detail["native_ip"], 16) == native_ip and far(item["native_handler_ghidra"]) ==
              (0x20f5, native_ip), "Native opcode handler")
        check((item["event"], int(item["resource_offset"], 16), int(item["archive_offset"], 16),
               bytes.fromhex(item["bytes"]), item["opcode"], item["operand"]) ==
              (row["event"], pc, start+pc, raw, name, operand), f"Bytecode at {pc:04X}")
        pc += length
    check([d["operand"] for r, d in zip(rows, details) if r["kind"]=="constant_op"] == ["0"]*3, "Constants")
    writes = [d for r, d in zip(rows, details) if r["kind"] == "static_written"]
    dest = [far(d["address"]) for d in writes]
    check(len(writes) == 2 and dest[1] == (dest[0][0], dest[0][1]+1)
          and all(d["value"] == "00" for d in writes), "Instance byte writes")
    cs, ip = far(details[-2]["target"])
    check((cs, ip) == far(rows[-1]["guest_cs_ip"]), "Native call destination")
    for d in details[-2:]:
        check(d["argc"] == "1" and int(d["argument"], 16) == 0, "Native arguments")
    check(far(details[-1]["return"]) == (base+0x10f5, 0x0e42), "Native return site")
    fn = 0x1c8f8 + 484
    check(struct.unpack_from("<HH", exe, fn) == (ip, cs-base), "Runtime function pointer")
    print("Verified create (0) to receiver 2000, handler 0x0369, eight opcodes and init_sound(0).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("game", type=Path, help="Folder containing AESOP.EXE, HACK.RES and HACK.TBL")
    parser.add_argument("--trace", type=Path, default=HERE/"dispatch.csv", help="Fresh observer CSV")
    parser.add_argument("--image", type=Path, help="Optional 1,121-byte live image from DH_VM_IMAGE")
    args = parser.parse_args()
    try:
        verify(args.game, args.trace, args.image)
    except (KeyError, ValueError, OSError, struct.error, IndexError) as error:
        sys.exit(f"Verification failed: {error}")
