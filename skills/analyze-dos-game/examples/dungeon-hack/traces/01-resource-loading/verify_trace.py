"""Check the recorded DOS reads against a local copy of Dungeon Hack (Python 3)."""
import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = {
    "AESOP.EXE": "d3676cb71fd9a869004ee08d3f75e96861e19aeb003d89d3c4ef93436796d450",
    "HACK.RES": "207eaf4081eee453c718fc8f761a707ab5c36bf974255185e2bc90ebe84cac66",
    "HACK.TBL": "5ad8586f21908e791ef27a357a35f11e64022af054c3ae15cc4d803b5db59e7f",
}
COMBINED = "e1a47c302aadefa700ed264c091d27ed6507779e00a631c009395351426738b0"


def check(passed, message):
    if not passed:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def csv_rows(name):
    with (HERE / name).open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader(source))


def resource_names(dictionary):
    count = struct.unpack_from("<H", dictionary)[0]
    names = {}
    for cursor in struct.unpack_from(f"<{count}I", dictionary, 2):
        while cursor:
            size = struct.unpack_from("<H", dictionary, cursor)[0]
            if size == 0:
                break
            name = dictionary[cursor+2:cursor+size+1].decode("cp437")
            cursor += 2 + size
            size = struct.unpack_from("<H", dictionary, cursor)[0]
            rid = int(dictionary[cursor+2:cursor+size+1])
            cursor += 2 + size
            names[rid] = name
    return names


def verify(game, capture):
    files = {p.name.upper(): p for p in game.iterdir() if p.is_file()}
    data = {}
    for name, expected in EXPECTED.items():
        check(name in files, f"Missing {name} in {game}")
        data[name] = files[name].read_bytes()
        actual = digest(data[name])
        check(actual == expected, f"{name} SHA-256 is {actual}, expected {expected}")
    exe, archive, sidecar = (data[n] for n in ("AESOP.EXE", "HACK.RES", "HACK.TBL"))
    mz_bytes = struct.unpack_from("<H", exe, 8)[0] * 16
    signature, length, _, first_dir, _, _ = struct.unpack_from("<16s5I", archive)
    check(signature.split(b"\0")[0] == b"AESOP/16 V1.00" and length == len(archive)
          and first_dir == 0x24, "Global archive header mismatch")

    events = csv_rows("events.csv")
    cursor, handles, reads = {}, {}, {}
    captured = bytearray()
    for seq, row in enumerate(events, 1):
        name, op = row["file"], row["operation"]
        label = f"Event {seq} ({name} {op})"
        check(int(row["event"]) == seq and row["carry"] == "0", label)
        seg, ip = (int(v, 16) for v in row["ghidra_cs_ip"].split(":"))
        offset = mz_bytes + 16 * (seg - 0x1000) + ip
        check(offset == int(row["exe_offset"], 16) and exe[offset:offset+2] == b"\xcd\x21", label)
        before, after, handle = int(row["before"]), int(row["after"]), int(row["handle"])
        if op == "open":
            check(name not in handles and row["path"].upper() == name and row["ah"] == "3D", label)
            handles[name], cursor[name] = handle, 0
        check(handles[name] == handle and cursor[name] == before, label)
        if op == "seek":
            origin = {"start": 0, "current": before, "end": len(data[name])}[row["seek_origin"]]
            cursor[name] = origin + int(row["seek_delta"])
        elif op == "read":
            size = int(row["returned"])
            block = data[name][before:before+size]
            check(size == int(row["requested"]) == len(block) and digest(block) == row["data_sha256"], label)
            reads[seq] = block
            captured.extend(block)
            cursor[name] += size
        check(cursor[name] == after, label)
    check((len(events), len(reads), len(captured)) == (34, 17, 73013), "Trace counts differ")
    check(digest(captured) == COMBINED, "Combined read digest differs")
    if capture:
        with capture.open("rb") as source:
            check(source.read(len(captured)) == captured, "Replay buffers differ")

    resources = csv_rows("resources.csv")
    names = resource_names(reads[9] + reads[10])
    check([int(row["id"]) for row in resources] == [0, 3, 2932, 2930, 2931], "Resource order differs")
    for row in resources:
        rid, tab = int(row["id"]), int(row["tbl_offset"], 16)
        if rid >= 5:
            check(names.get(rid) == row["name"], f"Dictionary name for {rid}")
        head = int(row["res_header"], 16)
        start, size = int(row["res_payload"], 16), int(row["bytes"])
        check(tab == 4 * rid and struct.unpack_from("<I", sidecar, tab)[0] == head, f"Table slot {rid}")
        check(struct.unpack("<I", reads[int(row["tbl_read_event"])])[0] == head, f"Lookup {rid}")
        check(start == head + 12 and struct.unpack_from("<I", archive, head+8)[0] == size, f"Entry {rid}")
        check(reads[int(row["header_read_event"])] == archive[head:start], f"Entry header {rid}")
        payload = b"".join(reads[int(n)] for n in row["payload_read_events"].split())
        check(digest(payload) == row["payload_sha256"] and payload == archive[start:start+size], f"Payload {rid}")
    print("Verified 34 DOS calls, 17 reads, 73,013 returned bytes and 5 resources.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("game", type=Path, help="Folder containing AESOP.EXE, HACK.RES and HACK.TBL")
    parser.add_argument("--capture", type=Path, help="Compare the first 73,013 bytes of a fresh DH_READS capture")
    args = parser.parse_args()
    try:
        verify(args.game, args.capture)
    except (OSError, ValueError, KeyError, struct.error) as exc:
        sys.exit(f"Verification failed: {exc}")
