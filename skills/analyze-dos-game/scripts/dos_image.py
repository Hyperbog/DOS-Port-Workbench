"""Read DOS load images and follow statically resolvable 16-bit control flow."""
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from collections import deque
from pathlib import Path

RULES = json.loads(Path(__file__).with_name("rules.json").read_text(encoding="utf-8"))
LINE = re.compile(r"^\s*([\da-f]+):\s*\t([\da-f ]+)\t(.+)$", re.M)
REGISTER = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")
PREFIXES = bytes.fromhex("26 2e 36 3e 64 65 66 67 f0 f2 f3")


def inspect_image(name, data, tool):
    report = {"sha256": hashlib.sha256(data).hexdigest(), "format": "unrecognized"}
    start, end, cs, ip, origin, reloc = 0, len(data), 0, 0x100, 0x100, set()
    if data[:2] in (b"MZ", b"ZM"):
        report["format"] = "DOS MZ"
        if len(data) < 28:
            return report | {"status": "truncated MZ header"}
        tail, pages, count, paras = struct.unpack_from("<4H", data, 2)
        ip, cs, table, overlay = struct.unpack_from("<4H", data, 20)
        start, end, origin = paras * 16, (pages - 1) * 512 + (tail or 512), 0
        if len(data) >= 64:
            new = struct.unpack_from("<I", data, 60)[0]
            sig = data[new:new+4]
            if 64 <= new <= len(data)-4 and (sig == b"PE\0\0" or sig[:2] == b"NE" or sig in (b"LE\0\0", b"LX\0\0")):
                return report | {"format": "MZ + " + sig[:2].decode(), "secondary_header": new,
                                 "status": "secondary image needs its own loader"}
        if not pages or tail > 511 or not 28 <= start <= end <= len(data):
            return report | {"status": "inconsistent MZ image bounds"}
        report["regions"] = {"loader_header": [0, start], "resident_image": [start, end]}
        if end < len(data):
            report["regions"]["preserve_appended_bytes"] = [end, len(data)]
        if count and (table < 28 or table + count * 4 > start):
            return report | {"status": "invalid relocation table bounds"}
        for off, seg in struct.iter_unpack("<HH", data[table:table+4*count]):
            reloc.add(16 * seg + off)
        report["relocation_count"] = count
        if any(r + 2 > end - start for r in reloc):
            return report | {"status": "relocation outside file-backed image"}
        if overlay:
            return report | {"status": "overlay module; locate its resident loader"}
        if data[end:end+4] in (b"LE\0\0", b"LX\0\0"):
            return report | {"status": "appended linear executable signature; inspect its payload"}
    elif name.lower().endswith(".com") and 0 < end <= 0xff00:
        report.update(format="DOS COM (assumed from name and size)", regions={"resident_image": [0, end]})
    else:
        return report | {"status": "outside supported COM/MZ formats"}
    image = data[start:end]
    report["entry_relative_cs_ip"] = f"{cs:04X}:{ip:04X}"
    if not 0 <= ((16 * cs + ip) & 0xfffff) - origin < len(image):
        return report | {"status": "entry outside file-backed image"}
    for marker in (b"PKLITE", b"LZ91", b"LZ09", b"UPX!", b"DOS/4G", b"DOS/32A", b"GO32STUB"):
        if marker in data[:start + min(len(image), 2048)].upper():
            return report | {"status": "possible packer or extender; inspect loader", "marker": marker.decode()}
    if not tool:
        return report | {"status": "layout only; install GNU objdump or supply --objdump"}
    with tempfile.TemporaryDirectory() as tmp:
        rawfile = Path(tmp, "resident.bin")
        rawfile.write_bytes(image)
        try:
            report["trace"] = trace(rawfile, tool, len(image), start, origin, cs, ip, reloc)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return report | {"status": "layout only; decoder failed", "decoder_error": str(exc)}
    return report | {"status": "partial static analysis"}


def decode_window(tool, path, pos, size, cache):
    stop = min(size, pos + 2048)
    cmd = [tool, "-D", "-w", "-z", "-b", "binary", "-m", "i8086", "-M", "intel",
           f"--start-address={pos}", f"--stop-address={stop}", str(path)]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10,
                            env=dict(os.environ, LC_ALL="C"))
    if result.returncode:
        raise ValueError(result.stderr.strip() or "GNU objdump could not decode i8086")
    for address, octets, asm in LINE.findall(result.stdout):
        offset = int(address, 16)
        if stop == size or offset <= stop - 15:
            cache[offset] = (bytes.fromhex(octets), asm.strip())


def register_hint(raw, pos, reloc, prior):
    if any(i in reloc or i-1 in reloc for i in range(pos+1, pos+len(raw))):
        return None
    if len(raw) == 3 and 0xb8 <= raw[0] <= 0xbf:
        return REGISTER[raw[0] - 0xb8], int.from_bytes(raw[1:], "little")
    if len(raw) == 2 and raw[0] == 0xb4:
        return "ah", raw[1]
    if raw in (b"\x31\xc0", b"\x33\xc0"):
        return "ax", 0
    if raw in (b"\x30\xe4", b"\x32\xe4"):
        return "ah", 0
    if prior and prior[0] in ("ax", "ah") and len(raw) == 2:
        high = prior[1] >> 8 if prior[0] == "ax" else prior[1]
        if raw[0] == 0xb0 or raw in (b"\x30\xc0", b"\x32\xc0"):
            return "ax", (high << 8) | (raw[1] if raw[0] == 0xb0 else 0)
    return None


def classify(op, args, hint):
    reg, value = hint or ("", 0)
    if op == "int" and args.startswith("0x"):
        vector = int(args, 16)
        ah = value >> 8 if reg == "ax" else value if reg == "ah" else None
        key = f"{vector:02X}:{ah:02X}" if ah is not None else ""
        detail = RULES["service"].get(key) or RULES["vector"].get(f"{vector:02X}", ["interrupt", "unclassified vector"])
        return detail, vector == 0x20 or (vector == 0x21 and ah in (0, 0x31, 0x4c))
    if op in ("in", "out", "ins", "outs"):
        port = args.split(",")[0 if op.startswith("out") else -1].strip()
        number = int(port, 16) if port.startswith("0x") else value if reg == "dx" else None
        label = RULES["port"].get(f"{number:X}", ["hardware", f"I/O port {number:04X}h"]) if number is not None else ["hardware", "I/O via unresolved DX"]
        return label, False
    if op == "mov" and reg and args in (f"es,{reg}", f"ds,{reg}", f"fs,{reg}", f"gs,{reg}"):
        if value in (0xa000, 0xb000, 0xb800):
            return ["video", f"possible video memory segment {value:04X}h"], False
    return None, False


def trace(path, tool, size, file_base, origin, cs, ip, reloc):
    queue = deque([(cs, ip, None)])
    seen, decoded, cache, findings, gaps = set(), set(), {}, {}, {}
    windows = 0
    while queue and len(seen) < 40000:
        seg, pc, hint = queue.popleft()
        state = (seg, pc, hint)
        if state in seen:
            continue
        seen.add(state)
        pos = ((16 * seg + pc) & 0xfffff) - origin
        address = f"{seg:04X}:{pc:04X}"
        if not 0 <= pos < size:
            gaps[address] = "target outside resident bytes"
            continue
        if pos not in cache:
            if windows >= 512:
                gaps[address] = "decoder window budget reached"
                break
            decode_window(tool, path, pos, size, cache)
            windows += 1
        raw, asm = cache.get(pos, (b"", ""))
        if not raw or "(bad)" in asm or asm.startswith(".") or pc + len(raw) > 0x10000:
            gaps[address] = "unknown, truncated or segment-crossing instruction"
            continue
        text = re.sub(r"^(?:(?:rep(?:z|nz|e|ne)?|data32|addr32|bnd|cs|ds|es|ss|fs|gs)\s+)+", "", asm)
        parts = text.split(None, 1)
        op, args = parts[0], parts[1].strip() if len(parts) == 2 else ""
        decoded.add((seg, pc))
        label, exits = classify(op, args, hint)
        if label:
            row = dict(file_offset=file_base+pos, cs_ip=address, bytes=raw.hex(" "), instruction=asm,
                       subsystem=label[0], meaning=label[1])
            if hint and (op == "mov" or (op == "int" and hint[0] in ("ah", "ax")) or
                         (op in ("in", "out", "ins", "outs") and "dx" in args and hint[0] == "dx")):
                row["local_register"] = f"{hint[0]}={hint[1]:X}h"
            findings[(address, label[1], row.get("local_register", ""))] = row
        if exits or op.startswith(("ret", "iret")):
            continue
        if op in ("hlt", "ud2", "int3", "int1", "icebp", "int") and (not label or label[0] == "dpmi"):
            gaps[address] = "control depends on a handler or CPU mode"
            continue
        if op.startswith(("j", "call", "loop", "lcall", "ljmp")):
            prefixes = raw[:len(raw) - len(raw.lstrip(PREFIXES))]
            if re.fullmatch(r"0x[0-9a-f]+", args) and not op.endswith("d") and 0x66 not in prefixes:
                queue.append((seg, (pc + int(args, 16) - pos) & 0xffff, None))
            elif len(raw) == 5 and raw[0] in (0x9a, 0xea) and pos+3 in reloc:
                off, target_seg = struct.unpack_from("<HH", raw, 1)
                queue.append((target_seg, off, None))
            else:
                gaps[address] = f"unresolved transfer: {asm}"
            if op.startswith(("jmp", "ljmp")):
                continue
        queue.append((seg, (pc+len(raw)) & 0xffff, register_hint(raw, pos, reloc, hint)))
    if queue and len(seen) >= 40000:
        gaps["budget"] = "40,000 instruction states reached"
    return dict(decoded_addresses=len(decoded), findings=sorted(findings.values(), key=lambda r: r["file_offset"]),
                unresolved=gaps)

