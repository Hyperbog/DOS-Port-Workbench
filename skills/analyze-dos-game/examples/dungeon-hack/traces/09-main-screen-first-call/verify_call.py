"""Verify the first native call in the phase-one main screen handler."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import (check, check_call_frame, check_instruction, check_native_import, dictionary,
                           dword, far, import_call_offsets, load_game, read_capture, run_cli, sample, word)

POINT_ORDER = (
    "first_opcode", "fetch_after_short", "branch_taken", "fetch_branch_target", "import_operand",
    "resolve_import", "import_stored", "fetch_after_import", "fetch_after_push", "fetch_after_short",
    "fetch_after_push", "fetch_after_short", "call_argc", "marshal_last", "marshal_first", "far_call",
    "set_palette_entry",
)


def verify(game, trace):
    exe, index, resource = load_game(game)
    rows = read_capture(trace, HERE/"main-screen.profile", expected_order=POINT_ORDER)
    first, entry = rows[0], rows[-1]
    records = {r["point"]: r for r in rows if r["point"] not in ("fetch_after_short", "fetch_after_push")}
    names = dictionary(resource(0))
    phase, palette = int(names["phase-one"]), int(names["Main Base Palette"])
    message = int(dictionary(resource(4))["main screen"])
    code = resource(phase)
    exports = dictionary(resource(names["phase-one.EXPT"]))
    header = int(exports[f"M:{message}"])
    check((phase, palette, message, header) == (2932, 26, 480, 0x0130) and exports["N:OBJECT"] == "phase-one"
          and dword(index, 4*phase)+12 == 0x687718, "Handler and palette resource mapping")
    code_seg, first_pc, caller_cursor, receiver = sample(first, "ds", "si", "stack1", "ax")
    vm_seg, vm_top, saved_top = sample(first, "es", "di", "stack0")
    check(first_pc == header+2 and word(code, header) == 7 and vm_top == ((saved_top-7-4) & 0xffff) and
          receiver == 2000 and code[caller_cursor-1:caller_cursor+3] == b"\x22\x00" + message.to_bytes(2, "little"),
          "Main screen frame and calling SEND")
    check(code[first_pc:first_pc+3] == bytes.fromhex("1D 01 00"), "Opening SHTC 1 and BRT")
    branch_pc = first_pc+2
    target_pc = word(code, branch_pc+1)
    imports = dictionary(resource(names["phase-one.IMPT"]))
    arguments = (0, palette)
    call_offsets = import_call_offsets(code, target_pc, int(imports["C:set_palette"]), arguments)
    call_pc = call_offsets[-1]
    check((target_pc, call_pc) == (0x013d, 0x0146), "Taken branch and first CALL")

    def check_code(row, pc):
        check(sample(row, "ds", "si", "ds_si_dword") == (code_seg, pc, dword(code, pc)),
              f"Live bytecode at +0x{pc:04X}")

    fetches = [r for r in rows if r["point"] == "first_opcode" or r["point"].startswith("fetch_")]
    pcs = [first_pc, branch_pc, *call_offsets]
    check(len(fetches) == len(pcs), "Executed opcode count")
    for row, pc in zip(fetches, pcs):
        check_instruction(exe, row, "8A 1C 46 03 DB 2E FF A7 41 06")
        check_code(row, pc)
    check_code(records["branch_taken"], branch_pc+1)
    check_instruction(exe, records["branch_taken"], "26 8B 05 26 0B 45 02 74 0E 8B 34", -9)
    check_code(records["import_operand"], target_pc+1)
    check_code(records["call_argc"], call_pc+1)
    check_native_import(exe, imports, dictionary(resource(3)), "set_palette", entry)
    check_instruction(exe, entry, "55 8B EC")
    target_cs, target_ip = far(entry["guest_cs_ip"])
    pointer = target_cs << 16 | target_ip
    check(sample(records["resolve_import"], "ds", "bx") == (target_cs, target_ip), "Resolved palette function")

    def check_slot(row, depth, value):
        check(sample(row, "es", "di", "es_di_dword") == (vm_seg, (vm_top-4*depth) & 0xffff, value),
              f"VM slot at event {row['event']}")

    # Each fetch sees the result of the preceding opcode. PUSH allocates a zeroed argument slot.
    slots_after_opcode = [(0, 1), (0, 1), (0, pointer)]
    for depth, arg in enumerate(arguments, 1):
        slots_after_opcode.extend(((depth, 0), (depth, arg)))
    for row, (depth, value) in zip(fetches[1:], slots_after_opcode):
        check_slot(row, depth, value)
    for point in ("branch_taken", "import_operand", "resolve_import"):
        check_slot(records[point], 0, 1)
    for row in (records["import_stored"], records["far_call"], entry):
        check_slot(row, 0, pointer)

    stack, sp = sample(first, "ss", "sp")
    check(sample(records["call_argc"], "ss", "sp") == (stack, sp), "Native stack before marshalling")
    for i, point in enumerate(("marshal_last", "marshal_first")):
        row = records[point]
        depth = len(arguments)-i
        check_instruction(exe, row, "26 FF 75 02 26 FF 35 83 C7 04")
        check_slot(row, depth, arguments[depth-1])
        check(sample(row, "ss", "sp", "cx") == (stack, (sp-4*i) & 0xffff, depth), f"Argument transfer at {point}")
    site = records["far_call"]
    check_instruction(exe, site, "26 FF 1D")
    cs, ip = far(site["guest_cs_ip"])
    check_call_frame(site, entry, arguments, call_pc+2, (stack, sp), (cs, (ip+3) & 0xffff))
    print(f"Verified {len(pcs)} opcodes and set_palette(0, {palette}) at {target_cs:04X}:{target_ip:04X}, "
          f"phase-one +0x{call_pc:04X}, resource {palette} = Main Base Palette.")


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
