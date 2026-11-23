"""Verify the tables program return and the zero-argument main screen message."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import (call_fetch_offsets, check, check_instruction, dictionary, dword, far, load_game,
                           read_capture, run_cli, sample, word)


def verify(game, trace):
    exe, index, resource = load_game(game)
    rows = {row["point"]: row for row in read_capture(trace, HERE/"phase-one.profile")}

    def values(point, *fields):
        return sample(rows[point], *fields)

    names, messages = dictionary(resource(0)), dictionary(resource(4))
    tables, phase = int(names["tables"]), int(names["phase-one"])
    create, message = int(messages["create"]), int(messages["main screen"])
    exports = dictionary(resource(names["tables.EXPT"]))
    check((tables, phase, create, message) == (2929, 2932, 0, 480) and exports["N:OBJECT"] == "tables"
          and f"M:{create}" not in exports, "Tables resources and missing create export")
    phase_exports = dictionary(resource(names["phase-one.EXPT"]))
    header = int(phase_exports[f"M:{message}"])
    code = resource(phase)
    check(phase_exports["N:OBJECT"] == "phase-one" and dword(index, 4*phase)+12 == 0x687718 and
          code[0x3aa:0x3b3] == bytes.fromhex("21 02 2D 02 00 22 00 E0 01"), "CALL, LAW and SEND in phase-one")
    check(header == 0x130 and code[header:header+4] == bytes.fromhex("07 00 1D 01"), "Main screen handler header")

    slot, receiver = 2003, 2000
    entry = "next_create_program_entry"
    local = int(dictionary(resource(names["phase-one.IMPT"]))["C:create_program"])
    vector = int(dictionary(resource(3))["create_program"])
    image_cs, image_ip = far(rows[entry]["image_cs_ip"])
    check(call_fetch_offsets(code, 0x39f, 2, local, (slot, tables))[-1] == 0x3aa and
          dword(exe, 0x1c8f8+vector) == (image_cs << 16 | image_ip), "Incoming create_program import and call")
    cs, ip = far(rows[entry]["guest_cs_ip"])
    vm_cs, vm_ip = far(rows["vm_resume"]["guest_cs_ip"])
    stack, sp = values(entry, "ss", "sp")
    frame = tuple(f"stack{i}" for i in range(7))
    for point in (entry, "tables_retf"):
        check(values(point, "ss", "sp", *frame) == (stack, sp, vm_ip, vm_cs, 2, slot, 0, tables, 0),
              f"Wrapper return address and arguments at {point}")
    check_instruction(exe, rows["store_instance"], "89 87 62 20")
    table_ds, table_index, instance = values("store_instance", "ds", "bx", "ax")
    check_instruction(exe, rows["tables_instance"], "8B 00 3D FF FF", -2)
    check(table_index == 2*slot and instance != 0xffff and values("tables_instance", "ds", "bx", "si", "ax") ==
          (table_ds, table_index, 0x2062, instance), "Instance table write and readback")
    check(values("send_create", *frame[:3]) == (slot, create, 0xffff), "Create send to tables")
    for point in ("tables_dispatch", "miss_retf"):
        check(values(point, *frame[:5]) == (0x0076, cs, slot, create, 0xffff), f"Create dispatch frame at {point}")
    check_instruction(exe, rows["lookup_miss"], "BA FF FF B8 FF FF EB 67")
    for point in ("miss_retf", "create_return", "load_slot"):
        check(values(point, "dx", "ax") == (0xffff, 0xffff), f"Message lookup result at {point}")
    check_instruction(exe, rows["load_slot"], "8B 56 0A 8B 46 08 5D CB")
    bp, local_sp, low, high = values("load_slot", "bp", "sp", "stack4", "stack5")
    check(bp == local_sp and (high, low) == (0, slot), "Saved slot argument")
    check(values("tables_retf", "dx", "ax") == (0, slot) and
          values("vm_resume", "ss", "sp", "si", "dx", "ax") == (stack, (sp+4) & 0xffff, 0x3ac, 0, slot),
          "Wrapper return to phase-one")

    dest = values("store_low", "es", "di")
    pointer = (cs << 16) | ip
    for point, value in ((entry, pointer), ("store_low", pointer), ("store_high", cs << 16 | slot),
                         ("result_stored", slot), ("fetch_law", slot), ("store_this", slot), ("fetch_send", receiver)):
        check(values(point, "es", "di", "es_di_dword") == (*dest, value), f"VM result slot at {point}")
    code_segment, = values("fetch_law", "ds")
    for point, pc in (("fetch_law", 0x3ac), ("auto_base", 0x3ad), ("fetch_send", 0x3af),
                      ("send_operands", 0x3b0), ("handler_frame", header), ("first_opcode", header+2)):
        check(values(point, "ds", "si", "ds_si_dword") == (code_segment, pc, dword(code, pc)),
              f"Live phase-one bytecode at {point}")
    check_instruction(exe, rows["read_this"], "26 8B 07 99 26 89 05 26 89 55 02")
    base, = values("auto_base", "bx")
    check(values("read_this", "es", "bx") == (dest[0], (base-2) & 0xffff) and
          values("store_this", "dx", "ax") == (0, receiver), "LAW 2 loads the phase-one receiver")
    check(values("send_zero_args", "cx", "bx", "di", "es_di_dword") == (0, dest[1], dest[1], receiver),
          "SEND with zero script arguments")
    check_instruction(exe, rows["call_dispatcher"], "E8 04 FA")
    send_args = (receiver, message, 0xffff)
    call_sp, = values("call_dispatcher", "sp")
    check(values("call_dispatcher", "ss", *frame[:4]) == (stack, vm_cs, *send_args) and
          values("main_dispatch", "ss", "sp", *frame[:5]) == (stack, (call_sp-2) & 0xffff, 0x0eee, vm_cs, *send_args),
          "Main screen dispatcher arguments")
    check(values("matched_message", "ds_si_dword") == ((header << 16) | message,), "Matched main screen export")
    check(values("handler_frame", "ax", "es", "di") == (receiver, *dest) and
          values("first_opcode", "es", "di") == (dest[0], (dest[1]-word(code, header)-4) & 0xffff),
          "Entered the main screen frame")
    print(f"Verified tables.create lookup -1, create_program return {slot}, SEND {message} to slot {receiver} "
          f"with 0 arguments, and phase-one +0x{header+2:04X} at the first opcode.")


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
