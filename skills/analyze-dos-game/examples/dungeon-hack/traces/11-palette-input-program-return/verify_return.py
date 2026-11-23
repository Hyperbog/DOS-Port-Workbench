"""Verify the automatic program slot and the main screen call to envval("F")."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import (argument_words, check, check_call_frame, check_instruction, check_native_import,
                           dictionary, dword, far, import_call_offsets, load_game, read_capture, run_cli, sample, word)

ORDER = (
    "create_program_entry", "free_search", "test_slot", "occupied_slot", "test_slot", "select_slot",
    "save_selected", "slot_saved", "create_helper", "store_instance", "send_create", "create_dispatch",
    "instance_loaded", "lookup_miss", "miss_retf", "create_return", "load_slot", "create_program_retf",
    "vm_resume", "store_low", "store_high", "result_stored", "fetch_save", "local_base", "store_local",
    "fetch_static", "read_static", "fetch_push", "fetch_pushed", "fetch_eq", "fetch_brf", "test_condition",
    "fetch_import", "resolve_import", "fetch_args", "fetch_pushed", "fetch_bra", "branch_over_string",
    "fetch_call", "call_argc", "marshal_argument", "far_call", "envval_entry",
)


def verify_creation(rows, records, values, program, message):
    entry = rows[0]
    create_cs, create_ip = far(entry["guest_cs_ip"])
    vm_cs, vm_ip = far(records["vm_resume"]["guest_cs_ip"])
    stack, sp = sample(entry, "ss", "sp")
    frame = tuple(f"stack{i}" for i in range(7))
    check(sample(entry, *frame) == (vm_ip, vm_cs, *argument_words((-1, program))), "Incoming automatic slot request")
    first, limit = values("free_search", "stack2", "stack3")
    check((first, limit) == (2000, 2048), "Automatic slot search bounds")
    slot, = values("select_slot", "dx")
    table_ds, = values("store_instance", "ds")
    tests = [sample(r, "ds", "bx", "dx", "cx") for r in rows if r["point"] == "test_slot"]
    check(slot == 2001 and tests == [(table_ds, 2*i, i, limit) for i in (first, slot)] and
          values("occupied_slot", "dx") == (first,), "First free slot after occupied slot 2000")
    check(values("save_selected", "ax", "dx", "stack4", "stack5") == (slot, 0, 0xffff, 0xffff) and
          values("slot_saved", "stack4", "stack5") == (slot, 0), "Replacement of the -1 slot argument")
    check(values("create_helper", "stack2", "stack3", "stack4") == (program, 0, slot), "Creation helper arguments")
    instance, index, receiver = values("store_instance", "ax", "bx", "si")
    check(index == 2*slot and receiver == slot and instance != 0xffff and
          values("instance_loaded", "ds", "bx", "si", "ax") == (table_ds, index, 0x2062, instance),
          "Instance table write and dispatcher readback")
    dispatch = (slot, message, 0xffff)
    check(values("send_create", *frame[:3]) == dispatch, "Nested create message")
    for point in ("create_dispatch", "miss_retf"):
        check(values(point, *frame[:5]) == (0x0076, create_cs, *dispatch), f"Nested dispatch frame at {point}")
    for point in ("miss_retf", "create_return", "load_slot"):
        check(values(point, "dx", "ax") == (0xffff, 0xffff), f"Missing create handler result at {point}")
    check(values("load_slot", "stack4", "stack5") == (slot, 0), "Saved slot at wrapper epilogue")
    check(values("create_program_retf", "ss", "sp", *frame) ==
          (stack, sp, vm_ip, vm_cs, *argument_words((slot, program))), "Wrapper return frame with assigned slot")
    for point in ("create_program_retf", "vm_resume", "store_low", "store_high", "result_stored"):
        check(values(point, "dx", "ax") == (0, slot), f"Slot returned in DX:AX at {point}")
    check(values("vm_resume", "ss", "sp", "si") == (stack, sp+4, 0x0155) and
          values("fetch_save", "ss", "sp") == (stack, sp+14), "VM resume and two-argument cleanup")
    seg, top = values("result_stored", "es", "di")
    for point, value in (("store_low", create_cs << 16 | create_ip), ("store_high", create_cs << 16 | slot),
                         ("result_stored", slot)):
        check(values(point, "es", "di", "es_di_dword") == (seg, top, value), f"VM result store at {point}")
    return slot


def verify(game, trace):
    exe, index, resource = load_game(game)
    rows = read_capture(trace, HERE/"main-screen.profile", expected_order=ORDER)
    records = {r["point"]: r for r in rows}

    def values(point, *fields):
        return sample(records[point], *fields)

    names = dictionary(resource(0))
    program, phase = int(names["palette input screen"]), int(names["phase-one"])
    exports = dictionary(resource(names["palette input screen.EXPT"]))
    messages = dictionary(resource(4))
    message = int(messages["create"])
    check((program, phase, message) == (1966, 2932, 0) and exports["N:OBJECT"] == "palette input screen" and
          f"M:{message}" not in exports, "Palette input screen class and missing create export")
    code = resource(phase)
    phase_exports = dictionary(resource(names["phase-one.EXPT"]))
    check(phase_exports["M:"+messages["main screen"]] == "304" and dword(index, 4*phase)+12 == 0x687718,
          "Main screen handler and code resource")
    imports, vectors = dictionary(resource(names["phase-one.IMPT"])), dictionary(resource(3))
    check(import_call_offsets(code, 0x0148, int(imports["C:create_program"]), (-1, program))[-1] == 0x0153,
          "Incoming create_program bytecode")
    for name in ("create_program", "envval"):
        check_native_import(exe, imports, vectors, name, records[name+"_entry"])

    for point, raw, displacement in (
        ("test_slot", "83 BF 62 20 FF 74 05 42 3B D1 7C F0", 0), ("select_slot", "8B C2 5D CB", 0),
        ("save_selected", "99 89 56 0A 89 46 08", -1), ("store_instance", "89 87 62 20", 0),
        ("instance_loaded", "8B 00 3D FF FF", -2), ("lookup_miss", "BA FF FF B8 FF FF EB 67", 0),
        ("load_slot", "8B 56 0A 8B 46 08 5D CB", 0), ("store_low", "26 89 05 26 89 55 02", 0),
        ("local_base", "2B 1C 83 C6 02", 0), ("store_local", "26 89 07 26 89 57 02", 0),
        ("read_static", "8A 07 98 99 26 89 05 26 89 55 02", 0),
        ("test_condition", "26 8B 05 26 0B 45 02 75 0E", 0), ("resolve_import", "26 89 1D 26 8C 5D 02", 0),
        ("fetch_bra", "AD 26 89 05 26 8C 5D 02", -10), ("branch_over_string", "8B 34", 0),
        ("marshal_argument", "26 FF 75 02 26 FF 35 83 C7 04", 0), ("far_call", "26 FF 1D", 0),
    ):
        check_instruction(exe, records[point], raw, displacement)

    slot = verify_creation(rows, records, values, program, message)
    segment, top = values("result_stored", "es", "di")
    code_seg, = values("fetch_save", "ds")
    target_cs, target_ip = far(rows[-1]["guest_cs_ip"])
    function = target_cs << 16 | target_ip
    string_pc = word(code, 0x0167)
    argument = code_seg << 16 | string_pc
    check(code[0x0155:0x0170] == bytes.fromhex("31 06 00 39 01 00 04 1D 00 17 01 74 01 20 18 00 "
                                               "04 54 6C 01 02 6E 01 46 00 21 01"), "Bytecode and inline F string")
    fetches = [r for r in rows if r["point"].startswith("fetch_")]
    states = ((0x155, 0, slot), (0x158, 0, slot), (0x15b, 0, 0), (0x15c, 1, 0), (0x15e, 1, 0),
              (0x15f, 0, 1), (0x162, 0, 1), (0x165, 0, function), (0x166, 1, 0),
              (0x169, 1, argument), (0x16e, 1, argument))
    check(len(fetches) == len(states), "Main screen instruction count")
    for row, (pc, depth, value) in zip(fetches, states):
        check(sample(row, "ds", "si", "ds_si_dword") == (code_seg, pc, dword(code, pc)), f"Bytecode at +{pc:04X}")
        check(sample(row, "es", "di", "es_di_dword") == (segment, top-4*depth, value), f"VM slot at +{pc:04X}")
    base, = values("local_base", "bx")
    check(values("fetch_save", "stack0") == (base,) and
          values("store_local", "es", "bx", "dx", "ax") == (segment, base-word(code, 0x156), 0, slot),
          "SAD 6 destination and assigned slot")
    check(values("fetch_push", "dx", "ax") == (0, 0), "LSB 1 read zero")
    check(values("test_condition", "ds", "si", "ds_si_dword", "es_di_dword") ==
          (code_seg, 0x0160, dword(code, 0x0160), 1), "BRF fallthrough")
    check(values("resolve_import", "ds", "bx") == (target_cs, target_ip), "Resolved envval pointer")
    check(values("branch_over_string", "ds", "si", "ds_si_dword", "es_di_dword") ==
          (code_seg, string_pc-2, dword(code, string_pc-2), argument), "Live branch operand and F string")
    check(values("call_argc", "ds", "si", "ds_si_dword") == (code_seg, 0x016f, dword(code, 0x016f)) and
          values("marshal_argument", "es", "di", "cx", "es_di_dword") == (segment, top-4, 1, argument),
          "Single string argument")
    for point in ("far_call", "envval_entry"):
        check(values(point, "si", "es", "di", "es_di_dword") == (0x0170, segment, top, function),
              f"envval target and script cursor at {point}")
    check_call_frame(records["far_call"], rows[-1], (argument,), 0x0170, values("call_argc", "ss", "sp"),
                     far(records["vm_resume"]["guest_cs_ip"]))
    print(f'Verified create_program(-1, {program}) returned slot {slot}, then envval("F") '
          f'at main screen +016E, guest {target_cs:04X}:{target_ip:04X}.')


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
