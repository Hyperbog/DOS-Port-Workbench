"""Verify the envval return, both main screen branch outcomes, and the first draw_bitmap call."""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import (check, check_argument_transfers, check_call_frame, check_instruction, check_native_import,
                           dictionary, dword, far, import_call_offsets, load_game, read_capture, run_cli, sample, word)

DRAW_ARGS = (1, 25, 0, 0, 0, 0, 0, 0, 0)
LITERAL = ("fetch_short", "fetch_after_short")
MARSHAL = ("marshal_a", "marshal_b", "marshal_c", "marshal_d")
MAIN_ORDER = (
    "envval_entry", "match_name", "value_address", "lookup_return", "convert_call", "decimal_digit", "converted",
    "envval_retf", "vm_resume", "store_low", "store_high", "result_stored", "fetch_resume", *LITERAL,
    "fetch_setb", "fetch_brf", "test_condition", "fetch_import", "resolve_import", "fetch_first_push",
    *(LITERAL * len(DRAW_ARGS)), "call_argc", *MARSHAL, *MARSHAL, "marshal_a", "far_call", "draw_bitmap_entry",
)


def check_code(row, code, segment, pc):
    check(sample(row, "ds", "si", "ds_si_dword") == (segment, pc, dword(code, pc)), f"Live bytecode at +{pc:04X}")


def verify_branch(exe, code, records, value):
    entry, match = records["envval_entry"], records["match_name"]
    code_seg, key = sample(match, "ds", "si")
    vm_cs, _ = far(records["result_stored"]["guest_cs_ip"])
    stack, sp = sample(entry, "ss", "sp")
    frame = (stack, sp, 0x0170, 0x0e42, vm_cs, 1, key, code_seg)
    for point in ("envval_entry", "envval_retf"):
        check(sample(records[point], "ss", "sp", "si", "stack0", "stack1", "stack2", "stack3", "stack4") == frame,
              f'envval("F") frame at {point}')
    check(key == 0x016c and code[key:key+2] == b"F\0", "Inline environment key")
    check_code(match, code, code_seg, key)
    env_text = int.from_bytes(f"F={value}\0".encode("ascii"), "little")
    check(sample(match, "cx", "es_di_dword") == (1, env_text), f"Matched environment entry F={value}")
    env_seg, env_off = sample(match, "es", "di")
    check(sample(records["decimal_digit"], "es", "si", "cx", "bx") == (env_seg, env_off+3, 10, value),
          "Decimal digit and radix")
    check_instruction(exe, match, "F3 A6")
    check_instruction(exe, records["decimal_digit"], "80 EB 30 72 2A F7 E1 03 C3", -5)
    check_instruction(exe, records["envval_retf"], "CB")
    check(sample(records["envval_retf"], "dx", "ax") == (0, value), f"Return value for F={value}")
    segment, top = sample(entry, "es", "di")
    check(sample(records["result_stored"], "ss", "sp", "es", "di", "es_di_dword") ==
          (stack, sp+4, segment, top, value), "Returned value in VM slot")
    condition = int(value == 0)
    for point, pc in (("fetch_setb", 0x174), ("fetch_brf", 0x175), ("test_condition", 0x176)):
        row = records[point]
        check_code(row, code, code_seg, pc)
        check(sample(row, "es", "di", "es_di_dword") == (segment, top, condition), f"Condition at {point}")
    destination = records["fetch_import" if condition else "branch_target"]
    pc = 0x178 if condition else word(code, 0x176)
    check_code(destination, code, code_seg, pc)
    check(sample(destination, "es", "di", "es_di_dword") == (segment, top, condition), "Branch destination slot")


def verify(game, trace, control):
    exe, index, resource = load_game(game)
    names, messages = dictionary(resource(0)), dictionary(resource(4))
    phase = int(names["phase-one"])
    code = resource(phase)
    exports = dictionary(resource(names["phase-one.EXPT"]))
    check(phase == 2932 and exports["M:"+messages["main screen"]] == "304" and
          dword(index, 4*phase)+12 == 0x687718, "Main screen handler and code resource")
    check(code[0x16e:0x178] == bytes.fromhex("21 01 04 1D 00 17 07 01 F8 01"), "CALL, zero test and branch")
    check(int(names["Main Screen"]) == DRAW_ARGS[1], "Main Screen bitmap resource")
    imports, vectors = dictionary(resource(names["phase-one.IMPT"])), dictionary(resource(3))
    rows = read_capture(trace, HERE/"main-screen.profile", expected_order=MAIN_ORDER)
    records = {r["point"]: r for r in rows}
    other = {r["point"]: r for r in read_capture(control, HERE/"f-one.profile")}
    for run, value in ((records, 0), (other, 1)):
        check_native_import(exe, imports, vectors, "envval", run["envval_entry"])
        verify_branch(exe, code, run, value)

    def values(point, *fields):
        return sample(records[point], *fields)

    env_seg, env_off = values("match_name", "es", "di")
    digit = env_off+2
    check(values("value_address", "es", "di") == (env_seg, digit) and
          values("value_address", "es_di_dword")[0] & 0xffff == ord("0"), "Text value after F=")
    check(values("lookup_return", "dx", "ax") == (env_seg, digit) and
          values("convert_call", "stack0", "stack1") == (digit, env_seg), "Lookup pointer passed to conversion")
    for point in ("converted", "vm_resume", "store_low", "store_high", "result_stored"):
        check(values(point, "dx", "ax") == (0, 0), f"Numeric zero at {point}")
    stack, sp = values("envval_entry", "ss", "sp")
    check(values("vm_resume", "ss", "sp", "si") == (stack, sp+4, 0x0170) and
          values("fetch_resume", "ss", "sp") == (stack, sp+10), "Return and native argument cleanup")
    env_cs, env_ip = far(rows[0]["guest_cs_ip"])
    segment, top = values("result_stored", "es", "di")
    for point, value in (("store_low", env_cs << 16 | env_ip), ("store_high", env_cs << 16)):
        check(values(point, "es", "di", "es_di_dword") == (segment, top, value), f"VM return store at {point}")

    target = rows[-1]
    check_native_import(exe, imports, vectors, "draw_bitmap", target)
    draw_cs, draw_ip = far(target["guest_cs_ip"])
    pointer = draw_cs << 16 | draw_ip
    check(values("resolve_import", "ds", "bx") == (draw_cs, draw_ip), "Resolved draw_bitmap pointer")
    call_offsets = import_call_offsets(code, 0x178, int(imports["C:draw_bitmap"]), DRAW_ARGS)
    call_pc = call_offsets[-1]
    check(call_pc == 0x196, "First draw_bitmap CALL offset")
    pcs = [0x170, 0x171, 0x173, 0x174, 0x175, *call_offsets]
    # Each opcode fetch sees the result of the preceding instruction. PUSH creates a zeroed slot.
    states = [(0, 0), (1, 0), (1, 0), (0, 1), (0, 1), (0, 1), (0, pointer)]
    for depth, value in enumerate(DRAW_ARGS, 1):
        states.extend(((depth, 0), (depth, value)))
    fetches = [r for r in rows if r["point"].startswith("fetch_")]
    check(len(fetches) == len(pcs) == len(states), "Bytecodes through the first native call")
    code_seg, = values("fetch_resume", "ds")
    for row, pc, (depth, value) in zip(fetches, pcs, states):
        check_code(row, code, code_seg, pc)
        check(sample(row, "es", "di", "es_di_dword") == (segment, top-4*depth, value), f"VM slot at +{pc:04X}")
    check_code(records["call_argc"], code, code_seg, call_pc+1)
    vm_stack = values("call_argc", "ss", "sp")
    check_argument_transfers(exe, rows, DRAW_ARGS, (segment, top), vm_stack)
    check_instruction(exe, records["far_call"], "26 FF 1D")
    for point in ("far_call", "draw_bitmap_entry"):
        check(values(point, "si", "es", "di", "es_di_dword") == (call_pc+2, segment, top, pointer),
              f"draw_bitmap target at {point}")
    check_call_frame(records["far_call"], target, DRAW_ARGS, call_pc+2, vm_stack, far(records["vm_resume"]["guest_cs_ip"]))
    print(f'Verified envval("F") returned 0, then draw_bitmap{DRAW_ARGS} at main screen +{call_pc:04X}.')
    print("Verified F=1 returned 1 and branched to +01F8.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, default=HERE/"f-one.csv", help="F=1 branch comparison CSV")
    run_cli(verify, HERE, __doc__, parser=parser)
