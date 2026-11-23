"""Verify the magic create handler, the return to phase-one and the request for tables."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import check, dictionary, dword, run_cli, verify_transition, word


def verify_magic_resource(resource, names, values):
    message = int(dictionary(resource(4))["create"])
    code = resource(names["magic"])
    exports = dictionary(resource(names["magic.EXPT"]))
    check(message == 0 and names["magic"] == "2922" and exports["N:OBJECT"] == "magic", "Magic class and message")
    header = int(exports[f"M:{message}"])
    check(values("match_create", "ds_si_dword") == ((header << 16) | message,), "Matched magic export")
    segment, pc, live = values("handler_header", "ds", "si", "ds_si_dword")
    check(pc == header and word(code, pc) == 2 and live == dword(code, pc), "Magic handler frame")
    check(values("first_opcode", "ds", "si", "ds_si_dword") == (segment, pc+2, dword(code, pc+2)),
          "First magic bytecode")
    end_segment, after_end, live = values("handler_end", "ds", "si", "ds_si_dword")
    check(end_segment == segment and after_end > pc+2 and code[after_end-1] == 0x56 and
          live == dword(code, after_end), "END in the magic code resource")


def verify_tail(values, instruction, registers):
    slot, resource_id = 2005, 2922
    check(values("create_helper", "stack2", "stack3", "stack4") == (resource_id, 0, slot), "Creation helper frame")
    instruction("store_instance", "89 87 62 20")
    ds, index, receiver, instance = values("store_instance", "ds", "bx", "si", "ax")
    check((index, receiver) == (2*slot, slot), "Instance table write index")
    instruction("lookup_instance", "8B 00 3D FF FF")
    check(values("lookup_instance", "ds", "bx", "si") == (ds, index, 0x2062) and
          values("instance_loaded", "ax") == (instance,) and instance != 0xffff, "Dispatcher read back the instance")

    instruction("send_create", "9A F2 08 F5 10")
    check(values("send_create", "stack0", "stack1", "stack2") == (slot, 0, 0xffff), "Create message arguments")
    wrapper_cs = values("create_program_entry", "es_di_dword")[0] >> 16
    frame_fields = ("stack0", "stack1", "stack2", "stack3", "stack4")
    for point in ("dispatch_create", "handler_retf"):
        check(values(point, *frame_fields) == (0x0076, wrapper_cs, slot, 0, 0xffff), f"Dispatch frame at {point}")
    check(values("dispatch_create", "ss", "sp") == values("handler_retf", "ss", "sp"), "Dispatch stack restoration")
    instruction("handler_result", "26 8B 05 26 8B 55 02")
    check(values("handler_end", "es", "di", "es_di_dword") == values("handler_result", "es", "di", "es_di_dword")
          and values("handler_result", "es_di_dword") == (0,), "Magic handler result slot")
    for point in ("handler_retf", "dispatch_return", "load_slot_result"):
        check(values(point, "dx", "ax") == (0, 0), f"Nested return value at {point}")

    instruction("load_slot_result", "8B 56 0A 8B 46 08 5D CB")
    bp, sp, low, high = values("load_slot_result", "bp", "sp", "stack4", "stack5")
    check(bp == sp and (high, low) == registers == (0, slot), "Wrapper returned its 32-bit slot argument")


def verify(game, trace):
    verify_transition(game, trace, HERE/"phase-one.profile", returned="create_program", next_call="create_program",
                      resume_pc=0x039f, arguments=(2005, 2922), next_arguments=(2003, 2929), program_class="tables",
                      prefix=(trace.with_name("magic.csv"), HERE/"magic.profile"),
                      check_archive=verify_magic_resource, check_tail=verify_tail)


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
