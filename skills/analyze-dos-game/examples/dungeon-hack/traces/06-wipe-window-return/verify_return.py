"""Verify the wipe_window return and the phase-one request for the magic program."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import check, run_cli, verify_transition


def verify_tail(values, instruction, registers):
    instruction("wipe_window_entry", "55 8B EC FF 76 0C FF 76 08")
    instruction("wipe_helper_call", "9A 5F 3F FC 12")
    instruction("wipe_helper_done", "2E FF 0E 06 00 5F 5E 1F 5D CB")
    instruction("wipe_helper_return", "59 59 5D CB")
    check(registers == (0x03c5, 0), "Raw wipe return differs from the reference run")
    for point in ("wipe_helper_done", "wipe_helper_retf", "wipe_helper_return"):
        check(values(point, "dx", "ax") == registers, f"DX:AX at {point}")

    stack, entry_sp = values("wipe_window_entry", "ss", "sp")
    wrapper_pointer, = values("store_low", "es_di_dword")
    # Saved BP followed by the two 16-bit words the wrapper forwards to the helper.
    call_sp = (entry_sp - 6) & 0xffff
    for point in ("wipe_helper_call", "wipe_helper_return"):
        check(values(point, "ss", "sp", "stack0", "stack1") == (stack, call_sp, 1, 0),
              f"Forwarded window arguments at {point}")
    frame = (stack, (call_sp-4) & 0xffff, 0x0b25, wrapper_pointer >> 16, 1, 0)
    for point in ("wipe_helper_entry", "wipe_helper_retf"):
        check(values(point, "ss", "sp", "stack0", "stack1", "stack2", "stack3") == frame,
              f"Graphics helper frame at {point}")

    instruction("result_stored", "5A D1 E2 D1 E2 03 E2")
    resume_sp, count = values("vm_resume", "sp", "stack0")
    check(count == 2 and values("release_arguments", "ss", "sp", "dx") ==
          (stack, (resume_sp+2) & 0xffff, 8), "Two 32-bit wipe arguments to release")
    check(values("fetch_import", "ss", "sp") == (stack, (resume_sp+10) & 0xffff),
          "VM stack after removing the count and arguments")


def verify(game, trace):
    verify_transition(game, trace, HERE/"phase-one.profile", returned="wipe_window", next_call="create_program",
                      resume_pc=0x0392, arguments=(1, 0), next_arguments=(2005, 2922),
                      program_class="magic", check_tail=verify_tail)


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
