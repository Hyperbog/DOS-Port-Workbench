"""Verify the phase-one interface return and both arguments to wipe_window."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import check, run_cli, verify_transition


def verify_tail(values, instruction, registers):
    instruction("interface_last_call", "9A AF 08 D8 04")
    instruction("interface_last_return", "59")
    instruction("interface_set_flag", "C7 06 AE 0F 01 00 8B E5 5D CB")
    check(registers == (0x1b1c, 1), "Raw interface return differs from the reference run")
    for point in ("interface_last_return", "interface_set_flag"):
        check(values(point, "dx", "ax") == registers, f"DX:AX at {point}")
    stack, sp = values("interface_last_call", "ss", "sp")
    check(values("interface_last_return", "ss", "sp") == (stack, sp) and
          values("interface_set_flag", "ss", "sp") == (stack, (sp+2) & 0xffff),
          "Interface helper return and one-word stack cleanup")
    check(values("interface_set_flag", "ds") == values("interface_entry", "ds"), "Interface data segment")


def verify(game, trace):
    verify_transition(game, trace, HERE/"phase-one.profile", returned="interface", next_call="wipe_window",
                      resume_pc=0x0387, arguments=(), next_arguments=(1, 0), check_tail=verify_tail)


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
