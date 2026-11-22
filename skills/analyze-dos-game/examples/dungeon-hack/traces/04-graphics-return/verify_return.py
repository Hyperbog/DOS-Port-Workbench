"""Verify the phase-one graphics return and interface call using the original game files."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import check, run_cli, verify_transition


def verify_tail(values, instruction, registers):
    instruction("graphics_last_call", "9A 64 28 FC 12")
    instruction("graphics_last_return", "83 C4 0A")
    instruction("graphics_save_ax", "A3 CC 32 5F 5E CB")
    check(registers == (0, 2), "Expected graphics return DX:AX = 0000:0002")
    for point in ("graphics_last_return", "graphics_save_ax"):
        check(values(point, "dx", "ax") == registers, f"DX:AX at {point}")
    stack, sp = values("graphics_last_call", "ss", "sp")
    check(values("graphics_last_return", "ss", "sp") == (stack, sp) and
          values("graphics_save_ax", "ss", "sp") == (stack, (sp+10) & 0xffff),
          "Graphics helper return and five-word stack cleanup")
    check(values("graphics_save_ax", "ds") == values("graphics_entry", "ds"), "Graphics data segment")


def verify(game, trace):
    verify_transition(game, trace, HERE/"phase-one.profile", returned="graphics", next_call="interface",
                      resume_pc=0x0382, arguments=(), check_tail=verify_tail)


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
