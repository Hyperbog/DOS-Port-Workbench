"""Verify the phase-one sound return and graphics call using the original game files."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import check, run_cli, verify_transition


def verify_tail(values, instruction, registers):
    instruction("sound_epilogue", "5F 5E 8B E5 5D CB")
    check(values("sound_epilogue", "dx", "ax") == registers, "DX:AX at sound_epilogue")


def verify(game, trace):
    verify_transition(game, trace, HERE/"phase-one.profile", returned="sound", next_call="graphics",
                      resume_pc=0x037d, arguments=(0,), check_tail=verify_tail)


if __name__ == "__main__":
    run_cli(verify, HERE, __doc__)
