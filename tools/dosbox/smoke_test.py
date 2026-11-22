"""Check the same DOSBox observer with a generated DOS executable and a second profile."""
import argparse
import csv
import os
import struct
import subprocess
import tempfile
from pathlib import Path


def run_fixture(binary, stack_data):
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp).resolve()
        # mov ax,1234h | mov dx,5678h | nop | mov ax,4c00h | int 21h
        body = bytes(16) + bytes.fromhex("B8 34 12 BA 78 56 90 B8 00 4C CD 21")
        stack_segment, stack_pointer = 2, 0x100
        if stack_data:
            body = body.ljust(16*stack_segment + stack_pointer, b"\0")
            body += struct.pack(f"<{len(stack_data)}H", *stack_data)
        header = struct.pack("<14H", 0x5a4d, 32+len(body), 1, 0, 2, 0x20, 0xffff, stack_segment,
                             stack_pointer, 0, 0, 1, 0x1c, 0)
        (work/"CHECK.EXE").write_bytes(header + bytes(4) + body)
        profile = work/"fixture.profile"
        depth = f"stack_words {len(stack_data)}\n" if stack_data else ""
        profile.write_text(f"image 0001:0000 0000 BA1234B8\n{depth}start 0001:0000 fixture_entry\n"
                           "watch 0001:0003 ax_set\nstop 0001:0006 both_set\n", encoding="ascii")
        capture = work/"trace.csv"
        env = dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy",
                   DPW_PROFILE=str(profile), DPW_TRACE=str(capture), XDG_CONFIG_HOME=temp)
        config = Path(__file__).resolve().with_name("trace.conf")
        subprocess.run([str(binary.resolve()), "-noconsole", "-conf", str(config), "-c",
                        f'mount c "{work}"', "-c", "c:", "-c", "check", "-c", "exit"],
                       cwd=work, env=env, check=True, timeout=20)
        if not capture.exists():
            raise SystemExit("No capture. Supply the DOSBox build with the observer enabled.")
        with capture.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
        if ([r["point"] for r in rows] != ["fixture_entry", "ax_set", "both_set"] or
                (rows[1]["ax"], rows[2]["ax"], rows[2]["dx"]) != ("1234", "1234", "5678")):
            raise SystemExit("Fixture checkpoints or register values differ.")
        columns = [key for key in rows[0] if key.startswith("stack")]
        if columns != [f"stack{i}" for i in range(len(stack_data) or 5)]:
            raise SystemExit("Unexpected stack columns.")
        if stack_data and any(tuple(int(row[key], 16) for key in columns) != stack_data for row in rows):
            raise SystemExit("Stack words differ from the fixture.")


def run(binary):
    run_fixture(binary, ())
    run_fixture(binary, tuple(range(0x4101, 0x4108)))
    print("Verified registers, the five-word default, and seven known stack words.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dosbox", type=Path, help="Path to the instrumented DOSBox 0.74-3 executable")
    run(parser.parse_args().dosbox)
