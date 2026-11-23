"""Verify the main screen palette return and the request for the palette input screen program."""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from native_return import check, far, read_capture, run_cli, sample, verify_transition, word

POINT_ORDER = (
    "set_palette_entry", "palette_lookup", "palette_resource", "first_color", "last_color", "colors_done",
    "final_rgb_distance", "release_call", "release_entry", "release_decrement", "release_retf", "release_return", "set_palette_retf",
    "vm_resume", "store_low", "store_high", "result_stored", "release_arguments", "fetch_import",
    "import_operand", "replace_low", "import_stored", "fetch_after_import", "fetch_constant", "fetch_after_short",
    "negate_slot", "fetch_after_negate", "fetch_constant", "fetch_after_word", "call_argc", "marshal_last",
    "marshal_first", "far_call", "create_program_entry",
)


def check_dac(path, rgb, values):
    count = len(rgb)//3
    channels = ("dac_index", "dac_red", "dac_green", "dac_blue")
    order = ["set_palette_entry", *(channels * count), "set_palette_retf"]
    rows = read_capture(path, HERE/"palette-dac.profile", expected_order=order)
    wrapper_cs = values("set_palette_entry", "es_di_dword")[0] >> 16
    for row in (rows[0], rows[-1]):
        fields = [k for k in row if k not in ("event", "point", "image_cs_ip", "guest_cs_ip")]
        check(far(row["guest_cs_ip"])[0] == wrapper_cs and sample(row, *fields) == values(row["point"], *fields),
              f"DAC and main captures disagree at {row['point']}")
    for index in range(count):
        outputs = rows[1+4*index:5+4*index]
        data = (index, *rgb[3*index:3*index+3])
        for row, port, expected in zip(outputs, (0x3c8, 0x3c9, 0x3c9, 0x3c9), data):
            dx, ax = sample(row, "dx", "ax")
            check(dx == port and (ax & 0xff) == expected, f"Palette entry {index}, {row['point']}")


def verify_tail(values, instruction, registers):
    instruction("palette_lookup", "9A 22 1B BF 06")
    check(values("palette_lookup", "stack2", "stack3") == (26, 0), "Palette resource lookup argument")
    handle, = values("palette_resource", "ax")
    wrapper_cs = values("set_palette_entry", "es_di_dword")[0] >> 16
    for point in ("first_color", "last_color"):
        check(values(point, "stack0", "stack1") == (0x0638, wrapper_cs), f"Palette helper caller at {point}")
    instruction("first_color", "8B 46 06 BA C8 03 EE 42 8B 46 08 EE 8B 46 0A EE 8B 46 0C EE", 0x0d)
    instruction("final_rgb_distance", "8B D9 8A 87 E3 32 B4 00 50 8B 46 F4 5A 2B C2 99 33 C2 2B C2 8B D0",
                0x08ed-0x0914)

    instruction("release_call", "9A C5 19 BF 06")
    instruction("release_entry", "55 8B EC 83 EC 04 8B 46 06")
    instruction("release_decrement", "26 FF 4F 0A")
    instruction("release_return", "59 5F 5E 8B E5 5D CB")
    check(values("release_call", "dx", "stack0") == (0x009f, handle), "State before the final resource call")
    for point in ("release_entry", "release_retf"):
        check(values(point, "stack0", "stack1", "stack2") == (0x092b, wrapper_cs, handle), f"Resource frame at {point}")
    check(values("release_decrement", "es", "bx", "ax") == (handle, 0, handle), "Resource record counter decrement")
    check(registers == (0x009f, handle), "Raw palette return")
    for point in ("release_decrement", "release_retf", "release_return"):
        check(values(point, "dx", "ax") == registers, f"DX:AX at {point}")
    stack, sp = values("vm_resume", "ss", "sp")
    check(values("release_arguments", "ss", "sp", "dx") == (stack, (sp+2) & 0xffff, 8) and
          values("fetch_import", "ss", "sp") == (stack, (sp+10) & 0xffff), "Palette argument cleanup")

    instruction("negate_slot", "66 26 F7 1D")
    seg, di, value = values("negate_slot", "es", "di", "es_di_dword")
    check(value == 1 and values("fetch_after_negate", "es", "di", "es_di_dword") == (seg, di, 0xffffffff),
          "32-bit NEG of the slot argument")
    # At entry, the -1 path supplies the bounds [2000, 2048) to the free-slot search.
    instruction("create_program_entry", "55 8B EC 83 7E 0A FF 75 1B 83 7E 08 FF 75 15 "
                "B8 00 08 50 B8 D0 07 50 0E E8 57 FF")
    instruction("create_program_entry", "8B DA D1 E3 83 BF 62 20 FF 74 05 42 3B D1 7C F0", 0x27-0xa8)


def verify(game, trace, dac_trace=None):
    def verify_palette(resource, names, values):
        check(names["Main Base Palette"] == "26", "Palette resource name")
        palette = resource(26)
        count, offset = word(palette, 0), word(palette, 2)
        rgb = palette[offset:offset+3*count]
        check((count, offset, len(rgb)) == (256, 0x1a, 768), "Palette header and RGB data")
        for index, point in ((0, "first_color"), (count-1, "last_color")):
            check(values(point, "stack2", "stack3", "stack4", "stack5") == (index, *rgb[3*index:3*index+3]),
                  f"Resource RGB values at palette entry {index}")
        check(values("colors_done", "di") == (count,), "Palette loop exit")
        source, reference, limit = values("final_rgb_distance", "di", "bx", "cx")
        check((source, reference, limit) == (223, 15, 16), "Last RGB comparison indices")
        source_sum = sum(rgb[3*source:3*source+3])
        reference_sum = sum(rgb[3*reference:3*reference+3])
        distance = abs(source_sum-reference_sum)
        check((source_sum, reference_sum) == (30, 189) and values("final_rgb_distance", "ax", "dx") ==
              (distance, distance) and values("release_call", "dx") == (distance,), "RGB difference in return high word")
        if dac_trace is not None:
            check_dac(dac_trace, rgb, values)

    verify_transition(game, trace, HERE/"main-screen.profile", returned="set_palette", next_call="create_program",
                      resume_pc=0x0148, arguments=(0, 26), next_arguments=(-1, 1966), program_class="palette input screen",
                      check_archive=verify_palette, check_tail=verify_tail, expected_order=POINT_ORDER)
    if dac_trace is not None:
        print("Verified 256 VGA palette indices and all 768 RGB bytes against Main Base Palette.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dac-trace", type=Path, help="Optional full CSV recorded with palette-dac.profile")
    run_cli(verify, HERE, __doc__, parser=parser)
