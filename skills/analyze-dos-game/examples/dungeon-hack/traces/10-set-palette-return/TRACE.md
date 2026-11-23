# Dungeon Hack · Return from `set_palette(0, 26)`

**`set_palette` returned the raw 32-bit value `0x009F26A2` to AESOP. The next `main screen` call was `create_program(-1, 1966)`, requesting the `palette input screen` class in an automatically selected slot.** The [34-event trace](trace.csv) starts at palette entry and ends on the first instruction of `create_program`.

## What produced the return value

| Word | Observed origin |
|---|---|
| `DX = 009Fh` | The final comparison in the palette loop used RGB sums from entries 223 and 15. Their sums were 30 and 189. The absolute difference, 159, remained in DX through the final resource call. |
| `AX = 26A2h` | The lookup for resource 26 supplied record segment `26A2h`. The final helper at guest `0862:19C5` loaded that segment into AX and decremented the record’s counter at offset `+0Ah`. |

The wrapper restored its saved registers and executed `RETF` at Ghidra `1C7E:0931` (`AESOP.EXE` file offset `0xE711`). AESOP resumed at guest `1298:0E42`, stored the two words at `9BAD:3FF3`, and removed the count and both four-byte arguments.

The VGA capture recorded 256 palette-index writes to port `03C8h` and 768 component writes to `03C9h`. Every index and every red, green and blue byte matched `Main Base Palette` in order. Its RGB data begins at `HACK.RES` offset `0x67460`, 26 bytes into resource 26. [DAC capture profile](palette-dac.profile) · [IBM VGA Technical Reference, pp. 2-104–2-105](https://bitsavers.trailing-edge.com/pdf/ibm/pc/cards/IBM_VGA_XGA_Technical_Reference_Manual_May92.pdf)

## Next call in `main screen`

| `phase-one` offset | `HACK.RES` offset | Bytes | Observed effect |
|---|---|---|---|
| `+0148` | `0x687860` | `20 00 00` | `RCRS 0` replaced the palette result with the `create_program` pointer. |
| `+014B`–`+014E` | `0x687863` | `04 1D 01 08` | `PUSH`, `SHTC 1`, then `NEG` produced `FFFFFFFFh` (−1) in the first argument slot. |
| `+014F`–`+0152` | `0x687867` | `04 1E AE 07` | `PUSH` and `INTC` supplied class resource 1966 (`07AEh`). |
| `+0153` | `0x68786B` | `21 02` | `CALL 2` entered guest `0D05:00A8` with the script cursor at `+0155`. |

At native entry the seven stack words were `0E42 1298 0002 FFFF FFFF 07AE 0000`. They give the far return address, the count, then both 32-bit arguments. Resource 0 maps `palette input screen` to 1966. Its export dictionary (2958) confirms the class name. The executable’s −1 path calls the free-slot search at image-relative `0B62:001A`, which checks slots 2000 through 2047 in ascending order. [AESOP opcode definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)

## Verify and replay

From this directory, verify the checked-in return trace against your game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For each fresh capture, use the [DOSBox 0.74-3 recorder and configuration](../../../../../../tools/dosbox/) with `SDL_VIDEODRIVER=dummy` and `SDL_AUDIODRIVER=dummy`. Set `DPW_PROFILE` to the profile’s absolute path and `DPW_TRACE` to a fresh output path. Mount a copy of the game as `C:`, switch to it, run `set F=0`, then `aesop hack phase-one`. Use the two outputs together with `py verify_return.py GAME_FOLDER --trace MAIN.csv --dac-trace DAC.csv`. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack)

| Profile | Events | CSV SHA-256, identical across two launches per profile |
|---|---:|---|
| [Main screen return](main-screen.profile) | 34 | `fd52bab1c8bec5950f0a091318b8e56b9ba8bfef6eb8199bc2574bdec7ce8f4b` |
| [Full DAC writes](palette-dac.profile) | 1,026 | `127ae9dc24908db35981bcfb1263eb659ee600a72ae6359da56c852606b37b2b` |

The first record matched the end of [checkpoint 9](../09-main-screen-first-call/TRACE.md) in every field except the event number. An independent run stopped at the VM’s first indirect native call after palette entry, before inspecting its destination. It reproduced the same function pointer and argument frame.
