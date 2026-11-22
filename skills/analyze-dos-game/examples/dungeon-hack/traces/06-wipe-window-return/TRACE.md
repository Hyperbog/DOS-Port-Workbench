# Dungeon Hack · Return from `wipe_window(1, 0)`

**AESOP received the raw value `0x03C50000`. The next `phase-one` call was `create_program(2005, 2922)`, a request to create the `magic` program in object slot 2005.** The [26-event trace](trace.csv) starts at the wipe entry and ends on the first native instruction of `create_program`.

## Where the return value came from

The wipe wrapper forwarded the low 16 bits of each argument to its graphics helper at guest `149F:3F5F`. The helper saw the words `0001 0000` after its far return address. At the end of its drawing loop, `DX=03C5` and `AX=0000`. These values survived the helper’s far return and the wrapper’s two `POP CX` instructions, `POP BP`, and `RETF` at Ghidra `1C7E:0B28` (`AESOP.EXE` file offset `0xE908`).

A separate [four-event capture](vga-ports.csv) observed `OUT DX,AL` first with port `03C4h` and value `02h`, then with port `03C5h` and value `01h`. The first write selects the VGA Map Mask register. The second writes its data. This identifies the port number left in the high word of the script result. [IBM VGA/XGA Technical Reference, Figure 2-28](https://bitsavers.trailing-edge.com/pdf/ibm/pc/cards/IBM_VGA_XGA_Technical_Reference_Manual_May92.pdf)

AESOP resumed at guest `1298:0E42` and stored the complete doubleword at `9BAD:3FFE`. After removing the two-byte argument count and both four-byte arguments, SP advanced from `0D78` to `0D82`. The first resumed bytecode replaced the result in that same slot.

## Next call in the script

| `phase-one` offset | `HACK.RES` offset | Bytes | Observed effect |
|---|---|---|---|
| `+0392` | `0x687AAA` | `20 00 00` | `RCRS 0` loaded the `create_program` pointer. |
| `+0395`, `+0396` | `0x687AAD`, `0x687AAE` | `04 1E D5 07` | `PUSH` and `INTC` placed `0x000007D5` (2005) in the first argument slot. |
| `+0399`, `+039A` | `0x687AB1`, `0x687AB2` | `04 1E 6A 0B` | `PUSH` and `INTC` placed `0x00000B6A` (2922) in the second. |
| `+039D` | `0x687AB5` | `21 02` | `CALL 2` entered guest `0D05:00A8` with the bytecode cursor at `+039F`. |

The class import dictionary maps `C:create_program` to local byte offset 0. The global function dictionary maps `create_program` to vector offset 520 (`0x208`). The relocatable pointer at executable file offset `0x1CB00` contains `A8 00 62 0B`. It resolves to the observed entry, Ghidra `1B62:00A8`, file offset `0xCCC8`.

At native entry, the stack held return address `1298:0E42`, count 2, then the 32-bit arguments 2005 and 2922. This is the same routine that took slot 2000 and class 2932 when starting `phase-one` in [checkpoint 2](../02-first-message/TRACE.md). Resource 0 maps `magic` to 2922. Its export dictionary, `magic.EXPT` (resource 2948), independently names `N:OBJECT` as `magic`.

## Verify and replay

From this directory in a repository checkout, verify the main capture against your original game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For a fresh capture, use the [DOSBox 0.74-3 recorder and configuration](../../../../../../tools/dosbox/). Set `DPW_PROFILE` to the absolute path of [phase-one.profile](phase-one.profile) and `DPW_TRACE` to a fresh CSV path. Set both `SDL_VIDEODRIVER` and `SDL_AUDIODRIVER` to `dummy`. Mount a game copy as `C:`, switch to it, run `set F=0`, then `aesop hack phase-one`. The recorder closes the CSV at `create_program_entry`. Check it with `py verify_return.py GAME_FOLDER --trace FRESH.csv`. To replay the port capture, start a fresh run with [vga-ports.profile](vga-ports.profile) and a separate output path.

| Capture | SHA-256 from two independent runs |
|---|---|
| Main trace · 26 events | `321050118ecd82b627629d1740ee98fad3f36e6eb01c20d0940753ca9aa7db1b` |
| Port capture · 4 events | `94f339ef3502d9e282d1b63bd35c4ed8afd7ae7a1296175c7cdae9a861af4fb9` |

The main trace begins with the same CPU, stack and memory state as the end of [checkpoint 5](../05-interface-return/TRACE.md). The two main runs also matched all 1,121 bytes of the live `phase-one` code to the resource archive. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack) · [AESOP instruction definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)
