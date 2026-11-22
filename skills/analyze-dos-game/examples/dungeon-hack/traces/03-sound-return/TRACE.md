# Dungeon Hack · Sound return and graphics startup

`init_sound(0)` returned to AESOP with `DX=277A` and `AX=0000`. The interpreter wrote `0x277A0000` into its value slot at guest `9BAD:3FFE`. The very next bytecode replaced that value with the address of `init_graphics`. The handler called it with zero arguments. It made no decision based on the sound return along this path.

## From the sound return to the graphics entry

| CSV events | Location | Observed behavior |
|---|---|---|
| 1–3 | Sound entry and `RETF`, Ghidra `1BB9:07F3` and `1BB9:0C5D` | The stack held return address `1298:0E42`, argument count 1, and a 32-bit argument of zero. At `RETF`, the same return address was on top of the stack. |
| 4–7 | Interpreter, Ghidra `20F5:0E42` | The far return advanced the guest stack pointer from `0D78` to `0D7C`. The interpreter stored AX at `ES:[DI]` and DX at `ES:[DI+2]`. The complete value was `277A0000`. |
| 8–11 | `phase-one` payload `+037D`, archive `0x687A95` | Bytes `20 3C 00` executed `RCRS 0x003C`. The same slot now contained the graphics far pointer `0E21:000E`. |
| 12–15 | `phase-one` payload `+0380`, archive `0x687A98` | Bytes `21 00` executed `CALL 0`. The VM issued the far call at Ghidra `20F5:0E3F`. At guest `0E21:000E`, the native stack held return address `1298:0E42` followed by argument count zero. |

**How the target gets its name.** Resource 2930, `phase-one.IMPT`, maps `C:init_graphics` to local byte offset 60 (`0x003C`). The global function dictionary, resource 3, maps `init_graphics` to vector byte offset 280 (`0x0118`). At `AESOP.EXE` file offset `0x1CA10`, the bytes `0E 00 7E 0C` encode image-relative `0C7E:000E`. The MZ relocation adds the actual load segment, `01A3`, giving exactly the address reached in both captures.

The sound `RETF` at executable file offset `0xDDED` sits one byte before the graphics entry at `0xDDEE` (Ghidra `1C7E:000E`). The intervening trace records the return to the interpreter, both bytecodes, and the new far call.

## Verification

Two clean DOSBox 0.74-3 runs produced byte-identical 15-event captures. Each also reproduced the previous 22-event first-message trace. All 1,121 bytes of the live `phase-one` resource matched the archive. Both launches used `F=0`, an emulated SB16, host audio output disabled, and MIDI device `none`. The raw register value records what AESOP received in these runs. Audio playback was outside the capture.

| Evidence | SHA-256 |
|---|---|
| Included `trace.csv` | `7b4194ed4e80e88139bf45338ad35f485b8402a41960490197b429a13c9779be` |
| Launch directory’s `SOUND.CFG` | `a9bbba6f71d8a251e734bd06d859db1540e50ae95d6acc565fbea5dd89bb7040` |

From this checkpoint directory in a repository checkout, verify the supplied trace against your game files on Windows with this command.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

The CSV records state immediately before each watched native instruction. `image_cs_ip` is load-relative. Add `1000h` to its segment for this Ghidra project. `guest_cs_ip` is the actual running address. `stack0` through `stack4` are consecutive 16-bit words starting at SS:SP. Register and memory columns are hexadecimal.

## Replaying the recorder

The [shared recorder and smoke test](../../../../../../tools/dosbox/) live in the repository’s tools directory. The recorder reads its checkpoints from a text profile. This package supplies the Dungeon Hack profile and a small second test that generates a 60-byte DOS MZ executable with an entry in another segment. The same recorder correctly observed `AX=1234` and `DX=5678` using that second profile.

1. For DOSBox 0.74-3, copy `realmode_observer.inc` into `src/cpu/`. In `core_normal.cpp`, add `#include "realmode_observer.inc"` before `CPU_Core_Normal_Run` and call `dpw_observe_instruction();` immediately after the main loop’s `LOADIP;`. Rebuild.
2. To run the independent test on Linux, execute `python3 smoke_test.py /path/to/instrumented/dosbox` from the shared recorder directory.
3. For Dungeon Hack, set `DPW_PROFILE` to the absolute path to `phase-one.profile` and `DPW_TRACE` to a fresh CSV path. Use the included `trace.conf`. For a headless run, set both `SDL_VIDEODRIVER` and `SDL_AUDIODRIVER` to `dummy`. Mount a copy of the game as `C:`, switch to `C:`, enter `set F=0`, and run `aesop hack phase-one`.
4. The recorder closes the CSV on entry to `init_graphics()`. You can then stop DOSBox and run `python3 verify_return.py GAME_FOLDER --trace FRESH.csv`.

The original executable and resource dictionaries establish the call target. The preserved AESOP instruction definitions supply the bytecode names. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack) · [AESOP instruction definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)

