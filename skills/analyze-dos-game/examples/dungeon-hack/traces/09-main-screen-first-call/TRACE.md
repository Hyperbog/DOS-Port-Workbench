# Dungeon Hack · First native call in `main screen`

**`phase-one` called `set_palette(0, 26)` at script offset `+0146`.** Resource 0, the name dictionary in `HACK.RES`, identifies 26 as `Main Base Palette`. The [17-event trace](trace.csv) starts at the first opcode of message 480 on receiver 2000 and ends on the first instruction of the native palette routine.

## Executed bytecode

| `phase-one` offset | `HACK.RES` offset | Bytes | Observed effect |
|---|---|---|---|
| `+0132` | `0x68784A` | `1D 01` | `SHTC 1` wrote 1 to the current VM slot at `9BAD:3FF3`. |
| `+0134` | `0x68784C` | `00 3D 01` | `BRT` tested the nonzero value and jumped directly to `+013D`. |
| `+013D` | `0x687855` | `20 0C 00` | `RCRS 12` replaced 1 with the native `set_palette` pointer. |
| `+0140` | `0x687858` | `04` | `PUSH` allocated the first argument slot at `9BAD:3FEF`. |
| `+0141` | `0x687859` | `1D 00` | `SHTC 0` supplied the first argument. |
| `+0143` | `0x68785B` | `04` | `PUSH` allocated the second argument slot at `9BAD:3FEB`. |
| `+0144` | `0x68785C` | `1D 1A` | `SHTC 26` supplied the palette resource ID. |
| `+0146` | `0x68785E` | `21 02` | `CALL 2` transferred both 32-bit arguments and entered `set_palette` with the script cursor at `+0148`. |

All eight fetches matched the bytes of code resource 2932. The two `BRA` instructions at `+0137` and `+013A` lie between the conditional branch and its observed target. [AESOP opcode definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)

## Native entry

`phase-one.IMPT` maps `C:set_palette` to local byte offset 12. The global function dictionary maps `set_palette` to vector offset 328 (`0x148`). At `AESOP.EXE` file offset `0x1CA40`, the pointer bytes `F9 04 7E 0C` designate image-relative `0C7E:04F9`. The MZ relocation on its segment word yielded guest `0E21:04F9` in both runs. The native entry is Ghidra `1C7E:04F9`, EXE file offset `0xE2D9`.

At entry, the seven words at `2555:0D52` were `0E42 1298 0002 0000 0000 001A 0000`. They give the far return address `1298:0E42`, argument count 2, and 32-bit arguments 0 and 26 in script order. [Native stack and call site](trace.csv)

## Verify and replay

From this directory, run the verifier against the original game files.

```powershell
py verify_call.py "D:\Games\Dungeon Hack"
```

For a fresh capture, use the [DOSBox 0.74-3 recorder and configuration](../../../../../../tools/dosbox/). Set `SDL_VIDEODRIVER=dummy` and `SDL_AUDIODRIVER=dummy`. Set `DPW_PROFILE` to the absolute path of [main-screen.profile](main-screen.profile) and `DPW_TRACE` to a fresh CSV path. Mount the game copy as `C:`, switch to it, run `set F=0`, then `aesop hack phase-one`. Check the output with `py verify_call.py GAME_FOLDER --trace FRESH.csv`. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack)

Two fresh launches produced byte-identical traces with SHA-256 `8d9712240324c290813cb44a53021f92956b864a4134fcff6bc908ab3ed92d32`. The first record matched the last record of [checkpoint 8](../08-tables-program-return/TRACE.md) in every field except the per-file event number.

A third launch kept the same start and replaced all later probes with `stop 10F5:0E3F first_native_call`. This stopped at the VM’s first indirect native call regardless of destination. It reproduced the function pointer and stack in event 16.
