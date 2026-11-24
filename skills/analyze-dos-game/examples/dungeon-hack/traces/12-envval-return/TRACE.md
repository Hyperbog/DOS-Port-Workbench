# Dungeon Hack · Return from `envval("F")`

**On the first launch, `envval("F")` returned 0. At `phase-one +0196`, the `main screen` handler called `draw_bitmap(1, 25, 0, 0, 0, 0, 0, 0, 0)`.** Resource 25 is named `Main Screen` in the archive. The [51-event trace](trace.csv) ends at the first native instruction of `draw_bitmap`.

## Return and branch

The original launcher sets `F=0` before its first `aesop hack phase-one` invocation and sets `F=1` after that process exits. A separate, fresh launch with the second setting tested the same branch. [Original HACK.BAT](https://github.com/Hyperbog/RLOFT/blob/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack/HACK.BAT)

| DOS setting | Bytes matched in memory | `DX:AX` at `envval` return | `BRF +01F8` at `+0175` |
|---|---|---|---|
| `F=0` | `46 3D 30 00` | `0000:0000` | The comparison with zero produced 1. Execution continued at `+0178` and reached the bitmap call. |
| `F=1` | `46 3D 31 00` | `0000:0001` | The comparison produced 0. Execution jumped to `+01F8`, skipping this bitmap call. [Nine-event comparison](f-one.csv) |

On the first run the lookup matched the key at `38DE:016C` against `F=0` at `0188:0039`. It returned a pointer to the ASCII digit at `0188:003B`. The decimal converter returned zero. The wrapper executed `RETF` at guest `0BF2:0E16` (`AESOP.EXE` offset `0xC906`), and the VM stored the result at `9BAD:3FF3`.

## First call after the return

| `phase-one` offset | `HACK.RES` offset | Observed behavior |
|---|---|---|
| `+0170`–`+0175` | `0x687888` | `PUSH`, `SHTC 0`, `EQ`, and `SETB` tested whether the returned value equaled zero. `BRF` used the resulting Boolean. |
| `+0178` | `0x687890` | `RCRS 28` resolved `C:draw_bitmap`. Its global vector at byte offset 320 points to image-relative `0C7E:0349`. |
| `+017B`–`+0195` | `0x687893` | Nine `PUSH`/`SHTC` pairs supplied 1, resource 25, and seven zeros in script order. |
| `+0196` | `0x6878AE` | `CALL 9` entered guest `0E21:0349` (Ghidra `1C7E:0349`, `AESOP.EXE` offset `0xE129`). The script cursor was `+0198`. |

The VM pushed the nine 32-bit arguments last to first. At native entry the 21 stack words at `2555:0D36` held the return address `1298:0E42`, the count 9 and all nine arguments in script order. [Native stack and bytecode samples](trace.csv) · [AESOP opcode definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)

## Verify and replay

From this directory, verify both checked-in captures against your original game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For each fresh capture, use the [DOSBox 0.74-3 recorder and configuration](../../../../../../tools/dosbox/) with `SDL_VIDEODRIVER=dummy` and `SDL_AUDIODRIVER=dummy`. Set `DPW_PROFILE` to the profile’s absolute path and `DPW_TRACE` to a fresh CSV path. Mount the game copy as `C:`, switch to that drive, apply the indicated `set` command, and run `aesop hack phase-one`. Verify the pair with `py verify_return.py GAME_FOLDER --trace MAIN.csv --control F_ONE.csv`. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack)

| Profile | DOS command | CSV SHA-256, identical in two launches per setting |
|---|---|---|
| [First launch](main-screen.profile) | `set F=0` | `634a65ebdf71d74fc5061006e6a16dfb17ca5648d5ca414358bafb59784ca105` |
| [Branch comparison](f-one.profile) | `set F=1` | `14f4b1cc682d2d0abb8f0f0c5b7ee3e16b415f43ad15e4f37b485e4336f55b40` |

The opening event matched all registers, seven shared stack words and both memory samples at the end of [checkpoint 11](../11-palette-input-program-return/TRACE.md). A separate `F=0` run stopped at the VM’s first indirect native call with the destination left open. Its function pointer and full argument frame matched event 50.
