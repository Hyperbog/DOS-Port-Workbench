# Dungeon Hack · Return from `init_interface()`

**AESOP received `0x1B1C0001` from `init_interface()`. The next `phase-one` call was `wipe_window(1, 0)`.** Two independent headless runs reached the same native entry with the same seven stack words.

## Native return

The last helper in `init_interface()` returned with `DX=1B1C` and `AX=0001`. At Ghidra `1DDD:07BB`, the routine executed `MOV word ptr [0FAEh],1` with `DS=1C62`. This writes the immediate value 1 to a native state word. The far return at `1DDD:07C4` preserved both registers. AESOP resumed at guest `1298:0E42` and wrote the complete 32-bit value to `9BAD:3FFE`. The first resumed bytecode reused that slot for the next function pointer.

## Executed bytecode

| Offset in `phase-one` | `HACK.RES` offset | Bytes | Observed effect |
|---|---|---|---|
| `+0387` | `0x687A9F` | `20 30 00` | `RCRS 0x30` resolved `wipe_window` and replaced the interface result. |
| `+038A`, `+038B` | `0x687AA2`, `0x687AA3` | `04 1D 01` | `PUSH`, then `SHTC 1`, placed the first argument at `9BAD:3FFA`. |
| `+038D`, `+038E` | `0x687AA5`, `0x687AA6` | `04 1D 00` | `PUSH`, then `SHTC 0`, placed the second argument at `9BAD:3FF6`. |
| `+0390` | `0x687AA8` | `21 02` | `CALL 2` entered native `wipe_window`. At entry, the bytecode cursor (SI) was `+0392`. |

The class import dictionary (resource 2930) maps `C:wipe_window` to byte offset 48. The global function dictionary (resource 3) maps `wipe_window` to vector offset 336 (`0x150`). In `AESOP.EXE`, the far pointer at file offset `0x1CA48` is `17 0B 7E 0C`. Its MZ relocation yields guest `0E21:0B17`, exactly where the new call landed. The entry is at Ghidra `1C7E:0B17`, executable file offset `0xE8F7`.

The VM pushed the second argument first. At native entry, `SS:SP` was `2555:0D74` and the recorder read these consecutive words directly.

| Offset from SP | Words | Meaning |
|---|---|---|
| `+00h` | `0E42 1298` | Return IP and CS, forming `1298:0E42` |
| `+04h` | `0002` | Two script arguments |
| `+06h` | `0001 0000` | First 32-bit argument, 1 |
| `+0Ah` | `0000 0000` | Second 32-bit argument, 0 |

## Verify and replay

From this directory in a repository checkout, run the verifier against your original game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For a fresh capture, build the [DOSBox 0.74-3 recorder](../../../../../../tools/dosbox/) with support for `stack_words`. Set `DPW_PROFILE` to the absolute path of [phase-one.profile](phase-one.profile) and `DPW_TRACE` to a fresh CSV path. Use the recorder’s `trace.conf`, set both SDL driver variables (`SDL_VIDEODRIVER` and `SDL_AUDIODRIVER`) to `dummy`, mount a copy of the game as `C:`, and switch to that drive. Run `set F=0` followed by `aesop hack phase-one`. The recorder closes the CSV at `wipe_window_entry`. Run `py verify_return.py GAME_FOLDER --trace FRESH.csv` to compare the new evidence with the reference behavior.

Both captures produced the same [23-event CSV](trace.csv), SHA-256 `ac6932833739619b5469120cc0f0c7b6aacda9cb8ad3d1081c8dd711b38dc7b8`. Its first snapshot matches every register, address and memory field previously captured at the end of [checkpoint 4](../04-graphics-return/TRACE.md). The earlier sound and graphics captures also replayed byte-for-byte with their five-word profiles.

The executable, resource files and sound configuration matched the pinned game revision. The preserved AESOP definitions supply the bytecode names. [Game files](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack) · [AESOP instruction definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)
