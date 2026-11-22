# Dungeon Hack · Return from `init_graphics()`

**`init_graphics()` returned 2. The next `phase-one` call was `init_interface()`, with zero arguments.** The graphics routine wrote the low word to its own data segment before returning. The script then reused the interpreter’s result slot for the interface function pointer.

| Trace events | Location | Observation |
|---|---|---|
| 1–4 | Ghidra `1C7E:0132` and `1C7E:0135` | The last internal call returned with `DX=0000`, `AX=0002`. The routine removed five words from the native stack and executed `MOV [32CCh],AX` with `DS=1C62`. |
| 5–9 | Graphics `RETF` at `1C7E:013A`, VM resume at `20F5:0E42` | The far return advanced guest SP from `0D7C` to `0D80`. The VM wrote the full value `00000002` to guest `9BAD:3FFE`. |
| 10–13 | `phase-one +0382`, `HACK.RES 0x687A9A` | Bytes `20 40 00` executed `RCRS 0x0040`. The VM replaced the value in that same slot with guest pointer `0F80:0642`. |
| 14–17 | `phase-one +0385`, `HACK.RES 0x687A9D` | Bytes `21 00` executed `CALL 0`. At the native entry the stack held return address `1298:0E42` followed by argument count zero. |

The native data word and the VM result slot are different addresses. `phase-one` made no decision based on the returned 2 before the interface call. The trace establishes the value and its destination. Its meaning inside the graphics subsystem remains open.

## Identifying the native call

The class import dictionary (resource 2930) maps `C:init_interface` to local offset 64 (`0x40`). The global function dictionary (resource 3) maps `init_interface` to vector offset 228 (`0xE4`). In `AESOP.EXE`, the pointer at file offset `0x1C9DC` contains `42 06 DD 0D`. Relocating its segment by the observed image base `01A3h` gives the exact guest address reached at event 17.

| Address convention | `init_interface` entry |
|---|---|
| MZ image-relative CS:IP | `0DDD:0642` |
| Ghidra CS:IP (image base `1000h`) | `1DDD:0642` |
| Guest CS:IP in these runs | `0F80:0642` |
| `AESOP.EXE` file offset | `0xFA12` |

## Verify and replay

Two fresh headless DOSBox 0.74-3 runs produced identical 17-event captures. The CPU, stack and memory fields at graphics entry match the end of [checkpoint 3](../03-sound-return/TRACE.md). The running 1,121-byte `phase-one` code image matched its archive payload. The SHA-256 of the [recorded CSV](trace.csv) is `7c661b4be77f9b55457bccdf207ab8a1b97e93b0648596a9f958d6ae20b17142`.

From this checkpoint directory in a repository checkout, run the verifier against your original game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For a fresh capture, use the [shared DOSBox recorder and configuration](../../../../../../tools/dosbox/) with the [checkpoint profile](phase-one.profile). Set `DPW_PROFILE` to the profile’s absolute path and `DPW_TRACE` to a fresh CSV path. For the headless setup, set both `SDL_VIDEODRIVER` and `SDL_AUDIODRIVER` to `dummy`. Mount the game copy as `C:`, switch to it, run `set F=0`, then run `aesop hack phase-one`. The recorder closes the CSV at `interface_entry`. Verify it with `py verify_return.py GAME_FOLDER --trace FRESH.csv`.

The executable, resource archive, index, and sound configuration matched the pinned game files. The AESOP instruction definitions supply the opcode names. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack) · [AESOP bytecodes](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)
