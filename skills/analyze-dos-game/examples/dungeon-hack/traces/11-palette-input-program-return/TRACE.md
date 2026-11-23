# Dungeon Hack · Return from `create_program(-1, 1966)`

**`create_program` returned slot 2001 for `palette input screen`. The next `main screen` call was `envval("F")` at `phase-one +016E`.** The [43-event capture](trace.csv) begins at the program creation request and ends on the first instruction of `envval`.

## How the game assigned slot 2001

| Events | Observed behavior |
|---|---|
| 1–8 | The allocator searched slots 2000 through 2047. Its first comparison found slot 2000 occupied. The second found the free marker `FFFFh` at slot 2001. The wrapper replaced its incoming 32-bit argument `FFFFFFFFh` with `000007D1h` (2001). |
| 9–13 | The helper created the instance for class resource 1966 and stored its record segment `26A7h` in the object table at guest `1C62:3004`. The dispatcher read the same segment when it looked up message 0 (`create`) on slot 2001. |
| 14–18 | The class export dictionary, resource 2958, has no `M:0` entry. The lookup returned −1 to the helper. At guest `0D05:011D` the wrapper loaded its saved slot. Its `RETF` at `0D05:0124` returned `DX:AX = 0000:07D1` to AESOP. |
| 19–25 | AESOP wrote 2001 to the result slot at `9BAD:3FF3`. The handler’s first instruction after the call, `SAD 6`, copied that doubleword to its local variable at `9BAD:3FF8`. |

## Next call in `main screen`

| `phase-one` offset | `HACK.RES` offset | Observed behavior |
|---|---|---|
| `+0158`–`+015F` | `0x687870` | `LSB 1` read zero. Comparing it with zero produced 1, so `BRF +0174` fell through to `+0162`. |
| `+0162` | `0x68787A` | `RCRS 24` resolved `C:envval`. The global vector at byte offset 136 points to image-relative `0A4F:0DE1`. |
| `+0165`–`+016D` | `0x68787D` | `PUSH` and `LECA +016C` supplied the far pointer `38DE:016C`. The pointed-to bytes were `46 00` (“F” followed by a zero byte). `BRA +016E` skipped those two data bytes. |
| `+016E` | `0x687886` | `CALL 1` entered guest `0BF2:0DE1` (Ghidra `1A4F:0DE1`, `AESOP.EXE` file offset `0xC8D1`). The script cursor advanced to `+0170`. |

The first five words at native entry were `0E42 1298 0001 016C 38DE`. These give the return address `1298:0E42`, one argument, and the pointer to “F”. The original launcher sets `F=0` before its first `aesop hack phase-one` invocation and sets `F=1` after that process returns. [Original HACK.BAT](https://github.com/Hyperbog/RLOFT/blob/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack/HACK.BAT) · [AESOP opcode definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)

## Verify and replay

From this directory, verify the capture against the original game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For a fresh capture, use the [DOSBox 0.74-3 recorder and configuration](../../../../../../tools/dosbox/). Set `SDL_VIDEODRIVER=dummy` and `SDL_AUDIODRIVER=dummy`. Point `DPW_PROFILE` at the absolute path of [main-screen.profile](main-screen.profile) and `DPW_TRACE` at a fresh CSV path. Mount the game copy as `C:`, switch to it, run `set F=0`, then run `aesop hack phase-one`. Check the new capture with `py verify_return.py GAME_FOLDER --trace FRESH.csv`. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack)

Two fresh launches produced identical CSVs with SHA-256 `15b473865b700613e1817892329df2665fed9e2bd753f513df986d3e0360f4a3`. The first event matched the end of [checkpoint 10](../10-set-palette-return/TRACE.md) in every field except the event number. A separate run stopped at the VM’s first indirect native call after the creation request, with the destination left open. Its pointer and stack matched event 42.
