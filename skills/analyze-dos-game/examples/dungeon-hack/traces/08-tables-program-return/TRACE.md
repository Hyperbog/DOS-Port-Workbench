# Dungeon Hack · Return from `create_program(2003, 2929)`

**`create_program` returned slot 2003. The next call was a zero-argument AESOP message from `phase-one` to itself, `main screen` (480), on slot 2000.** The [26-event capture](trace.csv) follows the original executable continuously from the `tables` request to the first opcode of the `main screen` handler.

## The return from creating `tables`

| Events | What the game did |
|---|---|
| 1–5 | `create_program` received slot 2003 and class resource 2929. The helper wrote instance segment `26A1h` to the object table at guest `1C62:3008`. The dispatcher read it back and looked up message 0 (`create`). |
| 6–8 | `tables.EXPT` (resource 2952) has no `M:0` entry. The dispatcher reached its lookup-miss path at Ghidra `20F5:097A` (EXE offset `0x12ECA`) and returned `FFFF:FFFF` (−1) to the helper. |
| 9–14 | The wrapper loaded its saved slot argument at `1B62:011D` (EXE offset `0xCD3D`). Its far return delivered `DX:AX = 0000:07D3` (2003) to the VM, which stored it at `9BAD:3FFE`. |

## How `phase-one` selected the receiver

| Script location | `HACK.RES` offset | Bytes | Observed behavior |
|---|---|---|---|
| `+03AC` | `0x687AC4` | `2D 02 00` | `LAW 2` loaded `THIS` from the current handler frame at `9BAD:4002`. It replaced 2003 with 2000 in the same VM slot. |
| `+03AF` | `0x687AC7` | `22 00 E0 01` | `SEND` specified zero script arguments and message `01E0h` (480). The dispatcher received `07D0 01E0 FFFF` for receiver, message and lookup selector. |
| `+0130` | `0x687848` | `07 00` | `phase-one.EXPT` maps `M:480` to this header. The live method table matched it and AESOP read the seven-byte frame size. |
| `+0132` | `0x68784A` | `1D 01` | The trace stops at the first opcode fetch in `main screen`, `SHTC 1`, at guest `38DE:0132`. |

Resource 4 names message 480 `main screen`. The first startup dispatch identifies slot 2000 as `phase-one`. The compiler also reserves auto offset 2 for `THIS`. [First dispatch](../02-first-message/TRACE.md) · [AESOP opcodes](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def) · [ARC message compiler](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/apps/arc/sopcomp.cpp)

## Verify and replay

From this directory, check the capture against the original game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For a fresh run, build the [DOSBox 0.74-3 recorder](../../../../../../tools/dosbox/) and use its `trace.conf`. Set `SDL_VIDEODRIVER=dummy` and `SDL_AUDIODRIVER=dummy`. Set `DPW_PROFILE` to the absolute path of [phase-one.profile](phase-one.profile) and `DPW_TRACE` to a fresh CSV path. Mount a copy of the game as `C:`, switch to it, run `set F=0`, then `aesop hack phase-one`. Verify the output with `py verify_return.py GAME_FOLDER --trace FRESH.csv`. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack)

Two fresh launches produced identical CSVs with SHA-256 `d8ba36f149f409b9739ad4a0f2313f4ae782cdbec9bac3c3a729a557e71158ef`. All registers, stack words and memory samples at the first event also matched the last event of [checkpoint 7](../07-magic-program-return/TRACE.md).
