# Dungeon Hack · Return from `create_program(2005, 2922)`

**`create_program` returned 2005 to `phase-one`. The next call was `create_program(2003, 2929)`, requesting the `tables` class in slot 2003.** The nested `magic.create` handler returned zero to the creation helper. The wrapper then explicitly loaded its own slot argument into `DX:AX`. [Magic dispatch](magic.csv) · [Return and next call](trace.csv)

## How the two returns differ

| Where | Evidence from the original executable and resources |
|---|---|
| Create the instance | The helper stored the instance segment `2699h` in slot 2005 at guest `1C62:300C`. The dispatcher read the same segment back. |
| Send `create` | The native arguments were `07D5 0000 FFFF` (receiver 2005, message 0, lookup selector). Resource 4 names message 0 `create`. |
| Enter `magic.create` | `magic.EXPT` (2948) maps `M:0` to `+033D`. The live handler table agreed. AESOP read a two-byte frame size of 2 at `3953:033D` and fetched the first opcode at `3953:033F`. The header is at `HACK.RES` offset `0x691C17`. |
| Return to the helper | `END` at `magic +03B4` left zero in the handler result slot. The interpreter loaded that doubleword and returned to guest `0D05:0076` with `DX:AX = 0000:0000`. |
| Return to `phase-one` | At Ghidra `1B62:011D` (EXE offset `0xCD3D`), the wrapper loaded `DX` from `[BP+0A]` and `AX` from `[BP+08]`. Its `RETF` at `1B62:0124` returned `0000:07D5` to guest `1298:0E42`. AESOP stored 2005 at `9BAD:3FFE`. |

## Next call in `phase-one`

| Script offset | `HACK.RES` offset | Bytes | Observed effect |
|---|---|---|---|
| `+039F` | `0x687AB7` | `20 00 00` | `RCRS 0` replaced the returned slot number with the `create_program` function pointer. |
| `+03A2` | `0x687ABA` | `04 1E D3 07` | `PUSH` and `INTC` supplied slot 2003. |
| `+03A6` | `0x687ABE` | `04 1E 71 0B` | `PUSH` and `INTC` supplied class resource 2929. |
| `+03AA` | `0x687AC2` | `21 02` | `CALL 2` entered guest `0D05:00A8` with the script cursor at `+03AC`. |

The native stack at entry held `0E42 1298 0002 07D3 0000 0B71 0000` (far return address, count and two 32-bit arguments). The resource-name dictionary maps `tables` to 2929, and `tables.EXPT` (2952) names the class `tables`. The capture ends on the first instruction of this second call.

## Verify and replay

From this directory, check both captures against the original game files.

```powershell
py verify_return.py "D:\Games\Dungeon Hack"
```

For fresh captures, use the [DOSBox recorder and configuration](../../../../../../tools/dosbox/). Set `SDL_VIDEODRIVER=dummy` and `SDL_AUDIODRIVER=dummy`. For each profile, launch a fresh copy of the same game installation, mount it as `C:`, run `set F=0` from that drive, then run `aesop hack phase-one`. Set `DPW_PROFILE` and `DPW_TRACE` to absolute paths and write both CSVs into the same output directory.

| Profile | Output | Events | SHA-256, identical across two launches per profile |
|---|---|---:|---|
| [Magic dispatch](magic.profile) | `magic.csv` | 17 | `921afa86fa2acd811f4493e9f9270b070efc914bdf70c8a9d11763cdca5a948f` |
| [Phase-one continuation](phase-one.profile) | `trace.csv` | 20 | `26475cf703d91b16b8a0ea66146d2967720c88e0f6776a640e55f18e7cab903d` |

Use `py verify_return.py GAME_FOLDER --trace PATH_TO_TRACE_CSV` to check that pair. The verifier compares every recorded field at the shared `RETF` except the per-file event counter. The wipe return and the first `create_program` entry also matched [checkpoint 6](../06-wipe-window-return/TRACE.md) across all captured registers, stack words and memory samples. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack) · [AESOP instruction definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)
