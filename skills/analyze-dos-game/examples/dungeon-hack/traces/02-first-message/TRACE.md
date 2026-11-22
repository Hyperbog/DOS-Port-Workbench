# Dungeon Hack · First message to phase-one

**The first AESOP message was `create` (ID 0).** Startup resolved `phase-one` to code resource **2932**, created its instance in **slot 2000**, and dispatched message 0 to that receiver. The handler zeroed two instance bytes and called `init_sound(0)`. The trace ends as the original DOS executable enters that sound routine.

## Locating the handler

| Original game record | Observed value |
|---|---|
| Resource 4, the message-name dictionary | `create` → `0` |
| Resource 2931, `phase-one.EXPT` | `N:OBJECT` → `phase-one`, `M:0` → `873` |
| Resource 2932, the `phase-one` code payload | Begins at `HACK.RES` offset `0x687718` |
| Handler header at payload `+0x0369` (873) | Archive `0x687A81`, bytes `02 00`, frame size 2 |
| First executable bytecode at payload `+0x036B` | Archive `0x687A83`, bytes `1D 00`, `SHTC 0` |
| First resolved runtime import | `phase-one.IMPT` maps `C:init_sound` to byte offset `56` (`0x38`) |

The interpreter matched message 0 to `0x0369` in its in-memory handler table. It read the frame-size word, advanced the bytecode pointer by two, and fetched opcode `1D`. A frame size of two reserves space for the receiver, `THIS`, on the VM stack. In these runs the handler header was at guest `38DE:0369` and the first fetch used `38DE:036B`.

## First eight executed instructions

| Payload offset | Bytes | AESOP instruction | Observed effect |
|---|---|---|---|
| `036B` | `1D 00` | `SHTC 0` | Loads zero |
| `036D` | `3C 00 00` | `SSB 0` | Writes zero to instance static byte 0, guest `3952:0002` |
| `0370` | `1D 00` | `SHTC 0` | Loads zero |
| `0372` | `3C 01 00` | `SSB 1` | Writes zero to instance static byte 1, guest `3952:0003` |
| `0375` | `20 38 00` | `RCRS 0x38` | Resolves the `init_sound` import |
| `0378` | `04` | `PUSH` | Reserves the next VM stack slot |
| `0379` | `1D 00` | `SHTC 0` | Loads the argument value zero |
| `037B` | `21 01` | `CALL 1` | Calls the native function with one argument |

At the native entry, the stack held an argument count of 1 and a 32-bit value of zero. The global runtime-function dictionary separately maps `init_sound` to offset 484. The original executable contains its relocatable far pointer at file offset `0x1CADC`, matching the destination reached in the trace.

## Debugger checkpoints

| Role | Ghidra CS:IP | AESOP.EXE file offset | Original bytes |
|---|---|---:|---|
| Startup calls the program-creation routine | `1668:041D` | `0x00809D` | `9A A8 00 62 0B` |
| Instance creation sends message 0 | `1B62:0071` | `0x00CC91` | `9A F2 08 F5 10` |
| Native message dispatcher entry | `20F5:08F2` | `0x012E42` | `C8 10 00 00` |
| Interpreter fetches the first opcode | `20F5:09DF` | `0x012F2F` | `8A 1C` |
| VM issues the indirect far call | `20F5:0E3F` | `0x01338F` | `26 FF 1D` |
| Native `init_sound` entry | `1BB9:07F3` | `0x00D983` | `55 8B EC` |

Ghidra 11.4.2 uses image segment `1000h`. Subtract `1000h` from a listed segment for load-relative CS:IP. The real-mode MZ header occupies `0x1600` bytes. Both runs loaded the image at guest segment `01A3h`. Register addresses in `dispatch.csv` refer to that layout.

## Verification and replay

Two independent DOSBox 0.74-3 launches of `aesop hack phase-one`, with `F=0`, produced identical 22-record dispatch logs. The observer recorded dispatcher entries from process entry onward. The send to slot 2000 was entry number one. Each run reproduced the previous checkpoint’s 34 archive operations. In both runs, all 1,121 bytes of the live code image matched resource 2932.

| Evidence | SHA-256 |
|---|---|
| Original `AESOP.EXE` | `d3676cb71fd9a869004ee08d3f75e96861e19aeb003d89d3c4ef93436796d450` |
| Live `phase-one` code and on-disk payload | `c2cbeca1f8108abb43b68c5d400c74238303868f4a1aa4a8a8ab2d9116c30b74` |
| Captured `dispatch.csv` | `bb6fcd959c26db0984e0726aee4ce357acc29bd505156c9f3a72f886ff66c4e9` |

From the extracted folder, run `py verify_dispatch.py "D:\Games\Dungeon Hack"` on Windows, using your game path. The verifier checks the executable and archives, the export, the opcode sequence, the two stores, and the native call. `bytecode.csv` includes archive offsets and the native opcode handlers.

For a fresh Linux capture, copy `dosbox_vm_observer.inc` into DOSBox 0.74-3’s `src/cpu/`. Include it immediately before the definition of `CPU_Core_Normal_Run` in `core_normal.cpp` and call `dh_trace_instruction();` after the main loop’s `LOADIP;`. Rebuild DOSBox. Set `DH_VM_TRACE` and `DH_VM_IMAGE` to two output paths. Launch with `trace.conf`, mount a game copy as `C:`, switch to it, run `set F=0`, then `aesop hack phase-one`. The observer closes the CSV at the first native call target. To check the fresh capture, run `python3 verify_dispatch.py GAME_FOLDER --trace CSV_FILE --image IMAGE_FILE`.

The original game files supply the message, object, offsets, and runtime evidence. The preserved Miles ARC compiler and the AESOP bytecode definitions supply the frame and opcode terminology. [Tested game revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack) · [ARC message compiler](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/apps/arc/sopcomp.cpp#L2864-L2906) · [AESOP bytecodes](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/files/bytecode.def)

