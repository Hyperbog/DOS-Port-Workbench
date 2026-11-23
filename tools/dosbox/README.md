# DOSBox real-mode recorder

`realmode_observer.inc` records CPU registers, stack words starting at SS:SP, and memory at ES:DI and DS:SI immediately before selected instructions in a DOS MZ program.

## Build and test

1. Copy `realmode_observer.inc` into the DOSBox 0.74-3 source directory `src/cpu/`.
2. In `core_normal.cpp`, include the file above `CPU_Core_Normal_Run`. Call `dpw_observe_instruction();` immediately after the main loop’s `LOADIP;`. Build DOSBox with the normal CPU core enabled.
3. From this directory, run `python3 smoke_test.py /absolute/path/to/dosbox` on Linux. The generated MZ fixture checks registers, the five-word default, seven known stack words, and selection of individual visits to a repeated address.

## Capture another program

Set `DPW_PROFILE` to an absolute profile path and `DPW_TRACE` to a fresh CSV path. Launch the program in the instrumented DOSBox with `core=normal`.

The first profile line specifies `image CS:IP offset signature`. CS is relative to the loaded MZ image. The signature is a four-byte little-endian integer read at the given offset in the entry segment. Choose bytes unaffected by relocation.

Profiles capture five 16-bit stack words by default. Add `stack_words N` after the image line to select a depth from 1 through 32768. Columns `stack0` through `stackN-1` follow ascending word offsets from SS:SP. In the [two-argument Dungeon Hack capture](../../skills/analyze-dos-game/examples/dungeon-hack/traces/05-interface-return/TRACE.md), seven words cover the far return address, the count, and both 32-bit arguments.

Each probe line specifies `start`, `watch`, or `stop`, followed by image-relative CS:IP and a checkpoint label. Use one start and one stop. A watch point records each visit to its address. The recorder closes the CSV at the stop point and lets the program continue. [Example profile](../../skills/analyze-dos-game/examples/dungeon-hack/traces/05-interface-return/phase-one.profile)

To select a particular invocation, append `stackN=hhhh` to a probe. The decimal index N (0–32767) selects the 16-bit word at SS:SP + 2×N. The value is one to four hexadecimal digits. For example, `start 0B62:00A8 tables_entry stack3=07D3` waits for slot 2003 at that routine. The check works at any capture depth. At a shared address, the first eligible matching line records the instruction. [Conditional profile](../../skills/analyze-dos-game/examples/dungeon-hack/traces/08-tables-program-return/phase-one.profile)
