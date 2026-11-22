# DOSBox real-mode recorder

`realmode_observer.inc` records CPU registers, the top five stack words, and memory at ES:DI and DS:SI immediately before selected instructions in a DOS MZ program.

## Build and test

1. Copy `realmode_observer.inc` into the DOSBox 0.74-3 source directory `src/cpu/`.
2. In `core_normal.cpp`, include the file above `CPU_Core_Normal_Run`. Call `dpw_observe_instruction();` immediately after the main loop’s `LOADIP;`. Build DOSBox with the normal CPU core enabled.
3. From this directory, run `python3 smoke_test.py /absolute/path/to/dosbox` on Linux. The test generates a small MZ executable and a temporary profile. It checks three checkpoints and the observed values of AX and DX.

## Capture another program

Set `DPW_PROFILE` to an absolute profile path and `DPW_TRACE` to a fresh CSV path. Launch the program in the instrumented DOSBox with `core=normal`.

The first profile line specifies `image CS:IP offset signature`. CS is relative to the loaded MZ image. The signature is a four-byte little-endian integer read at the given offset in the entry segment. Choose bytes unaffected by relocation. Each following line specifies `start`, `watch`, or `stop`, followed by image-relative CS:IP and a checkpoint label. Use one start and one stop. The recorder closes the CSV at the stop point and lets the program continue.

The [Dungeon Hack profile](../../skills/analyze-dos-game/examples/dungeon-hack/traces/03-sound-return/phase-one.profile) and its [verified capture](../../skills/analyze-dos-game/examples/dungeon-hack/traces/03-sound-return/TRACE.md) show the format in use.
