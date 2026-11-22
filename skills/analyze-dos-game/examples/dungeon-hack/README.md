# Dungeon Hack | AESOP.EXE

| Result | Verified value |
|---|---|
| Repository revision | `Hyperbog/RLOFT` · `DnD-Classics` · `30b5a3025f4eea711380c416667bc350fd5c5902` |
| Executable | `MASTER/Dungeon Hack/AESOP.EXE` · 151,968 bytes |
| SHA-256 | `d3676cb71fd9a869004ee08d3f75e96861e19aeb003d89d3c4ef93436796d450` |
| Git blob | `2d7d150e68d3c2d0c3c38de93d26491a83b0c504` |
| MZ load module | File offset `0x1600` through `0x251A0` exclusive · 1,223 relocations · entry `0000:0000` load-relative |
| Ghidra analysis | 11.4.2 · Old-style DOS Executable (MZ) · x86 16-bit real mode · default compiler specification |
| Scope | 14,439 statically decoded addresses · 136 unique finding sites mapped to 34 containing functions |

The launch menu’s game option runs `HACK.BAT`. The batch file invokes `aesop hack phase-one` and `aesop hack phase-two`. A separate `maze` command runs from the save directory. This map covers the AESOP executable. [Launch menu](https://github.com/Hyperbog/RLOFT/blob/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack/dosbox_dhack_single.conf) · [HACK.BAT](https://github.com/Hyperbog/RLOFT/blob/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack/HACK.BAT)

| Operation | File offset | Load-relative site | Ghidra site | Ghidra function entry |
|---|---|---|---|---|
| Open file or device by pathname | `0x5303` | `0000:3D03` | `1000:3D03` | `1000:3CDB` |
| Issue a zero-length DOS write | `0x5166` | `0000:3B66` | `1000:3B66` | `1000:3B5A` |
| Set timer channel 0 to mode 3 | `0x6924` | `04D8:05A4` | `14D8:05A4` | `14D8:059A` |
| Load the timer divisor, low then high | `0x692F / 0x6935` | `04D8:05AF / 05B5` | `14D8:05AF / 05B5` | `14D8:059A` |

Ghidra identifies calls from the same function, `1000:3B6C`, to both file routines. The open call loads the pathname into DS:DX and sets AH to 3Dh. The write routine clears CX and sets AH to 40h. On a disk file that sets the file length to the current position, which matters for a native file implementation. The project’s combined MS-DOS PDF also lists 3Dh as “Open Handle” on PDF page 2,839, printed page 31. [Microsoft Press system calls](https://msarchive.pcjs.org/mspl13/msdos/encyclopedia/section5/) · [Ralf Brown on zero-byte writes](https://fd.lod.bz/rbil/interrup/dos_kernel/2140.html)

The timer routine sends `36h` to port `43h`, then writes the low and high bytes of its argument to port `40h`. Measuring the game’s timer frequency requires the divisor from an observed invocation. [8253/8254 control word and ports](https://www.cs.yale.edu/flint/feng/cos/resources/BIOS/Resources/assembly/8253.html)

The initial trace left 28 control transfers unresolved and one path dependent on an interrupt handler or CPU mode. Ghidra function boundaries and incoming references describe this database. The runtime checkpoints below track startup file access and message dispatch. The timer frequency remains open.

**Files** · [Browse all 136 sites](Dungeon_Hack_AESOP_Function_Map.csv) · [Ghidra export and incoming calls](AESOP.functions.json) · [Workbench input report](AESOP.workbench.json)

## Runtime checkpoints

| Step | Captured behavior | Verify from the checkpoint directory |
|---|---|---|
| [1. Resource loading](traces/01-resource-loading/TRACE.md) | DOS opens and reads from the resource files | `py verify_trace.py "D:\Games\Dungeon Hack"` |
| [2. First message](traces/02-first-message/TRACE.md) | The AESOP interpreter dispatches `create` to `phase-one` and enters `init_sound(0)` | `py verify_dispatch.py "D:\Games\Dungeon Hack"` |
| [3. Sound return](traces/03-sound-return/TRACE.md) | The handler replaces the sound return value and calls `init_graphics()` | `py verify_return.py "D:\Games\Dungeon Hack"` |
| [4. Graphics return](traces/04-graphics-return/TRACE.md) | `init_graphics()` returns 2 and the handler calls `init_interface()` with zero arguments | `py verify_return.py "D:\Games\Dungeon Hack"` |

Each verifier reads your local game files and the checked-in capture. The two native-return checkpoints use the [same verification code](traces/native_return.py) for the bytecode, stack and function pointers. The latest trace ends at the interface routine’s entry.
