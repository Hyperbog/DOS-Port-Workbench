# Dungeon Hack · HACK.RES loading trace

**`AESOP.EXE hack phase-one` loads resource 2932 through `HACK.TBL`.** The executable opens `hack.RES` and `hack.TBL` for reading, reads the 36-byte archive header, then uses four-byte entries from the sidecar to find resources. For `phase-one`, the table entry at `0x2DD0` points to an archive header at `0x68770C`. Its 1,121-byte payload begins at `0x687718`.

## Observed load order

The rows follow DOS call order. Each archive entry has a 12-byte header. All positions below are byte offsets from the start of the indicated file.

| DOS events | Resource | ID | HACK.TBL slot offset | HACK.RES entry header | Payload start | Bytes returned |
|---|---|---:|---:|---:|---:|---:|
| 4–10 | Resource-name dictionary | 0 | `0x0000` | `0x69AB53` | `0x69AB5F` | 32,768 + 32,681 |
| 11–16 | Runtime-function dictionary | 3 | `0x000C` | `0x6BBCB1` | `0x6BBCBD` | 5,758 |
| 17–22 | `phase-one` | 2932 | `0x2DD0` | `0x68770C` | `0x687718` | 1,121 |
| 23–28 | `phase-one.IMPT` | 2930 | `0x2DC8` | `0x6874A3` | `0x6874AF` | 448 |
| 29–34 | `phase-one.EXPT` | 2931 | `0x2DCC` | `0x68767B` | `0x687687` | 121 |

Events 1 and 2 passed the relative paths `hack.RES` and `hack.TBL` to DOS with `AX=3D00h`. DOS returned handles 5 and 6 in these runs. Event 3 read 36 bytes from archive offset zero. The header contains the signature `AESOP/16 V1.00`, the file size 7,083,229 and a first-directory pointer of `0x24`. The first subsequent archive seek went directly to `0x69AB53`, using the four bytes just read from table slot zero.

For each resource, the loader seeks to `4 × ID` in `HACK.TBL`, reads a little-endian 32-bit archive offset, seeks there in `HACK.RES` and reads the entry header. The payload length is the little-endian 32-bit field at header offset 8. The loader queries the current file position with a zero-distance seek before reading the payload. The three `phase-one` names and IDs also appear as pairs in the captured resource-name dictionary. The second dictionary contains function names including `load_music` and `close_file`.

## Executable checkpoints

Ghidra 11.4.2 used image segment `1000h`. Subtract `1000h` from the listed segment for load-relative CS:IP. The DOSBox runs loaded the MZ image at segment `01A3h`. The file offsets and instruction bytes refer to the unrelocated `AESOP.EXE`.

| Ghidra call or interrupt site | EXE file offset | Bytes | Role |
|---|---:|---|---|
| `1668:0313` | `0x007F93` | `9A 4A 12 BF 06` | Startup calls the archive initializer at `16BF:124A` |
| `16BF:126E` | `0x00945E` | `9A 6C 3B 00 00` | Opens the archive through `1000:3B6C` |
| `16BF:12C1` | `0x0094B1` | `9A 6C 3B 00 00` | Opens the sidecar through the same routine |
| `1000:3C2E` | `0x00522E` | `E8 AA 00` | Calls the DOS open wrapper at `1000:3CDB` |
| `1000:3D03` | `0x005303` | `CD 21` | DOS open |
| `1000:10B4` | `0x0026B4` | `CD 21` | DOS seek |
| `1000:11D1` | `0x0027D1` | `CD 21` | DOS read |

Inside the lookup routine at `16BF:111C` (EXE `0x00930C`), the calls at `16BF:113B` and `16BF:1153` seek and read the table slot. Those at `16BF:116B` and `16BF:1188` seek and read the archive entry header. The saved return addresses in `calls.log` tie these sites to the observed requests.

## Verification and replay

Two DOSBox 0.74-3 runs produced identical records through event 34. All 17 reads matched the source files byte for byte, totaling 73,013 bytes. Their combined SHA-256 in read order is `e1a47c302aadefa700ed264c091d27ed6507779e00a631c009395351426738b0`. The capture covers the two named files, from their open calls through the export-table load. Bytecode execution is the next checkpoint.

| Input | SHA-256 |
|---|---|
| AESOP.EXE | `d3676cb71fd9a869004ee08d3f75e96861e19aeb003d89d3c4ef93436796d450` |
| HACK.RES | `207eaf4081eee453c718fc8f761a707ab5c36bf974255185e2bc90ebe84cac66` |
| HACK.TBL | `5ad8586f21908e791ef27a357a35f11e64022af054c3ae15cc4d803b5db59e7f` |

From the extracted folder, run `py verify_trace.py "D:\Games\Dungeon Hack"` on Windows, using the path to your copy. The verifier checks the three inputs, the executable interrupt sites, all recorded reads and the five resource mappings. `events.csv` has one row per call. `resources.csv` includes SHA-256 for each complete payload.

For a live replay on Linux, include `dosbox_observer.inc` immediately before `DOS_21Handler` in DOSBox 0.74-3’s `src/dos/dos.cpp` and declare `ArchiveCall archive_call;` as the first statement of that function. Rebuild DOSBox. Set `DH_IO_LOG` and `DH_READS` to separate output paths. Launch with `trace.conf`, mount the game folder as `C:`, switch to that drive, run `set F=0`, then `aesop hack phase-one`. This directly invokes the phase-one command from `HACK.BAT`. The opening movie and `MAZE.EXE` are separate launches. Check the returned buffers with `verify_trace.py GAME_FOLDER --capture READS_FILE`.

In `calls.log`, each `E` line records event, file, PSP, caller CS, interrupt IP, input AX/BX/CX/DX/DS, returned AX/DX, carry, prior file position, SS, BP and path. Registers are hexadecimal. Event, carry and prior position are decimal. Each following `F` line gives frame BP, saved BP, return IP and the following stack word in hexadecimal. The SHA-256 values derive from the guest buffers after DOS returned.

The pinned game files and launch batch are the primary evidence. MS-DOS service semantics and AESOP layout terminology were cross-checked against the references below.

- [Dungeon Hack files at the tested revision](https://github.com/Hyperbog/RLOFT/tree/30b5a3025f4eea711380c416667bc350fd5c5902/MASTER/Dungeon%20Hack)
- [Microsoft Press · The MS-DOS Encyclopedia, Section V](https://www.pcjs.org/documents/books/mspl13/msdos/encyclopedia/section5/)
- [Thirdeye · archive structures](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/apps/thirdeye/resources/res.hpp) and [dictionary definitions](https://github.com/psi29a/thirdeye/blob/4ec4e6a69bcca459bf73b35fcbe2d47fcee88617/apps/thirdeye/resources/res.cpp)
- [DOSBox 0.74-3 source archive](https://deb.debian.org/debian/pool/main/d/dosbox/dosbox_0.74-3.orig.tar.gz)

