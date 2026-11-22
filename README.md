# DOS Port Workbench

In ChatGPT Work or Codex, select **DOS Port Workbench**, attach the game ZIP or choose its working directory, and ask to identify the DOS-specific calls and the first subsystem to port.

To run the analyzer yourself on Windows, extract this package, open PowerShell in the folder containing `plugin.json`, and run the bundled script with Python 3.9 or later.

```powershell
py -3 .\skills\analyze-dos-game\scripts\workbench.py "C:\DOSGames\MYGAME" --entry PLAY.EXE
```

For instruction tracing, use GNU objdump with x86 support. Pass its full path with `--objdump` if it is outside PATH. MSYS2 UCRT64 supplies `ucrt64\bin\objdump.exe` in its Binutils package. [MSYS2 package](https://packages.msys2.org/packages/mingw-w64-ucrt-x86_64-binutils) · [GNU objdump manual](https://www.sourceware.org/binutils/docs/binutils/objdump.html)

The JSON includes file offsets, raw instruction bytes, unresolved paths, an asset manifest and native-port test ideas. A filtered ZIP requires `--bundle` and omits only explicit `--omit` paths. Example commands and interpretation guidance are in the plugin workflow. [Analyze a DOS game](skills/analyze-dos-game/SKILL.md)

## Ghidra function mapping

Follow the [Windows and Ghidra instructions](skills/analyze-dos-game/ghidra/README.md) to attach each traced platform call to its containing function. The [Dungeon Hack example](skills/analyze-dos-game/examples/dungeon-hack/README.md) includes a filterable CSV, the original Workbench report and the Ghidra export.

## Repository layout

| Location | Contents |
|---|---|
| [Analyzer](skills/analyze-dos-game/) | Plugin instructions, Python analyzer, classification rules and Ghidra scripts |
| [DOSBox recorder](tools/dosbox/) | Profile-driven real-mode instruction recorder and an independent DOS smoke test |
| [Dungeon Hack case study](skills/analyze-dos-game/examples/dungeon-hack/README.md#runtime-checkpoints) | Function map, three startup traces, game-specific probes and verification commands |

Use `main` for staging. Keep reusable tools under their component directory and game-specific profiles, captures and reproduction steps under the corresponding example. Supply original games locally when running the verifiers.
