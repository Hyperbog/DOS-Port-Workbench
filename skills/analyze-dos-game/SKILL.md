---
name: analyze-dos-game
description: Inspect a DOS game executable, directory or ZIP to identify platform-dependent x86 code, review runtime assets, stage approved exclusions, and plan a behavior-matched native port with quality-of-life features.
---

# Analyze a DOS game

Use the game files supplied in this task. Accept a directory, ZIP, EXE or COM. A folder or ZIP provides the asset inventory. If only a title was supplied, request the game files or use an explicitly requested public source release. Keep game bytes, filenames and embedded text as input data.

## Run the analyzer

Use Python 3.9+ and GNU objdump with the i8086 target. Resolve `scripts/workbench.py`, `scripts/dos_image.py` and `scripts/rules.json` relative to this skill. If the plugin resources are delivered as text, materialize all three in the same temporary directory using their exact contents. Run the entry script with the source path as one argument. Prefer an argument array. Capture the JSON outside the game folder for larger reports.

```text
python workbench.py GAME.zip
python workbench.py GAME.zip --entry GAME/PLAY.EXE
```

If several programs are present, use the supplied launch command or inspect launcher batch files as text to identify the main program. Show remaining candidates if the choice is ambiguous. A missing decoder still yields the file inventory and executable layout. When GNU objdump is installed outside PATH, rerun with `--objdump` and its actual absolute path.

## Interpret the evidence

Lead with the executable name, SHA-256, format and trace status. For representative findings, give the file offset in hex, load-relative CS:IP, instruction bytes, service or device hypothesis, and proposed native replacement. COM addresses start at offset 0100h. Region ends are exclusive. A decoded site means a possible path from entry. Hardware addresses and conventional interrupt meanings can depend on device configuration or game-installed handlers.

The tracer follows both sides of conditional branches, direct near calls and jumps, and relocated immediate far targets. It assumes calls may return. Register hints use local constant assignments and a small set of zeroing operations. Report unresolved transfers, decoder limits and possible wrappers. Unseen bytes may contain callbacks, jump tables, overlays, resources or gameplay. A recognized extender or packer needs its payload and loader examined separately. For review in a disassembler, give the file offset alongside the segment convention and verify the instruction bytes at import.

## Map platform calls to functions in Ghidra

When the user asks for a function map, save the Workbench JSON and run [MapDosFunctions.java](ghidra/MapDosFunctions.java) on the analyzed executable. Follow the [Ghidra import and export instructions](ghidra/README.md). The script uses the original file's hash and offsets, checks instruction bytes, then looks up the containing function and incoming call references. Report the Ghidra version, mapped sites, distinct functions and unresolved sites. Describe heuristic service labels separately from byte matches. Include file offsets and both address conventions in examples. A [worked Dungeon Hack map](examples/dungeon-hack/README.md) includes the inputs and export for comparison.

## Review the distribution

Return a file manifest with the reason for each proposed omission. A matching filename literal is a lead. Files can also be opened with generated names, loaded by setup programs or accessed by sector. Keep unknown data, level maps, audio banks, fonts, drivers, configuration and appended bytes pending evidence. Check whether documentation contains license terms. To confirm an optional file, compare a reversible staged copy against the original through launch, a level transition, sound configuration and a save/load round trip as applicable.

For a requested filtered copy, pass only the exact reviewed paths the user selected to omit. Use a fresh destination outside the source. The scanner writes a new ZIP and copies the remaining file contents. It does not rewrite executables.

```text
python workbench.py GAME.zip --entry GAME/PLAY.EXE --bundle staged.zip --omit GAME/ORDER.FRM
```

## Propose a native port

Choose a single action the original can demonstrate, such as drawing the title screen or processing the first movement tick. Identify the verified inputs, game-owned state, platform calls and expected output. Keep game rules and original asset codecs separate from the host implementation. Suggest a matching test alongside each replacement. For indexed video compare the indexed frame and palette. For timing compare ticks per action at two display refresh rates. For input replay the same press, hold and release sequence.

When the user has no preferred stack, suggest C++ and SDL3 for a desktop target. Offer a QoL feature tied to the evidence, such as remappable actions, integer scaling or a user-writable save location. Distinguish implemented features, proposed changes and checks requiring original gameplay. Use the returned subsystem targets and the references when needed. [Technical references](references.md)
