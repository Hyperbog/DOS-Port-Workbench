# Map DOS calls to Ghidra functions

Run these commands in PowerShell from the extracted plugin directory. Set the game path and use GNU objdump on your PATH. If it is installed elsewhere, add `--objdump "C:\Non-Native Applications\MSYS2\ucrt64\bin\objdump.exe"` to the Python command before the output redirection.

```powershell
$dosGame = 'C:\DOSGames\Dungeon Hack\AESOP.EXE'
$workbenchDir = (Resolve-Path '.\skills\analyze-dos-game').Path
py -3 "$workbenchDir\scripts\workbench.py" "$dosGame" > .\AESOP.workbench.json
```

### In the Ghidra desktop app

1. Import the same executable. For a DOS MZ file, select **Old-style DOS Executable (MZ)** and **x86:LE:16:Real Mode**. For a COM file, select **Raw Binary** with that language and base address `0000:0100`. At the COM entry, disassemble and create the entry function if the listing is empty.
2. Run **Auto Analyze**. Open **Window → Script Manager**, then **Manage Script Directories**. Add the plugin’s `skills\analyze-dos-game\ghidra` directory.
3. Run **MapDosFunctions.java**, select the Workbench report and choose a new JSON output filename.

### Headless MZ example

Set the Ghidra installation path. The import and analysis use a new Ghidra project.

```powershell
$ghidraInstall = 'C:\Tools\ghidra_11.4.2_PUBLIC'
$dosProjects = New-Item -ItemType Directory -Force '.\ghidra-projects'
& "$ghidraInstall\support\analyzeHeadless.bat" $dosProjects.FullName DungeonHack `
  -import "$dosGame" -loader MzLoader -processor 'x86:LE:16:Real Mode' -cspec default `
  -scriptPath "$workbenchDir\ghidra" -postScript MapDosFunctions.java `
  "$PWD\AESOP.workbench.json" "$PWD\AESOP.functions.json"
```

For later exports from this project, use `-process AESOP.EXE -noanalysis -readOnly` in place of the import and loader options. Choose a fresh output filename. The script reads the existing program database. Project-specific function names appear in the export.

### Reading the export

Each entry in `sites` retains the Workbench file offset, load-relative CS:IP and service hypothesis. A `mapped` site has a unique matching address, matching original bytes, an exact instruction match and a containing Ghidra function. Look up its `function_entry` in `functions` for the name, original file offset when available and incoming call references. Other statuses identify the check that needs review. Relocations or local patches can produce an instruction-byte difference.

Tested with Ghidra 11.4.2 on a DOS MZ game and a COM fixture. [Ghidra memory mapping API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html) · [Function lookup API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html)
