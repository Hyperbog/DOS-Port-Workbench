"""Inventory one DOS game distribution and save a reviewed copy when requested."""
import argparse
import json
import os
import re
import shutil
import stat
import sys
import zipfile
from contextlib import ExitStack
from functools import partial
from pathlib import Path, PurePosixPath

from dos_image import RULES, inspect_image

DISTRIBUTION_DOCS = {"FILE_ID.DIZ", "ORDER.FRM", "ORDER.TXT", "REGISTER.TXT", "README.TXT", "README.1ST"}
DOS_NAMES = re.compile(rb"(?<![A-Z0-9_.-])[A-Z0-9_$~-]{1,8}\.[A-Z0-9]{1,3}(?![A-Z0-9_.-])")


def inventory(source, stack):
    if source.is_dir():
        items = []
        def propagate(error):
            raise error
        for directory, dirs, files in os.walk(source, onerror=propagate):
            for leaf in dirs + files:
                path = Path(directory, leaf)
                if path.is_symlink() or not (path.is_dir() or path.is_file()):
                    raise ValueError(f"non-regular entry in source: {path}")
                if path.is_dir():
                    continue
                items.append((path.relative_to(source).as_posix(), path.stat().st_size, partial(path.open, "rb")))
    elif source.suffix.lower() == ".zip":
        archive = stack.enter_context(zipfile.ZipFile(source))
        items = []
        for entry in archive.infolist():
            if stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError(f"symbolic link in ZIP: {entry.filename}")
            if not entry.is_dir():
                items.append((entry.filename, entry.file_size, partial(archive.open, entry)))
    else:
        items = [(source.name, source.stat().st_size, partial(source.open, "rb"))]
    members = {}
    for name, size, opener in sorted(items, key=lambda item: item[0].casefold()):
        key = name.casefold()
        if key in members or any(part in ("", ".", "..") for part in name.split("/")) or "\\" in name or ":" in name:
            raise ValueError(f"ambiguous or nonportable input path: {name}")
        members[key] = (name, size, opener)
    return members


def disposition(name, references):
    base = PurePosixPath(name).name.upper()
    if base in references:
        return f"keep; filename literal at executable offset 0x{references[base]:X}"
    if base.startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
        return "keep distribution notice"
    if base in DISTRIBUTION_DOCS:
        return "review for exclusion; distribution document by name"
    if base in ("SETUP.EXE", "INSTALL.EXE", "SETUP.BAT", "INSTALL.BAT"):
        return "review configuration or unpacking dependencies; keep by default"
    if base.endswith((".OVL", ".OVR", ".DRV", ".DIG", ".MDI")):
        return "keep possible overlay or runtime driver"
    if base.endswith((".MAP", ".WAD", ".PAK", ".BNK", ".VOC")):
        return "keep possible game asset or container"
    return "keep pending runtime evidence"


def write_bundle(destination, members, omit):
    output = destination.open("xb")
    try:
        with output, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for key, (name, size, opener) in members.items():
                if key not in omit:
                    with opener() as reader, archive.open(name, "w", force_zip64=size >= (1 << 31)) as writer:
                        shutil.copyfileobj(reader, writer, 1024 * 1024)
                    if archive.getinfo(name).file_size != size:
                        raise ValueError(f"input size changed while staging {name}")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def run(args, stack):
    source = args.source.resolve(strict=True)
    members = inventory(source, stack)
    programs = [k for k in members if k.endswith((".exe", ".com"))]
    key = args.entry.replace("\\", "/").casefold() if args.entry else None
    if args.entry and key not in members:
        raise ValueError(f"entry not in game: {args.entry}")
    if not key and len(programs) == 1:
        key = programs[0]
    elif not key and source.is_file() and source.suffix.lower() != ".zip":
        key = source.name.casefold()
    report = {"report_version": 1, "programs": [members[k][0] for k in programs]}
    refs = {}
    if key:
        name, size, opener = members[key]
        binary = {"status": "executable exceeds 16 MiB inspection budget"}
        if size <= 16 << 20:
            with opener() as stream:
                data = stream.read((16 << 20) + 1)
            if len(data) != size:
                raise ValueError(f"input size changed while reading {name}")
            binary = inspect_image(name, data, shutil.which(args.objdump))
            for match in DOS_NAMES.finditer(data.upper()):
                refs.setdefault(match[0].decode("ascii"), match.start())
        report.update(entry=name, executable=binary)
        tags = {f["subsystem"] for f in binary.get("trace", {}).get("findings", [])}
        report["native_port_targets"] = {tag: RULES["targets"][tag] for tag in sorted(tags)}
    else:
        report["status"] = "choose a program using --entry" if programs else "no EXE or COM selected"
    omit = {s.replace("\\", "/").casefold() for s in args.omit}
    if omit - members.keys():
        raise ValueError("omit paths missing from game: " + ", ".join(sorted(omit - members.keys())))
    if omit and not args.bundle:
        raise ValueError("--omit requires --bundle")
    report["files"] = [dict(path=name, size=size, decision=disposition(name, refs),
                            included=k not in omit) for k, (name, size, _) in members.items()]
    if args.bundle:
        dest = args.bundle.resolve()
        if dest == source or (source.is_dir() and source in dest.parents):
            raise ValueError("choose a new bundle outside the source")
        write_bundle(dest, members, omit)
        report["bundle"] = str(dest)
    return report


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("source", type=Path, help="game directory, ZIP or single executable")
    cli.add_argument("--entry", help="relative path of the game executable")
    cli.add_argument("--objdump", default="objdump", help="GNU objdump executable or absolute path")
    cli.add_argument("--bundle", type=Path, help="create a new ZIP outside the source")
    cli.add_argument("--omit", action="append", default=[], help="one exact reviewed file path; repeat as needed")
    try:
        with ExitStack() as resources:
            json.dump(run(cli.parse_args(), resources), sys.stdout, indent=2)
            print()
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        cli.exit(2, f"{cli.prog}: {exc}\n")
