"""Build the native Ghidra script download from checked-in sources."""
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/cylindrical-earth"
OUTPUT = ROOT / "public/downloads/cylindrical-earth-acnh-scripts.zip"


def main():
    files = [path for path in SOURCE.rglob("*") if path.is_file()
             and "__pycache__" not in path.parts
             and (path.suffix in (".py", ".json", ".md") or path.name == "LICENSE")]
    build(OUTPUT, files)


def build(output, files):
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files):
            entry = ZipInfo(path.relative_to(SOURCE).as_posix(), (2026, 10, 17, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            archive.writestr(entry, path.read_bytes())
    print("Built %s (%d files, %d bytes)" % (output.name, len(files), output.stat().st_size))


if __name__ == "__main__":
    main()
