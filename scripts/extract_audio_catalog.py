"""Extract BARS asset identifiers and references from an xlink2 SLink text export.

Usage: python scripts/extract_audio_catalog.py ROMFS SLINK_TEXT
The SLink text export must be made with xlink2 --game Park.
Only metadata is exported; audio payloads are not copied.
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import struct
import zlib


def read_assets(root):
    rows = []
    for path in sorted((root / "Sound" / "Resource").rglob("*.bars")):
        with path.open("rb") as stream:
            header = stream.read(16)
            if header[:4] != b"BARS" or header[8:10] != b"\xff\xfe":
                raise ValueError(f"Unsupported BARS header: {path}")
            count = struct.unpack_from("<I", header, 12)[0]
            table = stream.read(count * 12)
            hashes = struct.unpack_from(f"<{count}I", table)
            if list(hashes) != sorted(hashes):
                raise ValueError(f"Unsorted BARS hash table: {path}")
            for index, name_hash in enumerate(hashes):
                metadata_offset, audio_offset = struct.unpack_from(
                    "<II", table, count * 4 + index * 8
                )
                stream.seek(metadata_offset)
                metadata = stream.read(40)
                if metadata[:4] != b"AMTA" or metadata[4:8] != b"\xff\xfe\x00\x05":
                    raise ValueError(f"Expected little-endian AMTA v5: {path}, {index}")
                metadata_size = struct.unpack_from("<I", metadata, 8)[0]
                name_offset = 36 + struct.unpack_from("<I", metadata, 36)[0]
                if not 40 <= name_offset < metadata_size:
                    raise ValueError(f"Invalid AMTA name offset: {path}, {index}")
                stream.seek(metadata_offset + name_offset)
                name_bytes = stream.read(metadata_size - name_offset).split(b"\0", 1)[0]
                name = name_bytes.decode("utf-8")
                if zlib.crc32(name_bytes) != name_hash:
                    raise ValueError(f"Name/hash mismatch: {path}, {index}, {name}")
                if audio_offset != 0xFFFFFFFF:
                    stream.seek(audio_offset)
                    if stream.read(4) != b"BWAV":
                        raise ValueError(f"Expected BWAV: {path}, {index}")
                rows.append({
                    "name": name,
                    "hash": f"0x{name_hash:08X}",
                    "archive": path.relative_to(root / "Sound" / "Resource").as_posix(),
                    "index": index,
                })
    if not rows:
        raise ValueError("No BARS assets found in Sound/Resource")
    return rows


def read_references(path):
    references = defaultdict(set)
    calls = []
    user = ""
    for line in path.open(encoding="utf-8"):
        indent = len(line) - len(line.lstrip())
        value = line.strip()
        if re.match(r"^  \S.*\{$", line):
            user = value[:-1].strip()
        if value == "}":
            while calls and calls[-1][0] >= indent:
                calls.pop()
        call = re.fullmatch(r"(.+)\[(0x[0-9a-fA-F]+)\] \{", value)
        if call:
            calls.append((indent, call[1], call[2]))
        asset = re.fullmatch(r'RuntimeAssetName = "(.*)"', value)
        if asset and asset[1] and asset[1] != "@Blank" and calls:
            references[asset[1]].add((user, calls[-1][1], calls[-1][2]))
    if not references:
        raise ValueError("No SLink references found; use the standard xlink2 text output")
    return {name: sorted(entries) for name, entries in sorted(references.items())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("romfs", type=Path)
    parser.add_argument("slink_text", type=Path)
    args = parser.parse_args()
    assets = read_assets(args.romfs)
    references = read_references(args.slink_text)
    for asset in assets:
        asset["calls"] = len(references.get(asset["name"], []))
    assets.sort(key=lambda asset: (asset["name"], asset["archive"], asset["index"]))
    missing = sorted(set(references) - {asset["name"] for asset in assets})
    if missing:
        raise ValueError(f"SLink names without BARS assets: {missing}")
    output = Path(__file__).resolve().parents[1] / "public" / "data"
    output.mkdir(parents=True, exist_ok=True)
    for filename, data in [("audio-assets.json", assets), ("slink-references.json", references)]:
        (output / filename).write_text(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    print(f"Validated {len(assets):,} assets in {len({a['archive'] for a in assets}):,} archives")
    print(f"Matched {len(references):,} SLink names; {sum(map(len, references.values())):,} call mappings")


if __name__ == "__main__":
    main()
