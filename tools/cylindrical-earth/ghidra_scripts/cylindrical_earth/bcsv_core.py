# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Adapted from Treeki/CylindricalEarth reader recognition and enum scraping.
from __future__ import print_function
import array
import hashlib
import re
import struct
import sys
import zlib
import io
import json
from collections import defaultdict


def load_definitions(path):
    with io.open(path, "r", encoding="utf-8") as source:
        definitions = json.load(source)
    if definitions.get("formatVersion") != 1:
        raise ValueError("Unsupported bundled-definition format")
    for schema in definitions["schemas"]:
        occupied = set()
        if len(schema["fields"]) != schema["fieldCount"]:
            raise ValueError("Invalid field count: " + schema["name"])
        for field in schema["fields"]:
            name = field["referenceName"]
            if name and zlib.crc32(name.encode("utf-8")) & 0xFFFFFFFF != int(field["hash"], 16):
                raise ValueError("Invalid field-name CRC32: " + name)
            start, width = field["rowOffset"], field["width"]
            if start < 0 or width <= 0 or start + width > schema["rowSize"]:
                raise ValueError("Invalid row-field bounds: " + schema["name"])
            span = set(range(start, start + width))
            if span & occupied:
                raise ValueError("Overlapping row fields: " + schema["name"])
            occupied.update(span)
    return definitions


def scan_index_tables(strings, tables, known, check_cancel=lambda: None):
    """Require an exact live string sequence before importing a known index enum."""
    memory = strings + tables
    cache = {}
    def string_at(address):
        if address in cache:
            return cache[address]
        result = None
        for base, raw in memory:
            if base <= address < base + len(raw):
                offset = address - base
                end = raw.find(b"\0", offset, min(offset + 512, len(raw)))
                if end >= 0:
                    try:
                        text = raw[offset:end].decode("utf-8")
                        if re.match(r"^[A-Za-z0-9_]+$", text):
                            result = text
                    except UnicodeError:
                        pass
                break
        cache[address] = result
        return result
    matches = []
    for base, raw in tables:
        run, first = [], 0
        def finish():
            if len(run) < 2:
                return
            key = hashlib.md5("***".join(run).encode("utf-8")).hexdigest()[:12]
            definition = known.get(key)
            if definition and definition["choices"] == run:
                matches.append({"address": first, "definition": definition})
        for offset in range(0, len(raw) - 7, 8):
            if offset % 0x10000 == 0:
                check_cancel()
            text = string_at(struct.unpack_from("<Q", raw, offset)[0])
            if text is None:
                finish()
                run = []
            else:
                if not run:
                    first = base + offset
                run.append(text)
        finish()
    return matches


def identifier(value):
    value = re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_") or "Field"
    return "Field_" + value if value[0].isdigit() else value

def scan_readers(texts, rodata, vtables, check_cancel=lambda: None):
    getters, readers = {}, {}
    memory = rodata + vtables
    def pointer_at(address):
        for base, data in memory:
            if base <= address and address + 8 <= base + len(data):
                return struct.unpack_from("<Q", data, address - base)[0]
        return None
    for start, raw in texts:
        words = array.array("I")
        loader = words.frombytes if hasattr(words, "frombytes") else words.fromstring
        loader(raw[:len(raw) // 4 * 4])
        if sys.byteorder != "little":
            words.byteswap()
        for i in range(len(words) - 2):
            if i % 0x40000 == 0:
                check_cancel()
            w = words[i]
            if w & 0x9F000000 != 0x90000000:
                continue
            pc = start + i * 4
            imm = ((w >> 29) & 3) | (((w >> 5) & 0x7FFFF) << 2)
            imm = (imm ^ 0x100000) - 0x100000
            address = (pc & ~4095) + (imm << 12)
            register, returned = w & 31, False
            # Newer direct string getters and the original SafeString pointer
            # getters: ADRP; ADD/LDR [; LDR]; RET. Some build the address in a
            # scratch register (ADRP X8; ADD X8; LDR X0, [X8]); X0 must hold it
            # at the RET.
            for j in range(i + 1, min(i + 4, len(words))):
                op = words[j]
                if op == 0xD65F03C0:
                    returned = register == 0
                    break
                if (op >> 5) & 31 != register:
                    break
                if op & 0xFFC00000 == 0x91000000:
                    address += (op >> 10) & 4095
                elif op & 0xFFC00000 == 0xF9400000:
                    address = pointer_at(address + (((op >> 10) & 4095) * 8))
                    if address is None:
                        break
                else:
                    break
                register = op & 31
            if not returned:
                continue
            for base, strings in memory:
                if base <= address < base + len(strings):
                    value = strings[address - base:address - base + 256].split(b"\0")[0]
                    if re.match(rb"^[A-Za-z0-9_]+\.bcsv$", value):
                        getters[pc] = value.decode("ascii")[:-5]
                    break
    def is_code(address):
        return any(base <= address < base + len(raw) for base, raw in texts)
    for base, raw in vtables:
        for offset in range(48, len(raw) - 15, 8):
            if offset % 0x10000 == 48:
                check_cancel()
            getter = struct.unpack_from("<Q", raw, offset)[0]
            if getter not in getters:
                continue
            methods = struct.unpack_from("<8Q", raw, offset - 48)
            if not all(is_code(method) for method in methods):
                continue
            name = getters[getter]
            record = readers.setdefault(name, {"name": name, "getFileName": getter, "vtables": [], "loadFunctions": []})
            record["vtables"].append(base + offset - 48)
            if methods[4] not in record["loadFunctions"]:
                record["loadFunctions"].append(methods[4])
    return sorted(readers.values(), key=lambda value: value["name"])

def cache_from_pcode(pcode, field_count, writable, function_name, pointer=lambda address: None):
    """Only accept a flag=1 followed by exactly field_count all-ones offsets.

    High P-code retains addresses after user labels/structures change. No symbol
    spelling or cached decompiler text is used for recognizing global stores.
    Larger caches are often reached through a GOT slot; `pointer` returns the
    value of such a relocation-read-only slot, or None for any other address.
    """
    flags, filled = set(), set()
    definitions, by_id = defaultdict(list), {}
    for op in pcode.get("high_pcodes", []):
        output = op.get("output")
        if "id" in op:
            by_id[op["id"]] = op
        if output and output.get("is_unique"):
            definitions[(output["offset"], output["size"])].append(op)
    def constant(node, depth=0):
        if node.get("is_constant"):
            return int(node["offset"], 16)
        if node.get("space") == "ram" and node.get("size") == 8:
            return pointer(int(node["offset"], 16))
        if not node.get("is_unique") or depth > 12:
            return None
        if node.get("def") in by_id:
            candidates = [by_id[node["def"]]]
        else:
            candidates = definitions.get((node["offset"], node["size"]), [])
        if len(candidates) != 1:
            return None
        op = candidates[0]
        if op["mnemonic"] not in ("COPY", "CAST", "PTRSUB", "INT_ADD", "PTRADD", "INT_MULT"):
            return None
        values = [constant(value, depth + 1) for value in op.get("inputs", [])]
        if not values or any(value is None for value in values):
            return None
        if op["mnemonic"] in ("COPY", "CAST"):
            return values[0]
        if op["mnemonic"] == "PTRADD":
            return values[0] + values[1] * values[2]
        if op["mnemonic"] == "INT_MULT":
            return values[0] * values[1]
        return values[0] + values[1]
    def valid(address, width):
        return any(start <= address and address + width <= end for start, end in writable)
    for op in pcode.get("high_pcodes", []):
        inputs, output = op.get("inputs", []), op.get("output")
        address, width, value = None, 0, None
        if op["mnemonic"] == "COPY" and output and output["space"] == "ram":
            address, width, value = int(output["offset"], 16), output["size"], constant(inputs[0])
        elif op["mnemonic"] == "STORE" and len(inputs) == 3:
            address, width, value = constant(inputs[1]), inputs[2]["size"], constant(inputs[2])
        elif op["mnemonic"] == "CALL" and len(inputs) >= 4:
            destination, fill, size = [constant(node) for node in inputs[1:4]]
            if destination is not None and fill is not None and size is not None and (fill & 255) == 255 and 0 < size <= 65536 and valid(destination, size):
                target = int(inputs[0]["offset"], 16)
                if "memset" in function_name(target).lower():
                    filled.update(range(destination, destination + size))
        if address is None or value is None or not valid(address, width):
            continue
        if width in (1, 4) and value == 1:
            flags.add(address)
        if 0 < width <= 32 and value == (1 << (width * 8)) - 1:
            filled.update(range(address, address + width))
    matches, partial = [], []
    for flag in flags:
        start = (flag + 4) & ~3
        slots = 0
        while slots < field_count and all(address in filled for address in range(start + slots * 4, start + slots * 4 + 4)):
            slots += 1
        if not slots or any(address in filled for address in range(start + slots * 4, start + slots * 4 + 4)):
            continue
        match = {"initFlag": flag, "offsetCache": start, "cacheSize": slots * 4}
        (matches if slots == field_count else partial).append(match)
    if len(matches) == 1:
        return matches[0]
    # The game caches only the fields its code reads, so some caches are
    # shorter than the schema. Their slots cannot be named from order alone.
    if not matches and len(partial) == 1:
        return dict(partial[0], partial=True)
    return None

def wide_constants(raw):
    """32-bit values built in a register by MOVZ/MOVN and MOVK (AArch64 LE).

    Field hashes are loaded this way before the row-header search, e.g.
    `mov w27,#0xc516; movk w27,#0xc187,LSL#16`. Every intermediate value is
    reported; callers intersect the result with known hashes.
    """
    words = array.array("I")
    loader = words.frombytes if hasattr(words, "frombytes") else words.fromstring
    loader(raw[:len(raw) // 4 * 4])
    if sys.byteorder != "little":
        words.byteswap()
    registers, found = {}, set()
    for word in words:
        if word & 0x1F800000 != 0x12800000:
            continue
        opc, shift = (word >> 29) & 3, ((word >> 21) & 3) * 16
        immediate, register = ((word >> 5) & 0xFFFF) << shift, word & 31
        mask = 0xFFFFFFFFFFFFFFFF if word >> 31 else 0xFFFFFFFF
        if opc == 0:
            value = ~immediate & mask
        elif opc == 2:
            value = immediate
        elif opc == 3 and register in registers:
            value = registers[register] & ~(0xFFFF << shift) & mask | immediate
        else:
            registers.pop(register, None)
            continue
        registers[register] = value
        if value <= 0xFFFFFFFF:
            found.add(value)
    return found


def own_slots(slots):
    """Slots a function uses itself, from {slot: (reads, writes)} reference counts.

    Inlined field reads also inline the cache's lazy initializer, which writes
    -1 to every slot, and reset methods rewrite slots without reading them, so
    only read slots count.
    """
    return sorted(slot for slot, (reads, writes) in slots.items() if reads)


def vote_cache_slots(field_hashes, functions):
    """Return {slot: set(field indices)} voted by inlined field reads.

    `functions` maps an entry to (constants, {slot: (reads, writes)}) from
    references to the cache slots. An inlined read loads its field's CRC32,
    reads its slot and stores the found offset back; the lazy initializer it
    may also inline writes -1 to every slot. So a function holding exactly one
    of the schema's hashes votes for the one slot it reads. Ambiguous
    functions do not vote.
    """
    index = {}
    for position, value in enumerate(field_hashes):
        index.setdefault(int(value, 16), position)
    votes = defaultdict(set)
    for constants, slots in functions.values():
        fields = set(index[value] for value in constants if value in index)
        own = own_slots(slots)
        if len(fields) == 1 and len(own) == 1:
            votes[own[0]].add(fields.pop())
    return dict(votes)


def map_cache_slots(slot_count, votes):
    """[field index per slot] if every slot has one unanimous, distinct vote."""
    mapping = []
    for slot in range(slot_count):
        fields = votes.get(slot, set())
        if len(fields) != 1:
            return None
        mapping.append(next(iter(fields)))
    return mapping if len(set(mapping)) == len(mapping) else None


def order_disagreements(votes):
    """[(slot, voted fields)] where a full cache's votes contradict schema order."""
    return [(slot, sorted(fields)) for slot, fields in sorted(votes.items()) if fields != set([slot])]


def field_names(fields):
    used, result = set(), []
    for field in fields:
        name = field["referenceName"]
        label = identifier(name.split(" ")[0].replace(".hshCstringRef", "")) if name else "Hash_" + field["hash"]
        if label in used:
            label += "_" + field["hash"]
        used.add(label)
        result.append(label)
    return result


ACCESSOR_SIZE = 0x300
LISTED_FIELDS = 16
FIELD_COMMENT = "Reads BCSV fields: "
FINDER_COMMENT = "Finds a field in a "
FINDER_SCAN = 0x60


def is_field_finder(code):
    """True for a table's FindField(row, slot, hash) helper, from its first instructions.

    It bounds-checks the slot in w1 (`cmp w1, #n`, then within a few
    instructions `csel xd, xzr, xs, hi`) and indexes the offset cache with it,
    so it reads any field. Ghidra only sees its reference to the cache's first
    slot, which looks like an accessor.
    """
    words = struct.unpack("<%dI" % (len(code) // 4), code[:len(code) // 4 * 4])
    return any(word & 0xFF8003FF == 0x7100003F and
               any(later & 0xFFE0FFE0 == 0x9A8083E0 for later in words[index + 1:index + 5])
               for index, word in enumerate(words))


def plan_accessors(uses, sizes, excluded=(), finders=()):
    """Return ({entry: (reader, name)}, {entry: comment}) for field readers.

    `uses` maps a function entry to {reader: set(field names)}, recovered from
    read/write references to offset-cache slots. The game inlines every field
    read (check the slot, else search the row header for the field's CRC32), so
    a small function that touches one slot is that field's accessor. Only those
    are named; every other function gets a comment listing the fields it reads.
    `finders` are FindField helpers, named after their table instead.
    """
    single, found, comments = defaultdict(list), defaultdict(list), {}
    for entry, readers in uses.items():
        if entry in excluded:
            continue
        if entry in finders:
            if len(readers) == 1:
                reader = next(iter(readers))
                comments[entry] = (FINDER_COMMENT + "row of %s.bcsv: w1 is the field's offset-cache slot and w2 its "
                                   "CRC32 hash. Returns the field's address, or null." % reader)
                found[reader].append(entry)
            continue
        fields = sorted("%s.%s" % (reader, name) for reader, names in readers.items() for name in names)
        if not fields:
            continue
        listed = ", ".join(fields[:LISTED_FIELDS])
        if len(fields) > LISTED_FIELDS:
            listed += " and %d more" % (len(fields) - LISTED_FIELDS)
        comments[entry] = FIELD_COMMENT + listed + "."
        if len(fields) == 1 and sizes.get(entry, ACCESSOR_SIZE + 1) <= ACCESSOR_SIZE:
            reader = next(iter(readers))
            single[(reader, next(iter(readers[reader])))].append(entry)
    names = {}
    for (reader, field), entries in single.items():
        for entry in entries:
            names[entry] = (reader, "Read_" + field if len(entries) == 1 else "Read_%s_%X" % (field, entry))
    for reader, entries in found.items():
        for entry in entries:
            names[entry] = (reader, "FindField" if len(entries) == 1 else "FindField_%X" % entry)
    return names, comments
