# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded binary recognition shared by the actor and custom RTTI passes."""
import hashlib
import re
import struct
from collections import Counter, defaultdict

CLASS_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def signed(value, bits):
    return (value ^ (1 << (bits - 1))) - (1 << (bits - 1))


class Image:
    def __init__(self, texts, constants, tables, writable):
        self.texts, self.constants, self.tables, self.writable = texts, constants, tables, writable
        self.blocks = texts + constants + tables

    def read(self, address, size):
        for base, raw in self.blocks:
            if base <= address and address + size <= base + len(raw):
                return raw[address - base:address - base + size]
        return None

    def word(self, address):
        raw = self.read(address, 4)
        return struct.unpack('<I', raw)[0] if raw is not None else None

    def pointer(self, address):
        raw = self.read(address, 8)
        return struct.unpack('<Q', raw)[0] if raw is not None else None

    def executable(self, address):
        return address % 4 == 0 and any(base <= address < base + len(raw) for base, raw in self.texts)

    def mutable(self, address, size=1):
        return any(start <= address and address + size <= end for start, end in self.writable)

    def table(self, address, size=1):
        return any(base <= address and address + size <= base + len(raw) for base, raw in self.tables)

    def string(self, address):
        for base, raw in self.constants + self.tables:
            if base <= address < base + len(raw):
                offset = address - base
                end = raw.find(b'\0', offset, min(len(raw), offset + 256))
                if end >= 0:
                    try:
                        return raw[offset:end].decode('utf-8')
                    except UnicodeError:
                        return None
        return None

    def signature(self, signature):
        needle = bytearray.fromhex(signature)
        matches = []
        for base, raw in self.texts:
            offset = raw.find(needle)
            while offset >= 0:
                if offset % 4 == 0:
                    matches.append(base + offset)
                offset = raw.find(needle, offset + 1)
        return matches[0] if len(matches) == 1 else None


def address_getter(image, function):
    """Recognize an ADRP/ADD return tail, including a guarded static getter.

    This is only a candidate. RTTI additionally requires independent emulation
    of the getter and membership predicate before accepting a table.
    """
    for offset in range(0, 160, 4):
        word = image.word(function + offset)
        if word is None:
            return None
        if word == 0xd65f03c0:
            for back in (8, 12, 16):
                pc = function + offset - back
                if pc < function:
                    continue
                adrp, add = image.word(pc), image.word(pc + 4)
                direct = add & 0xffc003ff == 0x91000000
                indirect = add & 0xffc003ff == 0xf9400000
                if adrp & 0x9f00001f == 0x90000000 and (direct or indirect):
                    # Every instruction between ADD and RET must only restore FP/LR.
                    tail = [image.word(a) for a in range(pc + 8, function + offset, 4)]
                    if any(w & 0xffc07fff not in (0xa9407bfd, 0xa8c07bfd) for w in tail):
                        continue
                    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2)
                    page = (pc & ~4095) + (signed(imm, 21) << 12)
                    displacement = ((add >> 10) & 4095) * (8 if indirect else 1)
                    return image.pointer(page + displacement) if indirect else page + displacement
            return None
    return None


def size_getter(image, function):
    """Recognize `mov w0, #size; [movk w0, #high, lsl #16;] ret`, the class-size getter."""
    words = [image.word(function + offset) for offset in (0, 4, 8)]
    if words[0] is None or words[0] & 0xff80001f != 0x52800000:
        return None
    value = ((words[0] >> 5) & 0xffff) << (16 * ((words[0] >> 21) & 3))
    if words[1] == 0xd65f03c0:
        return value
    if words[1] is not None and words[1] & 0xffe0001f == 0x72a00000 and words[2] == 0xd65f03c0:
        return (value & 0xffff) | (((words[1] >> 5) & 0xffff) << 16)
    return None


def class_identity(image, table):
    """Read the class-name and class-size getters stored just before a custom RTTI table.

    Actor and component vtables start with getClassName and getClassSize, followed
    by the RTTI predicate and getter that rtti_candidates found at `table`.
    """
    name_getter, size_function = image.pointer(table - 16), image.pointer(table - 8)
    if not all(a is not None and image.executable(a) for a in (name_getter, size_function)):
        return None
    address = address_getter(image, name_getter)
    if address is None or image.mutable(address) or image.executable(address):
        return None
    name, size = image.string(address), size_getter(image, size_function)
    if name is None or size is None or not size or not CLASS_NAME.match(name):
        return None
    return dict(name=name, size=size, nameGetter=name_getter, sizeGetter=size_function)


def address_constants(image, function, limit=64):
    """Return the addresses a function builds with ADRP/ADD or loads from the GOT before its first `ret`.

    Unconditional branches are followed, so a predicate that tail-calls a shared
    implementation reports that implementation's addresses.
    """
    pages, result, pc = {}, set(), function
    for _ in range(limit):
        word = image.word(pc)
        if word is None or word == 0xd65f03c0:
            break
        rd, rn = word & 31, (word >> 5) & 31
        if word & 0x9f000000 == 0x90000000:
            pages[rd] = (pc & ~4095) + (signed(((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2), 21) << 12)
        elif word & 0xffc00000 == 0x91000000 and rn in pages:
            result.add(pages[rn] + ((word >> 10) & 4095))
        elif word & 0xffc00000 == 0xf9400000 and rn in pages:
            result.add(image.pointer(pages[rn] + ((word >> 10) & 4095) * 8))
        elif word & 0xfc000000 == 0x14000000:
            pc += signed(word & 0x3ffffff, 26) * 4
            continue
        pc += 4
    result.discard(None)
    return result


def reader_classes(image, tables):
    """Split one BCSV file's reader vtables into the base reader and the classes derived from it.

    Returns (base type-info or None, {table: type-info}). Each `IsDerivedFrom`
    compares its argument with its own type-info and then with every ancestor's,
    so the base is the type that every other vtable's predicate refers to.
    """
    infos = {}
    for table in tables:
        getter = image.pointer(table + 8)
        infos[table] = address_getter(image, getter) if getter is not None else None
    if None in infos.values():
        return None, infos
    checked = dict((table, address_constants(image, image.pointer(table))) for table in tables)
    bases = [info for info in set(infos.values())
             if all(other == info or info in checked[table] for table, other in infos.items())]
    return (bases[0] if len(bases) == 1 else None), infos


def tail_target(image, function, limit=64):
    """Return the target of the first unconditional `b` before any `ret`, the usual tail call."""
    for offset in range(0, 4 * limit, 4):
        word = image.word(function + offset)
        if word is None or word == 0xd65f03c0:
            return None
        if word & 0xfc000000 == 0x14000000:
            return function + offset + signed(word & 0x3ffffff, 26) * 4
    return None


def destructors(image, table, deletes):
    """Return the (complete, deleting) destructor pair stored after a custom RTTI table.

    The Itanium ABI keeps a virtual destructor's two entries adjacent, complete first.
    The deleting one is only accepted when it tail-calls an operator delete in `deletes`.
    """
    complete, deleting = image.pointer(table + 16), image.pointer(table + 24)
    if not all(a is not None and image.executable(a) for a in (complete, deleting)) or complete == deleting:
        return None
    if tail_target(image, deleting) not in deletes or tail_target(image, complete) in deletes:
        return None
    return complete, deleting


def vtable_slots(image, table, limit=512):
    """Return (address point, slot count) of the vtable holding an RTTI table: the code pointers around it."""
    start = end = table
    while table - start < 8 * limit and image.executable(image.pointer(start - 8) or 1):
        start -= 8
    while end - start < 8 * limit and image.executable(image.pointer(end) or 1):
        end += 8
    return start, (end - start) // 8


def vtable_bounds(image, table, limit=512):
    """Return (address point, slot count) of the primary vtable holding an RTTI table, or None.

    Slots run back to the (offset-to-top, null RTTI) header and forward to the
    first entry that is not code. Secondary vtables, with a nonzero offset, are rejected.
    """
    start, count = vtable_slots(image, table, limit)
    if image.pointer(start - 16) != 0 or image.pointer(start - 8) != 0:
        return None
    return start, count


def pointer_chunks(blocks, size=8192):
    """Yield the 8-byte aligned values of the (base, raw) blocks, a tuple at a time."""
    for base, raw in blocks:
        start = -base % 8
        count = (len(raw) - start) // 8
        for index in range(0, count, size):
            yield struct.unpack_from('<%dQ' % min(size, count - index), raw, start + 8 * index)


def virtual_methods(image, rows, structured):
    """Map the functions in primary custom-RTTI vtables to the class whose `this` they take.

    A function that several vtables hold, through inheritance or identical-code
    folding, belongs to their deepest common ancestor, which must be in
    `structured`. A function is left out when its address is also stored
    anywhere else, such as a secondary vtable, another table or a callback,
    because it could then be called with another object.
    """
    chains, classes, slots, secondary, seen = {}, defaultdict(set), Counter(), set(), set()
    for row in rows:
        chains[row['info']] = row['chain']
        primary = vtable_bounds(image, row['vtable'])
        start, count = primary or vtable_slots(image, row['vtable'])
        if (start, count) in seen:
            continue
        seen.add((start, count))
        for index in range(count):
            function = image.pointer(start + 8 * index)
            slots[function] += 1
            if primary:
                classes[function].add(row['info'])
            else:
                secondary.add(function)
    wanted = set(classes) - secondary
    stored = Counter()
    for chunk in pointer_chunks(image.constants + image.tables):
        stored.update([value for value in chunk if value in wanted])
    result = {}
    for function in wanted:
        if stored[function] != slots[function]:
            continue
        owners = [chains[info] for info in classes[function]]
        common = set(owners[0]).intersection(*owners[1:])
        owner = next((info for info in owners[0] if info in common), None)
        if owner in structured:
            result[function] = owner
    return result


def vptr_stores(image, function, end, points, limit=1024):
    """Return the vtable address points in `points` that `function` stores at offset 0 of `this`, in order.

    `this` starts in x0 and follows `mov` copies until it is overwritten or a call
    clobbers x0-x18. Address points are built with ADRP/ADD, or loaded from the GOT
    with ADRP/LDR and adjusted with ADD.
    """
    this, values, result = set([0]), {}, []
    def forget(register):
        this.discard(register)
        values.pop(register, None)
    for pc in range(function, min(end + 1, function + 4 * limit), 4):
        word = image.word(pc)
        if word is None:
            break
        rd, rn = word & 31, (word >> 5) & 31
        if word & 0x9f000000 == 0x90000000:  # adrp xd, page
            forget(rd)
            values[rd] = (pc & ~4095) + (signed(((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2), 21) << 12)
        elif word & 0xffc00000 == 0x91000000 and values.get(rn) is not None:  # add xd, xn, #imm
            value = values[rn] + ((word >> 10) & 4095)
            forget(rd)
            values[rd] = value
        elif word & 0xffc00000 == 0xf9400000 and values.get(rn) is not None:  # ldr xd, [xn, #imm]
            value = image.pointer(values[rn] + ((word >> 10) & 4095) * 8)
            forget(rd)
            values[rd] = value
        elif word & 0xffe0ffe0 == 0xaa0003e0:  # mov xd, xm
            copy = (word >> 16) & 31 in this
            forget(rd)
            if copy:
                this.add(rd)
        elif word & 0xfffffc00 == 0xf9000000 or word & 0xffff8000 == 0xa9000000:  # str/stp at [xn]
            if rn in this and values.get(rd) in points:
                result.append(values[rd])
        elif word & 0xfc000000 == 0x94000000 or word & 0xfffffc1f == 0xd63f0000:  # bl, blr
            for register in range(19):
                forget(register)
        elif word & 0x0a000000 == 0x08000000:  # other loads and stores
            pair = word & 0x3a000000 == 0x28000000
            if (word & 0x00800000 if pair else word & 0x3b200400 == 0x38000400):
                forget(rn)  # pre- or post-indexed base
            if (word & 0x00400000 if pair else (word >> 22) & 3):
                forget(rd)
                if pair:
                    forget((word >> 10) & 31)
        else:
            forget(rd)
    return result


def this_extent(image, function, end, limit=4096):
    """Return the end of the highest field a method reads or writes at a constant offset from `this`.

    Scans the method's body linearly, as vptr_stores does. `this` starts in x0 and
    follows `mov` copies; a call clobbers x0-x18 but not copies kept in x19-x28.
    The result is a lower bound on the object's size.
    """
    this, top = set([0]), 0
    for pc in range(function, min(end + 1, function + 4 * limit), 4):
        word = image.word(pc)
        if word is None:
            break
        rd, rn = word & 31, (word >> 5) & 31
        vector = word & 0x04000000
        if word & 0xffe0ffe0 == 0xaa0003e0:  # mov xd, xm
            copy = (word >> 16) & 31 in this
            this.discard(rd)
            if copy:
                this.add(rd)
        elif word & 0x3b000000 == 0x39000000:  # ldr/str with an unsigned offset
            scale = 16 if vector and (word >> 23) & 1 else 1 << (word >> 30)
            if rn in this:
                top = max(top, ((word >> 10) & 4095) * scale + scale)
            if (word >> 22) & 3 and not vector:
                this.discard(rd)
        elif word & 0x3a000000 == 0x28000000:  # ldp/stp
            scale = 4 << ((word >> 30) & 3 if vector else word >> 31)
            if rn in this and (word >> 23) & 3 == 2:
                top = max(top, signed((word >> 15) & 127, 7) * scale + 2 * scale)
            if word & 0x00800000:
                this.discard(rn)  # pre- or post-indexed base
            if word & 0x00400000 and not vector:
                this.discard(rd)
                this.discard((word >> 10) & 31)
        elif word & 0xfc000000 == 0x94000000 or word & 0xfffffc1f == 0xd63f0000:  # bl, blr
            for register in range(19):
                this.discard(register)
        elif word & 0x0a000000 == 0x08000000:  # other loads and stores
            if word & 0x3b200400 == 0x38000400:
                this.discard(rn)
            if word & 0x3b000000 == 0x18000000 or (word >> 22) & 3 and not vector:  # literal or other load
                this.discard(rd)
        elif word & 0x1c000000 != 0x14000000:  # anything but a branch writes rd
            this.discard(rd)
    return top


def constructed_type(stores, points, chains):
    """Return the type whose constructor made `stores` (from vptr_stores), or None.

    A constructor stores its ancestors' vtables, from inlined parent constructors,
    before its own. A destructor stores them in the opposite order.
    """
    infos = [points[point] for point in stores]
    if not infos or len(set(infos)) != len(infos):
        return None
    chain = chains.get(infos[-1], ())
    return infos[-1] if all(info in chain for info in infos) else None


def class_layouts(image, rows):
    """Plan a structure for each type with a class-size getter.

    Returns {info: dict(size=, parent=, vtable=)}. `parent` is the direct RTTI
    parent when it has a size as well, `vtable` the (address point, slots) of the
    type's only primary vtable, or None.
    """
    sizes, parents, tables = {}, {}, {}
    for row in rows:
        if row.get('identity'):
            sizes[row['info']] = row['identity']['size']
        for child, parent in zip(row['chain'], row['chain'][1:]):
            parents[child] = parent
        bounds = vtable_bounds(image, row['vtable'])
        if bounds is not None:
            tables.setdefault(row['info'], set()).add(bounds)
    result = {}
    for info, size in sizes.items():
        parent = parents.get(info)
        candidates = tables.get(info, ())
        result[info] = dict(size=size, parent=parent if sizes.get(parent, size + 1) <= size else None,
                            vtable=next(iter(candidates)) if len(candidates) == 1 else None)
    return result


def rtti_candidates(image, check_cancel=lambda: None):
    cache, result = {}, []
    for base, raw in image.tables:
        for offset in range((-base) % 8, len(raw) - 23, 8):
            if offset % 0x10000 == 0:
                check_cancel()
            predicate, getter, third = struct.unpack_from('<QQQ', raw, offset)
            if not all(image.executable(a) for a in (predicate, getter, third)):
                continue
            if getter not in cache:
                info = address_getter(image, getter)
                cache[getter] = info if info is not None and image.mutable(info, 8) else None
            if cache[getter] is not None:
                result.append(dict(vtable=base + offset, predicate=predicate, getter=getter, info=cache[getter]))
    return result


def fingerprint(image, function):
    raw = image.read(function, 64)
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def reader_type_names(rows, readers):
    """Name the RTTI type of each BCSV reader after its file, as `Bcsv_<File>`.

    Derived readers inherit getFileName, so a file's vtables can belong to several
    types. Only the type that every other one derives from owns the name; the
    others are `Bcsv_<File>_Derived`, or `Bcsv_<File>_Derived_<type-info>` when
    a file has several, matching AnnotateBCSV's `bcsv::<File>::Derived` classes.
    """
    by_table, result = dict((row['vtable'], row) for row in rows), {}
    for reader in readers:
        chains = dict((by_table[t]['info'], by_table[t]['chain']) for t in reader['vtables'] if t in by_table)
        owners = [info for info in chains if all(info in chain for chain in chains.values())]
        if len(owners) != 1:
            continue
        result[owners[0]] = 'Bcsv_' + reader['name']
        derived = sorted(info for info in chains if info != owners[0])
        for info in derived:
            result[info] = 'Bcsv_%s_Derived' % reader['name'] + ('_%X' % info if len(derived) > 1 else '')
    return result


def type_names(rows, extra=None, existing=None):
    """Pick one name per type-info from getter fingerprints, class-name getters and `extra`.

    `extra` maps type-infos to names found by other recognizers. `existing` maps
    type-infos to names the user already gave them. A name shared by several
    type-infos (nested classes such as Body) gets the address appended.
    """
    evidence = {}
    for row in rows:
        for name in (row.get('name'), (row.get('identity') or {}).get('name')):
            if name:
                evidence.setdefault(row['info'], set()).add(name)
    for info, name in (extra or {}).items():
        evidence.setdefault(info, set()).add(name)
    names, conflicts = {}, []
    for info, values in evidence.items():
        if len(values) == 1:
            names[info] = next(iter(values))
        else:
            conflicts.append('%X: conflicting class names %s' % (info, ', '.join(sorted(values))))
    for info, name in (existing or {}).items():
        names.setdefault(info, name)
    counts = {}
    for name in names.values():
        counts[name] = counts.get(name, 0) + 1
    return dict((info, '%s_%X' % (name, info) if counts[name] > 1 else name) for info, name in names.items()), conflicts
