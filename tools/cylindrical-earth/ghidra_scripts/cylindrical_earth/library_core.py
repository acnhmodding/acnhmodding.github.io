# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable library, hot-function and singleton recognition; no Ghidra dependency.

Every rule works on an Image of the module (code, constants and tables) and
returns plain data. Addresses are absolute, so the same code serves a program
based at 0x7100000000 and test fixtures based at 0.
"""
import hashlib
import json
import os
import re
import struct
from collections import Counter, defaultdict

from .image import address_getter, pointer_chunks, reader_classes, signed
from .state_core import words_of

DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_JMPREL = 2, 5, 6, 10, 23
R_AARCH64_JUMP_SLOT = 1026
RET = 0xd65f03c0
# `Class::method` names given to delegates and threads. State names such as
# `Class::cIdle` name a nested state class instead, so they are left out.
DELEGATE_NAME = re.compile(r'^((?:[A-Z]\w*::)*[A-Z]\w*)::(?!c[A-Z])[A-Za-z_]\w*$')
GET_FILE_NAME = 0x30
READER_SLOTS = 9
# x0-x18 do not survive a call.
CALL_CLOBBERED = range(19)


def library_definitions(directory):
    with open(os.path.join(directory, 'cylindrical_earth', 'library.json'), 'r') as source:
        result = json.load(source)
    if result.get('formatVersion') != 1:
        raise ValueError('Unsupported library definitions')
    return result


def module_header(image):
    """Return the MOD0 header of the module whose text starts an Image block.

    The second word of a Switch module points (relative to the module start) to
    "MOD0", followed by the relative offsets of .dynamic, .bss and
    .eh_frame_hdr. Returns None when no text block carries one.
    """
    for base, raw in image.texts:
        if len(raw) < 8:
            continue
        offset = struct.unpack_from('<I', raw, 4)[0]
        header = image.read(base + offset, 28)
        if header is None or header[:4] != b'MOD0':
            continue
        values = struct.unpack_from('<6i', header, 4)
        names = ('dynamic', 'bssStart', 'bssEnd', 'ehFrameHdrStart', 'ehFrameHdrEnd', 'moduleObject')
        result = dict((name, base + offset + value) for name, value in zip(names, values))
        result['base'] = base
        return result
    return None


def dynamic_tags(image, header):
    tags = defaultdict(list)
    address = header['dynamic']
    for _ in range(512):
        raw = image.read(address, 16)
        if raw is None:
            return None
        tag, value = struct.unpack('<qQ', raw)
        if tag == 0:
            return tags
        tags[tag].append(value)
        address += 16
    return None


def dynamic_symbols(image, header=None):
    """Return (exports, imports) from the dynamic symbol table.

    exports maps defined function addresses to mangled names; imports maps
    each JUMP_SLOT GOT entry to the mangled name of the imported function.
    """
    header = header or module_header(image)
    tags = dynamic_tags(image, header) if header else None
    if not tags or not all(tags.get(t) for t in (DT_SYMTAB, DT_STRTAB, DT_STRSZ)):
        return {}, {}
    base = header['base']
    symtab, strtab, strsz = base + tags[DT_SYMTAB][0], base + tags[DT_STRTAB][0], tags[DT_STRSZ][0]
    strings = image.read(strtab, strsz)
    if strings is None or symtab >= strtab:
        return {}, {}

    def symbol(index):
        raw = image.read(symtab + index * 24, 24)
        if raw is None:
            return None
        name, info, other, section, value, size = struct.unpack('<IBBHQQ', raw)
        end = strings.find(b'\0', name)
        if end < 0:
            return None
        return strings[name:end].decode('ascii', 'replace'), info & 15, section, value

    exports = {}
    for index in range(1, (strtab - symtab) // 24):
        row = symbol(index)
        # STT_FUNC symbols defined in this module.
        if row and row[1] == 2 and row[2] and row[0] and image.executable(base + row[3]):
            exports[base + row[3]] = row[0]
    imports = {}
    if tags.get(DT_JMPREL) and tags.get(DT_PLTRELSZ):
        start = base + tags[DT_JMPREL][0]
        for offset in range(0, tags[DT_PLTRELSZ][0] - 23, 24):
            raw = image.read(start + offset, 24)
            if raw is None:
                break
            where, info, addend = struct.unpack('<QQq', raw)
            if info & 0xffffffff != R_AARCH64_JUMP_SLOT:
                continue
            row = symbol(info >> 32)
            if row and row[0]:
                imports[base + where] = row[0]
    return exports, imports


def adrp_target(pc, word):
    imm = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2)
    return (pc & ~4095) + (signed(imm, 21) << 12)


def plt_stubs(image, imports):
    """Map PLT stubs (ADRP x16; LDR x17, [x16]; ADD x16; BR x17) to imports."""
    result = {}
    for base, raw in image.texts:
        words = words_of(raw)
        for i in range(len(words) - 3):
            w = words[i]
            if w & 0x9f00001f != 0x90000010 or words[i + 3] != 0xd61f0220:
                continue
            load, add = words[i + 1], words[i + 2]
            if load & 0xffc003ff != 0xf9400211 or add & 0xffc003ff != 0x91000210:
                continue
            page = adrp_target(base + i * 4, w)
            slot = page + ((load >> 10) & 4095) * 8
            if slot == page + ((add >> 10) & 4095) and slot in imports:
                result[base + i * 4] = imports[slot]
    return result


def fde_ranges(image, header=None):
    """Return sorted [(start, end)] function ranges from .eh_frame_hdr."""
    header = header or module_header(image)
    if header is None:
        return []
    hdr = header['ehFrameHdrStart']
    raw = image.read(hdr, 12)
    if raw is None:
        return []
    version, frame, count_encoding, table_encoding = struct.unpack_from('<4B', raw)
    # Version 1 with a udata4 count and a datarel sdata4 binary-search table.
    if (version, count_encoding, table_encoding) != (1, 0x03, 0x3b):
        return []
    count = struct.unpack_from('<I', raw, 8)[0]
    table = image.read(hdr + 12, count * 8)
    if table is None:
        return []
    result = set()
    for i in range(count):
        start, fde = (hdr + v for v in struct.unpack_from('<ii', table, i * 8))
        entry = image.read(fde + 8, 8)
        if entry is None:
            continue
        begin, length = struct.unpack('<ii', entry)
        if fde + 8 + begin == start and length > 0:
            result.add((start, start + length))
    return sorted(result)


def call_counts(image, check_cancel=lambda: None):
    """Count direct BL call sites per target."""
    counts = Counter()
    for base, raw in image.texts:
        words = words_of(raw)
        for i, w in enumerate(words):
            if i % 0x40000 == 0:
                check_cancel()
            if w & 0xfc000000 == 0x94000000:
                counts[base + i * 4 + signed(w & 0x3ffffff, 26) * 4] += 1
    return counts


def branch_target(pc, word):
    return pc + signed(word & 0x3ffffff, 26) * 4


def is_store(w):
    """LDR/STR (unsigned offset) family with the load bit clear."""
    return w & 0x3b000000 == 0x39000000 and not w & 0x00400000


def masked_tokens(image, start, end, names):
    """Return the instructions of [start, end) with module addresses masked.

    ADRP pages, the low 12 bits added or loaded through such a page, ADR and
    literal loads are masked so a fingerprint survives relinking. Branches
    that leave the function become the callee's known name, or '?'.
    """
    raw = image.read(start, end - start)
    if raw is None:
        return None
    pages, tokens = set(), []
    for i, w in enumerate(words_of(raw)):
        pc = start + i * 4
        rd, rn = w & 31, (w >> 5) & 31
        if w & 0x9f000000 == 0x90000000:  # ADRP
            tokens.append('%08x' % (w & 0x9f00001f))
            pages.add(rd)
            continue
        if w & 0x7c000000 == 0x14000000:  # B, BL
            target = branch_target(pc, w)
            if not w >> 31 and start <= target < end:
                tokens.append('%08x' % w)
            else:
                tokens.append('%s %s' % ('bl' if w >> 31 else 'b', names.get(target, '?')))
            if w >> 31:
                pages.difference_update(CALL_CLOBBERED)
            continue
        if w & 0x9f000000 == 0x10000000:  # ADR
            w &= 0x9f00001f
        elif w & 0x3b000000 == 0x18000000:  # LDR (literal)
            w &= 0xff00001f
        elif rn in pages and (w & 0x7f800000 == 0x11000000 or w & 0x3b000000 == 0x39000000):
            w &= 0xffc003ff  # ADD (immediate) or LDR/STR (unsigned offset) from a page
        tokens.append('%08x' % w)
        if rd in pages and not is_store(w):
            pages.discard(rd)
    return tokens


def fingerprint(image, start, end, names):
    tokens = masked_tokens(image, start, end, names)
    if tokens is None:
        return None
    return hashlib.sha1('\n'.join(tokens).encode('utf-8')).hexdigest()[:20]


def match_library(image, ranges, entries, names, check_cancel=lambda: None):
    """Match fingerprint entries against function ranges.

    entries are {name, size, hash}. A match is accepted only when exactly one
    function carries the fingerprint. Matching repeats until no new names are
    found, because fingerprints refer to callees by name. Returns
    (matches {address: entry}, problems [message]).
    """
    sizes = defaultdict(list)
    for start, end in ranges:
        sizes[end - start].append(start)
    known = dict(names)
    matches, problems = {}, []
    pending = list(entries)
    while pending:
        check_cancel()
        found, left = {}, []
        for entry in pending:
            hits = [s for s in sizes.get(entry['size'], ())
                    if fingerprint(image, s, s + entry['size'], known) == entry['hash']]
            if len(hits) == 1 and hits[0] not in matches and hits[0] not in found:
                found[hits[0]] = entry
            else:
                left.append((entry, len(hits)))
        if not found:
            problems.extend('%s: %d matching functions' % (entry['name'], count) for entry, count in left)
            break
        for address, entry in found.items():
            matches[address] = entry
            known[address] = entry['name']
        pending = [entry for entry, count in left]
    return matches, problems


def wide_move(w):
    """Return (register, value) for MOVZ/MOVN, or None."""
    if w & 0x7f800000 not in (0x52800000, 0x12800000):
        return None
    value = ((w >> 5) & 0xffff) << (((w >> 21) & 3) * 16)
    if w & 0x7f800000 == 0x12800000:
        value = ~value & (0xffffffffffffffff if w >> 31 else 0xffffffff)
    return w & 31, value


def shape(image, start, end):
    """Classify a trivial body.

    Returns ('nop',), ('constant', value), ('field', offset, size) or
    ('thunk', target), or None for anything else.
    """
    raw = image.read(start, end - start)
    if raw is None or not 4 <= end - start <= 8:
        return None
    words = list(words_of(raw))
    if words == [RET]:
        return ('nop',)
    if len(words) == 1 and words[0] & 0xfc000000 == 0x14000000:
        return ('thunk', branch_target(start, words[0]))
    if len(words) != 2 or words[1] != RET:
        return None
    w = words[0]
    move = wide_move(w)
    if move and move[0] == 0:
        return ('constant', move[1])
    if w & 0xbfc003ff == 0xb9400000:  # LDR w0/x0, [x0, #imm]
        size = 8 if w & 0x40000000 else 4
        return ('field', ((w >> 10) & 4095) * size, size)
    if w & 0xffc003ff == 0x39400000:  # LDRB w0, [x0, #imm]
        return ('field', (w >> 10) & 4095, 1)
    return None


def shape_name(kind, address):
    if kind[0] == 'nop':
        return 'ACNH_Nop_%X' % address
    if kind[0] == 'constant':
        return 'ACNH_Return_0x%X_%X' % (kind[1], address)
    if kind[0] == 'field':
        return 'ACNH_GetField%d_0x%X_%X' % (kind[2] * 8, kind[1], address)
    return None


def hot_functions(counts, ranges, minimum):
    """Return [(address, call sites)] for function starts, most called first."""
    starts = set(start for start, end in ranges)
    rows = [(address, count) for address, count in counts.items() if count >= minimum and address in starts]
    return sorted(rows, key=lambda row: (-row[1], row[0]))


def callers(image, ranges, target, check_cancel=lambda: None):
    """Return the ranges whose body contains a BL to target."""
    result = []
    for index, (start, end) in enumerate(ranges):
        if index % 4096 == 0:
            check_cancel()
        raw = image.read(start, end - start)
        if raw is None:
            continue
        for i, w in enumerate(words_of(raw)):
            if w & 0xfc000000 == 0x94000000 and branch_target(start + i * 4, w) == target:
                result.append((start, end))
                break
    return result


def in_bss(header, address):
    return address is not None and header is not None and header['bssStart'] <= address < header['bssEnd']


def singleton_creator(image, header, start, end, disposer_ctor, known=()):
    """Recognize a sead createInstance(Heap*) body by linear register tracking.

    Expected flow: load sInstance and branch on it, allocate the object,
    construct its embedded SingletonDisposer through
    IDisposer(Heap*, HeapNullOption), store the disposer address to
    sSingletonDisposer_, and store the object to the sInstance it checked.
    Allocation paths join on the object register, so a linear walk suffices.
    Returns a dict or None.
    """
    raw = image.read(start, end - start)
    if raw is None:
        return None
    regs, immediates = {}, {}
    checked, stores, vtables = set(), {}, []
    disposer, constructor, size = None, None, None

    def location(base, offset):
        kind = regs.get(base)
        return kind[1] + offset if kind and kind[0] in ('page', 'addr') else None

    for i, w in enumerate(words_of(raw)):
        pc = start + i * 4
        rd, rn = w & 31, (w >> 5) & 31
        if w & 0x9f000000 == 0x90000000:  # ADRP
            regs[rd] = ('page', adrp_target(pc, w))
            immediates.pop(rd, None)
        elif w & 0xff800000 == 0x91000000:  # ADD Xd, Xn, #imm
            imm = ((w >> 10) & 4095) << (12 if w & 0x00400000 else 0)
            kind = regs.get(rn)
            if kind and kind[0] in ('page', 'addr'):
                regs[rd] = ('addr', kind[1] + imm)
            elif kind and kind[0] == 'object':
                regs[rd] = ('field', kind[1], imm)
            elif kind and kind[0] == 'field':
                regs[rd] = ('field', kind[1], kind[2] + imm)
            else:
                regs.pop(rd, None)
            immediates.pop(rd, None)
        elif w & 0xff20fc00 == 0x8b000000:  # ADD Xd, Xn, Xm (large field offsets)
            kind, rm = regs.get(rn), (w >> 16) & 31
            if kind and kind[0] == 'object' and rm in immediates:
                regs[rd] = ('field', kind[1], immediates[rm])
            else:
                regs.pop(rd, None)
            immediates.pop(rd, None)
        elif w & 0x7fe0ffe0 == 0x2a0003e0:  # MOV Rd, Rm
            rm = (w >> 16) & 31
            for table in (regs, immediates):
                if rm in table and w >> 31:
                    table[rd] = table[rm]
                else:
                    table.pop(rd, None)
        elif wide_move(w):
            register, value = wide_move(w)
            regs.pop(register, None)
            immediates[register] = value
        elif w & 0x7f800000 == 0x72800000:  # MOVK
            shift = ((w >> 21) & 3) * 16
            if rd in immediates:
                immediates[rd] = immediates[rd] & ~(0xffff << shift) | ((w >> 5) & 0xffff) << shift
        elif w & 0xffc00000 == 0xf9400000:  # LDR Xt, [Xn, #imm]
            where = location(rn, ((w >> 10) & 4095) * 8)
            regs.pop(rd, None)
            immediates.pop(rd, None)
            if in_bss(header, where):
                regs[rd] = ('global', where)
            elif where is not None and in_bss(header, image.pointer(where)):
                regs[rd] = ('addr', image.pointer(where))  # GOT slot of a .bss global
        elif w & 0xffc00000 == 0xf9000000:  # STR Xt, [Xn, #imm]
            offset = ((w >> 10) & 4095) * 8
            value, base, where = regs.get(rd), regs.get(rn), location(rn, offset)
            if in_bss(header, where) and value:
                stores[where] = value
            elif base and base[0] in ('object', 'field') and value and value[0] == 'addr':
                at = offset + (base[2] if base[0] == 'field' else 0)
                vtables.append((base[1], at, value[1]))
        elif w & 0xfe000000 == 0xb4000000:  # CBZ/CBNZ Xt
            kind = regs.get(rd)
            if kind and kind[0] == 'global':
                checked.add(kind[1])
        elif w & 0xfc000000 == 0x94000000 or w & 0xfffffc1f == 0xd63f0000:  # BL, BLR
            target = branch_target(pc, w) if w & 0xfc000000 == 0x94000000 else None
            first = regs.get(0)
            if target is not None and target == disposer_ctor and disposer is None:
                if first and first[0] == 'field':
                    disposer = (first[1], first[2])
                elif first and first[0] == 'object':
                    disposer = (first[1], 0)
            elif target is not None and disposer is not None and constructor is None and first == ('object', disposer[0]):
                constructor = target if target not in known else False
            if disposer is None:
                # malloc(size) or heap->tryAlloc(size, alignment)
                allocation = immediates.get(1 if target is None else 0)
                size = allocation if allocation else size
            for register in CALL_CLOBBERED:
                regs.pop(register, None)
                immediates.pop(register, None)
            regs[0] = ('object', pc)
        elif w & 0x7c000000 == 0x14000000 or w == RET or w & 0x7e000000 == 0x34000000 or w & 0xff000010 == 0x54000000:
            pass  # branches leave registers unchanged
        elif is_store(w) or w & 0x7e400000 in (0x28000000, 0x2c000000):
            pass  # stores and STP leave registers unchanged
        else:
            regs.pop(rd, None)
            immediates.pop(rd, None)
            if w & 0x7e400000 in (0x28400000, 0x2c400000):  # LDP also writes Rt2
                regs.pop((w >> 10) & 31, None)
                immediates.pop((w >> 10) & 31, None)
    if disposer is None:
        return None
    instance = [g for g in sorted(checked) if stores.get(g) == ('object', disposer[0])]
    holders = [g for g, v in sorted(stores.items()) if v == ('field', disposer[0], disposer[1])]
    if len(instance) != 1 or len(holders) > 1:
        return None
    def vtable(at):
        found = set(v for obj, offset, v in vtables if obj == disposer[0] and offset == at and image.table(v, 8))
        return found.pop() if len(found) == 1 else None
    return dict(function=start, instance=instance[0], disposer=holders[0] if holders else None,
                disposerOffset=disposer[1], size=size, constructor=constructor or None,
                vtable=vtable(0) if disposer[1] else None, disposerVtable=vtable(disposer[1]))


def singletons(image, header, ranges, disposer_ctor, known=(), check_cancel=lambda: None):
    """Recognize every createInstance among the callers of the disposer ctor.

    known holds library functions (memset, ...) that are never a constructor.
    A global claimed by two creators is dropped.
    """
    rows = []
    for start, end in callers(image, ranges, disposer_ctor, check_cancel):
        row = singleton_creator(image, header, start, end, disposer_ctor, known)
        if row is not None:
            rows.append(row)
    counts = Counter(row['instance'] for row in rows)
    rows = [row for row in rows if counts[row['instance']] == 1]
    # A constructor that was not inlined stores the vtable itself. A constructor
    # or vtable two singletons share is a base class's.
    ends, shared, found = dict(ranges), Counter(row['constructor'] for row in rows), {}
    for row in rows:
        start = row['constructor']
        if row['vtable'] is None and row['disposerOffset'] and start in ends and shared[start] == 1:
            found[row['instance']] = constructor_vtable(image, start, ends[start])
    tables = Counter(row['vtable'] or found.get(row['instance']) for row in rows)
    for row in rows:
        table = found.get(row['instance'])
        if table is not None and tables[table] == 1:
            row['vtable'] = table
    return rows


def constructor_vtable(image, start, end):
    """Return the vtable a constructor stores last at offset 0 of `this`, or None.

    Parent constructors, called or inlined, store their vtables first, so the
    class's own comes last. `this` arrives in x0 and may be copied to a
    callee-saved register. The vtable address is built with ADRP; ADD, or
    loaded from a GOT slot and moved to its address point with ADD.
    """
    raw = image.read(start, end - start)
    if raw is None:
        return None
    this, addresses, found = set([0]), {}, None
    for i, w in enumerate(words_of(raw)):
        pc = start + i * 4
        rd, rn = w & 31, (w >> 5) & 31
        stored = None
        if w & 0x3b200400 == 0x38000400 or w & 0x3a800000 == 0x28800000:  # pre- or post-index: Xn moves
            for register in (rn,) + ((rd, (w >> 10) & 31) if w & 0x00400000 else ()):
                this.discard(register)
                addresses.pop(register, None)
            continue
        if w & 0x9f000000 == 0x90000000:  # ADRP
            value = adrp_target(pc, w)
        elif w & 0xff800000 == 0x91000000:  # ADD Xd, Xn, #imm
            base = addresses.get(rn)
            value = base + (((w >> 10) & 4095) << (12 if w & 0x00400000 else 0)) if base is not None else None
        elif w & 0xffc00000 == 0xf9400000:  # LDR Xt, [Xn, #imm]
            base = addresses.get(rn)
            value = image.pointer(base + ((w >> 10) & 4095) * 8) if base is not None else None
            value = value if value is not None and image.table(value, 8) else None
        elif w & 0x7fe0ffe0 == 0x2a0003e0 and w >> 31:  # MOV Xd, Xm
            rm = (w >> 16) & 31
            if rm in this:
                this.add(rd)
                addresses.pop(rd, None)
                continue
            value = addresses.get(rm)
        elif w & 0xffc00000 == 0xf9000000:  # STR Xt, [Xn, #imm]
            if (w >> 10) & 4095:
                continue
            stored = rd
        elif w & 0xffff8000 == 0xa9000000:  # STP Xt, Xt2, [Xn] with no offset
            stored = rd
        elif w & 0xfc000000 == 0x94000000 or w & 0xfffffc1f == 0xd63f0000:  # BL, BLR
            for register in CALL_CLOBBERED:
                this.discard(register)
                addresses.pop(register, None)
            continue
        elif w & 0x7c000000 == 0x14000000 or w == RET or w & 0x7e000000 == 0x34000000 or w & 0xff000010 == 0x54000000:
            continue  # branches leave registers unchanged
        elif is_store(w) or w & 0x7e400000 in (0x28000000, 0x2c000000):
            continue  # other stores and STP leave registers unchanged
        else:
            value = None
            if w & 0x7e400000 in (0x28400000, 0x2c400000):  # LDP also writes Rt2
                this.discard((w >> 10) & 31)
                addresses.pop((w >> 10) & 31, None)
        if stored is not None:
            value = addresses.get(stored)
            if rn in this and value is not None and image.executable(image.pointer(value) or 0):
                found = value
            continue
        this.discard(rd)
        if value is None:
            addresses.pop(rd, None)
        else:
            addresses[rd] = value
    return found


def instance_calls(image, ranges, instances, check_cancel=lambda: None):
    """Classify what x0 holds at every direct call and tail call by linear register tracking.

    Returns (calls, escaped). calls maps each target to the set of what its
    call sites pass in x0: ('instance', sInstance) when the value loaded from
    a singleton's sInstance, directly or through its GOT slot; ('entry',
    caller) when the caller's own x0, unchanged or copied; None for anything
    else. escaped holds function starts whose address the code builds, so
    they may also be called through a pointer.
    """
    starts = set(start for start, end in ranges)
    calls, escaped = defaultdict(set), set()
    for index, (start, end) in enumerate(ranges):
        if index % 4096 == 0:
            check_cancel()
        raw = image.read(start, end - start)
        if raw is None:
            continue
        regs, slots = {0: ('entry', start)}, {}
        for i, w in enumerate(words_of(raw)):
            pc = start + i * 4
            rd, rn = w & 31, (w >> 5) & 31
            top = w & 0xfc000000
            slot = stack_slot(w)
            if slot is not None:  # spills and reloads through sp or x29
                kind, offset, pair = slot
                registers = (rd, (w >> 10) & 31) if pair else (rd,)
                for index, register in enumerate(registers):
                    if kind == 'store':
                        value = regs.get(register) if register != 31 else None
                        if value:
                            slots[(rn, offset + index * 8)] = value
                        else:
                            slots.pop((rn, offset + index * 8), None)
                    elif slots.get((rn, offset + index * 8)):
                        regs[register] = slots[(rn, offset + index * 8)]
                    else:
                        regs.pop(register, None)
                continue
            if top == 0x94000000 or top == 0x14000000:  # BL, B
                target = branch_target(pc, w)
                if top == 0x94000000 or target in starts and not start <= target < end:
                    calls[target].add(regs.get(0))
                if top == 0x94000000:
                    for register in CALL_CLOBBERED:
                        regs.pop(register, None)
                continue
            if w & 0x3b200400 == 0x38000400 or w & 0x3a800000 == 0x28800000:  # pre- or post-index: Xn moves
                for register in (rn,) + ((rd, (w >> 10) & 31) if w & 0x00400000 else ()):
                    regs.pop(register, None)
                continue
            if w & 0x9f000000 == 0x90000000:  # ADRP
                regs[rd] = ('page', adrp_target(pc, w))
                continue
            if w & 0x9f000000 == 0x10000000:  # ADR
                value = pc + signed(((w >> 29) & 3) | (((w >> 5) & 0x7ffff) << 2), 21)
                if value in starts:
                    escaped.add(value)
                regs[rd] = ('addr', value)
                continue
            if w & 0xff800000 == 0x91000000:  # ADD Xd, Xn, #imm
                kind = regs.get(rn)
                if kind and kind[0] in ('page', 'addr'):
                    value = kind[1] + (((w >> 10) & 4095) << (12 if w & 0x00400000 else 0))
                    if value in starts:
                        escaped.add(value)
                    regs[rd] = ('addr', value)
                else:
                    regs.pop(rd, None)
                continue
            if w & 0xffe0ffe0 == 0xaa0003e0:  # MOV Xd, Xm
                kind = regs.get((w >> 16) & 31)
                if kind:
                    regs[rd] = kind
                else:
                    regs.pop(rd, None)
                continue
            if w & 0xffc00000 == 0xf9400000:  # LDR Xt, [Xn, #imm]
                kind = regs.get(rn)
                where = kind[1] + ((w >> 10) & 4095) * 8 if kind and kind[0] in ('page', 'addr') else None
                regs.pop(rd, None)
                if where in instances:
                    regs[rd] = ('instance', where)
                elif where is not None:
                    value = image.pointer(where)
                    if value in instances:
                        regs[rd] = ('addr', value)  # GOT slot of an sInstance
                continue
            if w & 0xfffffc1f == 0xd63f0000:  # BLR
                for register in CALL_CLOBBERED:
                    regs.pop(register, None)
                continue
            if w & 0x7e000000 == 0x34000000 or w & 0xff000010 == 0x54000000 or w & 0xfffffc1f in (0xd65f0000, 0xd61f0000):
                continue  # conditional branches, RET and BR leave registers unchanged
            if is_store(w) or w & 0x7e400000 in (0x28000000, 0x2c000000):
                continue  # stores and STP leave registers unchanged
            regs.pop(rd, None)
            if rd == 31:  # sp moved
                slots = dict((key, value) for key, value in slots.items() if key[0] != 31)
            if w & 0x7e400000 in (0x28400000, 0x2c400000):  # LDP also writes Rt2
                regs.pop((w >> 10) & 31, None)
    return calls, escaped


def stack_slot(w):
    """Return ('store' or 'load', offset, pair) for a 64-bit STR/LDR/STUR/LDUR/STP/LDP at [sp or x29, #offset], or None."""
    if (w >> 5) & 31 not in (29, 31):
        return None
    if w & 0xff800000 == 0xf9000000:  # STR/LDR Xt, [Xn, #imm]
        return ('load' if w & 0x00400000 else 'store', ((w >> 10) & 4095) * 8, False)
    if w & 0xffa00c00 == 0xf8000000:  # STUR/LDUR Xt, [Xn, #simm]
        return ('load' if w & 0x00400000 else 'store', signed((w >> 12) & 511, 9), False)
    if w & 0xff800000 == 0xa9000000:  # STP/LDP Xt, Xt2, [Xn, #simm] with no write-back
        return ('load' if w & 0x00400000 else 'store', signed((w >> 15) & 127, 7) * 8, True)
    return None


def reads_first_argument(image, start, end):
    """True when the function reads x0 before anything writes it, walking linearly.

    A call or tail call passes x0 on, so it counts as a read. Instructions it
    does not recognize are skipped.
    """
    raw = image.read(start, end - start)
    if raw is None:
        return False
    for i, w in enumerate(words_of(raw)):
        rd, rn = w & 31, (w >> 5) & 31
        if w & 0xfc000000 == 0x14000000 and start <= branch_target(start + i * 4, w) < end:
            continue  # a branch within the function
        if w & 0x7c000000 == 0x14000000 or w & 0xfffffc1f in (0xd63f0000, 0xd61f0000):  # tail call, BL, BLR, BR
            return True
        if w & 0xfffffc1f == 0xd65f0000:  # RET
            return False
        if w & 0x7e000000 == 0x34000000 or w & 0x7e000000 == 0x36000000:  # CBZ/CBNZ, TBZ/TBNZ
            if rd == 0:
                return True
            continue
        if w & 0x0a000000 == 0x08000000:  # loads and stores
            vector, load = w & 0x04000000, w & 0x00400000
            pair = w & 0x38000000 == 0x28000000
            if rn == 0 or not vector and not load and (rd == 0 or pair and (w >> 10) & 31 == 0):
                return True
            if w & 0x3b000000 == 0x38000000 and w & 0x00200c00 == 0x00200800 and (w >> 16) & 31 == 0:
                return True  # register offset
            if not vector and load and (rd == 0 or pair and (w >> 10) & 31 == 0):
                return False
            continue
        if w & 0x1f000000 == 0x11000000 or w & 0x1f800000 == 0x12000000:  # ADD/SUB (immediate), logical (immediate)
            if rn == 0:
                return True
            if rd == 0:
                return False
            continue
        if w & 0x1f000000 in (0x0a000000, 0x0b000000) or w & 0x1fe00000 == 0x1a000000:  # logical, add/sub (register), adc/csel family
            if rn == 0 or (w >> 16) & 31 == 0:
                return True
            if rd == 0:
                return False
            continue
        if w & 0x1f000000 == 0x10000000 or wide_move(w) or w & 0x9f800000 == 0x92800000:  # ADR, ADRP, MOVZ/MOVN
            if rd == 0:
                return False
    return False


def instance_methods(image, ranges, rows, excluded=(), check_cancel=lambda: None):
    """Return {function: sInstance} for functions every caller passes that singleton as x0.

    Each direct call or tail call must pass the singleton's sInstance, or the
    x0 of a function already found to belong to it. The function must read
    x0, and its address must not be taken in code or stored in data, where a
    vtable or callback could pass it another object. excluded holds
    functions never moved, such as library code and the singletons' own
    createInstance and constructors.
    """
    instances = set(row['instance'] for row in rows)
    calls, escaped = instance_calls(image, ranges, instances, check_cancel)
    ends = dict(ranges)
    candidates = dict((target, sources) for target, sources in calls.items()
                      if target in ends and target not in excluded and target not in escaped and None not in sources)
    code = set(base for base, raw in image.texts)
    rejected = stored(((base, raw) for base, raw in image.blocks if base not in code), candidates)
    result = {}
    changed = True
    while changed:
        changed = False
        for target, sources in candidates.items():
            if target in result or target in rejected:
                continue
            owners = set()
            for kind, value in sources:
                if kind == 'instance':
                    owners.add(value)
                elif value in result:
                    owners.add(result[value])
                elif value != target:
                    owners.add(None)  # passed on by a caller not known to be a method
            if len(owners) != 1 or None in owners:
                continue
            if not reads_first_argument(image, target, ends[target]):
                rejected.add(target)
                continue
            result[target] = owners.pop()
            changed = True
    return result


def stored(blocks, addresses):
    """Return the addresses stored as 8-byte aligned pointers in the (base, raw) data blocks."""
    addresses, found = set(addresses), set()
    for chunk in pointer_chunks(blocks):
        found.update(addresses.intersection(chunk))
    return found


def instance_getter(image, start, end):
    """Return the global whose value a short getter returns, or None.

    Shapes: ADRP xN; LDR x0, [xN, #o]; RET and the GOT form
    ADRP xN; LDR xN, [xN, #o]; LDR x0, [xN]; RET.
    """
    raw = image.read(start, end - start)
    if raw is None or len(raw) not in (12, 16):
        return None
    words = words_of(raw)
    if words[-1] != RET or words[0] & 0x9f000000 != 0x90000000:
        return None
    page, base, load = adrp_target(start, words[0]), words[0] & 31, words[1]
    if load & 0xffc00000 != 0xf9400000 or (load >> 5) & 31 != base:
        return None
    where = page + ((load >> 10) & 4095) * 8
    if len(words) == 3:
        return where if load & 31 == 0 else None
    if words[2] != 0xf9400000 | ((load & 31) << 5):
        return None
    return image.pointer(where)


def string_references(image, start, end):
    """Return the strings whose address the code builds with ADRP; ADD, in order."""
    raw = image.read(start, end - start)
    if raw is None:
        return []
    pages, result = {}, []
    for i, w in enumerate(words_of(raw)):
        if w & 0x9f000000 == 0x90000000:
            pages[w & 31] = adrp_target(start + i * 4, w)
        elif w & 0xffc00000 == 0x91000000 and (w >> 5) & 31 in pages:
            value = image.string(pages[(w >> 5) & 31] + ((w >> 10) & 4095))
            if value:
                result.append(value)
    return result


def delegate_class(image, ranges):
    """Return the class that most `Class::method` strings in these functions name, or None on a tie."""
    counts = Counter()
    for start, end in ranges:
        for value in string_references(image, start, end):
            match = DELEGATE_NAME.match(value)
            if match:
                counts[match.group(1)] += 1
    top = counts.most_common(2)
    if not top or len(top) == 2 and top[0][1] == top[1][1]:
        return None
    return top[0][0]


def bcsv_file_name(image, getter):
    """Return the file a reader's GetFileName returns, without `.bcsv`, or None."""
    value = address_getter(image, getter) if getter is not None else None
    value = image.string(value) if value is not None else None
    return value[:-5] if value and re.match(r'^\w+\.bcsv$', value) else None


def reader_singletons(image, rows):
    """Return {sInstance: class parts} for singletons whose vtable is a BCSV reader's.

    The parts are ('bcsv', file) for the reader itself and ('bcsv', file,
    'Derived') for a class derived from it, `Derived_<type-info>` when the file
    has several, the same names the BCSV script gives these classes.
    """
    files = {}
    for row in rows:
        if row['vtable'] is not None:
            getter = image.pointer(row['vtable'] + GET_FILE_NAME)
            name = bcsv_file_name(image, getter)
            if name is not None:
                files[row['instance']] = (row['vtable'], getter, name)
    getters = set(getter for table, getter, name in files.values())
    tables = defaultdict(list)
    for base, raw in image.tables:
        for offset in range(GET_FILE_NAME, len(raw) - 7, 8):
            value = struct.unpack_from('<Q', raw, offset)[0]
            table = base + offset - GET_FILE_NAME
            if value in getters and all(image.executable(image.pointer(table + 8 * slot) or 1) for slot in range(READER_SLOTS)):
                tables[value].append(table)
    result = {}
    for instance, (table, getter, name) in files.items():
        base, infos = reader_classes(image, tables[getter])
        if base is None or infos.get(table) is None:
            continue
        derived = sorted(set(info for info in infos.values() if info != base))
        if infos[table] == base:
            result[instance] = ('bcsv', name)
        else:
            result[instance] = ('bcsv', name, 'Derived' if len(derived) == 1 else 'Derived_%X' % infos[table])
    return result
