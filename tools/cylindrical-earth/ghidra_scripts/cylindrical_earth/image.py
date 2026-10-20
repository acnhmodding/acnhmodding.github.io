# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded binary recognition shared by the actor and custom RTTI passes."""
import hashlib
import struct


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
