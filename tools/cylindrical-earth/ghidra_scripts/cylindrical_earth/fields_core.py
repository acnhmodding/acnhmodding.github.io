# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable field merging for class structures; no Ghidra dependency.

Every load or store a method makes through `this` is an observation
(offset, length, kind, key): `kind` is 'int', 'float', 'pointer' or 'other',
and `key` names the type, or the pointed-to type for a pointer (None when it
points to nothing in particular). Untyped accesses are not observations.
"""
from collections import Counter, defaultdict

KINDS = ('int', 'float', 'pointer', 'other')


def agreed_type(found):
    """The (kind, key) a set of observations at one offset agrees on, or None.

    Integers of one size may differ in sign, so the most common wins. Code
    often reads a pointer as an integer, to test or offset it, so integers and
    a pointer to a known type make a pointer; with pointers to nothing in
    particular, the more common kind wins. Pointers to different known types
    fall back to a pointer to nothing in particular. Any other mix of kinds,
    or of other types, disagrees.
    """
    kinds = set(kind for kind, key in found)
    if kinds == set(['int', 'pointer']):
        counts = Counter(kind for kind, key in found)
        known = any(kind == 'pointer' and key is not None for kind, key in found)
        kind = 'pointer' if known or counts['pointer'] >= counts['int'] else 'int'
        found = [(k, key) for k, key in found if k == kind]
        kinds = set([kind])
    if len(kinds) != 1:
        return None
    kind = kinds.pop()
    keys = Counter(key for _, key in found)
    if kind == 'pointer':
        known = set(keys) - set([None])
        return kind, known.pop() if len(known) == 1 else None
    if kind == 'other' and len(keys) > 1:
        return None
    return kind, sorted(keys.items(), key=lambda item: (-item[1], str(item[0])))[0][0]


def merge_fields(observations, free):
    """Return ({offset: (length, kind, key)}, disagreements) for one structure.

    A field is kept when every access at its offset has the same length and an
    agreed type, it overlaps no other access, and `free(offset, length)` says
    those bytes are still undefined.
    """
    found, lengths = defaultdict(list), defaultdict(set)
    for offset, length, kind, key in observations:
        if kind in KINDS and length > 0:
            found[offset].append((kind, key))
            lengths[offset].add(length)
    candidates, disagreements = {}, set()
    for offset in found:
        agreed = agreed_type(found[offset]) if len(lengths[offset]) == 1 else None
        if agreed is None:
            disagreements.add(offset)
        else:
            candidates[offset] = (next(iter(lengths[offset])),) + agreed
    # Overlaps count against every access, including the ones that disagreed.
    reach = None  # the access reaching furthest so far, as (end, offset)
    for offset in sorted(found):
        if reach is not None and offset < reach[0]:
            disagreements.update((reach[1], offset))
        end = offset + max(lengths[offset])
        if reach is None or end > reach[0]:
            reach = (end, offset)
    fields = dict((offset, field) for offset, field in candidates.items()
                  if offset not in disagreements and free(offset, field[0]))
    return fields, sorted(disagreements)
