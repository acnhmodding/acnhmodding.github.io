# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable state-machine recognition; no Ghidra dependency.

The game registers each state of a state manager by passing a SafeString such
as "NpcAIState::cTalk" with the state index, then fills a 0x40-byte delegate:
vtable, owner, and enter/exec/exit pointers-to-member. Everything here works on
values already recovered by emulation, so it can be unit tested directly.
"""
import array
import re
import struct
import sys
from collections import Counter, defaultdict

from .image import signed

REGISTERED_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$')
ROLES = ('Enter', 'Exec', 'Exit')
DELEGATE_SIZE = 0x40


def state_strings(image):
    """Return {address: name} for every NUL-delimited "Prefix::cState" string."""
    pattern = re.compile(br'(?<=\x00)([A-Za-z_][A-Za-z0-9_]*::c[A-Za-z0-9_]+)(?=\x00)')
    result = {}
    for base, raw in image.constants:
        for match in pattern.finditer(raw):
            result[base + match.start(1)] = match.group(1).decode('ascii')
    return result


def words_of(raw):
    words = array.array('I')
    (words.frombytes if hasattr(words, 'frombytes') else words.fromstring)(raw[:len(raw) // 4 * 4])
    if sys.byteorder != 'little':
        words.byteswap()
    return words


def find_registrar(image, check_cancel=lambda: None, window=40):
    """Find the state-name setter as the dominant call after state-name loads.

    Only ADRP+ADD pairs that materialize one of the bundled-shape strings count.
    The registrar must receive at least 90% of those calls; otherwise the
    executable is not recognized and nothing is annotated.
    """
    names = state_strings(image)
    calls, sites = Counter(), defaultdict(list)
    for base, raw in image.texts:
        words = words_of(raw)
        for i in range(len(words) - 1):
            if i % 0x40000 == 0:
                check_cancel()
            w = words[i]
            if w & 0x9F000000 != 0x90000000:
                continue
            add = words[i + 1]
            if add & 0xFF800000 != 0x91000000 or (add >> 5) & 31 != w & 31:
                continue
            pc = base + i * 4
            imm = ((w >> 29) & 3) | (((w >> 5) & 0x7FFFF) << 2)
            target = (pc & ~4095) + (signed(imm, 21) << 12) + ((add >> 10) & 4095)
            if target not in names:
                continue
            for j in range(i + 2, min(i + window, len(words))):
                if words[j] & 0xFC000000 == 0x94000000:
                    callee = base + j * 4 + signed(words[j] & 0x3FFFFFF, 26) * 4
                    calls[callee] += 1
                    sites[callee].append(base + j * 4)
                    break
    total = sum(calls.values())
    if not calls:
        return None
    registrar, count = calls.most_common(1)[0]
    if count < 20 or count * 10 < total * 9:
        return None
    return dict(registrar=registrar, references=count, total=total, names=len(names), sites=sites[registrar])


def member_function(pointer, adjustment, executable):
    """Decode an AArch64 Itanium pointer-to-member-function.

    The low bit of the adjustment marks a virtual call; the pointer is then a
    vtable byte offset. Returns None for an empty slot and raises ValueError for
    values that cannot be a member pointer.
    """
    pointer &= 0xFFFFFFFFFFFFFFFF
    adjustment = signed(adjustment & 0xFFFFFFFFFFFFFFFF, 64)
    this_adjust = adjustment >> 1
    if abs(this_adjust) >= 0x100000:
        raise ValueError('implausible this adjustment')
    if adjustment & 1:
        if pointer % 8 or pointer >= 0x10000:
            raise ValueError('implausible vtable offset')
        return dict(kind='virtual', offset=pointer, adjust=this_adjust)
    if pointer == 0:
        if this_adjust:
            raise ValueError('adjustment without a target')
        return None
    if not executable(pointer):
        raise ValueError('target is not code')
    return dict(kind='direct', target=pointer, adjust=this_adjust)


def delegate_records(written, image):
    """Find delegate-shaped records inside one emulated write segment.

    `written` maps byte addresses to values written during the segment. A record
    needs all 0x40 bytes written, a vtable whose first three methods are code,
    and three valid member pointers of which at least one is set.
    """
    records = []
    for start in sorted(a for a in written if a % 8 == 0):
        if any((start + i) not in written for i in range(DELEGATE_SIZE)):
            continue
        raw = bytearray(written[start + i] for i in range(DELEGATE_SIZE))
        values = struct.unpack('<8Q', bytes(raw))
        vtable, owner = values[0], values[1]
        if not image.table(vtable, 24):
            continue
        if not all(image.executable(image.pointer(vtable + 8 * i) or 1) for i in range(3)):
            continue
        try:
            callbacks = [member_function(values[2 + 2 * i], values[3 + 2 * i], image.executable) for i in range(3)]
        except ValueError:
            continue
        if not any(callbacks):
            continue
        records.append(dict(address=start, vtable=vtable, owner=owner, callbacks=callbacks))
    return records


def assign_delegates(calls, segments, image):
    """Pair registrations with delegates written next to them.

    `segments` has one more entry than `calls`: writes before the first call,
    between calls, and after the last. The source writes each delegate either
    right after or right before its name; the convention that explains more
    registrations wins. Per state manager, every delegate must share one
    vtable and owner; states without exactly one such record are reported.
    """
    found = [delegate_records(segment, image) for segment in segments]
    # Managers reached through uninitialized pointers alias one scratch
    # address; a repeated index for the same address starts another machine.
    seen, generation = defaultdict(set), Counter()
    for call in calls:
        if call['index'] in seen[call['mgr']]:
            generation[call['mgr']] += 1
            seen[call['mgr']] = set()
        seen[call['mgr']].add(call['index'])
        call['group'] = (call['mgr'], generation[call['mgr']])
    best = None
    for name, offset in (('after', 1), ('before', 0)):
        states, missing = [], []
        groups = defaultdict(list)
        for i, call in enumerate(calls):
            groups[call['group']].append(i)
        for mgr, indices in groups.items():
            # The majority vtable/owner pair identifies this manager's delegates.
            votes = Counter((r['vtable'], r['owner']) for i in indices for r in found[i + offset])
            key = votes.most_common(1)[0][0] if votes else None
            for i in indices:
                matches = [r for r in found[i + offset] if (r['vtable'], r['owner']) == key]
                if len(matches) == 1:
                    states.append(dict(calls[i], delegate=matches[0]))
                else:
                    missing.append(dict(calls[i], reason='%d delegate candidates' % len(matches)))
        if best is None or len(states) > len(best[1]):
            best = (name, states, missing)
    return best


def machine_namespaces(machines):
    """Choose a namespace for each machine from its state-name prefixes.

    A prefix such as "NpcAIState" used by one setup function becomes the
    namespace. A generic prefix such as "State" shared by several unrelated
    setup functions gets the setup address appended.
    """
    owners = defaultdict(set)
    for machine in machines:
        owners[machine['prefix']].add(machine['key'])
    result, used = {}, defaultdict(list)
    for machine in machines:
        prefix = machine['prefix']
        unique = len(owners[prefix]) == 1
        result[machine['key']] = prefix if unique else '%s_%X' % (prefix, machine['setup'])
        used[result[machine['key']]].append(machine['key'])
    # One setup can initialize several machines with the same prefix.
    for name, keys in used.items():
        if len(keys) > 1:
            for number, key in enumerate(sorted(keys)):
                result[key] = '%s_%d' % (name, number)
    return result


def plan_names(machines, namespaces):
    """Return ({address: (namespace, name)}, {address: [descriptions]}).

    A callback is named only when every use agrees on one state and role. ICF
    merges identical bodies (for example empty exits) across many states; those
    addresses only receive comments listing their uses.
    """
    uses = defaultdict(set)
    notes = defaultdict(list)
    for machine in machines:
        namespace = namespaces[machine['key']]
        for state in machine['states']:
            label = state['name'].split('::')[-1]
            for role, callback in zip(ROLES, state['delegate']['callbacks']):
                if callback and callback['kind'] == 'direct':
                    uses[callback['target']].add((namespace, '%s_%s' % (label, role)))
                    notes[callback['target']].append('%s %s (state %d, set up by 0x%X)' %
                                                     (state['name'], role.lower(), state['index'], machine['setup']))
                if callback and callback.get('resolved') is not None:
                    uses[callback['resolved']].add((namespace, '%s_%s' % (label, role)))
                    notes[callback['resolved']].append('%s %s via vtable +0x%X (state %d, set up by 0x%X)' %
                                                       (state['name'], role.lower(), callback['offset'],
                                                        state['index'], machine['setup']))
    names = {address: next(iter(choices)) for address, choices in uses.items() if len(choices) == 1}
    return names, notes
