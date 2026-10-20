# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Name state-machine callbacks from their registered state names."""
from __future__ import print_function
import struct
from collections import Counter, defaultdict
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.data import (
    CategoryPath, DataTypeConflictHandler, EnumDataType, PointerDataType,
    IntegerDataType, UnsignedCharDataType, UnsignedIntegerDataType,
    UnsignedLongLongDataType, VoidDataType,
)
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException
from .bcsv_core import identifier
from .image import signed
from .analysis import AnalysisFailure, Annotations, image_for, transaction
from .state_core import (
    REGISTERED_NAME, ROLES, assign_delegates, find_registrar,
    machine_namespaces, plan_names,
)

CATEGORY = '/ACNH/States'


class StateEmulation:
    """One reusable emulator over private scratch memory.

    Arguments point into scratch regions whose every word points into a shared
    pool, so uninitialized pointer fields can be followed and uninitialized
    counts compare larger than any state index. Every call except the name
    registrar is skipped; nothing in the program is executed or modified.
    """
    STACK = 0x6000000000
    STOP = 0x6000100000
    ARGUMENTS = 0x6100000000
    ARGUMENT_SIZE = 0x100000
    POOL = 0x6200000000
    POOL_SIZE = 0x100000
    # Uninitialized 32-bit counts read 0x100: above any state index, yet
    # small enough that clearing loops over such counts finish.
    FILL = POOL + 0x100

    def __init__(self, program, image, monitor, registrar):
        self.program, self.image, self.monitor, self.registrar = program, image, monitor, registrar
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        memory = program.getMemory()
        for start, size in self.regions():
            if memory.intersects(self.address(start), self.address(start + size - 1)):
                raise AnalysisFailure('Reserved emulation scratch addresses overlap program memory.')
        self.helper = EmulatorHelper(program)
        self.dirty = []
        self.pattern = struct.pack('<Q', self.FILL)
        for start, size in self.regions():
            self.fill(start, size)

    def regions(self):
        return [(self.STACK, 0x20000), (self.ARGUMENTS, 8 * self.ARGUMENT_SIZE), (self.POOL, self.POOL_SIZE)]

    def address(self, value):
        return self.space.getAddress(value)

    def close(self):
        self.helper.dispose()

    def fill(self, start, size):
        if self.STACK <= start < self.STACK + 0x20000:
            data = bytearray(size)
        elif self.ARGUMENTS <= start < self.POOL + self.POOL_SIZE:
            # Keep the 8-byte phase of the pattern for partial ranges.
            phase = start % 8
            data = bytearray((self.pattern * ((size + phase) // 8 + 2))[phase:phase + size])
        else:
            data = bytearray(size)
            memory = self.program.getMemory()
            block = memory.getBlock(self.address(start))
            if block is not None and block.isInitialized():
                raw = self.image.read(start, size)
                if raw is not None:
                    data = bytearray(raw)
        for offset in range(0, size, 0x10000):
            self.helper.writeMemory(self.address(start + offset), data[offset:offset + 0x10000])

    def reg(self, number):
        return int(self.helper.readRegister('x%d' % number).longValue()) & 0xffffffffffffffff if number < 31 else 0

    def read(self, address, size):
        return bytearray((int(b) & 255) for b in self.helper.readMemory(self.address(address), size))

    def pointer(self, address):
        return struct.unpack('<Q', bytes(self.read(address, 8)))[0]

    def string(self, address):
        value = str(self.helper.readNullTerminatedString(self.address(address), 256))
        if not value or len(value) >= 255 or not REGISTERED_NAME.match(value):
            raise AnalysisFailure('Invalid state name at %X' % address)
        return value

    def argument(self, value):
        """Describe a scratch address as argument N plus an offset."""
        if self.ARGUMENTS <= value < self.ARGUMENTS + 8 * self.ARGUMENT_SIZE:
            offset = value - self.ARGUMENTS
            return 'argument %d + 0x%X' % (offset // self.ARGUMENT_SIZE, offset % self.ARGUMENT_SIZE - 0x10000)
        if self.POOL <= value < self.POOL + self.POOL_SIZE:
            return 'an object reached through a pointer field'
        return '0x%X' % value

    def segment(self):
        """Collect writes since the last boundary and reset write tracking."""
        written = {}
        tracked = self.helper.getTrackedMemoryWriteSet()
        for item in tracked.getAddressRanges():
            start, size = int(item.getMinAddress().getOffset()), int(item.getLength())
            self.dirty.append((start, size))
            if size >= 8 and size <= 0x10000:
                for i, value in enumerate(self.read(start, size)):
                    written[start + i] = value
        self.helper.enableMemoryWriteTracking(False)
        self.helper.enableMemoryWriteTracking(True)
        return written

    def run(self, start, integer=None, limit=60000):
        """Emulate a setup function.

        Arguments are scratch objects, or with `integer` only the first is and
        the rest hold that value (for setups selected by a mode argument). An
        error after a registration keeps the registrations made so far; the
        remaining instructions only run unrelated initialization.
        """
        h = self.helper
        self.reset()
        for i in range(31):
            h.writeRegister('x%d' % i, 0)
        for i in range(8):
            value = self.ARGUMENTS + i * self.ARGUMENT_SIZE + 0x10000
            h.writeRegister('x%d' % i, value if integer is None or i == 0 else integer)
        h.writeRegister('sp', self.STACK + 0x10000)
        h.writeRegister('x30', self.STOP)
        h.writeRegister('pc', start)
        h.enableMemoryWriteTracking(True)
        calls, segments, others = [], [], []
        try:
            self.loop(limit, calls, segments, others)
            return calls, segments, others, None
        except CancelledException:
            raise
        except Exception as exc:
            if not calls:
                raise
            segments.append(self.segment())
            return calls, segments, others, str(exc)
        finally:
            self.untracked()

    def loop(self, limit, calls, segments, others):
        h = self.helper
        for count in range(limit):
            if count % 256 == 0:
                self.monitor.checkCancelled()
            pc = int(h.getExecutionAddress().getOffset())
            if pc == self.STOP:
                segments.append(self.segment())
                return
            word = self.image.word(pc)
            if word is None:
                raise AnalysisFailure('Emulation left executable memory at %X' % pc)
            direct = word & 0xfc000000 == 0x94000000
            tail = word & 0xfc000000 == 0x14000000
            indirect = word & 0xfffffc1f == 0xd63f0000
            if direct or indirect or tail:
                target = pc + signed(word & 0x3ffffff, 26) * 4 if not indirect else self.reg((word >> 5) & 31)
                if tail and target != self.registrar:
                    if not h.step(self.monitor):
                        raise AnalysisFailure(str(h.getLastError()))
                    continue
                if target == self.registrar:
                    segments.append(self.segment())
                    name = self.string(self.pointer(self.reg(2) + 8))
                    calls.append(dict(mgr=self.reg(0), index=self.reg(1) & 0xffffffff, name=name, site=pc))
                else:
                    others.append((target, self.reg(0), self.reg(1) & 0xffffffff))
                h.writeRegister('x0', 0)
                h.writeRegister('pc', self.reg(30) if tail else pc + 4)
                continue
            if not h.step(self.monitor):
                raise AnalysisFailure(str(h.getLastError()))
        raise AnalysisFailure('Instruction limit reached at %X' % int(h.getExecutionAddress().getOffset()))

    def untracked(self):
        """Stop tracking, remembering the remaining writes for the next reset."""
        tracked = self.helper.getTrackedMemoryWriteSet()
        if tracked is not None:
            for item in tracked.getAddressRanges():
                self.dirty.append((int(item.getMinAddress().getOffset()), int(item.getLength())))
        self.helper.enableMemoryWriteTracking(False)

    def reset(self):
        """Restore scratch and program bytes written by the previous run.

        Restoration is deferred so callers can inspect the final state first.
        """
        for begin, size in self.dirty:
            self.fill(begin, size)
        self.dirty = []

    def owner_vtable(self, owner, adjust):
        """Return the vtable the setup left in the owner, if it is a real table."""
        try:
            vtable = self.pointer(owner + adjust)
        except Exception:
            return None
        return vtable if self.image.table(vtable, 8) else None


def recover_machine(emulator, image, setup):
    for integer in (None, 1, 0, 2, 3):
        try:
            calls, segments, others, error = emulator.run(setup, integer)
        except CancelledException:
            raise
        except Exception as exc:
            calls, error = [], str(exc)
        if calls:
            break
    if not calls:
        raise AnalysisFailure('No state registration reached (%s)' % error if error else 'No state registration reached')
    convention, states, missing = assign_delegates(calls, segments, image)
    machines = []
    by_mgr = defaultdict(list)
    for state in states:
        by_mgr[state['group']].append(state)
    registered = Counter(call['group'] for call in calls)
    for group, rows in by_mgr.items():
        mgr = group[0]
        rows.sort(key=lambda s: s['index'])
        indices = [s['index'] for s in rows]
        if len(set(indices)) != len(indices):
            raise AnalysisFailure('Duplicate state indices for one manager')
        prefixes = Counter(s['name'].split('::')[0] for s in rows if '::' in s['name'])
        prefix = prefixes.most_common(1)[0][0] if prefixes else 'State'
        # The delegate array is indexed by state; strides must agree.
        bases = set(s['delegate']['address'] - s['index'] * 0x40 for s in rows)
        strided = len(bases) == 1
        for state in rows:
            for callback in state['delegate']['callbacks']:
                if callback and callback['kind'] == 'virtual':
                    vtable = emulator.owner_vtable(state['delegate']['owner'], callback['adjust'])
                    callback['vtable'] = vtable
                    target = image.pointer(vtable + callback['offset']) if vtable is not None else None
                    callback['resolved'] = target if target is not None and image.executable(target) else None
        initializer = [t for t, x0, x1 in others if x0 == mgr and x1 == registered[group]]
        machines.append(dict(key=(setup,) + group, setup=setup, mgr=mgr, manager=emulator.argument(mgr), prefix=prefix,
                             states=rows, strided=strided, registered=registered[group], convention=convention,
                             initializers=initializer, error=error, integer=integer,
                             vtables=sorted(set(s['delegate']['vtable'] for s in rows))))
    return machines, [dict(m, setup=setup) for m in missing]


def setup_functions(program, sites):
    manager, space = program.getFunctionManager(), program.getAddressFactory().getDefaultAddressSpace()
    starts, orphans = set(), 0
    for site in sites:
        function = manager.getFunctionContaining(space.getAddress(site))
        if function is None:
            orphans += 1
        else:
            starts.add(int(function.getEntryPoint().getOffset()))
    return sorted(starts), orphans


def scan_states(program, monitor, image, emit=print):
    found = find_registrar(image, monitor.checkCancelled)
    if found is None:
        raise AnalysisFailure('State-name registrar not recognized; no changes applied.')
    emit('State-name registrar 0x%X: %d of %d state-name references.' % (found['registrar'], found['references'], found['total']))
    starts, orphans = setup_functions(program, found['sites'])
    if not starts:
        raise AnalysisFailure('No analyzed functions contain registrar calls; run Ghidra auto-analysis first.')
    machines, missing, failures = [], [], []
    emulator = StateEmulation(program, image, monitor, found['registrar'])
    try:
        for index, start in enumerate(starts):
            monitor.checkCancelled()
            monitor.setMessage('State setup %d / %d' % (index + 1, len(starts)))
            try:
                rows, lost = recover_machine(emulator, image, start)
                machines.extend(rows)
                missing.extend(lost)
            except CancelledException:
                raise
            except Exception as exc:
                failures.append('%X: %s' % (start, exc))
            if index % 50 == 0:
                emit('State setups: %d / %d' % (index + 1, len(starts)))
    finally:
        emulator.close()
    if orphans:
        failures.append('%d registrar calls outside analyzed functions' % orphans)
    return found, machines, missing, failures


def run_states(program, monitor, directory, emit=print):
    image = image_for(program, monitor)
    found, machines, missing, failures = scan_states(program, monitor, image, emit)
    if not machines:
        raise AnalysisFailure('No state machines recovered; no changes applied.')
    namespaces = machine_namespaces(machines)
    names, notes = plan_names(machines, namespaces)
    annotations = Annotations(program, monitor)
    initializers = Counter(t for m in machines for t in set(m['initializers']))
    initializer = initializers.most_common(1)[0] if initializers else None
    initializer = initializer[0] if initializer and initializer[1] * 2 >= len(machines) else None

    def namespace(name):
        symbols = program.getSymbolTable()
        existing = symbols.getNamespace(name, program.getGlobalNamespace())
        return existing if existing is not None else symbols.createNameSpace(program.getGlobalNamespace(), name, SourceType.ANALYSIS)

    def rename(address, space, name):
        function = program.getFunctionManager().getFunctionAt(annotations.address(address))
        if function is not None and str(function.getName()).startswith(('FUN_', 'sub_')):
            function.setParentNamespace(namespace(space))
            function.setName(name, SourceType.ANALYSIS)
            return True
        return False

    def enum_for(machine):
        title = 'ACNH_State_' + identifier(namespaces[machine['key']])
        enum = EnumDataType(CategoryPath(CATEGORY), title, 4)
        for state in machine['states']:
            enum.add(identifier(namespaces[machine['key']] + '_' + state['name'].split('::')[-1]), state['index'])
        old = annotations.manager.getDataType(CategoryPath(CATEGORY), title)
        if old is not None and not old.isEquivalent(enum):
            annotations.skipped.append(title + ': existing enum differs')
            return
        if old is None:
            annotations.manager.addDataType(enum, DataTypeConflictHandler.DEFAULT_HANDLER)

    renamed = []

    def apply():
        manager = annotations.manager
        ptr = PointerDataType(VoidDataType.dataType, 8, manager)
        uint, sint, ulong = UnsignedIntegerDataType.dataType, IntegerDataType.dataType, UnsignedLongLongDataType.dataType
        byte = UnsignedCharDataType.dataType
        annotations.structure('ACNH_StateDelegate', 0x40, [
            (0, PointerDataType(ptr, 8, manager), 'vtable'), (8, ptr, 'owner'),
            (0x10, ptr, 'enterFunction'), (0x18, ulong, 'enterAdjust'),
            (0x20, ptr, 'execFunction'), (0x28, ulong, 'execAdjust'),
            (0x30, ptr, 'exitFunction'), (0x38, ulong, 'exitAdjust')], CATEGORY)
        delegate = manager.getDataType(CategoryPath(CATEGORY), 'ACNH_StateDelegate')
        annotations.structure('ACNH_StateMgr', 0x48, [
            (0, PointerDataType(ptr, 8, manager), 'vtable'), (8, sint, 'state'), (0xc, sint, 'step'),
            (0x10, sint, 'previousState'), (0x14, sint, 'previousStep'), (0x18, sint, 'nextState'),
            (0x1c, sint, 'stateCount'), (0x20, byte, 'pending'), (0x21, byte, 'changed'),
            (0x28, uint, 'delegateCount'), (0x30, PointerDataType(delegate, 8, manager) if delegate else ptr, 'delegates'),
            (0x38, uint, 'nameCount'), (0x40, ptr, 'names')], CATEGORY)
        annotations.function(found['registrar'], 'ACNH_StateMgr_SetStateName')
        if initializer is not None:
            annotations.function(initializer, 'ACNH_StateMgr_Initialize')
        vtables = defaultdict(set)
        for machine in machines:
            monitor.checkCancelled()
            space = namespaces[machine['key']]
            for vtable in machine['vtables']:
                vtables[vtable].add(space)
            lines = ['State machine %s at %s (%d states, delegates written %s their names):' %
                     (space, machine['manager'], len(machine['states']), machine['convention'])]
            for state in machine['states']:
                parts = []
                for role, callback in zip(ROLES, state['delegate']['callbacks']):
                    if callback is None:
                        parts.append('%s -' % role.lower())
                    elif callback['kind'] == 'direct':
                        parts.append('%s 0x%X' % (role.lower(), callback['target']))
                    else:
                        parts.append('%s vtable+0x%X%s' % (role.lower(), callback['offset'],
                                     ' = 0x%X' % callback['resolved'] if callback.get('resolved') else ''))
                lines.append('  %d %s: %s' % (state['index'], state['name'], ', '.join(parts)))
            annotations.comment(machine['setup'], '\n'.join(lines))
            enum_for(machine)
        for vtable, spaces in vtables.items():
            label = identifier(next(iter(spaces))) if len(spaces) == 1 else 'Shared'
            annotations.label(vtable, 'ACNH_StateDelegate_%s_vtable_%X' % (label, vtable))
        for address, (space, name) in sorted(names.items()):
            monitor.checkCancelled()
            if rename(address, space, name):
                renamed.append(address)
        for address, uses in sorted(notes.items()):
            monitor.checkCancelled()
            if address not in names or len(uses) > 1:
                annotations.comment(address, 'State callback for ' + '; '.join(sorted(set(uses))) + '.')
    transaction(program, 'Recover ACNH state machines', monitor, apply)
    states = sum(len(m['states']) for m in machines)
    emit('Finished. %d state machines in %d setup functions; %d states; %d callbacks named; %d shared callbacks commented; '
         '%d states without a delegate; %d setups stopped after their registrations; %d setup issues; %d type conflicts.' %
         (len(machines), len(set(m['setup'] for m in machines)), states, len(renamed),
          sum(1 for a in notes if a not in names), len(missing), len(set(m['setup'] for m in machines if m['error'])),
          len(failures), len(annotations.skipped)))
    for message in failures[:50] + annotations.skipped:
        emit('Skipped ' + message)
    return machines, missing, failures
