# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import json
import os
import re
import struct
from collections import defaultdict
from java.lang import String
from java.nio import ByteBuffer
from ghidra.app.emulator import EmulatorHelper
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import (
    ArrayDataType, CategoryPath, CharDataType, DataTypeConflictHandler,
    DataUtilities, EnumDataType, PointerDataType, Structure, StructureDataType,
    UnsignedCharDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
    VoidDataType,
)
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException
from .bcsv import read_blocks
from .bcsv_core import identifier
from .image import Image, address_getter, fingerprint, rtti_candidates, signed


class AnalysisFailure(Exception):
    pass


def definitions(directory):
    with open(os.path.join(directory, 'cylindrical_earth', 'analysis.json'), 'r') as source:
        result = json.load(source)
    if result.get('formatVersion') != 1:
        raise ValueError('Unsupported analysis definitions')
    return result


def image_for(program, monitor):
    if program is None or str(program.getLanguage().getProcessor()).lower() != 'aarch64':
        raise ValueError('Open an analyzed AArch64 game executable first.')
    if program.getDefaultPointerSize() != 8 or program.getLanguage().isBigEndian():
        raise ValueError('Expected a little-endian 64-bit program.')
    image = Image(*read_blocks(program, monitor))
    try:
        text_type = unicode
    except NameError:
        text_type = str
    # Some getter variants load their return address through the GOT.
    for block in program.getMemory().getBlocks():
        if str(block.getName()) in ('.got', '.got.plt') and block.isInitialized():
            buffer = ByteBuffer.allocate(int(block.getSize())).array()
            program.getMemory().getBytes(block.getStart(), buffer)
            pair = (int(block.getStart().getOffset()), text_type(String(buffer, 'ISO-8859-1')).encode('latin-1'))
            image.constants.append(pair)
            image.blocks.append(pair)
    return image


class Emulation:
    """Private emulated memory; no execution or writes in the game/program."""
    STACK = 0x6000000000
    STOP = 0x6000100000
    SENTINEL = 0x123456789ab

    def __init__(self, program, image, monitor):
        self.program, self.image, self.monitor = program, image, monitor
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        if program.getMemory().contains(self.address(self.STACK)) or program.getMemory().contains(self.address(self.STOP)):
            raise AnalysisFailure('Reserved emulation scratch addresses overlap program memory.')
        self.helper = EmulatorHelper(program)

    def address(self, value):
        return self.space.getAddress(value)

    def close(self):
        self.helper.dispose()

    def reg(self, number):
        return int(self.helper.readRegister('x%d' % number).longValue()) & 0xffffffffffffffff if number < 31 else 0

    def string(self, address):
        value = str(self.helper.readNullTerminatedString(self.address(address), 256))
        if not value or len(value) >= 255:
            raise AnalysisFailure('Invalid or unterminated actor name')
        return value

    def pointer(self, address):
        # Java bytes are signed; preserve each byte's unsigned representation.
        raw = bytearray((int(b) & 255) for b in self.helper.readMemory(self.address(address), 8))
        return struct.unpack('<Q', raw)[0]

    def run(self, start, argument=0, registration=None, limit=4000):
        h = self.helper
        h.writeMemory(self.address(self.STACK), bytearray(0x20000))
        for i in range(31):
            h.writeRegister('x%d' % i, 0)
        h.writeRegister('sp', self.STACK + 0x10000)
        h.writeRegister('x1', argument)
        h.writeRegister('x30', self.STOP)
        h.writeRegister('pc', start)
        chain, profiles = [], []
        for count in range(limit):
            self.monitor.checkCancelled()
            pc = int(h.getExecutionAddress().getOffset())
            if pc == self.STOP:
                return self.reg(0), chain, profiles
            word = self.image.word(pc)
            if word is None:
                raise AnalysisFailure('Emulation left executable memory at %X' % pc)
            if word & 0xff20001f == 0xeb00001f and word & 0x00c0fc00 == 0:
                a, b = self.reg((word >> 5) & 31), self.reg((word >> 16) & 31)
                candidate = b if a == self.SENTINEL else a if b == self.SENTINEL else None
                if candidate is not None and self.image.mutable(candidate, 8) and candidate not in chain:
                    chain.append(candidate)
            direct = word & 0xfc000000 == 0x94000000
            indirect = word & 0xfffffc1f == 0xd63f0000
            if direct or indirect:
                target = pc + signed(word & 0x3ffffff, 26) * 4 if direct else self.reg((word >> 5) & 31)
                if registration is not None:
                    if target == registration:
                        args = [self.reg(i) for i in range(8)]
                        row = dict(id=args[1] & 0xffffffff, profile=args[0], factory=args[2], size=args[3],
                                   profileName=self.string(self.pointer(args[4] + 8)),
                                   className=self.string(self.pointer(args[5] + 8)), flags=args[6], callback=args[7])
                        if not (self.image.mutable(row['profile'], 0xf0) and self.image.executable(row['factory']) and
                                0 <= row['id'] < 65536 and 8 <= row['size'] < 0x1000000 and
                                re.match(r'^[A-Za-z_][A-Za-z0-9_:<> ,]*$', row['className'])):
                            raise AnalysisFailure('Invalid actor registration arguments')
                        profiles.append(row)
                    # Initializers construct their string arguments locally. Other
                    # calls are excluded; never emulate arbitrary runtime services.
                    h.writeRegister('x0', 0)
                    h.writeRegister('pc', pc + 4)
                    continue
                # Guard acquisition returning false takes the existing-instance
                # path. Actual membership calls are followed, not substituted.
                if self.image.mutable(self.reg(0), 8):
                    h.writeRegister('x0', 0)
                    h.writeRegister('pc', pc + 4)
                    continue
            if not h.step(self.monitor):
                raise AnalysisFailure(str(h.getLastError()))
        raise AnalysisFailure('Instruction limit reached at %X' % int(h.getExecutionAddress().getOffset()))


class Annotations:
    def __init__(self, program, monitor):
        self.program, self.monitor = program, monitor
        self.manager, self.symbols = program.getDataTypeManager(), program.getSymbolTable()
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        self.skipped = []

    def address(self, value):
        return self.space.getAddress(value)

    def label(self, address, name):
        address = self.address(address)
        current = self.symbols.getPrimarySymbol(address)
        if current is not None and not current.isDynamic() and not str(current.getName()).startswith(('DAT_', 'PTR_', 'UNK_')):
            return
        self.symbols.createLabel(address, name, self.program.getGlobalNamespace(), SourceType.ANALYSIS)

    def function(self, address, name):
        function = self.program.getFunctionManager().getFunctionAt(self.address(address))
        if function is not None and str(function.getName()).startswith(('FUN_', 'sub_')):
            function.setName(name, SourceType.ANALYSIS)

    def comment(self, address, message):
        listing, address = self.program.getListing(), self.address(address)
        old = listing.getComment(CodeUnit.PRE_COMMENT, address)
        if old and message in str(old):
            return
        listing.setComment(address, CodeUnit.PRE_COMMENT, str(old) + '\n\n' + message if old else message)

    def structure(self, name, size, fields, category='/ACNH/Actors'):
        category = CategoryPath(category)
        existing = self.manager.getDataType(CategoryPath.ROOT, name) or self.manager.getDataType(category, name)
        if existing is not None:
            if not isinstance(existing, Structure) or existing.getLength() != size:
                self.skipped.append(name + ': existing type size/kind differs')
                return None
            for offset, dtype, field in fields:
                component = existing.getComponentAt(offset)
                if component is None or component.getOffset() != offset or component.getLength() != dtype.getLength() or not component.getDataType().isEquivalent(dtype):
                    self.skipped.append(name + ': existing field layout differs')
                    return None
            return existing
        result = StructureDataType(category, name, size, self.manager)
        for offset, dtype, field in fields:
            result.replaceAtOffset(offset, dtype, dtype.getLength(), field, None)
        return self.manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER)


def scan_actors(program, monitor, image, config, emit=print):
    targets = set(image.signature(s) for s in config['actorRegistrationSignatures']) - {None}
    # A known symbol may identify another revision, but recognition still needs
    # the constructor signature before using its argument/profile layout.
    if len(targets) != 1:
        raise AnalysisFailure('Actor registration signature not uniquely recognized; no changes applied.')
    target = next(iter(targets))
    starts = set()
    for base, raw in image.texts:
        for offset in range(0, len(raw) - 3, 4):
            if offset % 0x10000 == 0:
                monitor.checkCancelled()
            word = struct.unpack_from('<I', raw, offset)[0]
            if word & 0xfc000000 == 0x94000000 and base + offset + signed(word & 0x3ffffff, 26) * 4 == target:
                fn = program.getFunctionManager().getFunctionContaining(program.getAddressFactory().getDefaultAddressSpace().getAddress(base + offset))
                if fn is not None:
                    starts.add(int(fn.getEntryPoint().getOffset()))
    if not starts:
        raise AnalysisFailure('No analyzed registration callers found; run Ghidra auto-analysis first.')
    profiles, failures = [], []
    for index, start in enumerate(sorted(starts)):
        monitor.checkCancelled()
        monitor.setMessage('Actor initializer %d / %d' % (index + 1, len(starts)))
        emulator = Emulation(program, image, monitor)
        try:
            rows = emulator.run(start, registration=target)[2]
            if not rows:
                raise AnalysisFailure('No registration reached')
            profiles.extend(rows)
        except CancelledException:
            raise
        except Exception as exc:
            failures.append('%X: %s' % (start, exc))
        finally:
            emulator.close()
        if index % 25 == 0:
            emit('Actor initializers: %d / %d' % (index + 1, len(starts)))
    ids = defaultdict(list)
    for row in profiles:
        ids[row['id']].append(row)
    accepted = []
    for aid, rows in sorted(ids.items()):
        if any(row != rows[0] for row in rows[1:]):
            failures.append('Conflicting registrations for actor ID %d' % aid)
        else:
            accepted.append(rows[0])
    return target, accepted, failures


def rtti_hierarchy(program, monitor, image, config, emit=print):
    accepted, failures, cache = [], [], {}
    candidates = rtti_candidates(image, monitor.checkCancelled)
    for index, row in enumerate(candidates):
        monitor.checkCancelled()
        key = (row['predicate'], row['getter'])
        if key not in cache:
            emulator = Emulation(program, image, monitor)
            try:
                info = emulator.run(row['getter'], limit=250)[0]
                if info != row['info']:
                    raise AnalysisFailure('Getter did not return the candidate type-info')
                false, chain, unused = emulator.run(row['predicate'], Emulation.SENTINEL, limit=1000)
                if false != 0 or not chain or chain[0] != info:
                    raise AnalysisFailure('No matching membership chain')
                for parent in chain:
                    if emulator.run(row['predicate'], parent, limit=1000)[0] != 1:
                        raise AnalysisFailure('Ancestor membership test failed')
                cache[key] = chain
            except CancelledException:
                raise
            except Exception as exc:
                cache[key] = None
                failures.append('%X: %s' % (row['vtable'], exc))
            finally:
                emulator.close()
        if cache[key]:
            accepted.append(dict(row, chain=cache[key], name=config['rttiGetterNames'].get(fingerprint(image, row['getter']))))
        if index % 100 == 0:
            emit('RTTI candidates: %d / %d; accepted %d' % (index + 1, len(candidates), len(accepted)))
    # A type-info address must describe one consistent linear ancestry.
    chains = defaultdict(set)
    for row in accepted:
        for i, info in enumerate(row['chain']):
            chains[info].add(tuple(row['chain'][i:]))
    conflicts = set(info for info, paths in chains.items() if len(paths) > 1)
    accepted = [row for row in accepted if not conflicts.intersection(row['chain'])]
    if conflicts:
        failures.append('%d conflicting type-info chains omitted' % len(conflicts))
    return accepted, failures


class ActorVtables:
    """Follow stores to the returned object, excluding callback subobjects."""
    def __init__(self, program, image, monitor):
        self.program, self.image, self.monitor = program, image, monitor
        self.decompiler = DecompInterface()
        if not self.decompiler.openProgram(program):
            raise AnalysisFailure('Could not initialize the decompiler')
        self.cache = {}

    def close(self):
        self.decompiler.dispose()

    def constant(self, vn, depth=0):
        if vn is None or depth > 24:
            return None
        if vn.isConstant():
            return int(vn.getOffset()) & ((1 << (int(vn.getSize()) * 8)) - 1)
        op = vn.getDef()
        if op is None:
            return self.image.pointer(int(vn.getOffset())) if vn.isAddress() and vn.getSize() == 8 else None
        m, args = str(op.getMnemonic()), list(op.getInputs())
        if m in ('COPY', 'CAST', 'INT_ZEXT', 'INT_SEXT'):
            return self.constant(args[0], depth + 1)
        if m not in ('PTRSUB', 'PTRADD', 'INT_ADD', 'INT_MULT', 'LOAD', 'MULTIEQUAL'):
            return None
        values = [self.constant(a, depth + 1) for a in (args[1:] if m == 'LOAD' else args)]
        if any(v is None for v in values):
            return None
        if m == 'LOAD':
            return self.image.pointer(values[0]) if vn.getSize() == 8 else None
        if m == 'MULTIEQUAL':
            return values[0] if len(set(values)) == 1 else None
        if m == 'PTRADD':
            return values[0] + values[1] * values[2]
        return values[0] * values[1] if m == 'INT_MULT' else sum(values)

    def root(self, vn, depth=0):
        if vn is None or depth > 24:
            return vn
        op = vn.getDef()
        if op is None:
            return vn
        m = str(op.getMnemonic())
        if m in ('COPY', 'CAST', 'INDIRECT'):
            return self.root(op.getInput(0), depth + 1)
        if m in ('PTRSUB', 'INT_ADD') and self.constant(op.getInput(1)) == 0:
            return self.root(op.getInput(0), depth + 1)
        if m == 'MULTIEQUAL':
            roots = [self.root(a, depth + 1) for a in op.getInputs()]
            if roots and all(r == roots[0] for r in roots):
                return roots[0]
        return vn

    def getter_matches(self, vtable, class_name):
        if vtable is None or not self.image.table(vtable, 24):
            return False
        first = [self.image.pointer(vtable + i * 8) for i in range(3)]
        if not all(a is not None and self.image.executable(a) for a in first):
            return False
        string_address = address_getter(self.image, first[2])
        return string_address is not None and self.image.string(string_address) == class_name

    def find(self, address, class_name, parameter=False, path=()):
        self.monitor.checkCancelled()
        key = (address, class_name, parameter)
        if key in self.cache:
            return self.cache[key]
        if address in path or len(path) >= 6:
            return None
        fn = self.program.getFunctionManager().getFunctionAt(self.program.getAddressFactory().getDefaultAddressSpace().getAddress(address))
        if fn is None:
            return None
        result = self.decompiler.decompileFunction(fn, 30, self.monitor)
        if not result.decompileCompleted():
            return None
        high = result.getHighFunction()
        ops = list(high.getPcodeOps())
        if parameter:
            parameter_variable = high.getLocalSymbolMap().getParam(0)
            if parameter_variable is None:
                return None
            roots = [self.root(parameter_variable.getRepresentative())]
        else:
            roots = [self.root(op.getInput(op.getNumInputs() - 1)) for op in ops
                     if str(op.getMnemonic()) == 'RETURN' and op.getNumInputs() > 1]
        roots = [r for r in roots if r is not None]
        if not roots:
            return None
        matches = set()
        for op in ops:
            self.monitor.checkCancelled()
            m = str(op.getMnemonic())
            if m == 'STORE' and self.root(op.getInput(1)) in roots:
                vtable = self.constant(op.getInput(2))
                if self.getter_matches(vtable, class_name):
                    matches.add(vtable)
            elif m == 'CALL' and op.getNumInputs() > 1 and self.root(op.getInput(1)) in roots:
                target = int(op.getInput(0).getOffset())
                if target is not None:
                    vtable = self.find(target, class_name, True, path + (address,))
                    if vtable is not None:
                        matches.add(vtable)
        value = next(iter(matches)) if len(matches) == 1 else None
        self.cache[key] = value
        return value


def transaction(program, title, monitor, action):
    tx, committed = program.startTransaction(title), False
    try:
        result = action()
        monitor.checkCancelled()
        committed = True
        return result
    finally:
        program.endTransaction(tx, committed)


def run_actors(program, monitor, directory, emit=print):
    image = image_for(program, monitor)
    target, profiles, failures = scan_actors(program, monitor, image, definitions(directory), emit)
    if not profiles:
        raise AnalysisFailure('No valid actor profiles recovered; no changes applied.')
    finder = ActorVtables(program, image, monitor)
    try:
        for index, row in enumerate(profiles):
            monitor.checkCancelled()
            monitor.setMessage('Actor vtable %d / %d' % (index + 1, len(profiles)))
            vtable = finder.find(row['factory'], row['className'])
            if vtable is not None:
                row['vtable'] = vtable
            if index % 25 == 0:
                emit('Actor vtables: %d / %d' % (index + 1, len(profiles)))
    finally:
        finder.close()
    annotations = Annotations(program, monitor)
    def apply():
        enum = EnumDataType(CategoryPath('/ACNH/Actors'), 'ACNH_ActorId', 4)
        for row in profiles:
            enum.add('ActorId_%s_%d' % (identifier(row['className']), row['id']), row['id'])
        old = annotations.manager.getDataType(CategoryPath.ROOT, 'ACNH_ActorId') or annotations.manager.getDataType(enum.getCategoryPath(), enum.getName())
        if old is not None and not old.isEquivalent(enum):
            annotations.skipped.append('ACNH_ActorId: existing enum differs')
            aid = UnsignedIntegerDataType.dataType
        else:
            aid = old if old is not None else annotations.manager.addDataType(enum, DataTypeConflictHandler.DEFAULT_HANDLER)
        ptr = PointerDataType(VoidDataType.dataType, 8, annotations.manager)
        vptr = PointerDataType(ptr, 8, annotations.manager)
        uint, ulong = UnsignedIntegerDataType.dataType, UnsignedLongLongDataType.dataType
        charptr = PointerDataType(CharDataType.dataType, 8, annotations.manager)
        chars = ArrayDataType(CharDataType.dataType, 64, 1)
        fields = [(0, aid, 'id'), (8, ptr, 'factory'), (16, ulong, 'actorSize'), (24, uint, 'flags'),
                  (32, vptr, 'profileNameVtable'), (40, charptr, 'profileNameBuffer'), (48, uint, 'profileNameCapacity'),
                  (52, chars, 'profileName'), (120, vptr, 'classNameVtable'), (128, charptr, 'classNameBuffer'),
                  (136, uint, 'classNameCapacity'), (140, chars, 'className'), (208, ptr, 'callback'),
                  (216, uint, 'unknownD8'), (224, ptr, 'unknownE0'), (232, ptr, 'unknownE8')]
        profile_type = annotations.structure('ACNH_ActorProfile', 0xf0, fields)
        factories = defaultdict(list)
        for row in profiles:
            monitor.checkCancelled()
            name = identifier(row['className'])
            annotations.label(row['profile'], 'ACNH_ActorProfile_' + name)
            annotations.comment(row['profile'], 'Actor ID %d; class %s; profile %s; allocation size 0x%X; factory 0x%X.' %
                                (row['id'], row['className'], row['profileName'], row['size'], row['factory']))
            if profile_type is not None and DataUtilities.isUndefinedRange(program, annotations.address(row['profile']), annotations.address(row['profile'] + 0xef)):
                DataUtilities.createData(program, annotations.address(row['profile']), profile_type, -1, False,
                                         DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
            opaque = ArrayDataType(UnsignedCharDataType.dataType, row['size'] - 8, 1) if row['size'] > 8 else None
            actor_fields = [(0, vptr, 'vtable')] + ([(8, opaque, 'unknownFields')] if opaque is not None else [])
            annotations.structure('ACNH_Actor_' + name, row['size'], actor_fields)
            if 'vtable' in row:
                annotations.label(row['vtable'], 'ACNH_Actor_' + name + '_vtable')
                annotations.comment(row['vtable'], '%s actor vtable; factory root-object assignment and class-name getter at +0x10 agree.' % row['className'])
            factories[row['factory']].append(row)
        annotations.function(target, 'ACNH_ActorProfile_Register')
        for factory, rows in factories.items():
            names = set(row['className'] for row in rows)
            if len(names) == 1:
                annotations.function(factory, 'ACNH_Actor_' + identifier(rows[0]['className']) + '_Create')
            annotations.comment(factory, 'Actor factory for ' + ', '.join('%s (ID %d)' % (r['className'], r['id']) for r in rows) + '.')
    transaction(program, 'Recover ACNH actor profiles', monitor, apply)
    emit('Finished. %d actor profiles; %d validated actor vtables; %d initializer issues; %d type conflicts.' %
         (len(profiles), sum('vtable' in r for r in profiles), len(failures), len(annotations.skipped)))
    for message in failures + annotations.skipped:
        emit('Skipped ' + message)
    return profiles, failures


def run_rtti(program, monitor, directory, emit=print):
    image = image_for(program, monitor)
    rows, failures = rtti_hierarchy(program, monitor, image, definitions(directory), emit)
    if not rows:
        raise AnalysisFailure('No validated custom RTTI chains found; no changes applied.')
    annotations = Annotations(program, monitor)
    names, parents, methods = defaultdict(set), {}, defaultdict(set)
    for row in rows:
        if row['name']:
            names[row['info']].add(row['name'])
        for child, parent in zip(row['chain'], row['chain'][1:]):
            parents[child] = parent
    resolved = {info: next(iter(values)) for info, values in names.items() if len(values) == 1}
    def name(info):
        return resolved.get(info, 'TypeInfo_%X' % info)
    def apply():
        infos = set(info for row in rows for info in row['chain'])
        for info in sorted(infos):
            monitor.checkCancelled()
            annotations.label(info, 'ACNH_' + identifier(name(info)) + '_typeInfo')
            if info in parents:
                annotations.comment(info, 'Custom RTTI parent: %s (0x%X).' % (name(parents[info]), parents[info]))
        for row in rows:
            monitor.checkCancelled()
            label = identifier(name(row['info']))
            annotations.label(row['vtable'], 'ACNH_' + label + '_vtable_%X' % row['vtable'])
            annotations.comment(row['vtable'], 'Custom RTTI: ' + ' -> '.join('%s (0x%X)' % (name(info), info) for info in row['chain']) + '.')
            methods[row['predicate']].add('ACNH_' + label + '_IsDerivedFrom')
            methods[row['getter']].add('ACNH_' + label + '_GetTypeInfo')
        for address, choices in methods.items():
            if len(choices) == 1:
                annotations.function(address, next(iter(choices)))
    transaction(program, 'Recover ACNH custom RTTI hierarchy', monitor, apply)
    # Print each type once, without recursive traversal or unbounded trees.
    for info in sorted(set(info for row in rows for info in row['chain'])):
        emit('%s [0x%X]%s' % (name(info), info, ' -> ' + name(parents[info]) if info in parents else ''))
    emit('Finished. %d validated vtables; %d type-info nodes; %d rejected candidates.' %
         (len(rows), len(set(info for row in rows for info in row['chain'])), len(failures)))
    return rows, failures
