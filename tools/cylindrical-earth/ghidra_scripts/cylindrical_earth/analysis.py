# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import json
import os
import re
import struct
from collections import defaultdict
from ghidra.app.emulator import EmulatorHelper
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import (
    ArrayDataType, CategoryPath, CharDataType, DataTypeConflictHandler,
    DataUtilities, EnumDataType, PointerDataType, Structure, StructureDataType,
    UnsignedCharDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
    VoidDataType,
)
from ghidra.program.model.listing import CodeUnit, GhidraClass
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException
from .bcsv import got_blocks, make_thiscall, read_blocks
from .bcsv_core import identifier, scan_readers
from .image import (
    Image, address_constants, address_getter, class_identity, class_layouts, constructed_type, destructors, fingerprint,
    reader_type_names, rtti_candidates, signed, size_getter, type_names, virtual_methods, vptr_stores, vtable_bounds,
)

# Names that earlier runs gave to unnamed type-infos; later runs may improve them.
FALLBACK_NAME = re.compile(r'^ACNH_TypeInfo_[0-9A-F]+_')
# Deleting destructors tail-call one of these; the game folds operator delete into free.
DELETE_NAMES = ('free', 'operator.delete', '_ZdlPv', '_ZdlPvm')
# Methods this script names; vtable structure fields drop the class part.
METHOD_NAME = re.compile(r'^ACNH_\w+_(GetClassName|GetClassSize|IsDerivedFrom|GetTypeInfo|Destructor|DeletingDestructor)$')
CLASSES = '/ACNH/Classes'


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
    # Some getter variants load their return address through the GOT.
    for pair in got_blocks(program):
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

    def label(self, address, name, replace=None):
        """Label a default address; `replace` also matches our own earlier analysis names."""
        address = self.address(address)
        current = self.symbols.getPrimarySymbol(address)
        if current is not None and not current.isDynamic() and not str(current.getName()).startswith(('DAT_', 'PTR_', 'UNK_')):
            if replace is not None and current.getSource() == SourceType.ANALYSIS and replace.match(str(current.getName())):
                current.setName(name, SourceType.ANALYSIS)
            return
        self.symbols.createLabel(address, name, self.program.getGlobalNamespace(), SourceType.ANALYSIS)

    def function(self, address, name, replace=None):
        function = self.program.getFunctionManager().getFunctionAt(self.address(address))
        if function is None:
            return
        current = str(function.getName())
        if current.startswith(('FUN_', 'sub_')) or (replace is not None and function.getSymbol().getSource() == SourceType.ANALYSIS
                                                    and replace.match(current)):
            function.setName(name, SourceType.ANALYSIS)

    def klass(self, name):
        """The class `name` in the global namespace, converting a plain namespace or creating it."""
        symbols, root = self.symbols, self.program.getGlobalNamespace()
        value = symbols.getNamespace(name, root)
        if value is None:
            return symbols.createClass(root, name, SourceType.ANALYSIS)
        return value if isinstance(value, GhidraClass) else symbols.convertNamespaceToClass(value)

    def member(self, address, owner, name=None, old=None):
        """Move a function into class `owner` and return it, or None when it belongs elsewhere.

        Only functions in the global namespace with a default name, or with the
        name `old` that this script gave them, move; they are then renamed to
        `name` when one is given.
        """
        function = self.program.getFunctionManager().getFunctionAt(self.address(address))
        if function is None or function.isThunk():
            return None
        current = str(function.getName())
        ours = function.getSymbol().getSource() == SourceType.ANALYSIS and current == old
        if function.getParentNamespace().isGlobal() and (current.startswith(('FUN_', 'sub_')) or ours):
            function.setParentNamespace(owner)
            if name is not None:
                function.setName(name, SourceType.ANALYSIS)
        return function if function.getParentNamespace().getID() == owner.getID() else None

    def comment(self, address, message, replace=None):
        """Append a pre-comment; `replace` drops earlier paragraphs that start with that prefix."""
        listing, address = self.program.getListing(), self.address(address)
        old = listing.getComment(CodeUnit.PRE_COMMENT, address)
        if old and message in str(old):
            return
        if old and replace:
            old = '\n\n'.join(part for part in str(old).split('\n\n') if not part.startswith(replace))
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
            accepted.append(dict(row, chain=cache[key], name=config['rttiGetterNames'].get(fingerprint(image, row['getter'])),
                                 identity=class_identity(image, row['vtable'])))
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
                message = '%s actor vtable; factory root-object assignment and class-name getter at +0x10 agree.' % row['className']
                getter = image.pointer(row['vtable'] + 24)
                size = size_getter(image, getter) if getter is not None else None
                if size is not None:
                    # The allocation size and getClassSize are independent evidence for the same class.
                    message += ' Class-size getter at +0x18 returns 0x%X, %s the allocation size.' % (
                        size, 'matching' if size == row['size'] else 'unlike')
                annotations.comment(row['vtable'], message, '%s actor vtable;' % row['className'])
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
    parents, methods = {}, defaultdict(set)
    infos = set(info for row in rows for info in row['chain'])
    for row in rows:
        for child, parent in zip(row['chain'], row['chain'][1:]):
            parents[child] = parent
    monitor.setMessage('Identifying BCSV reader vtables')
    readers = reader_type_names(rows, scan_readers(image.texts, image.constants, image.tables, monitor.checkCancelled))
    users = user_names(program, annotations, infos)
    # A reader class you named yourself keeps your name.
    readers = dict((info, name) for info, name in readers.items() if info not in users)
    resolved, conflicts = type_names(rows, readers, users)
    failures.extend(conflicts)
    deletes = delete_functions(program)
    pairs = dict((row['vtable'], destructors(image, row['vtable'], deletes)) for row in rows)
    layouts, types = class_layouts(image, rows), {}
    monitor.setMessage('Finding constructors')
    constructors = find_constructors(program, image, annotations, rows, pairs)
    # Each getter initializes its type-info once, behind a guard variable just after it.
    guards = set(row['info'] for row in rows if row['info'] + 8 in address_constants(image, row['getter']))
    monitor.setMessage('Finding virtual methods')
    virtuals, typed = virtual_methods(image, rows, set(layouts)), defaultdict(int)
    def name(info):
        return resolved.get(info, 'TypeInfo_%X' % info)
    def apply():
        for info in sorted(infos):
            monitor.checkCancelled()
            annotations.label(info, 'ACNH_' + identifier(name(info)) + '_typeInfo', FALLBACK_NAME)
            if info in guards:
                annotations.label(info + 8, 'ACNH_' + identifier(name(info)) + '_typeInfoGuard', FALLBACK_NAME)
            if info in parents:
                annotations.comment(info, 'Custom RTTI parent: %s (0x%X).' % (name(parents[info]), parents[info]), 'Custom RTTI parent:')
        for row in rows:
            monitor.checkCancelled()
            label = identifier(name(row['info']))
            annotations.label(row['vtable'], 'ACNH_' + label + '_vtable_%X' % row['vtable'], FALLBACK_NAME)
            message = 'Custom RTTI: ' + ' -> '.join('%s (0x%X)' % (name(info), info) for info in row['chain']) + '.'
            identity = row.get('identity')
            if identity:
                # The size getter may be shared through identical-code folding; methods
                # are only named when a single class uses them.
                message += ' Class-name getter at -0x10 returns "%s"; class-size getter at -0x8 returns 0x%X.' % (identity['name'], identity['size'])
                methods[identity['nameGetter']].add((row['info'], 'GetClassName'))
                methods[identity['sizeGetter']].add((row['info'], 'GetClassSize'))
            pair = pairs[row['vtable']]
            if pair:
                message += ' Destructors at +0x10 (complete) and +0x18 (deleting).'
                methods[pair[0]].add((row['info'], 'Destructor'))
                methods[pair[1]].add((row['info'], 'DeletingDestructor'))
            annotations.comment(row['vtable'], message, 'Custom RTTI:')
            methods[row['predicate']].add((row['info'], 'IsDerivedFrom'))
            methods[row['getter']].add((row['info'], 'GetTypeInfo'))
        for address, info in constructors.items():
            methods[address].add((info, 'Constructor'))
        for address, choices in methods.items():
            if len(choices) == 1:
                info, short = next(iter(choices))
                annotations.function(address, 'ACNH_' + identifier(name(info)) + '_' + short, FALLBACK_NAME)
        # Structures come after the names, so vtable fields pick them up.
        for info in sorted(layouts):
            monitor.checkCancelled()
            class_structure(program, image, annotations, layouts, types, info, lambda i: 'ACNH_' + identifier(name(i)))
        # Then the methods of each class with a structure move into it, with short names, and take a typed this.
        members = dict((address, (info, None)) for address, info in virtuals.items())
        for address, choices in methods.items():
            info, short = next(iter(choices))
            if len(choices) == 1 and (short == 'Constructor' or virtuals.get(address) == info):
                members[address] = (info, short)
        for address, (info, short) in sorted(members.items()):
            monitor.checkCancelled()
            if types.get(info) is None:
                continue
            label = 'ACNH_' + identifier(name(info))
            try:
                function = annotations.member(address, annotations.klass(label), short and (label if short == 'Constructor' else short),
                                              short and label + '_' + short)
                outcome = make_thiscall(function)
            except Exception as error:
                annotations.skipped.append('%X: cannot make it a method of %s (%s)' % (address, label, error))
                continue
            if outcome is not None:
                typed[outcome] += 1
    transaction(program, 'Recover ACNH custom RTTI hierarchy', monitor, apply)
    # Print each type once, without recursive traversal or unbounded trees.
    for info in sorted(infos):
        emit('%s [0x%X]%s' % (name(info), info, ' -> ' + name(parents[info]) if info in parents else ''))
    named = dict(fingerprint=set(row['info'] for row in rows if row['name']),
                 classNameGetter=set(row['info'] for row in rows if row.get('identity')))
    emit('Finished. %d validated vtables; %d type-info nodes, %d named (%d from getter fingerprints, %d from class-name '
         'getters, %d BCSV readers); %d type-info guards; %d vtables with destructors; %d constructors; %d class structures; %d methods and '
         'constructors given a typed this; %d signatures an earlier run locked restored; %d rejected candidates or name conflicts; %d type conflicts.' %
         (len(rows), len(infos), len(infos.intersection(resolved)), len(named['fingerprint']), len(named['classNameGetter']),
          len(readers), len(guards), sum(1 for pair in pairs.values() if pair), len(constructors), sum(1 for t in types.values() if t is not None),
          typed['typed'], typed['unlocked'], len(failures), len(annotations.skipped)))
    if not deletes:
        emit('Skipped destructors: no free or operator delete symbol found.')
    for message in annotations.skipped:
        emit('Skipped ' + message)
    return rows, failures


def class_structure(program, image, annotations, layouts, types, info, label_of):
    """Create the class structure of `info`, embedding its parent's as `super` when it has one."""
    if info in types:
        return types[info]
    layout, manager, label = layouts[info], annotations.manager, label_of(info)
    pointer = PointerDataType(VoidDataType.dataType, 8, manager)
    table = None
    if layout['vtable'] is not None:
        start, slots = layout['vtable']
        fields, used = [], set()
        for index in range(slots):
            field = slot_name(program, annotations.address(image.pointer(start + 8 * index)), index)
            if field in used:
                field += '_%X' % (8 * index)
            used.add(field)
            fields.append((8 * index, pointer, field))
        table = annotations.structure(label + '_vtable', 8 * slots, fields, CLASSES)
    parent = layout['parent']
    parent_type = None
    if parent is not None:
        parent_type = class_structure(program, image, annotations, layouts, types, parent, label_of)
    first = (0, parent_type, 'super') if parent_type is not None else (0, PointerDataType(table or pointer, 8, manager), 'vtable')
    types[info] = annotations.structure(label, layout['size'], [first], CLASSES)
    return types[info]


def find_constructors(program, image, annotations, rows, pairs):
    """Map constructor addresses to the type they construct.

    Candidates are the functions that refer to a primary vtable, directly or
    through its GOT entry. A constructor stores the vtable at offset 0 of `this`.
    A lone store could also be a destructor, so it is only trusted when the type's
    virtual destructor is known; otherwise the parent's vtable must be stored first.
    """
    chains, owners = {}, defaultdict(set)
    for row in rows:
        chains[row['info']] = row['chain']
        bounds = vtable_bounds(image, row['vtable'])
        if bounds is not None:
            owners[bounds[0]].add(row['info'])
    points = dict((point, next(iter(infos))) for point, infos in owners.items() if len(infos) == 1)
    known = set(row['info'] for row in rows if pairs[row['vtable']])
    skip = set(address for pair in pairs.values() if pair for address in pair)
    references, functions, writers = program.getReferenceManager(), program.getFunctionManager(), {}
    for point in points:
        for target in (point, point - 16):
            for reference in references.getReferencesTo(annotations.address(target)):
                sources = [reference.getFromAddress()]
                if functions.getFunctionContaining(sources[0]) is None:
                    sources = [r.getFromAddress() for r in references.getReferencesTo(sources[0])]
                for source in sources:
                    function = functions.getFunctionContaining(source)
                    if function is not None:
                        entry = function.getEntryPoint()
                        end = function.getBody().getRangeContaining(entry).getMaxAddress()
                        writers[int(entry.getOffset())] = int(end.getOffset())
    result = {}
    for address, end in writers.items():
        if address in skip:
            continue
        stores = vptr_stores(image, address, end, points)
        info = constructed_type(stores, points, chains)
        if info is not None and (info in known or len(stores) > 1):
            result[address] = info
    return result


def slot_name(program, address, index):
    function = program.getFunctionManager().getFunctionAt(address)
    name = str(function.getName()) if function is not None else ''
    if not name or name.startswith(('FUN_', 'sub_')):
        return 'vfunc_%X' % (8 * index)
    match = METHOD_NAME.match(name)
    return match.group(1) if match else identifier(name)


def delete_functions(program):
    result = set()
    for name in DELETE_NAMES:
        for symbol in program.getSymbolTable().getSymbols(name):
            if not symbol.isExternal():
                result.add(int(symbol.getAddress().getOffset()))
    return result


def user_names(program, annotations, infos):
    """Names the user already gave type-infos, such as `Foo::sTypeInfo`, `Foo::sStaticTypeInfo` or `ACNH_Foo_typeInfo`.

    A name given to several type-infos is ambiguous and ignored.
    """
    result, counts = {}, defaultdict(int)
    for info in infos:
        symbol = annotations.symbols.getPrimarySymbol(annotations.address(info))
        if symbol is None or symbol.getSource() != SourceType.USER_DEFINED:
            continue
        name = re.sub(r'(?:::sTypeInfo|::sStaticTypeInfo|_typeInfo)$', '', str(symbol.getName(True)))
        name = identifier(re.sub(r'^ACNH_', '', name))
        if name != 'Field':
            result[info] = name
            counts[name] += 1
    return dict((info, name) for info, name in result.items() if counts[name] == 1)
