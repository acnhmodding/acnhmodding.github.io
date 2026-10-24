# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Name library functions, sead singletons and trivial hot functions."""
from __future__ import print_function
import re
from collections import Counter
from java.lang import String
from java.nio import ByteBuffer
from ghidra.app.util import NamespaceUtils
from ghidra.app.util.demangler import DemanglerOptions, DemanglerUtil
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (
    CategoryPath, DataTypeConflictHandler, DataUtilities, Pointer, PointerDataType, Structure,
    StructureDataType, Undefined, VoidDataType,
)
from ghidra.program.model.listing import Function, GhidraClass, ParameterImpl, ReturnParameterImpl, VariableUtilities
from ghidra.program.model.symbol import SourceType
from .bcsv import make_thiscall
from .bcsv_core import identifier
from .analysis import CLASSES, AnalysisFailure, Annotations, image_for, transaction
from .library_core import (
    call_counts, delegate_class, dynamic_symbols, fde_ranges, hot_functions, instance_getter, instance_methods,
    library_definitions, match_library, module_header, plt_stubs, reader_singletons, shape,
    shape_name, singletons,
)

DEFAULT_NAME = ('FUN_', 'sub_')
VTABLE_LABEL = re.compile(r'^(?:ACNH_)?(?:Actor_)?(.+?)_vtable(?:_[0-9A-Fa-f]+)?$')
# Labels from the other scripts that are placeholders, not class names. A BCSV
# reader's `ACNH_Bcsv_<File>` label gives way to the `bcsv::<File>` class.
PLACEHOLDER_LABEL = re.compile(r'^(?:TypeInfo_[0-9A-Fa-f]+|StateDelegate_\w+|Bcsv_\w+)$')
PLACEHOLDER_SPACE = 'ACNH_Singleton_%X'
# sead keeps the singleton's disposer in this member, an IDisposer subclass.
DISPOSER_FIELD = 'mSingletonDisposerBuf_'
SINGLETON_COMMENT = 'sead singleton '


def complete_image(program, monitor):
    """image_for plus every other initialized block (.dynamic, .dynsym, ...)."""
    image = image_for(program, monitor)
    try:
        text_type = unicode
    except NameError:
        text_type = str
    covered = set(base for base, raw in image.blocks)
    for block in program.getMemory().getBlocks():
        start = int(block.getStart().getOffset())
        if not block.isInitialized() or start in covered or block.getSize() > 0x10000000:
            continue
        monitor.checkCancelled()
        buffer = ByteBuffer.allocate(int(block.getSize())).array()
        program.getMemory().getBytes(block.getStart(), buffer)
        image.blocks.append((start, text_type(String(buffer, 'ISO-8859-1')).encode('latin-1')))
    return image


def function_ranges(program, image, header, monitor):
    """FDE ranges, or the program's function bodies when there are none."""
    ranges = fde_ranges(image, header)
    if ranges:
        return ranges
    result = []
    for function in program.getFunctionManager().getFunctions(True):
        monitor.checkCancelled()
        body = function.getBody()
        start = int(function.getEntryPoint().getOffset())
        result.append((start, int(body.getMaxAddress().getOffset()) + 1))
    return sorted(result)


def scan_library(program, monitor, image, config, emit=print):
    """Collect everything the pass names, without changing the program."""
    header = module_header(image)
    if header is None:
        raise AnalysisFailure('No MOD0 header at the start of .text; open a Switch NSO module.')
    monitor.setMessage('Reading dynamic symbols')
    exports, imports = dynamic_symbols(image, header)
    stubs = plt_stubs(image, imports)
    names = dict(exports)
    names.update(stubs)
    emit('Dynamic symbols: %d exported functions, %d PLT stubs.' % (len(exports), len(stubs)))
    monitor.setMessage('Reading function ranges')
    ranges = function_ranges(program, image, header, monitor)
    monitor.setMessage('Matching library fingerprints')
    matches, problems = match_library(image, ranges, config['functions'], names, monitor.checkCancelled)
    emit('Library fingerprints: %d of %d matched.' % (len(matches), len(config['functions'])))
    known = dict(names)
    known.update((address, entry['name']) for address, entry in matches.items())
    disposer = [a for a, entry in matches.items() if entry['name'] == config['disposerConstructor']]
    rows = []
    if disposer:
        monitor.setMessage('Recognizing sead singletons')
        rows = singletons(image, header, ranges, disposer[0], set(known), monitor.checkCancelled)
    else:
        problems.append('IDisposer(Heap*, HeapNullOption) not found; singletons skipped')
    emit('sead singletons: %d createInstance functions.' % len(rows))
    methods = {}
    if rows:
        monitor.setMessage('Finding functions called with a singleton as this')
        excluded = set(known) | set(disposer)
        excluded.update(start for row in rows for start in (row['function'], row['constructor']) if start is not None)
        methods = instance_methods(image, ranges, rows, excluded, monitor.checkCancelled)
    emit('Singleton methods: %d functions always called with a singleton as this.' % len(methods))
    readers = reader_singletons(image, rows)
    ends = dict(ranges)
    delegates = {}
    for row in rows:
        code = [(start, ends[start]) for start in (row['function'], row['constructor']) if start in ends]
        delegates[row['instance']] = delegate_class(image, code)
    instances = set(row['instance'] for row in rows)
    getters = {}
    for start, end in ranges:
        if end - start in (12, 16):
            target = instance_getter(image, start, end)
            if target in instances:
                getters[start] = target
    monitor.setMessage('Counting call sites')
    counts = call_counts(image, monitor.checkCancelled)
    hot = hot_functions(counts, ranges, config.get('hotMinimumCallSites', 200))
    shapes = {}
    for address, count in hot:
        kind = shape(image, address, dict(ranges)[address])
        if kind is not None:
            shapes[address] = kind
    emit('Hot functions: %d with at least %d direct call sites.' % (len(hot), config.get('hotMinimumCallSites', 200)))
    return dict(header=header, exports=exports, stubs=stubs, matches=matches, problems=problems, known=known,
                singletons=rows, readers=readers, delegates=delegates, getters=getters, methods=methods, hot=hot,
                shapes=shapes)


class LibraryAnnotations(Annotations):
    def __init__(self, program, monitor):
        Annotations.__init__(self, program, monitor)
        self.functions = program.getFunctionManager()
        self.listing = program.getListing()
        self.renamed = Counter()

    def namespace(self, name):
        return NamespaceUtils.createNamespaceHierarchy(name, None, self.program, SourceType.ANALYSIS)

    def renameable(self, address, size=16, create=False):
        function = self.functions.getFunctionAt(self.address(address))
        if function is None and create:
            body = AddressSet(self.address(address), self.address(address + size - 1))
            function = self.functions.createFunction(None, self.address(address), body, SourceType.DEFAULT)
        if function is not None and str(function.getName()).startswith(DEFAULT_NAME):
            return function
        return None

    def library(self, address, mangled, kind, create=False):
        """Name a library function, demangled into its namespace when possible."""
        function = self.renameable(address, create=create)
        if function is None:
            return
        options = DemanglerOptions()
        options.setApplySignature(False)
        try:
            for demangled in DemanglerUtil.demangle(self.program, mangled, self.address(address)) or []:
                demangled.applyTo(self.program, self.address(address), options, self.monitor)
                break
        except Exception:
            pass
        if str(function.getName()).startswith(DEFAULT_NAME):
            function.setName(mangled, SourceType.ANALYSIS)
        self.renamed[kind] += 1

    def member(self, address, space, name, kind):
        function = self.renameable(address)
        if function is not None:
            function.setParentNamespace(self.namespace(space))
            function.setName(name, SourceType.ANALYSIS)
            self.renamed[kind] += 1

    def global_label(self, address, space, name):
        address = self.address(address)
        current = self.symbols.getPrimarySymbol(address)
        if current is not None and not current.isDynamic() and not str(current.getName()).startswith(('DAT_', 'PTR_', 'UNK_')):
            return
        symbol = self.symbols.createLabel(address, name, self.namespace(space), SourceType.ANALYSIS)
        symbol.setPrimary()
        self.renamed['globals'] += 1

    def klass(self, space):
        """The class `space`, converting the namespace an earlier run created."""
        value = self.namespace(space)
        return value if isinstance(value, GhidraClass) else self.symbols.convertNamespaceToClass(value)

    def adopt(self, instance, space):
        """Move what an earlier run put in a singleton's placeholder namespace into its class."""
        placeholder = PLACEHOLDER_SPACE % instance
        old = self.symbols.getNamespace(placeholder, self.program.getGlobalNamespace())
        if space == placeholder or old is None:
            return
        target, short = self.klass(space), space.split('::')[-1]
        for symbol in list(self.symbols.getChildren(old.getSymbol())):
            try:
                if str(symbol.getName()) == placeholder:
                    symbol.setName(short, SourceType.ANALYSIS)  # its constructor
                symbol.setNamespace(target)
            except Exception as error:
                self.skipped.append('%s: cannot move %s from %s (%s)' % (space, symbol.getName(), placeholder, error))
        if not list(self.symbols.getChildren(old.getSymbol())):
            old.getSymbol().delete()
        self.renamed['adopted'] += 1
        old_type = self.manager.getDataType(CategoryPath(CLASSES), placeholder)
        if old_type is None:
            return
        category = class_category(space)
        existing = self.manager.getDataType(category, short)
        if existing is None:
            old_type.setNameAndCategory(category, short)
        elif isinstance(existing, Structure) and isinstance(old_type, Structure):
            if existing.getLength() < old_type.getLength():
                existing.growStructure(old_type.getLength() - existing.getLength())
            self.manager.replaceDataType(old_type, existing, False)

    def disposer_type(self):
        """sead::IDisposer: vtable, mDisposerHeap and the mListNode that links it into its heap."""
        category = CategoryPath(CLASSES + '/sead')
        existing = self.manager.getDataType(category, 'IDisposer')
        if existing is not None:
            return existing
        pointer = PointerDataType(VoidDataType.dataType, 8, self.manager)
        node = self.manager.getDataType(category, 'ListNode')
        if node is None:
            node = StructureDataType(category, 'ListNode', 0, self.manager)
            node.add(pointer, 8, 'mPrev', None)
            node.add(pointer, 8, 'mNext', None)
            node = self.manager.addDataType(node, DataTypeConflictHandler.DEFAULT_HANDLER)
        result = StructureDataType(category, 'IDisposer', 0, self.manager)
        result.add(pointer, 8, 'vtable', None)
        result.add(pointer, 8, 'mDisposerHeap', None)
        result.add(node, node.getLength(), 'mListNode', None)
        return self.manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER)

    def singleton_type(self, owner, space, row):
        """The structure Ghidra types `this` with in the singleton's class, at least as large as its allocation.

        An existing structure, such as a BCSV reader's, grows to that size and
        keeps its fields. The vtable and disposer members are only added over
        undefined bytes.
        """
        disposer = self.disposer_type()
        offset = row['disposerOffset']
        size = max(row['size'] or 0, offset + disposer.getLength(), 8)
        structure = VariableUtilities.findExistingClassStruct(owner, self.manager)
        if structure is None:
            category, short = class_category(space), space.split('::')[-1]
            if self.manager.getDataType(category, short) is not None:
                self.skipped.append('%s: %s/%s is not a structure' % (space, category, short))
                return None
            result = StructureDataType(category, short, size, self.manager)
            result.setDescription('sead singleton %s, allocated with 0x%X bytes.' % (space, size) if row['size'] else
                                  'sead singleton %s. Its allocation size is unknown, so it ends after the disposer.' % space)
            structure = self.manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER)
            self.renamed['types'] += 1
        elif structure.getLength() < size:
            structure.growStructure(size - structure.getLength())
            self.renamed['grownTypes'] += 1
        if row['vtable'] is not None and offset >= 8 and free(structure, 0, 8):
            structure.replaceAtOffset(0, PointerDataType(VoidDataType.dataType, 8, self.manager), 8, 'vtable', None)
            self.renamed['vtableFields'] += 1
        if free(structure, offset, offset + disposer.getLength()):
            structure.replaceAtOffset(offset, disposer, disposer.getLength(), DISPOSER_FIELD, None)
        return structure

    def method(self, address, owner):
        """Move a function every caller passes the singleton to into its class, keeping its name, and make it `__thiscall`.

        Only functions with a default name in the global namespace move.
        """
        function = self.renameable(address)
        if function is None or function.isThunk():
            return
        if function.getParentNamespace().isGlobal():
            function.setParentNamespace(owner)
            self.renamed['methods'] += 1
        if function.getParentNamespace().getID() == owner.getID():
            self.type_method(function)

    def heap_pointer(self):
        """A pointer to sead::Heap when the program has that type, else `void *`."""
        heap = self.manager.getDataType(CategoryPath(CLASSES + '/sead'), 'Heap')
        return PointerDataType(heap if heap is not None else VoidDataType.dataType, 8, self.manager)

    def typed_global(self, address, pointee):
        """Make a global a pointer to `pointee`, replacing only undefined data or an untyped pointer."""
        where, wanted = self.address(address), PointerDataType(pointee, 8, self.manager)
        data = self.listing.getDefinedDataContaining(where)
        if data is not None:
            if data.getMinAddress() != where or not untyped(data.getDataType()) or data.getDataType().isEquivalent(wanted):
                return
        try:
            DataUtilities.createData(self.program, where, wanted, -1, False,
                                     DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
            self.renamed['typedGlobals'] += 1
        except Exception as error:
            self.skipped.append('0x%X: cannot type it as %s (%s)' % (address, wanted.getName(), error))

    def typed_return(self, address, pointee, parameters=()):
        """Make a function return a pointer to `pointee` when its return type is still untyped.

        A typed return locks the signature, so the decompiler stops looking for
        parameters. The known `parameters`, as (name, data type), are set with
        it, and a signature an earlier run locked without them gets them back.
        These functions are static, so a locked `__thiscall` or unknown calling
        convention becomes the default one.
        """
        function = self.functions.getFunctionAt(self.address(address))
        wanted = PointerDataType(pointee, 8, self.manager)
        if function is None or function.getSignatureSource() not in (SourceType.DEFAULT, SourceType.ANALYSIS):
            return
        current = function.getReturnType()
        convention = function.getCallingConvention()
        static = convention is not None and str(convention.getName()) != '__thiscall'
        if current.isEquivalent(wanted):
            given = [parameter for parameter in function.getParameters() if not parameter.isAutoParameter()]
            if function.getSignatureSource() == SourceType.DEFAULT or (static and len(given) >= len(parameters)):
                return
            self.renamed['unlocked'] += 1
        elif untyped(current):
            self.renamed['typedReturns'] += 1
        else:
            return
        function.updateFunction(None if static else Function.DEFAULT_CALLING_CONVENTION_STRING, ReturnParameterImpl(wanted, self.program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                True, SourceType.ANALYSIS, *[ParameterImpl(name, dtype, self.program) for name, dtype in parameters])

    def type_method(self, function):
        """Make a constructor or method `__thiscall`; see make_thiscall."""
        try:
            outcome = make_thiscall(function)
        except Exception as error:
            self.skipped.append('%s: cannot make it __thiscall (%s)' % (function.getName(True), error))
            return
        if outcome == 'typed':
            self.renamed['typedMethods'] += 1
        elif outcome == 'unlocked':
            self.renamed['unlocked'] += 1

def class_category(space):
    """Where Ghidra looks for the structure of class `space`: a category named after its parent namespace."""
    return CategoryPath('/'.join([CLASSES] + space.split('::')[:-1]))


def free(structure, start, end):
    """True when no defined field of the structure overlaps [start, end)."""
    return not any(c.getOffset() < end and c.getOffset() + c.getLength() > start for c in structure.getDefinedComponents())


def untyped(dtype):
    """Undefined data, or a pointer to nothing in particular."""
    if Undefined.isUndefined(dtype):
        return True
    if isinstance(dtype, Pointer):
        target = dtype.getDataType()
        return target is None or Undefined.isUndefined(target) or str(target.getName()) == 'void'
    return False


def vtable_class(symbols, address):
    """The class a vtable label names: `Class::vtable`, or `ACNH_<Class>_vtable` from the other scripts."""
    for symbol in symbols.getSymbols(address):
        if symbol.isDynamic():
            continue
        name, parent = str(symbol.getName()), symbol.getParentNamespace()
        if name == 'vtable' and not parent.isGlobal():
            space = str(parent.getName(True))
            if not space.startswith(PLACEHOLDER_SPACE[:-2]):
                return space
        match = VTABLE_LABEL.match(name)
        if match and parent.isGlobal() and not PLACEHOLDER_LABEL.match(match.group(1)):
            return match.group(1)
    return None


def class_names(program, rows, known, readers, delegates):
    """Pick a class per singleton and say where the name came from.

    In order: the BCSV reader its vtable belongs to, a labelled vtable, a
    constructor named after its class, then the `Class::method` names in its
    code. A name two singletons share is dropped.
    """
    symbols, functions = program.getSymbolTable(), program.getFunctionManager()
    space = program.getAddressFactory().getDefaultAddressSpace()
    chosen = {}
    for row in rows:
        name, source = None, None
        if row['instance'] in readers:
            name, source = '::'.join(readers[row['instance']]), 'its BCSV reader vtable'
        if name is None and row['vtable'] is not None:
            name, source = vtable_class(symbols, space.getAddress(row['vtable'])), 'its vtable label'
        if name is None and row['constructor'] is not None and row['constructor'] not in known:
            function = functions.getFunctionAt(space.getAddress(row['constructor']))
            if function is not None and not function.getParentNamespace().isGlobal():
                parent = str(function.getParentNamespace().getName(True))
                if str(function.getName()) == parent.split('::')[-1] and not parent.startswith(PLACEHOLDER_SPACE[:-2]):
                    name, source = parent, "its constructor's name"
        if name is None and delegates.get(row['instance']):
            name, source = delegates[row['instance']], 'the Class::method names in its code'
        chosen[row['instance']] = (name, source)
    duplicates = set(n for n, count in Counter(name for name, source in chosen.values()).items() if n and count > 1)
    return dict((instance, ('::'.join(identifier(part) for part in name.split('::')), source)
                 if name and name not in duplicates else (PLACEHOLDER_SPACE % instance, None))
                for instance, (name, source) in chosen.items())


def run_library(program, monitor, directory, emit=print):
    image = complete_image(program, monitor)
    config = library_definitions(directory)
    found = scan_library(program, monitor, image, config, emit)
    if not found['exports'] and not found['stubs'] and not found['matches']:
        raise AnalysisFailure('No dynamic symbols or library fingerprints recognized; no changes applied.')
    annotations = LibraryAnnotations(program, monitor)
    names = class_names(program, found['singletons'], found['known'], found['readers'], found['delegates'])
    spaces = dict((instance, name) for instance, (name, source) in names.items())
    constructors = Counter(row['constructor'] for row in found['singletons'] if row['constructor'] is not None)
    types, owners = {}, {}
    ranks = dict((address, index + 1) for index, (address, count) in enumerate(found['hot']))

    def apply():
        for address, name in sorted(found['exports'].items()):
            monitor.checkCancelled()
            annotations.library(address, name, 'exports')
        for address, name in sorted(found['stubs'].items()):
            monitor.checkCancelled()
            annotations.library(address, name, 'imports', create=True)
        for address, entry in sorted(found['matches'].items()):
            monitor.checkCancelled()
            annotations.library(address, entry['name'], 'library')
            annotations.comment(address, 'Library function %s recognized by its masked fingerprint (%d bytes). %s' %
                                (entry['name'], entry['size'], entry.get('evidence', '')))
        for row in found['singletons']:
            monitor.checkCancelled()
            space, source = names[row['instance']]
            annotations.adopt(row['instance'], space)
            owner = owners[row['instance']] = annotations.klass(space)
            annotations.member(row['function'], space, 'createInstance', 'singletons')
            annotations.global_label(row['instance'], space, 'sInstance')
            if row['disposer'] is not None:
                annotations.global_label(row['disposer'], space, 'sSingletonDisposer_')
                annotations.typed_global(row['disposer'], annotations.disposer_type())
            structure = types[row['instance']] = annotations.singleton_type(owner, space, row)
            if structure is not None:
                annotations.typed_global(row['instance'], structure)
                annotations.typed_return(row['function'], structure, [('heap', annotations.heap_pointer())])
            # A constructor two singletons share is a base class's, not theirs.
            if row['constructor'] is not None and constructors[row['constructor']] == 1:
                short = space.split('::')[-1]
                annotations.member(row['constructor'], space, short, 'constructors')
                function = annotations.functions.getFunctionAt(annotations.address(row['constructor']))
                if (function is not None and str(function.getName()) == short and
                        function.getParentNamespace().getID() == owner.getID()):
                    annotations.type_method(function)
            if row['disposerVtable'] is not None:
                annotations.global_label(row['disposerVtable'], space + '::SingletonDisposer_', 'vtable')
                for slot, name in enumerate(('~SingletonDisposer_', '~SingletonDisposer_deleting')):
                    target = image.pointer(row['disposerVtable'] + slot * 8)
                    if target is not None and image.executable(target):
                        annotations.member(target, space + '::SingletonDisposer_', name, 'disposers')
            details = [SINGLETON_COMMENT + '%s: sInstance 0x%X' % (space, row['instance'])]
            if row['disposer'] is not None:
                details.append('sSingletonDisposer_ 0x%X' % row['disposer'])
            details.append('disposer at +0x%X' % row['disposerOffset'])
            if row['size']:
                details.append('instance size 0x%X' % row['size'])
            if row['constructor'] is not None:
                details.append('constructor 0x%X' % row['constructor'])
            if row['vtable'] is not None:
                details.append('vtable 0x%X' % row['vtable'])
            message = '; '.join(details) + '.'
            if source:
                message += ' Named after %s.' % source
            annotations.comment(row['function'], message, SINGLETON_COMMENT)
        for address, instance in sorted(found['getters'].items()):
            annotations.member(address, spaces[instance], 'instance', 'getters')
            if types.get(instance) is not None:
                annotations.typed_return(address, types[instance])
        for address, instance in sorted(found['methods'].items()):
            monitor.checkCancelled()
            annotations.method(address, owners[instance])
        for address, count in found['hot']:
            monitor.checkCancelled()
            if address in found['shapes']:
                name = shape_name(found['shapes'][address], address)
                function = annotations.renameable(address) if name else None
                if function is not None:
                    function.setName(name, SourceType.ANALYSIS)
                    annotations.renamed['hot'] += 1
            annotations.comment(address, 'Hot function: %d direct call sites (rank %d of %d with at least %d).' %
                                (count, ranks[address], len(found['hot']), found['hot'][-1][1]))
    transaction(program, 'Name ACNH library functions and singletons', monitor, apply)
    found['problems'].extend(annotations.skipped)
    renamed = annotations.renamed
    emit('Finished. %d exports, %d imports, %d fingerprinted library functions, %d singletons '
         '(%d globals, %d disposer destructors, %d getters, %d constructors) and %d trivial hot functions named; '
         '%d hot functions commented; %d problems.' %
         (renamed['exports'], renamed['imports'], renamed['library'], renamed['singletons'], renamed['globals'],
          renamed['disposers'], renamed['getters'], renamed['constructors'], renamed['hot'], len(found['hot']),
          len(found['problems'])))
    named = sum(1 for name, source in names.values() if source)
    emit('Singleton classes: %d of %d named (%d placeholders replaced); %d structures created, %d grown, '
         '%d vtable fields added; %d globals and %d return types typed; %d functions moved into their class; '
         '%d constructors and methods made __thiscall; %d signatures an earlier run locked restored.' %
         (named, len(names), renamed['adopted'], renamed['types'], renamed['grownTypes'], renamed['vtableFields'],
          renamed['typedGlobals'], renamed['typedReturns'], renamed['methods'], renamed['typedMethods'],
          renamed['unlocked']))
    for message in found['problems']:
        emit('Skipped ' + message)
    for address, count in found['hot'][:25]:
        function = program.getFunctionManager().getFunctionAt(annotations.address(address))
        emit('  %6d calls  0x%X  %s' % (count, address, function.getName(True) if function else '-'))
    return found
