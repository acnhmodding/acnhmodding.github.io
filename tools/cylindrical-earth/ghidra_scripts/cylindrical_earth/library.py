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
from ghidra.program.model.symbol import SourceType
from .bcsv_core import identifier
from .analysis import AnalysisFailure, Annotations, image_for, transaction
from .library_core import (
    call_counts, dynamic_symbols, fde_ranges, hot_functions, instance_getter,
    library_definitions, match_library, module_header, plt_stubs, shape,
    shape_name, singletons,
)

DEFAULT_NAME = ('FUN_', 'sub_')
VTABLE_LABEL = re.compile(r'^(?:ACNH_)?(?:Actor_)?(.+?)_vtable(?:_[0-9A-Fa-f]+)?$')


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
                singletons=rows, getters=getters, hot=hot, shapes=shapes)


class LibraryAnnotations(Annotations):
    def __init__(self, program, monitor):
        Annotations.__init__(self, program, monitor)
        self.functions = program.getFunctionManager()
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


def class_names(program, rows, known):
    """Pick a namespace per singleton from a labelled vtable or a named constructor."""
    symbols, functions = program.getSymbolTable(), program.getFunctionManager()
    space = program.getAddressFactory().getDefaultAddressSpace()
    chosen = {}
    for row in rows:
        name = None
        if row['vtable'] is not None:
            for symbol in symbols.getSymbols(space.getAddress(row['vtable'])):
                match = VTABLE_LABEL.match(str(symbol.getName()))
                if match and not symbol.isDynamic():
                    name = match.group(1)
                    break
        if name is None and row['constructor'] is not None and row['constructor'] not in known:
            function = functions.getFunctionAt(space.getAddress(row['constructor']))
            if function is not None and not function.getParentNamespace().isGlobal():
                parent = str(function.getParentNamespace().getName(True))
                if str(function.getName()) == parent.split('::')[-1]:
                    name = parent
        chosen[row['instance']] = name
    duplicates = set(n for n, count in Counter(chosen.values()).items() if n and count > 1)
    return dict((instance, '::'.join(identifier(part) for part in name.split('::'))
                 if name and name not in duplicates else 'ACNH_Singleton_%X' % instance)
                for instance, name in chosen.items())


def run_library(program, monitor, directory, emit=print):
    image = complete_image(program, monitor)
    config = library_definitions(directory)
    found = scan_library(program, monitor, image, config, emit)
    if not found['exports'] and not found['stubs'] and not found['matches']:
        raise AnalysisFailure('No dynamic symbols or library fingerprints recognized; no changes applied.')
    annotations = LibraryAnnotations(program, monitor)
    spaces = class_names(program, found['singletons'], found['known'])
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
            space = spaces[row['instance']]
            annotations.member(row['function'], space, 'createInstance', 'singletons')
            annotations.global_label(row['instance'], space, 'sInstance')
            if row['disposer'] is not None:
                annotations.global_label(row['disposer'], space, 'sSingletonDisposer_')
            if row['disposerVtable'] is not None:
                annotations.global_label(row['disposerVtable'], space + '::SingletonDisposer_', 'vtable')
                for slot, name in enumerate(('~SingletonDisposer_', '~SingletonDisposer_deleting')):
                    target = image.pointer(row['disposerVtable'] + slot * 8)
                    if target is not None and image.executable(target):
                        annotations.member(target, space + '::SingletonDisposer_', name, 'disposers')
            details = ['sead singleton %s: sInstance 0x%X' % (space, row['instance'])]
            if row['disposer'] is not None:
                details.append('sSingletonDisposer_ 0x%X' % row['disposer'])
            details.append('disposer at +0x%X' % row['disposerOffset'])
            if row['size']:
                details.append('instance size 0x%X' % row['size'])
            if row['constructor'] is not None:
                details.append('constructor 0x%X' % row['constructor'])
            if row['vtable'] is not None:
                details.append('vtable 0x%X' % row['vtable'])
            annotations.comment(row['function'], '; '.join(details) + '.')
        for address, instance in sorted(found['getters'].items()):
            annotations.member(address, spaces[instance], 'instance', 'getters')
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
    renamed = annotations.renamed
    emit('Finished. %d exports, %d imports, %d fingerprinted library functions, %d singletons '
         '(%d globals, %d disposer destructors, %d getters) and %d trivial hot functions named; '
         '%d hot functions commented; %d problems.' %
         (renamed['exports'], renamed['imports'], renamed['library'], renamed['singletons'], renamed['globals'],
          renamed['disposers'], renamed['getters'], renamed['hot'], len(found['hot']), len(found['problems'])))
    for message in found['problems']:
        emit('Skipped ' + message)
    for address, count in found['hot'][:25]:
        function = program.getFunctionManager().getFunctionAt(annotations.address(address))
        emit('  %6d calls  0x%X  %s' % (count, address, function.getName(True) if function else '-'))
    return found
