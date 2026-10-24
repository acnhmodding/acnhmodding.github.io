# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fill the undefined bytes of ACNH class structures from the methods that use them."""
from __future__ import print_function
from collections import defaultdict
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.app.decompiler.util import FillOutStructureHelper
from ghidra.program.model.data import (
    AbstractFloatDataType, AbstractIntegerDataType, Pointer, PointerDataType, Structure, TypeDef, Undefined, VoidDataType,
)
from ghidra.program.model.listing import GhidraClass
from .analysis import AnalysisFailure, transaction
from .fields_core import merge_fields
from .library import free

# Only structures the ACNH scripts create are filled.
ROOT = '/ACNH/'


def ours(structure):
    return isinstance(structure, Structure) and (str(structure.getCategoryPath().getPath()) + '/').startswith(ROOT)


def this_structure(function):
    """The ACNH structure a method's `this` points to, or None."""
    if not isinstance(function.getParentNamespace(), GhidraClass) or str(function.getCallingConventionName()) != '__thiscall':
        return None
    parameters = function.getParameters()
    if not parameters or not parameters[0].isAutoParameter() or not isinstance(parameters[0].getDataType(), Pointer):
        return None
    target = parameters[0].getDataType().getDataType()
    return target if ours(target) else None


def described(dtype):
    """(kind, key) for an accessed value's type, or None for an untyped access; keys are data-type paths."""
    while isinstance(dtype, TypeDef):
        dtype = dtype.getBaseDataType()
    if dtype is None or Undefined.isUndefined(dtype):
        return None
    if isinstance(dtype, Pointer):
        target = dtype.getDataType()
        vague = target is None or Undefined.isUndefined(target) or isinstance(target, VoidDataType)
        return 'pointer', None if vague else str(target.getDataTypePath())
    if isinstance(dtype, AbstractFloatDataType):
        return 'float', str(dtype.getDataTypePath())
    if isinstance(dtype, AbstractIntegerDataType):
        return 'int', str(dtype.getDataTypePath())
    return 'other', str(dtype.getDataTypePath())


def place(structure, offset, length):
    """The (structure, offset) that holds an access: the deepest embedded ACNH structure around it.

    None when the access falls outside the structure or on a field that is already defined.
    """
    while 0 <= offset and offset + length <= structure.getLength():
        component = structure.getComponentAt(offset)
        if component is None or Undefined.isUndefined(component.getDataType()):
            return structure, offset
        inner, start = component.getDataType(), component.getOffset()
        if not ours(inner) or offset + length > start + component.getLength():
            return None
        structure, offset = inner, offset - start
    return None


class Accesses:
    """Collect the typed loads and stores each method makes through `this`."""
    def __init__(self, program, monitor):
        self.program, self.monitor = program, monitor
        self.helper = FillOutStructureHelper(program, monitor)
        options = DecompileOptions()
        options.grabFromProgram(program)
        self.decompiler = self.helper.setUpDecompiler(options)
        if self.decompiler is None:
            raise AnalysisFailure('Could not initialize the decompiler')
        self.decompiler.toggleCCode(False)  # only the syntax tree is read
        self.types = {}  # key -> data type
        self.failed = 0

    def close(self):
        self.decompiler.dispose()

    def read(self, function):
        """Yield (offset, length, kind, key) for each typed access through `this`."""
        results = self.decompiler.decompileFunction(function, 60, self.monitor)
        high = results.getHighFunction() if results is not None else None
        symbols = high.getLocalSymbolMap() if high is not None else None
        symbol = symbols.getParamSymbol(0) if symbols is not None and symbols.getNumParams() > 0 else None
        if high is None:
            self.failed += 1
            return
        variable = symbol.getHighVariable() if symbol is not None else None
        if variable is None:
            return  # this is unused
        # A new structure leaves the real one alone; only the access lists are used.
        self.helper.processStructure(variable, function, True, False, None)
        accesses = [(pair, pair.getPcodeOp().getOutput(), True) for pair in self.helper.getLoadPcodeOps()]
        accesses += [(pair, pair.getPcodeOp().getInput(2), False) for pair in self.helper.getStorePcodeOps()]
        for pair, value, load in accesses:
            dtype = DecompilerUtils.getDataTypeTraceForward(value) if load else DecompilerUtils.getDataTypeTraceBackward(value)
            kind = described(dtype)
            if kind is None or dtype.getLength() != value.getSize():
                continue
            self.types.setdefault(kind[1], dtype.getDataType() if kind[0] == 'pointer' else dtype)
            yield int(pair.getOffset()), int(value.getSize()), kind[0], kind[1]


def run_fields(program, monitor, emit=print):
    manager = program.getDataTypeManager()
    methods = [f for f in program.getFunctionManager().getFunctions(True) if this_structure(f) is not None]
    if not methods:
        raise AnalysisFailure('No methods with an ACNH structure as this; run the other scripts first.')
    monitor.initialize(len(methods))
    monitor.setMessage('Reading class methods')
    accesses, found, outside = Accesses(program, monitor), defaultdict(list), 0
    structures = {}
    try:
        for function in methods:
            monitor.checkCancelled()
            monitor.incrementProgress(1)
            root = this_structure(function)
            for offset, length, kind, key in accesses.read(function):
                spot = place(root, offset, length)
                if spot is None:
                    outside += 1
                    continue
                path = str(spot[0].getDataTypePath())
                structures[path] = spot[0]
                found[path].append((spot[1], length, kind, key))
    finally:
        accesses.close()
    added, filled, disagreed, skipped = [0], set(), [0], []
    def apply():
        for path in sorted(found):
            monitor.checkCancelled()
            structure = structures[path]
            fields, disagreements = merge_fields(found[path], lambda offset, length: free(structure, offset, offset + length))
            disagreed[0] += len(disagreements)
            for offset, (length, kind, key) in sorted(fields.items()):
                dtype = accesses.types[key] if key is not None else VoidDataType.dataType
                if kind == 'pointer':
                    dtype = PointerDataType(dtype, 8, manager)
                try:
                    structure.replaceAtOffset(offset, dtype, length, 'field_0x%x' % offset, None)
                except Exception as error:
                    skipped.append('%s+0x%X: cannot add a %s field (%s)' % (path, offset, dtype.getName(), error))
                    continue
                added[0] += 1
                filled.add(path)
    transaction(program, 'Fill ACNH class structures', monitor, apply)
    emit('Finished. %d methods read (%d could not be decompiled); %d fields added to %d structures; %d offsets left undefined '
         'because their accesses disagree; %d accesses on defined fields or outside the structure ignored.' %
         (len(methods), accesses.failed, added[0], len(filled), disagreed[0], outside))
    for message in skipped:
        emit('Skipped ' + message)
