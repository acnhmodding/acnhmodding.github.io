# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Updated native Ghidra adaptation of Treeki/CylindricalEarth's BCSV scripts.
from __future__ import print_function
import os
import re
from collections import defaultdict
from java.lang import String
from java.nio import ByteBuffer
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (
    ArrayDataType, CategoryPath, CharDataType, DataTypeConflictHandler,
    DataUtilities, EnumDataType, FloatDataType, IntegerDataType, Pointer, PointerDataType,
    ShortDataType, SignedByteDataType, Structure, StructureDataType, Undefined,
    UnsignedCharDataType, UnsignedIntegerDataType, UnsignedShortDataType, VoidDataType,
)
from ghidra.program.model.listing import CodeUnit, Function, GhidraClass, VariableUtilities
from ghidra.program.model.symbol import SourceType, SymbolType
from .bcsv_core import (FIELD_COMMENT, FINDER_COMMENT, FINDER_SCAN, cache_from_pcode, field_names, identifier,
                   is_field_finder, load_definitions, map_cache_slots, order_disagreements, own_slots,
                   plan_accessors, scan_index_tables, scan_readers, vote_cache_slots, wide_constants)
from .image import Image, reader_classes, this_extent

RELRO_BLOCKS = (".got", ".got.plt", ".data.rel.ro")
RTTI_VTABLE = re.compile(r"^ACNH_\w+_vtable_[0-9A-F]+$")
# Reader class structures go in a category named after the class's parent
# namespace, which is where Ghidra looks for the type of `this`.
CLASSES = "/ACNH/Classes"
# Every BCSV reader vtable has these nine slots, from the shared reader base class.
SLOT_NAMES = ("IsDerivedFrom", "GetTypeInfo", "Destructor", "DeletingDestructor", "Load", "Reload",
              "GetFileName", "Clear", "SetupRows")
# Placeholder names from RecoverRTTIHierarchy and other tools, replaced by the slot name.
PLACEHOLDER = re.compile(r"^(?:VirtualMethod_\w+|\w+_at_[0-9A-Fa-f]+|"
                         r"ACNH_\w+_(?:IsDerivedFrom|GetTypeInfo|Destructor|DeletingDestructor))$")
# Names this script gives field readers; a rerun corrects them when its plan changes.
OWN_ACCESSOR = re.compile(r"^(?:Read_\w+|FindField(?:_[0-9A-F]+)?)$")

try:
    text_type = unicode
except NameError:
    text_type = str


def read_bytes(memory, address, size):
    buffer = ByteBuffer.allocate(size).array()
    if memory.getBytes(address, buffer) != size:
        raise ValueError("Short read at " + str(address))
    return text_type(String(buffer, "ISO-8859-1")).encode("latin-1")


def read_blocks(program, monitor):
    """Use the open program's relocated memory, not raw NSO pointer values."""
    texts, strings, tables, writable = [], [], [], []
    memory = program.getMemory()
    for block in memory.getBlocks():
        monitor.checkCancelled()
        name = str(block.getName())
        start, size = int(block.getStart().getOffset()), int(block.getSize())
        if name in (".bss", ".data"):
            writable.append((start, start + size))
        target = None
        if name in (".text", ".plt", ".rocrt.init"):
            target = texts
        elif name.startswith(".rodata"):
            target = strings
        elif name in (".data.rel.ro", ".data"):
            target = tables
        if target is None or not block.isInitialized():
            continue
        monitor.setMessage("Reading " + name)
        target.append((start, read_bytes(memory, block.getStart(), size)))
    if not texts or not strings or not tables or not writable:
        raise ValueError("Expected Switch memory blocks are missing. Import and analyze the NSO first.")
    return texts, strings, tables, writable


def got_blocks(program):
    """The GOT, through which some getters load the address they return."""
    result = []
    for block in program.getMemory().getBlocks():
        if str(block.getName()) in (".got", ".got.plt") and block.isInitialized():
            result.append((int(block.getStart().getOffset()),
                           read_bytes(program.getMemory(), block.getStart(), int(block.getSize()))))
    return result


def make_thiscall(function):
    """Make a method `__thiscall`, so Ghidra types `this` as its class's structure.

    Returns 'typed', 'unlocked' or None. A default signature only changes its
    calling convention, so the decompiler still finds the other parameters;
    one an earlier run locked with nothing but `this` is unlocked again.
    Signatures you set yourself are left alone. In one an analyzer set, a
    first parameter already in x0 is that same pointer, so `this` replaces it.
    """
    if function is None or function.hasCustomVariableStorage():
        return None
    source, thiscall = function.getSignatureSource(), str(function.getCallingConventionName()) == "__thiscall"
    parameters = [parameter for parameter in function.getParameters() if not parameter.isAutoParameter()]
    if source == SourceType.DEFAULT:
        if thiscall:
            return None
        function.setCallingConvention("__thiscall")
        return "typed"
    if source != SourceType.ANALYSIS:
        return None
    if thiscall:
        if parameters or not Undefined.isUndefined(function.getReturnType()):
            return None
        function.setSignatureSource(SourceType.DEFAULT)
        return "unlocked"
    if parameters and parameters[0].isRegisterVariable() and str(parameters[0].getRegister().getName()) == "x0":
        parameters = parameters[1:]
    function.updateFunction("__thiscall", function.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                            True, SourceType.ANALYSIS, *parameters)
    return "typed"


def pcode_node(node, ops=None):
    size = int(node.getSize())
    offset = int(node.getOffset())
    if node.isConstant():
        offset &= (1 << (size * 8)) - 1
    result = {"space": str(node.getAddress().getAddressSpace().getName()),
              "offset": "%x" % offset, "size": size,
              "is_constant": bool(node.isConstant()), "is_unique": bool(node.isUnique())}
    # High P-code reuses unique offsets; the defining op identifies the value.
    definition = node.getDef() if ops is not None else None
    if definition is not None:
        result["def"] = ops.setdefault(str(definition.getSeqnum()), len(ops))
    return result


def pcode_operations(high_function):
    result, ops = [], {}
    iterator = high_function.getPcodeOps()
    while iterator.hasNext():
        op = iterator.next()
        output = op.getOutput()
        entry = {"mnemonic": str(op.getMnemonic()),
                 "inputs": [pcode_node(node, ops) for node in op.getInputs()],
                 "output": pcode_node(output) if output is not None else None,
                 "id": ops.setdefault(str(op.getSeqnum()), len(ops))}
        result.append(entry)
    return {"high_pcodes": result}


class NativeBcsv:
    def __init__(self, program, monitor, definitions):
        self.program, self.monitor, self.definitions = program, monitor, definitions
        self.manager = program.getDataTypeManager()
        self.listing = program.getListing()
        self.symbols = program.getSymbolTable()
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        self.schemas = dict((schema["name"], schema) for schema in definitions["schemas"])
        self.summary = {"readers": 0, "derivedReaders": 0, "readerMethods": 0, "readerTypes": 0, "typedMethods": 0, "unlockedMethods": 0,
                        "matchedCaches": 0, "rows": 0,
                        "indexEnumTypes": 0, "fieldReaders": 0, "accessors": 0, "finders": 0, "staleComments": 0, "partialCaches": 0, "orderChecked": 0,
                        "orderDisagreements": [], "skipped": []}
        self.caches = []
        self.constants = {}

    def address(self, value):
        return self.space.getAddress(value)

    def comment(self, address, message, replace=None):
        """Append a pre-comment paragraph; `replace` drops other paragraphs that start with that prefix.

        Returns True if the comment changed. A `message` of None only drops.
        """
        address = self.address(address)
        previous = self.listing.getComment(CodeUnit.PRE_COMMENT, address)
        previous = str(previous) if previous else ""
        parts = [part for part in previous.split("\n\n") if part]
        if replace:
            parts = [part for part in parts if part == message or not part.startswith(replace)]
        elif message in previous:
            return False
        if message and message not in parts:
            parts.append(message)
        value = "\n\n".join(parts)
        if value == previous:
            return False
        self.listing.setComment(address, CodeUnit.PRE_COMMENT, value or None)
        return True

    def namespace(self, parent, name):
        value = self.symbols.getNamespace(name, parent)
        return value if value is not None else self.symbols.createNameSpace(parent, name, SourceType.ANALYSIS)

    def klass(self, parent, name):
        """The class `parent::name`, converting a namespace an earlier run created."""
        value = self.namespace(parent, name)
        return value if isinstance(value, GhidraClass) else self.symbols.convertNamespaceToClass(value)

    def label(self, value, name, namespace=None):
        address = self.address(value)
        previous = self.symbols.getPrimarySymbol(address)
        if namespace is None:
            namespace = self.program.getGlobalNamespace()
        if previous is not None and not previous.isDynamic() and not str(previous.getName()).startswith(("DAT_", "PTR_", "UNK_")):
            # An earlier run's label of the same name may sit in another namespace.
            if previous.getSource() == SourceType.ANALYSIS and str(previous.getName()) == name:
                if previous.getParentNamespace().getID() != namespace.getID():
                    previous.setNamespace(namespace)
                return
            # RecoverRTTIHierarchy labels every reader vtable first; keep its label
            # as a secondary name rather than skipping the reader's own label.
            if previous.getSource() == SourceType.ANALYSIS and RTTI_VTABLE.match(str(previous.getName())):
                self.symbols.createLabel(address, name, namespace, SourceType.ANALYSIS).setPrimary()
            return
        self.symbols.createLabel(address, name, namespace, SourceType.ANALYSIS)

    def root(self):
        """The `bcsv` namespace, after moving anything an older version put in `Bcsv` into it."""
        symbols, top = self.symbols, self.program.getGlobalNamespace()
        root = self.namespace(top, "bcsv")
        old = symbols.getNamespace("Bcsv", top)
        if old is None:
            return root
        for child in list(symbols.getChildren(old.getSymbol())):
            target = None
            if child.getSymbolType() == SymbolType.NAMESPACE:
                target = symbols.getNamespace(child.getName(), root)
            if target is None:
                child.setNamespace(root)
                continue
            namespace = symbols.getNamespace(child.getName(), old)
            for symbol in list(symbols.getChildren(child)):
                symbol.setNamespace(target)
            if not symbols.getChildren(namespace.getSymbol()).hasNext():
                namespace.getSymbol().delete()
        if not symbols.getChildren(old.getSymbol()).hasNext():
            old.getSymbol().delete()
        return root

    def function(self, value):
        """The function at a vtable slot, created when Ghidra has not found it yet."""
        address = self.address(value)
        function = self.program.getFunctionManager().getFunctionAt(address)
        if function is None:
            if self.listing.getInstructionAt(address) is None:
                DisassembleCommand(address, None, True).applyTo(self.program, self.monitor)
            CreateFunctionCmd(address).applyTo(self.program, self.monitor)
            function = self.program.getFunctionManager().getFunctionAt(address)
        return function

    def name_readers(self, readers, image):
        """Label each reader vtable and name its nine slots in the class `bcsv::<File>`.

        A class derived from the reader is `bcsv::<File>::Derived`, with only the
        slots it overrides; the slots it inherits keep the base reader's names.
        Each class gets a structure, and its methods take `this` as a pointer to it.
        """
        root, methods, classes = self.root(), defaultdict(set), []
        for reader in readers:
            self.monitor.checkCancelled()
            namespace = self.klass(root, identifier(reader["name"]))
            # [class, base class or None, the slot functions it defines]
            owned = {namespace.getID(): [namespace, None, set()]}
            base, infos = reader_classes(image, reader["vtables"])
            if base is None:
                self.summary["skipped"].append(reader["name"] + ": cannot tell the base reader from its derived classes")
            derived = sorted(set(info for info in infos.values() if info != base)) if base is not None else []
            self.summary["derivedReaders"] += len(derived)
            inherited = defaultdict(set)
            for table in reader["vtables"]:
                if infos[table] == base:
                    for index in range(len(SLOT_NAMES)):
                        inherited[index].add(image.pointer(table + 8 * index))
            for table in reader["vtables"]:
                owner, kept = namespace, []
                if derived and infos[table] != base:
                    owner = self.klass(namespace, "Derived" if len(derived) == 1 else "Derived_%X" % infos[table])
                    owner = owned.setdefault(owner.getID(), [owner, namespace, set()])[0]
                self.label(table, "vtable", owner)
                for index, slot in enumerate(SLOT_NAMES):
                    address = image.pointer(table + 8 * index)
                    if owner is not namespace and address in inherited[index]:
                        kept.append("+0x%02X %s" % (8 * index, slot))
                        continue
                    owned[owner.getID()][2].add(address)
                    if base is not None or slot == "GetFileName":
                        methods[address].add((owner, slot))
                if owner is namespace:
                    message = "BCSV reader for %s.bcsv. Slots: %s." % (reader["name"], ", ".join(
                        "+0x%02X %s" % (8 * index, slot) for index, slot in enumerate(SLOT_NAMES)))
                else:
                    message = "BCSV reader for %s.bcsv, derived from %s; it inherits %s and overrides the other slots." % (
                        reader["name"], namespace.getName(True), ", ".join(kept) or "no slots")
                self.comment(table, message, "BCSV reader for ")
            # Base classes first, so derived structures can embed them.
            classes.extend(sorted(owned.values(), key=lambda value: value[1] is not None))
        for address, choices in sorted(methods.items()):
            self.monitor.checkCancelled()
            if len(choices) != 1:
                continue
            owner, name = next(iter(choices))
            self.name_method(address, owner, name)
        self.summary["readers"] = len(readers)
        functions, types = self.program.getFunctionManager(), {}
        for owner, base, slots in classes:
            self.monitor.checkCancelled()
            types[owner.getID()] = self.reader_type(owner, image, slots, types.get(base.getID()) if base else None)
            if types[owner.getID()] is None:
                continue
            for symbol in list(self.symbols.getChildren(owner.getSymbol())):
                if symbol.getSymbolType() == SymbolType.FUNCTION and int(symbol.getAddress().getOffset()) in slots:
                    self.type_method(functions.getFunctionAt(symbol.getAddress()))

    def reader_type(self, owner, image, slots, base_type):
        """The structure Ghidra types `this` with in `owner`'s methods, created when missing.

        Its size is the end of the highest field the class's own slot functions
        use, so the real object may be larger. A derived class starts with its
        base reader's structure as `super`.
        """
        existing = VariableUtilities.findExistingClassStruct(owner, self.manager)
        category = CategoryPath("/".join([CLASSES] + str(owner.getParentNamespace().getName(True)).split("::")))
        name = str(owner.getName())
        if existing is not None:
            if base_type is not None and isinstance(existing, Structure):
                self.embed_base(existing, base_type)
            elif isinstance(existing, Structure):
                self.type_vtable(existing, self.vtable_type(category, name))
            return existing
        if self.manager.getDataType(category, name) is not None:
            self.summary["skipped"].append("%s: %s/%s is not a structure" % (owner.getName(True), category, name))
            return None
        extent = 8
        for address in slots:
            function = self.function(address)
            if function is not None:
                entry = function.getEntryPoint()
                end = function.getBody().getRangeContaining(entry).getMaxAddress()
                extent = max(extent, this_extent(image, address, int(end.getOffset())))
        size = (extent + 7) & ~7
        if base_type is not None:
            first, field = base_type, "super"
        else:
            first, field = PointerDataType(self.vtable_type(category, name), 8, self.manager), "vtable"
        result = StructureDataType(category, name, max(size, int(first.getLength())), self.manager)
        result.replaceAtOffset(0, first, first.getLength(), field, None)
        result.setDescription("BCSV reader class %s. The size is the end of the highest field its own methods use; "
                              "the object may be larger." % owner.getName(True))
        self.summary["readerTypes"] += 1
        return self.manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER)

    def vtable_type(self, category, name):
        """The reader's `<Name>_vtable` structure, one pointer field per method, created when missing."""
        table = self.manager.getDataType(category, name + "_vtable")
        if table is None:
            pointer = PointerDataType(VoidDataType.dataType, 8, self.manager)
            table = StructureDataType(category, name + "_vtable", 8 * len(SLOT_NAMES), self.manager)
            for index, slot in enumerate(SLOT_NAMES):
                table.replaceAtOffset(8 * index, pointer, 8, slot, None)
            table = self.manager.addDataType(table, DataTypeConflictHandler.DEFAULT_HANDLER)
        return table

    def type_vtable(self, structure, table):
        """Point a base reader's existing `vtable` field at its vtable structure.

        NameLibraryFunctions.py gives a singleton reader's structure a `void *`
        vtable before this script runs. A field you typed yourself is kept.
        """
        first = [component for component in structure.getDefinedComponents() if component.getOffset() == 0]
        dtype = first[0].getDataType() if first else None
        if (not first or str(first[0].getFieldName()) != "vtable" or not isinstance(dtype, Pointer) or
                dtype.getLength() != 8 or str(dtype.getDataType().getName()) != "void"):
            return
        structure.replaceAtOffset(0, PointerDataType(table, 8, self.manager), 8, "vtable", None)

    def embed_base(self, structure, base_type):
        """Put the base reader's structure first in a derived reader's existing structure.

        NameLibraryFunctions.py creates the structure of a singleton derived
        reader with only a vtable pointer before this script runs. Any other
        field in the base's bytes keeps the structure as it is.
        """
        length = base_type.getLength()
        defined = [component for component in structure.getDefinedComponents() if component.getOffset() < length]
        first = defined[0] if len(defined) == 1 else None
        if structure.getLength() < length or first is None or first.getOffset() != 0 or str(first.getFieldName()) != "vtable":
            return
        try:
            structure.replaceAtOffset(0, base_type, length, "super", None)
        except Exception as error:
            self.summary["skipped"].append("%s: cannot embed %s (%s)" % (structure.getName(), base_type.getName(), error))

    def type_method(self, function):
        """Make a reader method `__thiscall`; see make_thiscall."""
        try:
            outcome = make_thiscall(function)
        except Exception as error:
            self.summary["skipped"].append("%s: cannot make it __thiscall (%s)" % (function.getName(True), error))
            return
        if outcome == "typed":
            self.summary["typedMethods"] += 1
        elif outcome == "unlocked":
            self.summary["unlockedMethods"] += 1

    def name_method(self, address, owner, name):
        """Name a reader method unless you named it yourself or another tool gave it a real name."""
        function = self.function(address)
        if function is None:
            self.summary["skipped"].append("0x%X: no function for %s::%s" % (address, owner.getName(True), name))
            return
        symbol, current = function.getSymbol(), str(function.getName())
        if not current.startswith(("FUN_", "sub_")):
            if symbol.getSource() == SourceType.USER_DEFINED:
                return
            if not PLACEHOLDER.match(current) and not (symbol.getSource() == SourceType.ANALYSIS and current in SLOT_NAMES):
                return
        if current == name and function.getParentNamespace().getID() == owner.getID():
            return
        try:
            symbol.setNameAndNamespace(name, owner, SourceType.ANALYSIS)
            self.summary["readerMethods"] += 1
        except Exception as error:
            self.summary["skipped"].append("0x%X: cannot name %s::%s (%s)" % (address, owner.getName(True), name, error))

    def existing_type(self, category, name):
        # Reuse older imports at the root, then this package's category. Never
        # replace an existing type merely because its category differs.
        root = self.manager.getDataType(CategoryPath.ROOT, name)
        return root if root is not None else self.manager.getDataType(CategoryPath(category), name)

    def row_field_type(self, field):
        types = {"signed char": SignedByteDataType.dataType,
                 "unsigned char": UnsignedCharDataType.dataType,
                 "short": ShortDataType.dataType, "unsigned short": UnsignedShortDataType.dataType,
                 "int": IntegerDataType.dataType, "unsigned int": UnsignedIntegerDataType.dataType,
                 "float": FloatDataType.dataType, "char": CharDataType.dataType}
        scalar = types[field["cType"]]
        width = field["width"]
        if field["kind"] in ("String", "Opaque", "BitField") or field.get("typeWarning"):
            return ArrayDataType(scalar, width, 1)
        if int(scalar.getLength()) != width:
            raise ValueError("Invalid scalar width for " + field["hash"])
        return scalar

    def structure(self, schema, cache=False, slots=None):
        """Row layout, or an offset cache whose slots hold the given field indices."""
        category = "/ACNH/BCSV/OffsetCaches" if cache else "/ACNH/BCSV/Rows"
        name = ("ACNH_BcsvOffsets_" if cache else "ACNH_BcsvRow_") + identifier(schema["name"])
        if slots is None:
            slots = list(range(schema["fieldCount"]))
        size = len(slots) * 4 if cache else schema["rowSize"]
        labels = field_names(schema["fields"])
        specs = []
        for position, index in enumerate(slots if cache else range(schema["fieldCount"])):
            field, label = schema["fields"][index], labels[index]
            data_type = IntegerDataType.dataType if cache else self.row_field_type(field)
            offset = position * 4 if cache else field["rowOffset"]
            description = "CRC32 field %s; row +0x%X" % (field["hash"], field["rowOffset"])
            if field["referenceName"]:
                description += "; " + field["referenceName"]
            if field.get("enumValues"):
                description += "; %d dictionary CRC32 choices (not runtime ordinals)" % len(field["enumValues"])
            if field.get("bitfieldLabels"):
                description += "; bitfield labels: " + ", ".join(field["bitfieldLabels"])
            specs.append((offset, data_type, label, description))
        current = self.existing_type(category, name)
        if current is not None:
            if not isinstance(current, Structure) or int(current.getLength()) != size:
                self.summary["skipped"].append(name + ": existing type has a different size/kind")
                return None
            for offset, data_type, label, description in specs:
                component = current.getComponentAt(offset)
                if component is None or component.getOffset() != offset or component.getLength() != data_type.getLength():
                    self.summary["skipped"].append(name + ": existing field layout differs")
                    return None
                if cache and str(component.getDataType().getName()) not in ("int", "int32", "int32_t"):
                    self.summary["skipped"].append(name + ": existing cache is not signed 32-bit offsets")
                    return None
            for offset, data_type, label, description in specs:
                component = current.getComponentAt(offset)
                old_name = component.getFieldName()
                if old_name is not None and str(old_name).startswith("Hash_") and not label.startswith("Hash_"):
                    component.setFieldName(label)
                if not component.getComment():
                    component.setComment(description)
            return current
        result = StructureDataType(CategoryPath(category), name, size, self.manager)
        if not cache:
            result.setDescription("BCSV row layout from bundled " + self.definitions["schemaVersion"] + " resources")
        elif len(slots) < schema["fieldCount"]:
            result.setDescription("Runtime signed row-offset cache for the %d of %d fields the game reads; "
                                  "slots mapped from the field hashes their accessors compare" % (len(slots), schema["fieldCount"]))
        else:
            result.setDescription("Runtime signed row-offset cache")
        for offset, data_type, label, description in specs:
            result.replaceAtOffset(offset, data_type, data_type.getLength(), label, description)
        return self.manager.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER)

    def apply_cache(self, reader, schema, slots):
        cache_type = self.structure(schema, cache=True, slots=slots)
        if cache_type is None:
            return False
        address = self.address(reader["offsetCache"])
        end = address.add(int(cache_type.getLength()) - 1)
        instructions = self.listing.getInstructions(address, True)
        if instructions.hasNext() and instructions.next().getAddress().compareTo(end) <= 0:
            self.summary["skipped"].append(reader["name"] + ": instructions overlap the cache")
            return False
        existing = self.listing.getDefinedDataAt(address)
        applied = existing is not None and existing.getDataType().isEquivalent(cache_type)
        if not applied:
            # Auto-analysis leaves undefinedN placeholders where code stores to
            # small caches; replace those, but keep any other existing data.
            overlapping = list(self.listing.getDefinedData(AddressSet(address, end), True))
            containing = self.listing.getDefinedDataContaining(address)
            if containing is not None:
                overlapping.append(containing)
            if any(not Undefined.isUndefined(data.getDataType()) for data in overlapping):
                self.summary["skipped"].append(reader["name"] + ": preserving existing data at cache address")
                return False
            DataUtilities.createData(self.program, address, cache_type, -1, False,
                                     DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
        self.label(reader["offsetCache"], "g_BcsvOffsets_" + identifier(reader["name"]))
        message = "%s runtime field-offset cache: %d signed 32-bit entries, initialized to -1. These are offsets, not row values or enum IDs." % (reader["name"], len(slots))
        if len(slots) < schema["fieldCount"]:
            message += " The game caches only %d of %d schema fields; slots were mapped from the field hashes their accessors compare." % (len(slots), schema["fieldCount"])
        self.comment(reader["offsetCache"], message)
        self.summary["matchedCaches"] += 1
        return True

    def import_index_enums(self, matches):
        seen = set()
        for match in matches:
            self.monitor.checkCancelled()
            definition = match["definition"]
            for width in definition["widths"]:
                name = definition["name"] + ("_u16" if width == 2 else "")
                if name in seen:
                    continue
                seen.add(name)
                category = "/ACNH/BCSV/IndexEnums"
                labels, used = [], set()
                for index, choice in enumerate(definition["choices"]):
                    label = ("Value_" + choice) if choice and choice[0].isdigit() else choice
                    label = label or "Value_%d" % index
                    if label in used:
                        label += "_%d" % index
                    used.add(label)
                    labels.append(label)
                current = self.existing_type(category, name)
                if current is not None:
                    if not isinstance(current, EnumDataType) and not hasattr(current, "getValue"):
                        self.summary["skipped"].append(name + ": existing non-enum type")
                        continue
                    try:
                        valid = current.getLength() == width and set(str(value) for value in current.getNames()) == set(labels)
                        valid = valid and all(current.getValue(label) == index for index, label in enumerate(labels))
                    except Exception:
                        valid = False
                    if not valid:
                        self.summary["skipped"].append(name + ": preserving an existing enum with different values")
                        continue
                else:
                    current = EnumDataType(CategoryPath(category), name, width, self.manager)
                    current.setDescription("Live string-table ordinals; not CRC32 hashes. Imported only after an exact bundled-choice match.")
                    for index, label in enumerate(labels):
                        current.add(label, index)
                    self.manager.addDataType(current, DataTypeConflictHandler.DEFAULT_HANDLER)
                self.summary["indexEnumTypes"] += 1
            self.label(match["address"], definition["name"] + "_Table")

    def relro_pointer(self, value):
        """Read a pointer from a GOT or .data.rel.ro slot; None for other memory."""
        address = self.address(value)
        block = self.program.getMemory().getBlock(address)
        if block is None or not block.isInitialized() or str(block.getName()) not in RELRO_BLOCKS:
            return None
        try:
            return int(self.program.getMemory().getLong(address)) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            return None

    def function_constants(self, function):
        entry = int(function.getEntryPoint().getOffset())
        if entry not in self.constants:
            found = set()
            for span in function.getBody().getAddressRanges():
                found.update(wide_constants(read_bytes(self.program.getMemory(), span.getMinAddress(), int(span.getLength()))))
            self.constants[entry] = found
        return self.constants[entry]

    def slot_uses(self, start, count, excluded=()):
        """({entry: {slot: (reads, writes)}}, {entry: function}) from Ghidra's references."""
        references = self.program.getReferenceManager()
        functions = self.program.getFunctionManager()
        uses, owners = defaultdict(lambda: defaultdict(lambda: [0, 0])), {}
        for slot in range(count):
            self.monitor.checkCancelled()
            for reference in references.getReferencesTo(self.address(start + 4 * slot)):
                kind = reference.getReferenceType()
                if not (kind.isRead() or kind.isWrite()):
                    continue
                function = functions.getFunctionContaining(reference.getFromAddress())
                if function is None:
                    continue
                entry = int(function.getEntryPoint().getOffset())
                if entry in excluded:
                    continue
                owners[entry] = function
                counts = uses[entry][slot]
                counts[0] += 1 if kind.isRead() else 0
                counts[1] += 1 if kind.isWrite() else 0
        return dict((entry, dict((slot, tuple(value)) for slot, value in slots.items()))
                    for entry, slots in uses.items()), owners

    def slot_votes(self, reader, start, count, schema):
        """Vote slot -> field from the field hash each slot's accessors compare."""
        excluded = set(reader["loadFunctions"]) | set([reader["getFileName"]])
        uses, owners = self.slot_uses(start, count, excluded)
        candidates = {}
        for entry, slots in uses.items():
            self.monitor.checkCancelled()
            candidates[entry] = (self.function_constants(owners[entry]), slots)
        return vote_cache_slots([field["hash"] for field in schema["fields"]], candidates)

    def scrape(self, readers, writable):
        decompiler = DecompInterface()
        decompiler.openProgram(self.program)
        self.monitor.initialize(len(readers))
        try:
            for index, reader in enumerate(readers):
                self.monitor.checkCancelled()
                self.monitor.setMessage("BCSV cache: " + reader["name"])
                self.monitor.setProgress(index)
                schema = self.schemas.get(reader["name"])
                if schema is None:
                    self.summary["skipped"].append(reader["name"] + ": no bundled schema")
                    continue
                matches = []
                for address in reader["loadFunctions"]:
                    function = self.program.getFunctionManager().getFunctionAt(self.address(address))
                    if function is None:
                        continue
                    result = decompiler.decompileFunction(function, 60, self.monitor)
                    if not result.decompileCompleted():
                        continue
                    def function_name(value):
                        target = self.program.getFunctionManager().getFunctionAt(self.address(value))
                        return str(target.getName()) if target is not None else ""
                    found = cache_from_pcode(pcode_operations(result.getHighFunction()), schema["fieldCount"], writable,
                                             function_name, self.relro_pointer)
                    if found:
                        matches.append(found)
                if len(matches) != len(reader["loadFunctions"]) or not matches or any(value != matches[0] for value in matches):
                    self.summary["skipped"].append(reader["name"] + ": cache initializer does not match the bundled schema")
                    continue
                count = matches[0]["cacheSize"] // 4
                votes = self.slot_votes(reader, matches[0]["offsetCache"], count, schema)
                if matches[0].get("partial"):
                    slots = map_cache_slots(count, votes)
                    if slots is None:
                        self.summary["skipped"].append("%s: cache holds %d of %d schema fields; the game omits unused fields" %
                                                       (reader["name"], count, schema["fieldCount"]))
                        continue
                    self.summary["partialCaches"] += 1
                else:
                    slots = list(range(count))
                    disagreements = order_disagreements(votes)
                    if votes and not disagreements:
                        self.summary["orderChecked"] += 1
                    labels = field_names(schema["fields"])
                    for slot, fields in disagreements:
                        self.summary["orderDisagreements"].append("%s slot %d (%s): accessors compare %s" % (
                            reader["name"], slot, labels[slot], ", ".join(labels[field] for field in fields)))
                reader.update(matches[0])
                self.caches.append((reader, schema, slots))
                self.apply_cache(reader, schema, slots)
        finally:
            decompiler.dispose()
        for schema in self.definitions["schemas"]:
            self.monitor.checkCancelled()
            if self.structure(schema) is not None:
                self.summary["rows"] += 1

    def name_accessors(self):
        """Comment every function that reads a matched cache and name accessors.

        Uses Ghidra's own read/write references to each cache slot, so no
        function is decompiled. Loaders and filename getters are excluded, and
        slots a function only writes (initializers, resets) are not reads.
        Earlier runs' field comments are replaced, and the accessor names they
        gave are corrected.
        """
        functions = self.program.getFunctionManager()
        uses, sizes, excluded = defaultdict(lambda: defaultdict(set)), {}, set()
        for reader, schema, slots in self.caches:
            excluded.add(reader["getFileName"])
            excluded.update(reader["loadFunctions"])
            labels = field_names(schema["fields"])
            references, owners = self.slot_uses(reader["offsetCache"], len(slots))
            for entry, counts in references.items():
                for position in own_slots(counts):
                    uses[entry][reader["name"]].add(labels[slots[position]])
                    sizes[entry] = int(owners[entry].getBody().getNumAddresses())
        memory = self.program.getMemory()
        finders = set(entry for entry in uses if entry not in excluded and is_field_finder(
            read_bytes(memory, self.address(entry), min(FINDER_SCAN, sizes[entry]) // 4 * 4)))
        names, comments = plan_accessors(uses, sizes, excluded, finders)
        parent = self.root()
        stale = (FIELD_COMMENT, FINDER_COMMENT)
        for entry in sorted(comments):
            self.monitor.checkCancelled()
            self.comment(entry, comments[entry], stale)
            self.summary["fieldReaders"] += 1
            if entry not in names:
                continue
            reader, name = names[entry]
            function = functions.getFunctionAt(self.address(entry))
            owner = self.namespace(parent, identifier(reader))
            current = str(function.getName())
            if current.startswith(("FUN_", "sub_")):
                pass
            elif not (function.getSymbol().getSource() == SourceType.ANALYSIS and OWN_ACCESSOR.match(current)):
                continue
            elif current == name and function.getParentNamespace() == owner:
                continue
            try:
                function.getSymbol().setNameAndNamespace(name, owner, SourceType.ANALYSIS)
                self.summary["finders" if name.startswith("FindField") else "accessors"] += 1
            except Exception as error:
                self.summary["skipped"].append("0x%X: cannot name %s accessor %s (%s)" % (entry, reader, name, error))
        # Field comments earlier runs left on functions that no longer read a matched cache.
        for address in self.listing.getCommentAddressIterator(CodeUnit.PRE_COMMENT, memory, True):
            entry = int(address.getOffset())
            if entry not in comments and functions.getFunctionAt(address) is not None and                     FIELD_COMMENT in str(self.listing.getComment(CodeUnit.PRE_COMMENT, address)):
                if self.comment(entry, None, stale):
                    self.summary["staleComments"] += 1


def run(program, monitor, script_directory, emit=print):
    if program is None or not str(program.getLanguageID()).startswith("AARCH64:LE:64"):
        raise ValueError("Open the analyzed ACNH AArch64 executable first")
    definitions = load_definitions(os.path.join(script_directory, "cylindrical_earth", "bcsv.json"))
    emit("Bundled BCSV schemas: %s; target executable: %s" % (definitions["schemaVersion"], definitions["targetVersion"]))
    blocks = read_blocks(program, monitor)
    monitor.setMessage("Identifying BCSV filename getters and reader vtables")
    readers = scan_readers(blocks[0], blocks[1], blocks[2], monitor.checkCancelled)
    if not readers:
        raise ValueError("No supported BCSV readers found; no annotations applied")
    # Copies, so the GOT is not scanned for enum strings below.
    image = Image(*[list(block) for block in blocks])
    for pair in got_blocks(program):
        image.constants.append(pair)
        image.blocks.append(pair)
    native = NativeBcsv(program, monitor, definitions)
    transaction = program.startTransaction("CylindricalEarth BCSV update")
    committed = False
    try:
        native.name_readers(readers, image)
        native.scrape(readers, blocks[3])
        monitor.setMessage("Matching known enum string tables")
        matches = scan_index_tables(blocks[1], blocks[2], definitions["indexEnums"], monitor.checkCancelled)
        native.import_index_enums(matches)
        monitor.setMessage("Naming BCSV field accessors")
        native.name_accessors()
        monitor.checkCancelled()
        committed = True
    finally:
        program.endTransaction(transaction, committed)
    emit("BCSV readers: %d (%d derived classes, %d methods named); matched caches: %d; row layouts: %d; index enum types: %d" %
          (native.summary["readers"], native.summary["derivedReaders"], native.summary["readerMethods"],
           native.summary["matchedCaches"], native.summary["rows"], native.summary["indexEnumTypes"]))
    emit("Reader class structures created: %d; methods given a typed this: %d; signatures an earlier run locked restored: %d" %
         (native.summary["readerTypes"], native.summary["typedMethods"], native.summary["unlockedMethods"]))
    emit("Partial caches mapped by accessor hashes: %d; full caches whose accessor hashes confirm schema order: %d" %
         (native.summary["partialCaches"], native.summary["orderChecked"]))
    emit("Functions reading cached fields: %d commented; %d single-field accessors and %d FindField helpers named; "
         "%d outdated field comments removed" % (native.summary["fieldReaders"], native.summary["accessors"],
                                                 native.summary["finders"], native.summary["staleComments"]))
    for disagreement in native.summary["orderDisagreements"]:
        emit("Order check: " + disagreement)
    for skipped in native.summary["skipped"]:
        emit("Skipped: " + skipped)
    emit("Finished. Review the annotations and save the program.")
    return native.summary
