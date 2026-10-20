# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Updated native Ghidra adaptation of Treeki/CylindricalEarth's BCSV scripts.
from __future__ import print_function
import os
from collections import defaultdict
from java.lang import String
from java.nio import ByteBuffer
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (
    ArrayDataType, CategoryPath, CharDataType, DataTypeConflictHandler,
    DataUtilities, EnumDataType, FloatDataType, IntegerDataType,
    ShortDataType, SignedByteDataType, Structure, StructureDataType, Undefined,
    UnsignedCharDataType, UnsignedIntegerDataType, UnsignedShortDataType,
)
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from .bcsv_core import (cache_from_pcode, field_names, identifier, load_definitions, map_cache_slots,
                   order_disagreements, own_slots, plan_accessors, scan_index_tables, scan_readers,
                   vote_cache_slots, wide_constants)

RELRO_BLOCKS = (".got", ".got.plt", ".data.rel.ro")

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
        self.summary = {"readers": 0, "matchedCaches": 0, "rows": 0, "indexEnumTypes": 0,
                        "fieldReaders": 0, "accessors": 0, "partialCaches": 0, "orderChecked": 0,
                        "orderDisagreements": [], "skipped": []}
        self.caches = []
        self.constants = {}

    def address(self, value):
        return self.space.getAddress(value)

    def comment(self, address, message):
        address = self.address(address)
        previous = self.listing.getComment(CodeUnit.PRE_COMMENT, address)
        if previous and message in str(previous):
            return
        self.listing.setComment(address, CodeUnit.PRE_COMMENT,
                                str(previous) + "\n\n" + message if previous else message)

    def namespace(self, parent, name):
        value = self.symbols.getNamespace(name, parent)
        return value if value is not None else self.symbols.createNameSpace(parent, name, SourceType.ANALYSIS)

    def label(self, value, name, namespace=None):
        address = self.address(value)
        previous = self.symbols.getPrimarySymbol(address)
        if previous is not None and not previous.isDynamic() and not str(previous.getName()).startswith(("DAT_", "PTR_", "UNK_")):
            return
        if namespace is None:
            namespace = self.program.getGlobalNamespace()
        self.symbols.createLabel(address, name, namespace, SourceType.ANALYSIS)

    def name_readers(self, readers):
        parent = self.namespace(self.program.getGlobalNamespace(), "Bcsv")
        for reader in readers:
            self.monitor.checkCancelled()
            namespace = self.namespace(parent, identifier(reader["name"]))
            for table in reader["vtables"]:
                self.label(table, "vtable", namespace)
                self.comment(table, "BCSV reader for " + reader["name"] + ".bcsv; filename getter at vtable +0x30 and loader at +0x20.")
            methods = [(reader["getFileName"], "GetFileName")]
            methods.extend((address, "Load") for address in reader["loadFunctions"])
            for address, name in methods:
                function = self.program.getFunctionManager().getFunctionAt(self.address(address))
                if function is not None and str(function.getName()).startswith(("FUN_", "sub_")):
                    function.setParentNamespace(namespace)
                    function.setName(name, SourceType.ANALYSIS)
        self.summary["readers"] = len(readers)

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
        names, comments = plan_accessors(uses, sizes, excluded)
        parent = self.namespace(self.program.getGlobalNamespace(), "Bcsv")
        for entry in sorted(comments):
            self.monitor.checkCancelled()
            self.comment(entry, comments[entry])
            self.summary["fieldReaders"] += 1
            if entry not in names:
                continue
            reader, name = names[entry]
            function = functions.getFunctionAt(self.address(entry))
            if not str(function.getName()).startswith(("FUN_", "sub_")):
                continue
            try:
                function.getSymbol().setNameAndNamespace(name, self.namespace(parent, identifier(reader)),
                                                         SourceType.ANALYSIS)
                self.summary["accessors"] += 1
            except Exception as error:
                self.summary["skipped"].append("0x%X: cannot name %s accessor %s (%s)" % (entry, reader, name, error))


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
    native = NativeBcsv(program, monitor, definitions)
    transaction = program.startTransaction("CylindricalEarth BCSV update")
    committed = False
    try:
        native.name_readers(readers)
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
    emit("BCSV readers: %d; matched caches: %d; row layouts: %d; index enum types: %d" %
          (native.summary["readers"], native.summary["matchedCaches"], native.summary["rows"], native.summary["indexEnumTypes"]))
    emit("Partial caches mapped by accessor hashes: %d; full caches whose accessor hashes confirm schema order: %d" %
         (native.summary["partialCaches"], native.summary["orderChecked"]))
    emit("Functions reading cached fields: %d commented; %d single-field accessors named" %
         (native.summary["fieldReaders"], native.summary["accessors"]))
    for disagreement in native.summary["orderDisagreements"]:
        emit("Order check: " + disagreement)
    for skipped in native.summary["skipped"]:
        emit("Skipped: " + skipped)
    emit("Finished. Review the annotations and save the program.")
    return native.summary
