# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native Ghidra importer for serialized payloads, independent of SaveIO nodes."""
from __future__ import print_function
import os
from ghidra.program.model.data import (
    ArrayDataType, BooleanDataType, CategoryPath, DataTypeConflictHandler,
    DoubleDataType, FloatDataType, IntegerDataType, LongLongDataType,
    ShortDataType, SignedByteDataType, Structure, StructureDataType, TypedefDataType,
    UnsignedCharDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
    UnsignedShortDataType,
)
from .save_core import load, validate


def placeholder(name):
    return str(name).startswith(('Unknown_', 'Hash_', 'ACNH_Unknown_'))


class SaveImporter:
    def __init__(self, program, monitor, schema):
        self.manager = program.getDataTypeManager()
        self.monitor, self.schema = monitor, schema
        self.category = CategoryPath('/ACNH/Save/' + schema['schema'])
        self.types, self.skipped = {}, []
        self.updated = 0
        self.existing = {}
        iterator = self.manager.getAllDataTypes()
        while iterator.hasNext():
            dt = iterator.next()
            if str(dt.getCategoryPath()) == str(self.category):
                description = str(dt.getDescription() or '')
                if description.startswith('saveschema '):
                    self.existing[description.split()[1].lower()] = dt

    def existing_type(self, h, entry):
        return self.existing.get('%08x' % int(h)) or self.manager.getDataType(self.category, entry['cname'])

    def store(self, h, entry, fresh):
        old = self.existing_type(h, entry)
        if old is not None:
            if old.getLength() != fresh.getLength():
                self.skipped.append(entry['cname'] + ': incompatible size')
                return
            if isinstance(fresh, Structure):
                if not isinstance(old, Structure):
                    self.skipped.append(entry['cname'] + ': incompatible type kind')
                    return
                a, b = list(old.getDefinedComponents()), list(fresh.getDefinedComponents())
                if len(a) != len(b) or any(x.getOffset() != y.getOffset() or
                        x.getLength() != y.getLength() or
                        not x.getDataType().isEquivalent(y.getDataType()) for x, y in zip(a, b)):
                    self.skipped.append(entry['cname'] + ': incompatible field layout')
                    return
                for previous, new in zip(a, b):
                    if placeholder(previous.getFieldName()) and not placeholder(new.getFieldName()):
                        previous.setFieldName(new.getFieldName())
                        self.updated += 1
            elif not old.isEquivalent(fresh):
                self.skipped.append(entry['cname'] + ': incompatible external type')
                return
            if placeholder(old.getName()) and not placeholder(entry['cname']):
                occupied = self.manager.getDataType(self.category, entry['cname'])
                if occupied is None:
                    old.setName(entry['cname'])
                    self.updated += 1
            self.types[h] = old
        else:
            if isinstance(fresh, Structure):
                fresh.setDescription('saveschema %08x schema %s; %s' %
                                     (int(h), self.schema['schema'], entry['name']))
            self.types[h] = self.manager.addDataType(fresh, DataTypeConflictHandler.DEFAULT_HANDLER)

    def import_types(self):
        ordered = validate(self.schema)
        scalar = {'bool': BooleanDataType.dataType, 'u8': UnsignedCharDataType.dataType,
                  's8': SignedByteDataType.dataType, 'u16': UnsignedShortDataType.dataType,
                  'char16': UnsignedShortDataType.dataType, 's16': ShortDataType.dataType,
                  'u32': UnsignedIntegerDataType.dataType, 's32': IntegerDataType.dataType,
                  'u64': UnsignedLongLongDataType.dataType, 's64': LongLongDataType.dataType,
                  'f32': FloatDataType.dataType, 'f64': DoubleDataType.dataType}
        for h, entry in sorted(self.schema['primitives'].items()):
            self.monitor.checkCancelled()
            base = scalar.get(entry['name'])
            if base is not None and base.getLength() == entry['size']:
                fresh = TypedefDataType(self.category, entry['cname'], base, self.manager)
            else:
                fresh = StructureDataType(self.category, entry['cname'], entry['size'], self.manager)
                raw = ArrayDataType(UnsignedCharDataType.dataType, entry['size'], 1)
                fresh.replaceAtOffset(0, raw, raw.getLength(), 'opaque',
                                      'External type; internal layout is not described by Smmh.')
            self.store(h, entry, fresh)
        for h in ordered:
            self.monitor.checkCancelled()
            entry = self.schema['types'][h]
            self.monitor.setMessage('Importing ' + entry['cname'])
            if any(str(f['type']) not in self.types for f in entry['fields']):
                self.skipped.append(entry['cname'] + ': incompatible dependency')
                continue
            fresh = StructureDataType(self.category, entry['cname'], entry['size'], self.manager)
            for f in entry['fields']:
                dt = self.types[str(f['type'])]
                for count in reversed(f['length']):
                    if count > 1:
                        dt = ArrayDataType(dt, count, dt.getLength())
                comment = 'field %08X; type %08X; schema alignment %d' % (f['id'], f['type'], f['alignment'])
                fresh.replaceAtOffset(f['offset'], dt, dt.getLength(), f['name'], comment)
            self.store(h, entry, fresh)
        return self


def run(program, monitor, directory, emit=print):
    if program is None:
        raise ValueError('Open the game program before running this script.')
    schema = load(os.path.join(directory, 'cylindrical_earth', 'save.json'))
    tx = program.startTransaction('Import ACNH 3.0 save schema')
    committed = False
    try:
        importer = SaveImporter(program, monitor, schema).import_types()
        monitor.checkCancelled()
        committed = True
    finally:
        program.endTransaction(tx, committed)
    emit('ACNH save schema %s: %d payload structures, %d external types imported/reused; %d names improved.' %
         (schema['schema'], sum(h in importer.types for h in schema['types']),
          sum(h in importer.types for h in schema['primitives']), importer.updated))
    for message in importer.skipped:
        emit('Skipped ' + message)
    emit('Types: /ACNH/Save/%s. These are serialized payloads; apply them to payload buffers.' % schema['schema'])
    return importer
