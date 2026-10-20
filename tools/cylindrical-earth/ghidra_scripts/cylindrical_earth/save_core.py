# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable schema validation and save-name hashing; no Ghidra dependency."""
import json


def murmur32(value):
    data = bytearray(value.encode('utf-8'))
    mask = 0xffffffff
    def rotate(v, n):
        return ((v << n) | (v >> (32 - n))) & mask
    h = 0
    for i in range(0, len(data) - len(data) % 4, 4):
        k = sum(data[i + j] << (8 * j) for j in range(4))
        k = rotate(k * 0xcc9e2d51 & mask, 15) * 0x1b873593 & mask
        h = rotate(h ^ k, 13)
        h = (h * 5 + 0xe6546b64) & mask
    tail = len(data) - len(data) % 4
    k = sum(data[tail + j] << (8 * j) for j in range(len(data) % 4))
    if len(data) % 4:
        h ^= rotate(k * 0xcc9e2d51 & mask, 15) * 0x1b873593 & mask
    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85ebca6b & mask
    h ^= h >> 13
    h = h * 0xc2b2ae35 & mask
    return (h ^ (h >> 16)) & mask


def validate(schema):
    types = schema['types']
    all_types = dict(schema['primitives'])
    all_types.update(types)
    seen_names = set()
    for h, t in all_types.items():
        if t['size'] <= 0 or t['cname'] in seen_names:
            raise ValueError('Invalid size or duplicate type name: ' + h)
        seen_names.add(t['cname'])
        if not t['name'].startswith('Unknown_') and murmur32(t['name']) != int(h):
            raise ValueError('Type name does not match hash: ' + h)
        end = 0
        fields = set()
        for f in t.get('fields', []):
            if f['offset'] < end or f['id'] in fields:
                raise ValueError('Overlapping or duplicate field in ' + h)
            fields.add(f['id'])
            if not f['name'].startswith('Unknown_') and murmur32(f['name']) != f['id']:
                raise ValueError('Field name does not match hash in ' + h)
            child = all_types[str(f['type'])]
            if f['size'] != child['size'] or len(f['length']) != 2 or min(f['length']) < 1:
                raise ValueError('Invalid field dimensions in ' + h)
            end = f['offset'] + f['size'] * f['length'][0] * f['length'][1]
            if end > t['size']:
                raise ValueError('Field exceeds structure in ' + h)
    visiting, done, ordered = set(), set(), []
    def visit(h):
        if h in visiting:
            raise ValueError('Recursive payload type: ' + h)
        if h in done:
            return
        visiting.add(h)
        for f in types[h]['fields']:
            child = str(f['type'])
            if child in types:
                visit(child)
        visiting.remove(h)
        done.add(h)
        ordered.append(h)
    for h in sorted(types):
        visit(h)
    return ordered


def load(path):
    with open(path, 'r') as stream:
        schema = json.load(stream)
    validate(schema)
    return schema
