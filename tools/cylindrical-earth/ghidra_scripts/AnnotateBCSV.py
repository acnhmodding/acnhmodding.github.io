# -*- coding: utf-8 -*-
# Identify ACNH BCSV readers, import bundled row layouts, offset caches and enums.
#@category ACNH.CylindricalEarth
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import os
import sys

script_directory = os.path.dirname(str(getSourceFile().getAbsolutePath()))
if script_directory not in sys.path:
    sys.path.insert(0, script_directory)
from cylindrical_earth.bcsv import run

run(currentProgram, monitor, script_directory, emit=println)
