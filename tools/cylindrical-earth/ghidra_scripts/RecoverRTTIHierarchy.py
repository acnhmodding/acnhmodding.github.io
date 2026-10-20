# -*- coding: utf-8 -*-
# Recover and validate the game's custom RTTI chains and annotate matching vtables.
#@category ACNH.CylindricalEarth
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import os
import sys
script_directory = os.path.dirname(str(getSourceFile().getAbsolutePath()))
if script_directory not in sys.path:
    sys.path.insert(0, script_directory)
from cylindrical_earth.analysis import run_rtti
run_rtti(currentProgram, monitor, script_directory, emit=println)
