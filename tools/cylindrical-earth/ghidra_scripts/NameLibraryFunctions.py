# -*- coding: utf-8 -*-
# Name library functions (dynamic symbols, sead fingerprints), sead singletons and hot functions.
#@category ACNH.CylindricalEarth
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import os
import sys
script_directory = os.path.dirname(str(getSourceFile().getAbsolutePath()))
if script_directory not in sys.path:
    sys.path.insert(0, script_directory)
from cylindrical_earth.library import run_library
run_library(currentProgram, monitor, script_directory, emit=println)
