# -*- coding: utf-8 -*-
# Name state-machine enter/exec/exit callbacks from their registered state names.
#@category ACNH.CylindricalEarth
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import print_function
import os
import sys
script_directory = os.path.dirname(str(getSourceFile().getAbsolutePath()))
if script_directory not in sys.path:
    sys.path.insert(0, script_directory)
from cylindrical_earth.states import run_states
run_states(currentProgram, monitor, script_directory, emit=println)
